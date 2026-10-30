/*
 * Copyright (C) 2025-2026 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 * Copyright (C) 2026 Håvard Sørbø <havard@hsorbo.no>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gummoduleregistry-priv.h"

#include "gummodule-windows.h"
#include "gum/guminterceptor.h"

#include <psapi.h>
#include <winternl.h>

#define GUM_DLL_NOTIFICATION_REASON_LOADED 1
#define GUM_DLL_NOTIFICATION_REASON_UNLOADED 2

typedef struct _GumDllNotificationData GumDllNotificationData;
typedef void (CALLBACK * GumDllNotificationFunc) (ULONG reason,
    const GumDllNotificationData * data, PVOID context);
typedef NTSTATUS (NTAPI * GumLdrRegisterDllNotificationFunc) (ULONG flags,
    GumDllNotificationFunc func, PVOID context, PVOID * cookie);
typedef NTSTATUS (NTAPI * GumLdrUnregisterDllNotificationFunc) (PVOID cookie);

struct _GumDllNotificationData
{
  ULONG flags;
  PCUNICODE_STRING full_dll_name;
  PCUNICODE_STRING base_dll_name;
  PVOID dll_base;
  ULONG size_of_image;
};

static gboolean gum_try_subscribe_to_loader (GumModuleRegistry * registry);
static void gum_unsubscribe_from_loader (void);
static void CALLBACK gum_module_registry_on_dll_notification (ULONG reason,
    const GumDllNotificationData * data, PVOID context);
static void gum_hook_loader (GumModuleRegistry * registry);
static void gum_unhook_loader (void);
static void gum_module_registry_on_loader_leave (GumInvocationContext * ic,
    gpointer user_data);
static void gum_module_registry_synchronize_modules (
    GumModuleRegistry * registry);
static GPtrArray * gum_snapshot_loaded_modules (void);
static void gum_module_registry_add_module (GumModuleRegistry * registry,
    HMODULE handle);
static void gum_module_registry_remove_module (GumModuleRegistry * registry,
    HMODULE handle);

static GHashTable * gum_current_modules;

static gpointer gum_loader_subscription;

static GumInterceptor * gum_ldr_interceptor;
static GumInvocationListener * gum_loader_handler;

void
_gum_module_registry_activate (GumModuleRegistry * self)
{
  gum_current_modules = g_hash_table_new (NULL, NULL);

  if (!gum_try_subscribe_to_loader (self))
    gum_hook_loader (self);
  gum_module_registry_synchronize_modules (self);
}

void
_gum_module_registry_deactivate (GumModuleRegistry * self)
{
  if (gum_loader_subscription != NULL)
    gum_unsubscribe_from_loader ();
  else
    gum_unhook_loader ();

  g_clear_pointer (&gum_current_modules, g_hash_table_unref);
}

static gboolean
gum_try_subscribe_to_loader (GumModuleRegistry * registry)
{
  GumLdrRegisterDllNotificationFunc register_impl;

  register_impl = (GumLdrRegisterDllNotificationFunc) GetProcAddress (
      GetModuleHandleW (L"ntdll.dll"), "LdrRegisterDllNotification");
  if (register_impl == NULL)
    return FALSE;

  register_impl (0, gum_module_registry_on_dll_notification, registry,
      &gum_loader_subscription);

  return TRUE;
}

static void
gum_unsubscribe_from_loader (void)
{
  GumLdrUnregisterDllNotificationFunc unregister_impl;

  unregister_impl = (GumLdrUnregisterDllNotificationFunc) GetProcAddress (
      GetModuleHandleW (L"ntdll.dll"), "LdrUnregisterDllNotification");

  unregister_impl (gum_loader_subscription);
  gum_loader_subscription = NULL;
}

static void CALLBACK
gum_module_registry_on_dll_notification (ULONG reason,
                                         const GumDllNotificationData * data,
                                         PVOID context)
{
  GumModuleRegistry * registry = context;
  HMODULE handle = data->dll_base;

  if (reason == GUM_DLL_NOTIFICATION_REASON_LOADED)
    gum_module_registry_add_module (registry, handle);
  else
    gum_module_registry_remove_module (registry, handle);
}

static void
gum_hook_loader (GumModuleRegistry * registry)
{
  HMODULE ntdll;
  gpointer load_impl, unload_impl;
  GumAttachOptions options = { .ignorability = GUM_INVOCATION_UNIGNORABLE };

  ntdll = GetModuleHandleW (L"ntdll.dll");
  load_impl = GetProcAddress (ntdll, "LdrLoadDll");
  unload_impl = GetProcAddress (ntdll, "LdrUnloadDll");
  if (load_impl == NULL || unload_impl == NULL)
    g_error ("Unsupported Windows version; please file a bug");

  gum_ldr_interceptor = gum_interceptor_obtain ();
  gum_loader_handler = gum_make_call_listener (NULL,
      gum_module_registry_on_loader_leave, registry, NULL);

  gum_interceptor_begin_transaction (gum_ldr_interceptor);
  gum_interceptor_attach (gum_ldr_interceptor, load_impl, gum_loader_handler,
      &options);
  gum_interceptor_attach (gum_ldr_interceptor, unload_impl, gum_loader_handler,
      &options);
  gum_interceptor_end_transaction (gum_ldr_interceptor);
}

static void
gum_unhook_loader (void)
{
  if (gum_loader_handler == NULL)
    return;

  gum_interceptor_detach (gum_ldr_interceptor, gum_loader_handler);

  g_object_unref (gum_loader_handler);
  g_object_unref (gum_ldr_interceptor);
  gum_loader_handler = NULL;
  gum_ldr_interceptor = NULL;
}

static void
gum_module_registry_on_loader_leave (GumInvocationContext * ic,
                                     gpointer user_data)
{
  gum_module_registry_synchronize_modules (user_data);
}

static void
gum_module_registry_synchronize_modules (GumModuleRegistry * registry)
{
  GPtrArray * handles;
  GHashTable * modules;
  guint i;
  GHashTableIter iter;
  gpointer handle;
  GQueue removed = G_QUEUE_INIT;

  gum_module_registry_lock (registry);

  handles = gum_snapshot_loaded_modules ();
  if (handles == NULL)
    goto beach;

  modules = g_hash_table_new (NULL, NULL);
  for (i = 0; i != handles->len; i++)
    g_hash_table_add (modules, g_ptr_array_index (handles, i));

  g_hash_table_iter_init (&iter, gum_current_modules);
  while (g_hash_table_iter_next (&iter, &handle, NULL))
  {
    if (!g_hash_table_contains (modules, handle))
      g_queue_push_tail (&removed, handle);
  }

  while ((handle = g_queue_pop_head (&removed)) != NULL)
    gum_module_registry_remove_module (registry, handle);

  for (i = 0; i != handles->len; i++)
    gum_module_registry_add_module (registry, g_ptr_array_index (handles, i));

  g_hash_table_unref (modules);
  g_ptr_array_unref (handles);

beach:
  gum_module_registry_unlock (registry);
}

static GPtrArray *
gum_snapshot_loaded_modules (void)
{
  GPtrArray * modules;
  HANDLE this_process;
  DWORD needed;

  modules = g_ptr_array_sized_new (1);
  g_ptr_array_set_size (modules, 1);

  this_process = GetCurrentProcess ();

  while (TRUE)
  {
    if (!EnumProcessModules (this_process, (HMODULE *) modules->pdata,
          modules->len * sizeof (HMODULE), &needed))
      goto failure;

    if (needed <= modules->len * sizeof (HMODULE))
      break;

    g_ptr_array_set_size (modules, needed / sizeof (HMODULE));
  }

  g_ptr_array_set_size (modules, needed / sizeof (HMODULE));

  return modules;

failure:
  {
    g_ptr_array_unref (modules);
    return NULL;
  }
}

static void
gum_module_registry_add_module (GumModuleRegistry * registry,
                                HMODULE handle)
{
  GumNativeModule * module;

  gum_module_registry_lock (registry);

  if (g_hash_table_contains (gum_current_modules, handle))
    goto beach;

  g_hash_table_add (gum_current_modules, handle);

  module = _gum_native_module_make (handle);
  _gum_module_registry_register (registry, GUM_MODULE (module));
  g_object_unref (module);

beach:
  gum_module_registry_unlock (registry);
}

static void
gum_module_registry_remove_module (GumModuleRegistry * registry,
                                   HMODULE handle)
{
  gum_module_registry_lock (registry);

  if (g_hash_table_remove (gum_current_modules, handle))
    _gum_module_registry_unregister (registry, GUM_ADDRESS (handle));

  gum_module_registry_unlock (registry);
}
