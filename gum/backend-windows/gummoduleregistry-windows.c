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

static void gum_hook_loader (GumModuleRegistry * registry);
static void gum_unhook_loader (void);
static void gum_module_registry_on_loader_leave (GumInvocationContext * ic,
    gpointer user_data);
static void gum_module_registry_synchronize_modules (
    GumModuleRegistry * registry);
static GHashTable * gum_snapshot_loaded_modules (void);

static GHashTable * gum_current_modules;

static GumInterceptor * gum_ldr_interceptor;
static GumInvocationListener * gum_loader_handler;

void
_gum_module_registry_activate (GumModuleRegistry * self)
{
  gum_current_modules = g_hash_table_new (NULL, NULL);

  gum_hook_loader (self);
  gum_module_registry_synchronize_modules (self);
}

void
_gum_module_registry_deactivate (GumModuleRegistry * self)
{
  gum_unhook_loader ();

  g_clear_pointer (&gum_current_modules, g_hash_table_unref);
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
  GHashTable * modules;
  GHashTableIter iter;
  gpointer handle;
  GQueue added = G_QUEUE_INIT;
  GQueue removed = G_QUEUE_INIT;

  gum_module_registry_lock (registry);

  modules = gum_snapshot_loaded_modules ();
  if (modules == NULL)
    goto beach;

  g_hash_table_iter_init (&iter, modules);
  while (g_hash_table_iter_next (&iter, &handle, NULL))
  {
    if (!g_hash_table_contains (gum_current_modules, handle))
      g_queue_push_tail (&added, handle);
  }

  g_hash_table_iter_init (&iter, gum_current_modules);
  while (g_hash_table_iter_next (&iter, &handle, NULL))
  {
    if (!g_hash_table_contains (modules, handle))
      g_queue_push_tail (&removed, handle);
  }

  g_hash_table_unref (gum_current_modules);
  gum_current_modules = modules;

  while ((handle = g_queue_pop_head (&removed)) != NULL)
    _gum_module_registry_unregister (registry, GUM_ADDRESS (handle));

  while ((handle = g_queue_pop_head (&added)) != NULL)
  {
    GumNativeModule * module = _gum_native_module_make (handle);

    _gum_module_registry_register (registry, GUM_MODULE (module));

    g_object_unref (module);
  }

beach:
  gum_module_registry_unlock (registry);
}

static GHashTable *
gum_snapshot_loaded_modules (void)
{
  GHashTable * modules;
  HANDLE this_process;
  HMODULE * handles;
  DWORD size, needed;
  guint n, i;

  this_process = GetCurrentProcess ();

  size = sizeof (HMODULE);
  handles = g_malloc (size);

  while (TRUE)
  {
    if (!EnumProcessModules (this_process, handles, size, &needed))
      goto failure;
    if (needed <= size)
      break;
    size = needed;
    handles = g_realloc (handles, size);
  }

  modules = g_hash_table_new (NULL, NULL);

  n = needed / sizeof (HMODULE);
  for (i = 0; i != n; i++)
    g_hash_table_add (modules, handles[i]);

  g_free (handles);

  return modules;

failure:
  {
    g_free (handles);
    return NULL;
  }
}
