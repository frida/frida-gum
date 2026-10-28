/*
 * Copyright (C) 2026 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gum/gumwindowsmoduleresolver.h"

#include "gummodule-windows.h"

#include <psapi.h>
#include <string.h>

struct _GumWindowsModuleResolver
{
  GObject parent;

  HANDLE process;
  GHashTable * modules;
  GumAddress load_library;
};

static void gum_windows_module_resolver_iface_init (gpointer g_iface,
    gpointer iface_data);
static void gum_windows_module_resolver_dispose (GObject * object);
static void gum_windows_module_resolver_finalize (GObject * object);
static GumModule * gum_windows_module_resolver_find_module_by_name (
    GumModuleResolver * resolver, const gchar * name);
static GumAddress gum_windows_module_resolver_find_dynamic_address (
    GumModuleResolver * resolver, const gchar * symbol);
static GumNativeModule * gum_windows_module_resolver_find_loaded_module (
    GumWindowsModuleResolver * self, const gchar * name, guint32 handle);
static guint32 gum_windows_module_resolver_load_module (
    GumWindowsModuleResolver * self, const gchar * name);
static GumNativeModule * gum_windows_module_resolver_get_module (
    GumWindowsModuleResolver * self, HMODULE handle);

static gchar * gum_normalize_module_name (const gchar * name);

G_DEFINE_TYPE_WITH_CODE (GumWindowsModuleResolver,
                         gum_windows_module_resolver,
                         G_TYPE_OBJECT,
                         G_IMPLEMENT_INTERFACE (GUM_TYPE_MODULE_RESOLVER,
                             gum_windows_module_resolver_iface_init))

static void
gum_windows_module_resolver_class_init (GumWindowsModuleResolverClass * klass)
{
  GObjectClass * object_class = G_OBJECT_CLASS (klass);

  object_class->dispose = gum_windows_module_resolver_dispose;
  object_class->finalize = gum_windows_module_resolver_finalize;
}

static void
gum_windows_module_resolver_iface_init (gpointer g_iface,
                                        gpointer iface_data)
{
  GumModuleResolverInterface * iface = g_iface;

  iface->find_module_by_name = gum_windows_module_resolver_find_module_by_name;
  iface->find_dynamic_address =
      gum_windows_module_resolver_find_dynamic_address;
}

static void
gum_windows_module_resolver_init (GumWindowsModuleResolver * self)
{
  self->modules = g_hash_table_new_full (NULL, NULL, NULL, g_object_unref);
  self->load_library = GUM_ADDRESS (
      GetProcAddress (GetModuleHandleW (L"kernel32.dll"), "LoadLibraryW"));
}

static void
gum_windows_module_resolver_dispose (GObject * object)
{
  GumWindowsModuleResolver * self = GUM_WINDOWS_MODULE_RESOLVER (object);
  GHashTableIter iter;
  GumNativeModule * module;

  g_hash_table_iter_init (&iter, self->modules);
  while (g_hash_table_iter_next (&iter, NULL, (gpointer *) &module))
    _gum_native_module_detach_resolver (module);
  g_hash_table_remove_all (self->modules);

  G_OBJECT_CLASS (gum_windows_module_resolver_parent_class)->dispose (object);
}

static void
gum_windows_module_resolver_finalize (GObject * object)
{
  GumWindowsModuleResolver * self = GUM_WINDOWS_MODULE_RESOLVER (object);

  g_hash_table_unref (self->modules);
  CloseHandle (self->process);

  G_OBJECT_CLASS (gum_windows_module_resolver_parent_class)->finalize (
      object);
}

GumWindowsModuleResolver *
gum_windows_module_resolver_new (HANDLE process)
{
  GumWindowsModuleResolver * resolver;

  resolver = g_object_new (GUM_WINDOWS_TYPE_MODULE_RESOLVER, NULL);
  DuplicateHandle (GetCurrentProcess (), process, GetCurrentProcess (),
      &resolver->process, 0, FALSE, DUPLICATE_SAME_ACCESS);

  return resolver;
}

static GumModule *
gum_windows_module_resolver_find_module_by_name (GumModuleResolver * resolver,
                                                 const gchar * name)
{
  GumWindowsModuleResolver * self = GUM_WINDOWS_MODULE_RESOLVER (resolver);
  gchar * normalized_name;
  GumNativeModule * module;

  normalized_name = gum_normalize_module_name (name);

  module = gum_windows_module_resolver_find_loaded_module (self,
      normalized_name, 0);
  if (module == NULL)
  {
    guint32 handle = gum_windows_module_resolver_load_module (self, name);

    if (handle != 0)
    {
      module = gum_windows_module_resolver_find_loaded_module (self, NULL,
          handle);
    }
  }

  g_free (normalized_name);

  return (module != NULL) ? g_object_ref (GUM_MODULE (module)) : NULL;
}

static GumAddress
gum_windows_module_resolver_find_dynamic_address (GumModuleResolver * resolver,
                                                  const gchar * symbol)
{
  GumWindowsModuleResolver * self = GUM_WINDOWS_MODULE_RESOLVER (resolver);
  GumAddress address = 0;
  HMODULE handles[1024];
  DWORD size_needed;
  guint i;

  if (!EnumProcessModules (self->process, handles, sizeof (handles),
      &size_needed))
  {
    return 0;
  }

  for (i = 0; i != MIN (size_needed, sizeof (handles)) / sizeof (HMODULE) &&
      address == 0; i++)
  {
    GumNativeModule * module;

    module = gum_windows_module_resolver_get_module (self, handles[i]);
    address = gum_module_find_export_by_name (GUM_MODULE (module), symbol);
  }

  return address;
}

static GumNativeModule *
gum_windows_module_resolver_find_loaded_module (GumWindowsModuleResolver * self,
                                                const gchar * name,
                                                guint32 handle)
{
  HMODULE handles[1024];
  DWORD size_needed;
  guint i;

  if (!EnumProcessModules (self->process, handles, sizeof (handles),
      &size_needed))
  {
    return NULL;
  }

  for (i = 0; i != MIN (size_needed, sizeof (handles)) / sizeof (HMODULE); i++)
  {
    GumNativeModule * module;
    gchar * module_name;
    gboolean matches;

    if (name != NULL)
    {
      module = gum_windows_module_resolver_get_module (self, handles[i]);
      module_name = gum_normalize_module_name (
          gum_module_get_name (GUM_MODULE (module)));
      matches = strcmp (module_name, name) == 0;
      g_free (module_name);
    }
    else
    {
      matches = (guint32) GPOINTER_TO_SIZE (handles[i]) == handle;
    }

    if (matches)
      return gum_windows_module_resolver_get_module (self, handles[i]);
  }

  return NULL;
}

static guint32
gum_windows_module_resolver_load_module (GumWindowsModuleResolver * self,
                                         const gchar * name)
{
  DWORD result = 0;
  gunichar2 * name_utf16;
  glong name_length;
  gsize name_size;
  gpointer remote_name;
  HANDLE thread;

  name_utf16 = g_utf8_to_utf16 (name, -1, NULL, &name_length, NULL);
  name_size = (name_length + 1) * sizeof (gunichar2);

  remote_name = VirtualAllocEx (self->process, NULL, name_size,
      MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
  if (remote_name == NULL)
    goto beach;

  if (!WriteProcessMemory (self->process, remote_name, name_utf16, name_size,
      NULL))
  {
    goto beach;
  }

  thread = CreateRemoteThread (self->process, NULL, 0,
      GUM_POINTER_TO_FUNCPTR (LPTHREAD_START_ROUTINE,
          GSIZE_TO_POINTER (self->load_library)),
      remote_name, 0, NULL);
  if (thread == NULL)
    goto beach;

  WaitForSingleObject (thread, INFINITE);
  GetExitCodeThread (thread, &result);
  CloseHandle (thread);

beach:
  if (remote_name != NULL)
    VirtualFreeEx (self->process, remote_name, 0, MEM_RELEASE);
  g_free (name_utf16);

  return result;
}

static GumNativeModule *
gum_windows_module_resolver_get_module (GumWindowsModuleResolver * self,
                                        HMODULE handle)
{
  GumNativeModule * module;

  module = g_hash_table_lookup (self->modules, handle);
  if (module == NULL)
  {
    module = _gum_native_module_make_remote (handle, self->process, self);
    g_hash_table_insert (self->modules, handle, module);
  }

  return module;
}

static gchar *
gum_normalize_module_name (const gchar * name)
{
  const gchar * base_name;
  gchar * result;

  base_name = strrchr (name, '\\');
  base_name = (base_name != NULL) ? base_name + 1 : name;

  result = g_ascii_strdown (base_name, -1);
  if (strchr (result, '.') == NULL)
  {
    gchar * with_extension = g_strconcat (result, ".dll", NULL);
    g_free (result);
    result = with_extension;
  }

  return result;
}
