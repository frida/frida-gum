/*
 * Copyright (C) 2008-2026 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 * Copyright (C) 2020 Matt Oh <oh.jeongwook@gmail.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gum/gumdbghelp.h"

#include "gum-init.h"
#include "gumpemodule.h"
#include "gumprocess.h"

#include <string.h>

typedef struct _GumImportRedirect GumImportRedirect;

struct _GumDbghelpImplPrivate
{
  HMODULE module;
  gboolean owns_module;
};

struct _GumImportRedirect
{
  const gchar * name;
  GCallback replacement;
};

static gpointer do_init (gpointer data);
static void do_deinit (void);

static HMODULE load_dbghelp (void);
static gpointer gum_dbghelp_find_export (HMODULE module, const gchar * name);
static gpointer gum_find_mapped_export (HMODULE module, GumPeModule * pe,
    const gchar * name);
static void gum_dbghelp_redirect_symsrv_loading (HMODULE dbghelp);
static gboolean gum_redirect_import (const GumPeImportDetails * details,
    gpointer user_data);
static void gum_write_import_slot (gpointer * slot, gpointer value);
static HMODULE WINAPI gum_load_library_a (LPCSTR name);
static HMODULE WINAPI gum_load_library_w (LPCWSTR name);
static HMODULE WINAPI gum_load_library_ex_a (LPCSTR name, HANDLE file,
    DWORD flags);
static HMODULE WINAPI gum_load_library_ex_w (LPCWSTR name, HANDLE file,
    DWORD flags);
static FARPROC WINAPI gum_get_proc_address (HMODULE module, LPCSTR name);
static BOOL WINAPI gum_free_library (HMODULE module);
static gboolean gum_is_symsrv (const gchar * name);
static gboolean gum_is_symsrv_utf16 (LPCWSTR name);

static void gum_dbghelp_impl_lock (void);
static void gum_dbghelp_impl_unlock (void);

#define INIT_IMPL_FUNC(func) \
    *((gpointer *) (&impl->func)) = \
        gum_dbghelp_find_export (mod, G_STRINGIFY (func)); \
    g_assert (impl->func != NULL)

static HMODULE gum_mapped_dbghelp = NULL;
static HMODULE gum_mapped_symsrv = NULL;
static GumPeModule * gum_mapped_symsrv_pe = NULL;

static const GumImportRedirect gum_symsrv_redirects[] =
{
  { "LoadLibraryA", G_CALLBACK (gum_load_library_a) },
  { "LoadLibraryW", G_CALLBACK (gum_load_library_w) },
  { "LoadLibraryExA", G_CALLBACK (gum_load_library_ex_a) },
  { "LoadLibraryExW", G_CALLBACK (gum_load_library_ex_w) },
  { "GetProcAddress", G_CALLBACK (gum_get_proc_address) },
  { "FreeLibrary", G_CALLBACK (gum_free_library) },
};

void
gum_dbghelp_impl_use_modules (HMODULE dbghelp,
                              HMODULE symsrv)
{
  gum_mapped_dbghelp = dbghelp;
  gum_mapped_symsrv = symsrv;
  gum_mapped_symsrv_pe = gum_pe_module_new_from_memory (GUM_ADDRESS (symsrv),
      NULL);
}

GumDbghelpImpl *
gum_dbghelp_impl_try_obtain (void)
{
  static GOnce init_once = G_ONCE_INIT;

  g_once (&init_once, do_init, NULL);

  return init_once.retval;
}

static gpointer
do_init (gpointer data)
{
  HMODULE mod;
  gboolean owns_module;
  GumDbghelpImpl * impl;

  if (gum_mapped_dbghelp != NULL)
  {
    mod = gum_mapped_dbghelp;
    owns_module = FALSE;
    gum_dbghelp_redirect_symsrv_loading (mod);
  }
  else
  {
    mod = load_dbghelp ();
    if (mod == NULL)
      return NULL;
    owns_module = TRUE;
  }

  impl = g_slice_new0 (GumDbghelpImpl);
  impl->priv = g_slice_new (GumDbghelpImplPrivate);
  impl->priv->module = mod;
  impl->priv->owns_module = owns_module;

  INIT_IMPL_FUNC (StackWalk64);
  INIT_IMPL_FUNC (SymSetOptions);
  INIT_IMPL_FUNC (SymInitialize);
  INIT_IMPL_FUNC (SymCleanup);
  INIT_IMPL_FUNC (SymEnumSymbols);
  INIT_IMPL_FUNC (SymFromAddr);
  INIT_IMPL_FUNC (SymFunctionTableAccess64);
  INIT_IMPL_FUNC (SymGetLineFromAddr64);
  INIT_IMPL_FUNC (SymLoadModuleExW);
  INIT_IMPL_FUNC (SymGetModuleBase64);
  INIT_IMPL_FUNC (SymGetModuleInfo);
  INIT_IMPL_FUNC (SymGetTypeInfo);

  impl->Lock = gum_dbghelp_impl_lock;
  impl->Unlock = gum_dbghelp_impl_unlock;

  impl->SymInitialize (GetCurrentProcess (), NULL, TRUE);

  _gum_register_destructor (do_deinit);

  return impl;
}

static void
do_deinit (void)
{
  GumDbghelpImpl * impl;

  impl = gum_dbghelp_impl_try_obtain ();
  g_assert (impl != NULL);

  impl->SymCleanup (GetCurrentProcess ());

  if (impl->priv->owns_module)
    FreeLibrary (impl->priv->module);
  g_slice_free (GumDbghelpImplPrivate, impl->priv);
  g_slice_free (GumDbghelpImpl, impl);
}

static HMODULE
load_dbghelp (void)
{
  HMODULE mod;
  BOOL success G_GNUC_UNUSED;
  DWORD length G_GNUC_UNUSED;
  WCHAR path[MAX_PATH + 1] = { 0, };
  WCHAR * filename;

  if (GetModuleHandleExW (0, L"dbghelp.dll", &mod))
    return mod;

  success = GetModuleHandleExW (
      GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
      GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
      GUM_FUNCPTR_TO_POINTER (load_dbghelp),
      &mod);
  g_assert (success);

  length = GetModuleFileNameW (mod, path, MAX_PATH);
  g_assert (length != 0);

  filename = wcsrchr (path, L'\\');
  g_assert (filename != NULL);
  filename++;
  wcscpy (filename, L"dbghelp.dll");

  return LoadLibraryW (path);
}

static gpointer
gum_dbghelp_find_export (HMODULE module,
                         const gchar * name)
{
  GumPeModule * pe;
  gpointer address;

  if (module != gum_mapped_dbghelp)
    return GSIZE_TO_POINTER (GetProcAddress (module, name));

  pe = gum_pe_module_new_from_memory (GUM_ADDRESS (module), NULL);
  address = gum_find_mapped_export (module, pe, name);
  g_object_unref (pe);

  return address;
}

static gpointer
gum_find_mapped_export (HMODULE module,
                        GumPeModule * pe,
                        const gchar * name)
{
  GumPeExportDetails details;

  if (!gum_pe_module_find_export_by_name (pe, name, &details) ||
      details.type != GUM_PE_EXPORT_REGULAR)
  {
    return NULL;
  }

  return (guint8 *) module + details.rva;
}

static void
gum_dbghelp_redirect_symsrv_loading (HMODULE dbghelp)
{
  GumPeModule * pe;

  pe = gum_pe_module_new_from_memory (GUM_ADDRESS (dbghelp), NULL);
  gum_pe_module_enumerate_imports (pe, gum_redirect_import, dbghelp);
  g_object_unref (pe);
}

static gboolean
gum_redirect_import (const GumPeImportDetails * details,
                     gpointer user_data)
{
  guint8 * dbghelp = user_data;
  guint i;

  if (details->type != GUM_PE_IMPORT_BY_NAME)
    return TRUE;

  for (i = 0; i != G_N_ELEMENTS (gum_symsrv_redirects); i++)
  {
    const GumImportRedirect * redirect = &gum_symsrv_redirects[i];

    if (strcmp (details->name, redirect->name) == 0)
    {
      gum_write_import_slot ((gpointer *) (dbghelp + details->slot_rva),
          GUM_FUNCPTR_TO_POINTER (redirect->replacement));
      break;
    }
  }

  return TRUE;
}

static void
gum_write_import_slot (gpointer * slot,
                       gpointer value)
{
  MEMORY_BASIC_INFORMATION mbi;
  DWORD old_protect;

  VirtualQuery (slot, &mbi, sizeof (mbi));
  VirtualProtect (slot, sizeof (gpointer),
      (mbi.Type == MEM_MAPPED) ? PAGE_WRITECOPY : PAGE_READWRITE,
      &old_protect);
  *slot = value;
  VirtualProtect (slot, sizeof (gpointer), old_protect, &old_protect);
}

static HMODULE WINAPI
gum_load_library_a (LPCSTR name)
{
  if (gum_is_symsrv (name))
    return gum_mapped_symsrv;

  return LoadLibraryA (name);
}

static HMODULE WINAPI
gum_load_library_w (LPCWSTR name)
{
  if (gum_is_symsrv_utf16 (name))
    return gum_mapped_symsrv;

  return LoadLibraryW (name);
}

static HMODULE WINAPI
gum_load_library_ex_a (LPCSTR name,
                       HANDLE file,
                       DWORD flags)
{
  if (gum_is_symsrv (name))
    return gum_mapped_symsrv;

  return LoadLibraryExA (name, file, flags);
}

static HMODULE WINAPI
gum_load_library_ex_w (LPCWSTR name,
                       HANDLE file,
                       DWORD flags)
{
  if (gum_is_symsrv_utf16 (name))
    return gum_mapped_symsrv;

  return LoadLibraryExW (name, file, flags);
}

static FARPROC WINAPI
gum_get_proc_address (HMODULE module,
                      LPCSTR name)
{
  if (module == gum_mapped_symsrv && !IS_INTRESOURCE (name))
  {
    return GUM_POINTER_TO_FUNCPTR (FARPROC,
        gum_find_mapped_export (module, gum_mapped_symsrv_pe, name));
  }

  return GetProcAddress (module, name);
}

static BOOL WINAPI
gum_free_library (HMODULE module)
{
  if (module == gum_mapped_symsrv)
    return TRUE;

  return FreeLibrary (module);
}

static gboolean
gum_is_symsrv (const gchar * name)
{
  const gchar * base_name;

  base_name = strrchr (name, '\\');
  base_name = (base_name != NULL) ? base_name + 1 : name;

  return g_ascii_strcasecmp (base_name, "symsrv.dll") == 0;
}

static gboolean
gum_is_symsrv_utf16 (LPCWSTR name)
{
  gchar * name_utf8;
  gboolean result;

  name_utf8 = g_utf16_to_utf8 ((const gunichar2 *) name, -1, NULL, NULL, NULL);
  result = gum_is_symsrv (name_utf8);
  g_free (name_utf8);

  return result;
}

static GMutex _gum_dbghelp_mutex;

static void
gum_dbghelp_impl_lock (void)
{
  g_mutex_lock (&_gum_dbghelp_mutex);
}

static void
gum_dbghelp_impl_unlock (void)
{
  g_mutex_unlock (&_gum_dbghelp_mutex);
}
