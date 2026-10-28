/*
 * Copyright (C) 2009-2026 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 * Copyright (C) 2023 Francesco Tamagni <mrmacete@protonmail.ch>
 * Copyright (C) 2025 William Tan <1284324+Ninja3047@users.noreply.github.com>
 * Copyright (C) 2026 T Shivanesh Kumar <tshivaneshk@users.noreply.github.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gummodule-windows.h"

#include <psapi.h>

typedef struct _GumEnumerateImportsContext GumEnumerateImportsContext;
typedef struct _GumEnumerateExportsContext GumEnumerateExportsContext;
typedef struct _GumEnumerateSymbolsContext GumEnumerateSymbolsContext;
typedef struct _GumEnumerateSectionsContext GumEnumerateSectionsContext;
typedef struct _GumFindExportContext GumFindExportContext;

struct _GumNativeModule
{
  GObject parent;

  HMODULE handle;
  gchar * name;
  gchar * path;
  GumMemoryRange range;
  GumPeModule * pe;

  HANDLE process;
  GumWindowsModuleResolver * resolver;
  guint8 * image;
};

struct _GumEnumerateImportsContext
{
  GumFoundImportFunc func;
  gpointer user_data;
  GumNativeModule * module;
};

struct _GumEnumerateExportsContext
{
  GumFoundExportFunc func;
  gpointer user_data;
  GumAddress base;
  gsize page_size;
  gsize num_pages;
  guint8 * bitmap;
};

struct _GumEnumerateSymbolsContext
{
  GumFoundSymbolFunc func;
  gpointer user_data;
};

struct _GumEnumerateSectionsContext
{
  GumFoundSectionFunc func;
  gpointer user_data;
  GumAddress base;
  guint index;
};

struct _GumFindExportContext
{
  const gchar * symbol_name;
  GumAddress result;
};

static void gum_native_module_iface_init (gpointer g_iface,
    gpointer iface_data);
static void gum_native_module_dispose (GObject * object);
static void gum_native_module_finalize (GObject * object);
static const gchar * gum_native_module_get_name (GumModule * module);
static const gchar * gum_native_module_get_path (GumModule * module);
static const GumMemoryRange * gum_native_module_get_range (GumModule * module);
static void gum_native_module_ensure_initialized (GumModule * module);
static void gum_native_module_enumerate_imports (GumModule * module,
    GumFoundImportFunc func, gpointer user_data);
static gboolean gum_emit_import (const GumPeImportDetails * details,
    gpointer user_data);
static void gum_native_module_enumerate_exports (GumModule * module,
    GumFoundExportFunc func, gpointer user_data);
static gboolean gum_collect_code_pages (const GumRangeDetails * details,
    gpointer user_data);
static gboolean gum_emit_export (const GumPeExportDetails * details,
    gpointer user_data);
static void gum_native_module_enumerate_symbols (GumModule * module,
    GumFoundSymbolFunc func, gpointer user_data);
static BOOL CALLBACK gum_emit_symbol (PSYMBOL_INFO info, ULONG symbol_size,
    PVOID user_context);
static void gum_native_module_enumerate_ranges (GumModule * module,
    GumPageProtection prot, GumFoundRangeFunc func, gpointer user_data);
static void gum_native_module_enumerate_sections (GumModule * module,
    GumFoundSectionFunc func, gpointer user_data);
static gboolean gum_emit_section (const GumPeSectionDetails * details,
    gpointer user_data);
static void gum_native_module_enumerate_dependencies (GumModule * module,
    GumFoundDependencyFunc func, gpointer user_data);
static GumAddress gum_native_module_find_export_by_name (GumModule * module,
    const gchar * symbol_name);
static GumAddress gum_native_module_find_remote_export (GumNativeModule * self,
    const gchar * symbol_name);
static gchar * gum_native_module_resolve_api_set_host (GumNativeModule * self,
    const gchar * symbol_name);
static gboolean gum_store_address_if_module_has_export (GumModule * module,
    gpointer user_data);

static GumNativeModule * gum_native_module_new (HMODULE handle,
    HANDLE process, GumWindowsModuleResolver * resolver);
static gboolean gum_native_module_file_matches_image (GumNativeModule * self);
static guint8 * gum_native_module_copy_image (GumNativeModule * self);

G_DEFINE_TYPE_EXTENDED (GumNativeModule,
                        gum_native_module,
                        G_TYPE_OBJECT,
                        0,
                        G_IMPLEMENT_INTERFACE (GUM_TYPE_MODULE,
                            gum_native_module_iface_init))

static void
gum_native_module_class_init (GumNativeModuleClass * klass)
{
  GObjectClass * object_class = G_OBJECT_CLASS (klass);

  object_class->dispose = gum_native_module_dispose;
  object_class->finalize = gum_native_module_finalize;
}

static void
gum_native_module_iface_init (gpointer g_iface,
                              gpointer iface_data)
{
  GumModuleInterface * iface = g_iface;

  iface->get_name = gum_native_module_get_name;
  iface->get_path = gum_native_module_get_path;
  iface->get_range = gum_native_module_get_range;
  iface->ensure_initialized = gum_native_module_ensure_initialized;
  iface->enumerate_imports = gum_native_module_enumerate_imports;
  iface->enumerate_exports = gum_native_module_enumerate_exports;
  iface->enumerate_symbols = gum_native_module_enumerate_symbols;
  iface->enumerate_ranges = gum_native_module_enumerate_ranges;
  iface->enumerate_sections = gum_native_module_enumerate_sections;
  iface->enumerate_dependencies = gum_native_module_enumerate_dependencies;
  iface->find_export_by_name = gum_native_module_find_export_by_name;
}

static void
gum_native_module_init (GumNativeModule * self)
{
}

static void
gum_native_module_dispose (GObject * object)
{
  GumNativeModule * self = GUM_NATIVE_MODULE (object);

  g_clear_object (&self->pe);

  G_OBJECT_CLASS (gum_native_module_parent_class)->dispose (object);
}

static void
gum_native_module_finalize (GObject * object)
{
  GumNativeModule * self = GUM_NATIVE_MODULE (object);

  g_free (self->image);
  g_free (self->path);

  G_OBJECT_CLASS (gum_native_module_parent_class)->finalize (object);
}

GumModule *
gum_module_load (const gchar * module_name,
                 GError ** error)
{
  gunichar2 * wide_name;
  HMODULE handle;

  wide_name = g_utf8_to_utf16 (module_name, -1, NULL, NULL, NULL);
  handle = LoadLibraryW ((LPCWSTR) wide_name);
  g_free (wide_name);

  if (handle == NULL)
    goto not_found;

  return GUM_MODULE (_gum_native_module_make (handle));

not_found:
  {
    g_set_error (error, GUM_ERROR, GUM_ERROR_NOT_FOUND,
        "LoadLibrary failed: 0x%08lx", GetLastError ());
    return NULL;
  }
}

GumNativeModule *
_gum_native_module_make (HMODULE handle)
{
  return gum_native_module_new (handle, GetCurrentProcess (), NULL);
}

GumNativeModule *
_gum_native_module_make_remote (HMODULE handle,
                                HANDLE process,
                                GumWindowsModuleResolver * resolver)
{
  return gum_native_module_new (handle, process, resolver);
}

void
_gum_native_module_detach_resolver (GumNativeModule * self)
{
  self->process = NULL;
  self->resolver = NULL;
}

GumPeModule *
_gum_native_module_get_pe_module (GumNativeModule * self)
{
  return self->pe;
}

static const gchar *
gum_native_module_get_name (GumModule * module)
{
  return GUM_NATIVE_MODULE (module)->name;
}

static const gchar *
gum_native_module_get_path (GumModule * module)
{
  return GUM_NATIVE_MODULE (module)->path;
}

static const GumMemoryRange *
gum_native_module_get_range (GumModule * module)
{
  return &GUM_NATIVE_MODULE (module)->range;
}

static void
gum_native_module_ensure_initialized (GumModule * module)
{
}

static void
gum_native_module_enumerate_imports (GumModule * module,
                                     GumFoundImportFunc func,
                                     gpointer user_data)
{
  GumNativeModule * self = GUM_NATIVE_MODULE (module);
  GumEnumerateImportsContext ctx;

  ctx.func = func;
  ctx.user_data = user_data;
  ctx.module = self;

  gum_pe_module_enumerate_imports (self->pe, gum_emit_import, &ctx);
}

static gboolean
gum_emit_import (const GumPeImportDetails * details,
                 gpointer user_data)
{
  GumEnumerateImportsContext * ctx = user_data;
  GumAddress slot;
  gpointer value = NULL;
  GumImportDetails d;

  if (details->type != GUM_PE_IMPORT_BY_NAME)
    return TRUE;

  slot = ctx->module->range.base_address + details->slot_rva;
  ReadProcessMemory (ctx->module->process, GSIZE_TO_POINTER (slot), &value,
      sizeof (value), NULL);

  d.type = GUM_IMPORT_FUNCTION;
  d.name = details->name;
  d.module = details->module_name;
  d.address = GUM_ADDRESS (value);
  d.slot = slot;

  return ctx->func (&d, ctx->user_data);
}

static void
gum_native_module_enumerate_exports (GumModule * module,
                                     GumFoundExportFunc func,
                                     gpointer user_data)
{
  GumNativeModule * self = GUM_NATIVE_MODULE (module);
  GumEnumerateExportsContext ctx;

  ctx.func = func;
  ctx.user_data = user_data;
  ctx.base = self->range.base_address;
  ctx.page_size = gum_query_page_size ();
  ctx.num_pages =
      GUM_ALIGN_SIZE (self->range.size, ctx.page_size) / ctx.page_size;
  ctx.bitmap = g_malloc0 (GUM_ALIGN_SIZE (ctx.num_pages, 8) / 8);

  gum_module_enumerate_ranges (module, GUM_PAGE_EXECUTE, gum_collect_code_pages,
      &ctx);

  gum_pe_module_enumerate_exports (self->pe, gum_emit_export, &ctx);

  g_free (ctx.bitmap);
}

static gboolean
gum_collect_code_pages (const GumRangeDetails * details,
                        gpointer user_data)
{
  GumEnumerateExportsContext * ctx = user_data;
  gsize start_page, end_page, page;

  start_page = (details->range->base_address - ctx->base) / ctx->page_size;
  end_page = start_page + (details->range->size / ctx->page_size);

  for (page = start_page; page != end_page; page++)
    ctx->bitmap[page / 8] |= 1 << (page % 8);

  return TRUE;
}

static gboolean
gum_emit_export (const GumPeExportDetails * details,
                 gpointer user_data)
{
  GumEnumerateExportsContext * ctx = user_data;
  gsize page_index;
  GumExportDetails d;

  if (details->type != GUM_PE_EXPORT_REGULAR || details->name == NULL)
    return TRUE;

  page_index = details->rva / ctx->page_size;

  d.type = (page_index < ctx->num_pages &&
      (ctx->bitmap[page_index / 8] & (1 << (page_index % 8))) != 0)
      ? GUM_EXPORT_FUNCTION
      : GUM_EXPORT_VARIABLE;
  d.name = details->name;
  d.address = ctx->base + details->rva;
  d.size = -1;

  return ctx->func (&d, ctx->user_data);
}

static void
gum_native_module_enumerate_symbols (GumModule * module,
                                     GumFoundSymbolFunc func,
                                     gpointer user_data)
{
  GumNativeModule * self;
  GumDbghelpImpl * dbghelp;
  GumEnumerateSymbolsContext ctx;

  self = GUM_NATIVE_MODULE (module);

  if (self->resolver != NULL)
    return;

  dbghelp = gum_dbghelp_impl_try_obtain ();
  if (dbghelp == NULL)
    return;

  ctx.func = func;
  ctx.user_data = user_data;
  dbghelp->SymEnumSymbols (GetCurrentProcess (),
      GPOINTER_TO_SIZE (self->handle), NULL, gum_emit_symbol, &ctx);
}

static BOOL CALLBACK
gum_emit_symbol (PSYMBOL_INFO info,
                 ULONG symbol_size,
                 PVOID user_context)
{
  GumEnumerateSymbolsContext * ctx = user_context;
  GumSymbolDetails details;

  details.is_global = info->Tag == SymTagPublicSymbol ||
      (info->Flags & SYMFLAG_EXPORT) != 0;

  if (info->Tag == SymTagPublicSymbol || info->Tag == SymTagFunction)
  {
    details.type = GUM_SYMBOL_FUNCTION;
  }
  else if (info->Tag == SymTagData)
  {
    details.type = ((info->Flags & SYMFLAG_TLSREL) != 0)
        ? GUM_SYMBOL_TLS
        : GUM_SYMBOL_OBJECT;
  }
  else
  {
    return TRUE;
  }

  details.section = NULL;
  details.name = info->Name;
  details.address = info->Address;
  details.size = symbol_size;

  return ctx->func (&details, ctx->user_data);
}

static void
gum_native_module_enumerate_ranges (GumModule * module,
                                    GumPageProtection prot,
                                    GumFoundRangeFunc func,
                                    gpointer user_data)
{
  GumNativeModule * self;
  guint8 * cur_base_address, * end_address;

  self = GUM_NATIVE_MODULE (module);

  cur_base_address = GSIZE_TO_POINTER (self->range.base_address);
  end_address = cur_base_address + self->range.size;

  do
  {
    MEMORY_BASIC_INFORMATION mbi;
    SIZE_T ret G_GNUC_UNUSED;

    ret = VirtualQueryEx (self->process, cur_base_address, &mbi, sizeof (mbi));
    g_assert (ret != 0);

    if (mbi.Protect != 0)
    {
      GumPageProtection cur_prot;

      cur_prot = gum_page_protection_from_windows (mbi.Protect);

      if ((cur_prot & prot) == prot)
      {
        GumMemoryRange range;
        GumRangeDetails details;

        range.base_address = GUM_ADDRESS (cur_base_address);
        range.size = mbi.RegionSize;

        details.range = &range;
        details.protection = cur_prot;
        details.file = NULL; /* TODO */

        if (!func (&details, user_data))
          return;
      }
    }

    cur_base_address += mbi.RegionSize;
  }
  while (cur_base_address < end_address);
}

static void
gum_native_module_enumerate_sections (GumModule * module,
                                      GumFoundSectionFunc func,
                                      gpointer user_data)
{
  GumNativeModule * self = GUM_NATIVE_MODULE (module);
  GumEnumerateSectionsContext ctx;

  ctx.func = func;
  ctx.user_data = user_data;
  ctx.base = self->range.base_address;
  ctx.index = 0;

  gum_pe_module_enumerate_sections (self->pe, gum_emit_section, &ctx);
}

static gboolean
gum_emit_section (const GumPeSectionDetails * details,
                  gpointer user_data)
{
  GumEnumerateSectionsContext * ctx = user_data;
  gboolean carry_on;
  GumSectionDetails d;

  d.id = g_strdup_printf ("%u.%s", ctx->index++, details->name);
  d.name = details->name;
  d.address = ctx->base + details->virtual_address;
  d.size = (details->virtual_size != 0)
      ? details->virtual_size
      : details->raw_data_size;

  carry_on = ctx->func (&d, ctx->user_data);

  g_free ((gpointer) d.id);

  return carry_on;
}

static void
gum_native_module_enumerate_dependencies (GumModule * module,
                                          GumFoundDependencyFunc func,
                                          gpointer user_data)
{
  gum_pe_module_enumerate_dependencies (GUM_NATIVE_MODULE (module)->pe, func,
      user_data);
}

static GumAddress
gum_native_module_find_export_by_name (GumModule * module,
                                       const gchar * symbol_name)
{
  GumNativeModule * self = GUM_NATIVE_MODULE (module);

  if (self->resolver != NULL)
    return gum_native_module_find_remote_export (self, symbol_name);

  return GUM_ADDRESS (GetProcAddress (self->handle, symbol_name));
}

static GumAddress
gum_native_module_find_remote_export (GumNativeModule * self,
                                      const gchar * symbol_name)
{
  GumPeExportDetails details;
  gchar ** forwarder;
  gchar * module_name;
  GumModule * module;
  GumAddress address;

  if (!gum_pe_module_find_export_by_name (self->pe, symbol_name, &details))
    return 0;

  if (details.type == GUM_PE_EXPORT_REGULAR)
    return self->range.base_address + details.rva;

  forwarder = g_strsplit (details.forwarder, ".", 2);
  module_name = (g_ascii_strncasecmp (forwarder[0], "api-", 4) == 0 ||
      g_ascii_strncasecmp (forwarder[0], "ext-", 4) == 0)
      ? gum_native_module_resolve_api_set_host (self, symbol_name)
      : g_strdup (forwarder[0]);

  module = (module_name != NULL)
      ? gum_module_resolver_find_module_by_name (
          GUM_MODULE_RESOLVER (self->resolver), module_name)
      : NULL;
  address = (module != NULL)
      ? gum_module_find_export_by_name (module, forwarder[1])
      : 0;
  g_clear_object (&module);
  g_free (module_name);
  g_strfreev (forwarder);

  return address;
}

static gchar *
gum_native_module_resolve_api_set_host (GumNativeModule * self,
                                        const gchar * symbol_name)
{
  gunichar2 * path_utf16;
  HMODULE local_module, host;
  FARPROC implementation;
  WCHAR host_path[MAX_PATH];

  path_utf16 = g_utf8_to_utf16 (self->path, -1, NULL, NULL, NULL);
  local_module = LoadLibraryExW ((LPCWSTR) path_utf16, NULL, 0);
  g_free (path_utf16);
  if (local_module == NULL)
    return NULL;

  implementation = GetProcAddress (local_module, symbol_name);
  if (implementation == NULL ||
      !GetModuleHandleExW (GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
          GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
          (LPCWSTR) implementation, &host))
  {
    FreeLibrary (local_module);
    return NULL;
  }

  GetModuleFileNameW (host, host_path, MAX_PATH);
  FreeLibrary (local_module);

  return g_utf16_to_utf8 ((const gunichar2 *) wcsrchr (host_path, L'\\') + 1,
      -1, NULL, NULL, NULL);
}

GumAddress
gum_module_find_global_export_by_name (const gchar * symbol_name)
{
  GumFindExportContext ctx;

  ctx.symbol_name = symbol_name;
  ctx.result = 0;

  gum_process_enumerate_modules (gum_store_address_if_module_has_export, &ctx);

  return ctx.result;
}

static gboolean
gum_store_address_if_module_has_export (GumModule * module,
                                        gpointer user_data)
{
  GumFindExportContext * ctx = user_data;

  ctx->result = gum_module_find_export_by_name (module, ctx->symbol_name);

  return ctx->result == 0;
}

static GumNativeModule *
gum_native_module_new (HMODULE handle,
                       HANDLE process,
                       GumWindowsModuleResolver * resolver)
{
  GumNativeModule * module;
  WCHAR path_utf16[MAX_PATH];
  MODULEINFO mi;

  module = g_object_new (GUM_TYPE_NATIVE_MODULE, NULL);
  module->handle = handle;
  module->process = process;
  module->resolver = resolver;

  GetModuleFileNameExW (process, handle, path_utf16, MAX_PATH);
  module->path = g_utf16_to_utf8 ((const gunichar2 *) path_utf16, -1, NULL,
      NULL, NULL);
  module->name = strrchr (module->path, '\\') + 1;

  GetModuleInformation (process, handle, &mi, sizeof (mi));
  module->range.base_address = GUM_ADDRESS (mi.lpBaseOfDll);
  module->range.size = mi.SizeOfImage;

  if (resolver != NULL)
  {
    module->pe = gum_pe_module_new_from_file (module->path, NULL);
    if (module->pe == NULL || !gum_native_module_file_matches_image (module))
    {
      g_clear_object (&module->pe);
      module->pe = gum_pe_module_new_from_memory (
          GUM_ADDRESS (gum_native_module_copy_image (module)), NULL);
    }
  }
  else
  {
    module->pe = gum_pe_module_new_from_memory (module->range.base_address,
        NULL);
  }

  return module;
}

static gboolean
gum_native_module_file_matches_image (GumNativeModule * self)
{
  const IMAGE_DOS_HEADER * dos;
  const IMAGE_NT_HEADERS * nt;
  IMAGE_FILE_HEADER image_header;

  dos = gum_pe_module_get_data_at_rva (self->pe, 0);
  nt = (const IMAGE_NT_HEADERS *) ((const guint8 *) dos + dos->e_lfanew);

  if (!ReadProcessMemory (self->process,
      GSIZE_TO_POINTER (self->range.base_address + dos->e_lfanew +
          G_STRUCT_OFFSET (IMAGE_NT_HEADERS, FileHeader)),
      &image_header, sizeof (image_header), NULL))
  {
    return FALSE;
  }

  return image_header.Machine == nt->FileHeader.Machine &&
      image_header.TimeDateStamp == nt->FileHeader.TimeDateStamp &&
      gum_pe_module_get_size_of_image (self->pe) == self->range.size;
}

static guint8 *
gum_native_module_copy_image (GumNativeModule * self)
{
  guint8 * base, * cur, * end;

  self->image = g_malloc0 (self->range.size);

  base = GSIZE_TO_POINTER (self->range.base_address);
  cur = base;
  end = base + self->range.size;

  do
  {
    MEMORY_BASIC_INFORMATION mbi;
    gsize size;

    VirtualQueryEx (self->process, cur, &mbi, sizeof (mbi));
    size = MIN (mbi.RegionSize, end - cur);

    if (mbi.State == MEM_COMMIT &&
        (mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)) == 0)
    {
      ReadProcessMemory (self->process, cur, self->image + (cur - base), size,
          NULL);
    }

    cur += size;
  }
  while (cur < end);

  return self->image;
}
