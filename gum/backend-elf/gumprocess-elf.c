/*
 * Copyright (C) 2010-2023 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumprocess-elf.h"

#include "gumelfmodule.h"

#include <dlfcn.h>

typedef struct _GumEnumerateImportsContext GumEnumerateImportsContext;
typedef struct _GumDependencyExport GumDependencyExport;
typedef struct _GumEnumerateSymbolsContext GumEnumerateSymbolsContext;
typedef struct _GumEnumerateRangesContext GumEnumerateRangesContext;
typedef struct _GumEnumerateSectionsContext GumEnumerateSectionsContext;

struct _GumEnumerateImportsContext
{
  GumFoundImportFunc func;
  gpointer user_data;

  GHashTable * dependency_exports;
  GumElfModule * current_dependency;
  GumModuleMap * module_map;
};

struct _GumDependencyExport
{
  gchar * module;
  GumAddress address;
};

struct _GumEnumerateSymbolsContext
{
  GumFoundSymbolFunc func;
  gpointer user_data;
};

struct _GumEnumerateRangesContext
{
  gchar * module_name;
  GumFoundRangeFunc func;
  gpointer user_data;
};

struct _GumEnumerateSectionsContext
{
  GumFoundSectionFunc func;
  gpointer user_data;
};

static gboolean gum_emit_import (const GumImportDetails * details,
    gpointer user_data);
static gboolean gum_collect_dependency_exports (
    const GumDependencyDetails * details, gpointer user_data);
static gboolean gum_collect_dependency_export (const GumExportDetails * details,
    gpointer user_data);
static GumDependencyExport * gum_dependency_export_new (const gchar * module,
    GumAddress address);
static void gum_dependency_export_free (GumDependencyExport * export);
static gboolean gum_emit_symbol (const GumElfSymbolDetails * details,
    gpointer user_data);
static gboolean gum_emit_range_if_module_name_matches (
    const GumRangeDetails * details, gpointer user_data);
static gboolean gum_emit_section (const GumElfSectionDetails * details,
    gpointer user_data);

static GumElfModule * gum_open_elf_module (const gchar * name);

void
gum_module_enumerate_imports (const gchar * module_name,
                              GumFoundImportFunc func,
                              gpointer user_data)
{
  GumElfModule * module;
  GumEnumerateImportsContext ctx;

  module = gum_open_elf_module (module_name);
  if (module == NULL)
    return;

  ctx.func = func;
  ctx.user_data = user_data;

  ctx.dependency_exports = g_hash_table_new_full (g_str_hash, g_str_equal,
      g_free, (GDestroyNotify) gum_dependency_export_free);
  ctx.current_dependency = NULL;
  ctx.module_map = NULL;

  gum_elf_module_enumerate_dependencies (module, gum_collect_dependency_exports,
      &ctx);

  gum_elf_module_enumerate_imports (module, gum_emit_import, &ctx);

  if (ctx.module_map != NULL)
    gum_object_unref (ctx.module_map);
  g_hash_table_unref (ctx.dependency_exports);

  gum_object_unref (module);
}

static gboolean
gum_emit_import (const GumImportDetails * details,
                 gpointer user_data)
{
  GumEnumerateImportsContext * ctx = user_data;
  GumImportDetails d;
  GumDependencyExport * exp;

  d.type = details->type;
  d.name = details->name;
  d.slot = details->slot;

  exp = g_hash_table_lookup (ctx->dependency_exports, details->name);
  if (exp != NULL)
  {
    d.module = exp->module;
    d.address = exp->address;
  }
  else
  {
    d.module = NULL;
    d.address = GUM_ADDRESS (dlsym (RTLD_DEFAULT, details->name));

    if (d.address != 0)
    {
      const GumModuleDetails * module;

      if (ctx->module_map == NULL)
        ctx->module_map = gum_module_map_new ();
      module = gum_module_map_find (ctx->module_map, d.address);
      if (module != NULL)
        d.module = module->path;
    }
  }

  return ctx->func (&d, ctx->user_data);
}

static gboolean
gum_collect_dependency_exports (const GumDependencyDetails * details,
                                gpointer user_data)
{
  GumEnumerateImportsContext * ctx = user_data;
  GumElfModule * module;

  module = gum_open_elf_module (details->name);
  if (module == NULL)
    return TRUE;
  ctx->current_dependency = module;
  gum_elf_module_enumerate_exports (module, gum_collect_dependency_export, ctx);
  ctx->current_dependency = NULL;
  gum_object_unref (module);

  return TRUE;
}

static gboolean
gum_collect_dependency_export (const GumExportDetails * details,
                               gpointer user_data)
{
  GumEnumerateImportsContext * ctx = user_data;
  GumElfModule * module = ctx->current_dependency;

  g_hash_table_insert (ctx->dependency_exports,
      g_strdup (details->name),
      gum_dependency_export_new (gum_elf_module_get_source_path (module),
          details->address));

  return TRUE;
}

static GumDependencyExport *
gum_dependency_export_new (const gchar * module,
                           GumAddress address)
{
  GumDependencyExport * export;

  export = g_slice_new (GumDependencyExport);
  export->module = g_strdup (module);
  export->address = address;

  return export;
}

static void
gum_dependency_export_free (GumDependencyExport * export)
{
  g_free (export->module);
  g_slice_free (GumDependencyExport, export);
}

void
gum_module_enumerate_exports (const gchar * module_name,
                              GumFoundExportFunc func,
                              gpointer user_data)
{
  GumElfModule * module;

  module = gum_open_elf_module (module_name);
  if (module == NULL)
    return;
  gum_elf_module_enumerate_exports (module, func, user_data);
  gum_object_unref (module);
}

void
gum_module_enumerate_symbols (const gchar * module_name,
                              GumFoundSymbolFunc func,
                              gpointer user_data)
{
  GumElfModule * module;
  GumEnumerateSymbolsContext ctx;

  module = gum_open_elf_module (module_name);
  if (module == NULL)
    return;

  ctx.func = func;
  ctx.user_data = user_data;

  gum_elf_module_enumerate_symbols (module, gum_emit_symbol, &ctx);

  gum_object_unref (module);
}

static gboolean
gum_emit_symbol (const GumElfSymbolDetails * details,
                 gpointer user_data)
{
  GumEnumerateSymbolsContext * ctx = user_data;
  GumSymbolDetails symbol;
  const GumElfSectionDetails * section;
  GumSymbolSection symsect;

  symbol.is_global = details->bind == GUM_ELF_BIND_GLOBAL ||
      details->bind == GUM_ELF_BIND_WEAK;

  switch (details->type)
  {
    case GUM_ELF_SYMBOL_OBJECT:  symbol.type = GUM_SYMBOL_OBJECT;   break;
    case GUM_ELF_SYMBOL_FUNC:    symbol.type = GUM_SYMBOL_FUNCTION; break;
    case GUM_ELF_SYMBOL_SECTION: symbol.type = GUM_SYMBOL_SECTION;  break;
    case GUM_ELF_SYMBOL_FILE:    symbol.type = GUM_SYMBOL_FILE;     break;
    case GUM_ELF_SYMBOL_COMMON:  symbol.type = GUM_SYMBOL_COMMON;   break;
    case GUM_ELF_SYMBOL_TLS:     symbol.type = GUM_SYMBOL_TLS;      break;
    default:                     symbol.type = GUM_SYMBOL_UNKNOWN;  break;
  }

  section = details->section;
  if (section != NULL)
  {
    symsect.id = section->id;
    symsect.protection = section->protection;
    symbol.section = &symsect;
  }
  else
  {
    symbol.section = NULL;
  }

  symbol.name = details->name;
  symbol.address = details->address;
  symbol.size = details->size;

  return ctx->func (&symbol, ctx->user_data);
}

void
gum_module_enumerate_ranges (const gchar * module_name,
                             GumPageProtection prot,
                             GumFoundRangeFunc func,
                             gpointer user_data)
{
  GumEnumerateRangesContext ctx;

  if (!_gum_process_resolve_module_name (module_name, &ctx.module_name, NULL))
    return;
  ctx.func = func;
  ctx.user_data = user_data;

  gum_process_enumerate_ranges (prot, gum_emit_range_if_module_name_matches,
      &ctx);

  g_free (ctx.module_name);
}

static gboolean
gum_emit_range_if_module_name_matches (const GumRangeDetails * details,
                                       gpointer user_data)
{
  GumEnumerateRangesContext * ctx = user_data;

  if (details->file == NULL)
    return TRUE;
  if (strcmp (details->file->path, ctx->module_name) != 0)
    return TRUE;

  return ctx->func (details, ctx->user_data);
}

void
gum_module_enumerate_sections (const gchar * module_name,
                               GumFoundSectionFunc func,
                               gpointer user_data)
{
  GumElfModule * module;
  GumEnumerateSectionsContext ctx;

  module = gum_open_elf_module (module_name);
  if (module == NULL)
    return;

  ctx.func = func;
  ctx.user_data = user_data;

  gum_elf_module_enumerate_sections (module, gum_emit_section, &ctx);

  gum_object_unref (module);
}

static gboolean
gum_emit_section (const GumElfSectionDetails * details,
                  gpointer user_data)
{
  GumEnumerateSectionsContext * ctx = user_data;
  GumSectionDetails section;

  section.id = details->id;
  section.name = details->name;
  section.address = details->address;
  section.size = details->size;

  return ctx->func (&section, ctx->user_data);
}

void
gum_module_enumerate_dependencies (const gchar * module_name,
                                   GumFoundDependencyFunc func,
                                   gpointer user_data)
{
  GumElfModule * module = gum_open_elf_module (module_name);
  if (module == NULL)
    return;

  gum_elf_module_enumerate_dependencies (module, func, user_data);

  gum_object_unref (module);
}

GumAddress
gum_module_find_base_address (const gchar * module_name)
{
  GumAddress base;

  if (!_gum_process_resolve_module_name (module_name, NULL, &base))
    return 0;

  return base;
}

static GumElfModule *
gum_open_elf_module (const gchar * name)
{
  gchar * path;
  GumAddress base_address;
  GumElfModule * module;

  if (!_gum_process_resolve_module_name (name, &path, &base_address))
    return NULL;

  module = gum_elf_module_new_from_memory (path, base_address, NULL);

  g_free (path);

  return module;
}
