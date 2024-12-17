/*
 * Copyright (C) 2010-2024 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gummodule-elf.h"

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
  GumModule * module;
  GumFoundRangeFunc func;
  gpointer user_data;
};

struct _GumEnumerateSectionsContext
{
  GumFoundSectionFunc func;
  gpointer user_data;
};

static void gum_module_dispose (GObject * object);
static void gum_module_finalize (GObject * object);
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

G_DEFINE_TYPE (GumModule, gum_module, G_TYPE_OBJECT)

static void
gum_module_class_init (GumModuleClass * klass)
{
  GObjectClass * object_class = G_OBJECT_CLASS (klass);

  object_class->dispose = gum_module_dispose;
  object_class->finalize = gum_module_finalize;
}

static void
gum_module_init (GumModule * self)
{
}

static void
gum_module_dispose (GObject * object)
{
  GumModule * self = GUM_MODULE (object);

  g_clear_pointer (&self->handle, self->destroy_handle);
  g_clear_object (&self->elf_module);

  G_OBJECT_CLASS (gum_module_parent_class)->dispose (object);
}

static void
gum_module_finalize (GObject * object)
{
  GumModule * self = GUM_MODULE (object);

  g_free (self->name);
  g_free (self->path);

  G_OBJECT_CLASS (gum_module_parent_class)->finalize (object);
}

GumModule *
_gum_module_make (gpointer handle,
                  GDestroyNotify destroy_handle,
                  const gchar * path)
{
  GumModule * module;

  if (handle == NULL)
    return NULL;

  module = g_object_new (GUM_TYPE_MODULE, NULL);

  module->handle = handle;
  module->destroy_handle = destroy_handle;

  module->path = g_strdup (path);

  return module;
}

const gchar *
gum_module_get_name (GumModule * self)
{
  return self->name;
}

const gchar *
gum_module_get_path (GumModule * self)
{
  return self->path;
}

const GumMemoryRange *
gum_module_get_range (GumModule * self)
{
  return &self->range;
}

void
gum_module_enumerate_imports (GumModule * self,
                              GumFoundImportFunc func,
                              gpointer user_data)
{
  GumEnumerateImportsContext ctx;

  ctx.func = func;
  ctx.user_data = user_data;

  ctx.dependency_exports = g_hash_table_new_full (g_str_hash, g_str_equal,
      g_free, (GDestroyNotify) gum_dependency_export_free);
  ctx.current_dependency = NULL;
  ctx.module_map = NULL;

  gum_elf_module_enumerate_dependencies (self->elf_module,
      gum_collect_dependency_exports, &ctx);

  gum_elf_module_enumerate_imports (self->elf_module, gum_emit_import, &ctx);

  if (ctx.module_map != NULL)
    gum_object_unref (ctx.module_map);
  g_hash_table_unref (ctx.dependency_exports);
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
_gum_module_enumerate_exports (GumModule * self,
                               GumFoundExportFunc func,
                               gpointer user_data)
{
  gum_elf_module_enumerate_exports (self->elf_module, func, user_data);
}

void
gum_module_enumerate_symbols (GumModule * self,
                              GumFoundSymbolFunc func,
                              gpointer user_data)
{
  GumEnumerateSymbolsContext ctx;

  ctx.func = func;
  ctx.user_data = user_data;

  gum_elf_module_enumerate_symbols (self->elf_module, gum_emit_symbol, &ctx);
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
gum_module_enumerate_ranges (GumModule * self,
                             GumPageProtection prot,
                             GumFoundRangeFunc func,
                             gpointer user_data)
{
  GumEnumerateRangesContext ctx;

  ctx.module = self;
  ctx.func = func;
  ctx.user_data = user_data;

  gum_process_enumerate_ranges (prot, gum_emit_range_if_module_name_matches,
      &ctx);
}

static gboolean
gum_emit_range_if_module_name_matches (const GumRangeDetails * details,
                                       gpointer user_data)
{
  GumEnumerateRangesContext * ctx = user_data;

  if (details->file == NULL)
    return TRUE;
  if (strcmp (details->file->path, ctx->module->path) != 0)
    return TRUE;

  return ctx->func (details, ctx->user_data);
}

void
gum_module_enumerate_sections (GumModule * self,
                               GumFoundSectionFunc func,
                               gpointer user_data)
{
  GumEnumerateSectionsContext ctx;

  ctx.func = func;
  ctx.user_data = user_data;

  gum_elf_module_enumerate_sections (self->elf_module, gum_emit_section, &ctx);
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
gum_module_enumerate_dependencies (GumModule * self,
                                   GumFoundDependencyFunc func,
                                   gpointer user_data)
{
  gum_elf_module_enumerate_dependencies (self->elf_module, func, user_data);
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
