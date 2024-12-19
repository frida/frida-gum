/*
 * Copyright (C) 2010-2024 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gummodule-elf.h"

#define GUM_MODULE_LOCK(o) g_mutex_lock (&(o)->mutex)
#define GUM_MODULE_UNLOCK(o) g_mutex_unlock (&(o)->mutex)

typedef struct _GumEnumerateImportsContext GumEnumerateImportsContext;
typedef struct _GumEnumerateSymbolsContext GumEnumerateSymbolsContext;
typedef struct _GumEnumerateRangesContext GumEnumerateRangesContext;
typedef struct _GumEnumerateSectionsContext GumEnumerateSectionsContext;

struct _GumEnumerateImportsContext
{
  GumFoundImportFunc func;
  gpointer user_data;
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
static gboolean gum_emit_symbol (const GumElfSymbolDetails * details,
    gpointer user_data);
static gboolean gum_emit_range_if_module_name_matches (
    const GumRangeDetails * details, gpointer user_data);
static gboolean gum_emit_section (const GumElfSectionDetails * details,
    gpointer user_data);

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
  g_mutex_init (&self->mutex);
}

static void
gum_module_dispose (GObject * object)
{
  GumModule * self = GUM_MODULE (object);

  g_clear_object (&self->cached_elf_module);

  if (self->destroy_handle != NULL)
    g_clear_pointer (&self->cached_handle, self->destroy_handle);
  else
    self->cached_handle = NULL;

  G_OBJECT_CLASS (gum_module_parent_class)->dispose (object);
}

static void
gum_module_finalize (GObject * object)
{
  GumModule * self = GUM_MODULE (object);

  g_mutex_clear (&self->mutex);

  g_free (self->path);

  G_OBJECT_CLASS (gum_module_parent_class)->finalize (object);
}

GumModule *
_gum_module_make (const gchar * path,
                  const GumMemoryRange * range,
                  GumCreateModuleHandleFunc create_handle,
                  gpointer create_handle_data,
                  GDestroyNotify create_handle_data_destroy,
                  GDestroyNotify destroy_handle)
{
  GumModule * module;
  gchar * name;

  module = g_object_new (GUM_TYPE_MODULE, NULL);

  module->path = g_strdup (path);
  module->range = *range;
  module->create_handle = create_handle;
  module->create_handle_data = create_handle_data;
  module->create_handle_data_destroy = create_handle_data_destroy;
  module->destroy_handle = destroy_handle;

  name = strrchr (module->path, '/');
  if (name != NULL)
    name++;
  else
    name = module->path;
  module->name = name;

  return module;
}

GumModule *
_gum_module_make_handleless (const gchar * path,
                             const GumMemoryRange * range)
{
  return _gum_module_make (path, range, NULL, NULL, NULL, NULL);
}

gpointer
_gum_module_get_handle (GumModule * self)
{
  GUM_MODULE_LOCK (self);

  if (!self->attempted_handle_creation)
  {
    self->attempted_handle_creation = TRUE;

    if (self->create_handle != NULL)
    {
      self->cached_handle = self->create_handle (self,
          self->create_handle_data);
    }
  }

  GUM_MODULE_UNLOCK (self);

  return self->cached_handle;
}

GumElfModule *
_gum_module_get_elf_module (GumModule * self)
{
  GUM_MODULE_LOCK (self);

  if (!self->attempted_elf_module_creation)
  {
    self->attempted_elf_module_creation = TRUE;

    self->cached_elf_module = gum_elf_module_new_from_memory (self->path,
        self->range.base_address, NULL);
  }

  GUM_MODULE_UNLOCK (self);

  return self->cached_elf_module;
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
  GumElfModule * elf_module;
  GumEnumerateImportsContext ctx;

  elf_module = _gum_module_get_elf_module (self);
  if (elf_module == NULL)
    return;

  ctx.func = func;
  ctx.user_data = user_data;

  gum_elf_module_enumerate_imports (elf_module, gum_emit_import, &ctx);
}

static gboolean
gum_emit_import (const GumImportDetails * details,
                 gpointer user_data)
{
  GumEnumerateImportsContext * ctx = user_data;
  GumImportDetails d;

  d.type = details->type;
  d.name = details->name;
  d.slot = details->slot;

  d.address = (d.slot != 0)
      ? GUM_ADDRESS (*((gpointer *) GSIZE_TO_POINTER (d.slot)))
      : 0;
  d.module = (d.address != 0)
      ? _gum_module_find_path_by_address (d.address)
      : NULL;

  return ctx->func (&d, ctx->user_data);
}

void
_gum_module_enumerate_exports (GumModule * self,
                               GumFoundExportFunc func,
                               gpointer user_data)
{
  GumElfModule * elf_module;

  elf_module = _gum_module_get_elf_module (self);
  if (elf_module == NULL)
    return;

  gum_elf_module_enumerate_exports (elf_module, func, user_data);
}

void
gum_module_enumerate_symbols (GumModule * self,
                              GumFoundSymbolFunc func,
                              gpointer user_data)
{
  GumElfModule * elf_module;
  GumEnumerateSymbolsContext ctx;

  elf_module = _gum_module_get_elf_module (self);
  if (elf_module == NULL)
    return;

  ctx.func = func;
  ctx.user_data = user_data;

  gum_elf_module_enumerate_symbols (elf_module, gum_emit_symbol, &ctx);
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
  GumElfModule * elf_module;
  GumEnumerateSectionsContext ctx;

  elf_module = _gum_module_get_elf_module (self);
  if (elf_module == NULL)
    return;

  ctx.func = func;
  ctx.user_data = user_data;

  gum_elf_module_enumerate_sections (elf_module, gum_emit_section, &ctx);
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
  GumElfModule * elf_module;

  elf_module = _gum_module_get_elf_module (self);
  if (elf_module == NULL)
    return;

  gum_elf_module_enumerate_dependencies (elf_module, func, user_data);
}
