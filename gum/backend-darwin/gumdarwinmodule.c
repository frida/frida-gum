/*
 * Copyright (C) 2015-2016 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumdarwinmodule.h"

#include "gumdarwin.h"
#include "gumleb.h"

#include <mach-o/fat.h>
#include <mach-o/loader.h>

#define MAX_METADATA_SIZE (64 * 1024)

enum
{
  PROP_0,
  PROP_NAME,
  PROP_TASK,
  PROP_CPU_TYPE,
  PROP_PAGE_SIZE,
  PROP_BASE_ADDRESS
};

typedef struct _GumResolveSymbolContext GumResolveSymbolContext;

typedef struct _GumEmitImportContext GumEmitImportContext;
typedef struct _GumEmitInitPointersContext GumEmitInitPointersContext;
typedef struct _GumEmitTermPointersContext GumEmitTermPointersContext;

typedef struct _GumExportsTrieForeachContext GumExportsTrieForeachContext;

typedef struct _GumDyldCacheHeader GumDyldCacheHeader;
typedef struct _GumDyldCacheMappingInfo GumDyldCacheMappingInfo;
typedef struct _GumDyldCacheImageInfo GumDyldCacheImageInfo;

struct _GumResolveSymbolContext
{
  const gchar * name;
  GumAddress result;
};

struct _GumEmitImportContext
{
  GumFoundImportFunc func;
  gpointer user_data;

  GumDarwinModule * module;
  GHashTable * imports_seen;
  gboolean carry_on;
};

struct _GumEmitInitPointersContext
{
  GumDarwinFoundInitPointersFunc func;
  gpointer user_data;
  gsize pointer_size;
};

struct _GumEmitTermPointersContext
{
  GumDarwinFoundTermPointersFunc func;
  gpointer user_data;
  gsize pointer_size;
};

struct _GumExportsTrieForeachContext
{
  GumDarwinFoundExportFunc func;
  gpointer user_data;

  GString * prefix;
  const guint8 * exports;
  const guint8 * exports_end;
};

struct _GumDyldCacheHeader
{
  gchar magic[16];
  guint32 mapping_offset;
  guint32 mapping_count;
  guint32 images_offset;
  guint32 images_count;
};

struct _GumDyldCacheMappingInfo
{
  GumAddress address;
  guint64 size;
  guint64 offset;
  guint32 max_protection;
  guint32 initial_protection;
};

struct _GumDyldCacheImageInfo
{
  GumAddress address;
  guint64 mtime;
  guint64 inode;
  guint32 name_offset;
  guint32 padding;
};

static void gum_darwin_module_constructed (GObject * object);
static void gum_darwin_module_finalize (GObject * object);
static void gum_darwin_module_get_property (GObject * object,
    guint property_id, GValue * value, GParamSpec * pspec);
static void gum_darwin_module_set_property (GObject * object,
    guint property_id, const GValue * value, GParamSpec * pspec);

static gboolean gum_store_address_if_name_matches (
    const GumDarwinSymbolDetails * details, gpointer user_data);
static gboolean gum_emit_import (const GumDarwinBindDetails * details,
    gpointer user_data);
static gboolean gum_emit_section_init_pointers (
    const GumDarwinSectionDetails * details, gpointer user_data);
static gboolean gum_emit_section_term_pointers (
    const GumDarwinSectionDetails * details, gpointer user_data);
static gboolean gum_darwin_module_ensure_image_loaded (GumDarwinModule * self);
static gboolean gum_darwin_module_try_load_image_from_cache (
    GumDarwinModule * self, const gchar * name, GumCpuType cpu_type,
    GMappedFile * cache_file);
static void gum_darwin_module_load_image_from_filesystem (
    GumDarwinModule * self, const gchar * name, GumCpuType cpu_type);
static void gum_darwin_module_load_image_from_blob (GumDarwinModule * self,
    GBytes * blob);
static gboolean gum_darwin_module_load_image_from_memory (
    GumDarwinModule * self);
static gboolean gum_darwin_module_take_image (GumDarwinModule * self,
    GumDarwinModuleImage * image);
static void gum_darwin_module_read_and_assign (GumDarwinModule * self,
    GumAddress address, gsize size, const guint8 ** start, const guint8 ** end,
    gpointer * malloc_data);
static gboolean gum_add_text_range_if_text_section (
    const GumDarwinSectionDetails * details, gpointer user_data);
static gboolean gum_section_flags_indicate_text_section (uint32_t flags);

static gboolean gum_exports_trie_find (const guint8 * exports,
    const guint8 * exports_end, const gchar * name,
    GumDarwinExportDetails * details);
static gboolean gum_exports_trie_foreach (const guint8 * exports,
    const guint8 * exports_end, GumDarwinFoundExportFunc func,
    gpointer user_data);
static gboolean gum_exports_trie_traverse (const guint8 * p,
    GumExportsTrieForeachContext * ctx);

static void gum_darwin_export_details_init_from_node (
    GumDarwinExportDetails * details, const gchar * name, const guint8 * node,
    const guint8 * exports_end);

static const GumDyldCacheImageInfo * gum_dyld_cache_find_image_by_name (
    const gchar * name, const GumDyldCacheImageInfo * images, gsize image_count,
    gconstpointer cache);
static guint64 gum_dyld_cache_compute_image_size (
    const GumDyldCacheImageInfo * image, const GumDyldCacheImageInfo * images,
    gsize image_count);
static guint64 gum_dyld_cache_offset_from_address (GumAddress address,
    const GumDyldCacheMappingInfo * mappings, gsize mapping_count);

G_DEFINE_TYPE (GumDarwinModule, gum_darwin_module, G_TYPE_OBJECT)

static void
gum_darwin_module_class_init (GumDarwinModuleClass * klass)
{
  GObjectClass * object_class = G_OBJECT_CLASS (klass);

  object_class->constructed = gum_darwin_module_constructed;
  object_class->finalize = gum_darwin_module_finalize;
  object_class->get_property = gum_darwin_module_get_property;
  object_class->set_property = gum_darwin_module_set_property;

  g_object_class_install_property (object_class, PROP_NAME,
      g_param_spec_string ("name", "Name", "Name", NULL,
      G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY | G_PARAM_STATIC_STRINGS));
  g_object_class_install_property (object_class, PROP_TASK,
      g_param_spec_uint ("task", "Task", "Mach task", 0, G_MAXUINT,
      MACH_PORT_NULL, G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY |
      G_PARAM_STATIC_STRINGS));
  g_object_class_install_property (object_class, PROP_CPU_TYPE,
      g_param_spec_uint ("cpu-type", "CpuType", "CPU type", 0, G_MAXUINT,
      GUM_CPU_INVALID, G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY |
      G_PARAM_STATIC_STRINGS));
  g_object_class_install_property (object_class, PROP_PAGE_SIZE,
      g_param_spec_uint ("page-size", "PageSize", "Page size", 0, G_MAXUINT,
      0, G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY | G_PARAM_STATIC_STRINGS));
  g_object_class_install_property (object_class, PROP_BASE_ADDRESS,
      g_param_spec_uint64 ("base-address", "BaseAddress", "Base address", 0,
      G_MAXUINT64, 0, G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS));
}

static void
gum_darwin_module_init (GumDarwinModule * self)
{
  self->segments = g_array_new (FALSE, FALSE, sizeof (GumDarwinSegment));
  self->text_ranges = g_array_new (FALSE, FALSE, sizeof (GumMemoryRange));
  self->dependencies = g_ptr_array_sized_new (5);
  self->reexports = g_ptr_array_sized_new (5);
}

static void
gum_darwin_module_constructed (GObject * object)
{
  GumDarwinModule * self = GUM_DARWIN_MODULE (object);

  g_assert (self->name != NULL);
  g_assert (self->task != MACH_PORT_NULL);

  self->is_local = self->task == mach_task_self ();

  if (self->cpu_type == GUM_CPU_INVALID)
  {
    int pid;

    if (pid_for_task (self->task, &pid) != KERN_SUCCESS ||
        !gum_darwin_cpu_type_from_pid (pid, &self->cpu_type))
    {
      self->cpu_type = GUM_NATIVE_CPU;
    }
  }

  switch (self->cpu_type)
  {
    case GUM_CPU_IA32:
    case GUM_CPU_ARM:
      self->pointer_size = 4;
      break;
    case GUM_CPU_AMD64:
    case GUM_CPU_ARM64:
      self->pointer_size = 8;
      break;
    default:
      g_assert_not_reached ();
  }

  if (self->page_size == 0)
  {
    if (self->is_local)
    {
      self->page_size = gum_query_page_size ();
    }
    else
    {
      guint page_size = 4096;

      gum_darwin_query_page_size (self->task, &page_size);

      self->page_size = page_size;
    }
  }
}

static void
gum_darwin_module_finalize (GObject * object)
{
  GumDarwinModule * self = GUM_DARWIN_MODULE (object);

  g_ptr_array_unref (self->dependencies);
  g_ptr_array_unref (self->reexports);

  g_free (self->rebases_malloc_data);
  g_free (self->binds_malloc_data);
  g_free (self->lazy_binds_malloc_data);
  g_free (self->exports_malloc_data);

  g_array_unref (self->segments);
  g_array_unref (self->text_ranges);

  if (self->image != NULL)
    gum_darwin_module_image_free (self->image);

  g_free (self->name);

  G_OBJECT_CLASS (gum_darwin_module_parent_class)->finalize (object);
}

static void
gum_darwin_module_get_property (GObject * object,
                                guint property_id,
                                GValue * value,
                                GParamSpec * pspec)
{
  GumDarwinModule * self = GUM_DARWIN_MODULE (object);

  switch (property_id)
  {
    case PROP_NAME:
      g_value_set_string (value, self->name);
      break;
    case PROP_TASK:
      g_value_set_uint (value, self->task);
      break;
    case PROP_CPU_TYPE:
      g_value_set_uint (value, self->cpu_type);
      break;
    case PROP_PAGE_SIZE:
      g_value_set_uint (value, self->page_size);
      break;
    case PROP_BASE_ADDRESS:
      g_value_set_uint64 (value, self->base_address);
      break;
    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, property_id, pspec);
  }
}

static void
gum_darwin_module_set_property (GObject * object,
                                guint property_id,
                                const GValue * value,
                                GParamSpec * pspec)
{
  GumDarwinModule * self = GUM_DARWIN_MODULE (object);

  switch (property_id)
  {
    case PROP_NAME:
      g_free (self->name);
      self->name = g_value_dup_string (value);
      break;
    case PROP_TASK:
      self->task = g_value_get_uint (value);
      break;
    case PROP_CPU_TYPE:
      self->cpu_type = g_value_get_uint (value);
      break;
    case PROP_PAGE_SIZE:
      self->page_size = g_value_get_uint (value);
      break;
    case PROP_BASE_ADDRESS:
      self->base_address = g_value_get_uint64 (value);
      break;
    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, property_id, pspec);
  }
}

GumDarwinModule *
gum_darwin_module_new_from_file (const gchar * name,
                                 mach_port_t task,
                                 GumCpuType cpu_type,
                                 guint page_size,
                                 GMappedFile * cache_file)
{
  GumDarwinModule * module;

  module = g_object_new (GUM_DARWIN_TYPE_MODULE,
      "name", name,
      "task", task,
      "cpu-type", cpu_type,
      "page-size", page_size,
      NULL);
  if (cache_file == NULL ||
      !gum_darwin_module_try_load_image_from_cache (module, name, cpu_type,
      cache_file))
  {
    gum_darwin_module_load_image_from_filesystem (module, name, cpu_type);
  }

  return module;
}

GumDarwinModule *
gum_darwin_module_new_from_blob (const gchar * name,
                                 GBytes * blob,
                                 mach_port_t task,
                                 GumCpuType cpu_type,
                                 guint page_size)
{
  GumDarwinModule * module;

  module = g_object_new (GUM_DARWIN_TYPE_MODULE,
      "name", name,
      "task", task,
      "cpu-type", cpu_type,
      "page-size", page_size,
      NULL);
  gum_darwin_module_load_image_from_blob (module, blob);

  return module;
}

GumDarwinModule *
gum_darwin_module_new_from_memory (const gchar * name,
                                   mach_port_t task,
                                   GumCpuType cpu_type,
                                   guint page_size,
                                   GumAddress base_address)
{
  return g_object_new (GUM_DARWIN_TYPE_MODULE,
      "name", name,
      "task", task,
      "cpu-type", cpu_type,
      "page-size", page_size,
      "base-address", base_address,
      NULL);
}

gboolean
gum_darwin_module_resolve_export (GumDarwinModule * self,
                                  const gchar * name,
                                  GumDarwinExportDetails * details)
{
  if (!gum_darwin_module_ensure_image_loaded (self))
    return FALSE;

  return gum_exports_trie_find (self->exports, self->exports_end, name,
      details);
}

GumAddress
gum_darwin_module_resolve_symbol_address (GumDarwinModule * self,
                                          const gchar * name)
{
  GumResolveSymbolContext ctx;

  ctx.name = name;
  ctx.result = 0;

  gum_darwin_module_enumerate_symbols (self, gum_store_address_if_name_matches,
      &ctx);

  return ctx.result;
}

static gboolean
gum_store_address_if_name_matches (const GumDarwinSymbolDetails * details,
                                   gpointer user_data)
{
  GumResolveSymbolContext * ctx = user_data;
  gboolean carry_on = TRUE;

  if (strcmp (details->name, ctx->name) == 0)
  {
    ctx->result = details->address;
    carry_on = FALSE;
  }

  return carry_on;
}

gboolean
gum_darwin_module_lacks_exports_for_reexports (GumDarwinModule * self)
{
  uint32_t flags;

  if (!gum_darwin_module_ensure_image_loaded (self))
    return FALSE;

  /*
   * FIXME: There must be a better way to detect this behavioral change
   *        introduced in macOS 10.11 and iOS 9.0, but this will have to
   *        do for now.
   */
  flags = ((struct mach_header *) self->image->data)->flags;

  return (flags & MH_PREBOUND) == 0;
}

void
gum_darwin_module_enumerate_imports (GumDarwinModule * self,
                                     GumFoundImportFunc func,
                                     gpointer user_data)
{
  GumEmitImportContext ctx;

  ctx.func = func;
  ctx.user_data = user_data;

  ctx.module = self;
  ctx.imports_seen = g_hash_table_new_full (g_str_hash, g_str_equal, g_free,
      NULL);
  ctx.carry_on = TRUE;
  gum_darwin_module_enumerate_binds (self, gum_emit_import, &ctx);
  if (ctx.carry_on)
    gum_darwin_module_enumerate_lazy_binds (self, gum_emit_import, &ctx);

  g_hash_table_unref (ctx.imports_seen);
}

static gboolean
gum_emit_import (const GumDarwinBindDetails * details,
                 gpointer user_data)
{
  GumEmitImportContext * ctx = user_data;
  GumImportDetails d;
  gchar * key;

  d.type = GUM_IMPORT_UNKNOWN;
  d.name = details->symbol_name;
  switch (details->library_ordinal)
  {
    case BIND_SPECIAL_DYLIB_MAIN_EXECUTABLE:
    case BIND_SPECIAL_DYLIB_SELF:
      return TRUE;
    case BIND_SPECIAL_DYLIB_FLAT_LOOKUP:
    {
      d.module = NULL;
      break;
    }
    default:
      d.module = gum_darwin_module_dependency (ctx->module,
          details->library_ordinal);
      break;
  }
  d.address = 0;

  key = g_strconcat (
      (d.module != NULL) ? d.module : "",
      "|",
      d.name,
      NULL);
  if (g_hash_table_lookup (ctx->imports_seen, key) == NULL)
  {
    g_hash_table_insert (ctx->imports_seen, key, key);

    ctx->carry_on = ctx->func (&d, ctx->user_data);
  }
  else
  {
    g_free (key);
  }

  return ctx->carry_on;
}

void
gum_darwin_module_enumerate_exports (GumDarwinModule * self,
                                     GumDarwinFoundExportFunc func,
                                     gpointer user_data)
{
  if (!gum_darwin_module_ensure_image_loaded (self))
    return;

  gum_exports_trie_foreach (self->exports, self->exports_end, func, user_data);
}

void
gum_darwin_module_enumerate_symbols (GumDarwinModule * self,
                                     GumDarwinFoundSymbolFunc func,
                                     gpointer user_data)
{
  GumDarwinModuleImage * image;
  const struct symtab_command * symtab;
  GumAddress slide, linkedit;
  gsize symbol_size;
  gpointer symbols = NULL, strings = NULL;
  gsize symbol_index;

  if (!gum_darwin_module_ensure_image_loaded (self))
    goto beach;
  image = self->image;

  symtab = self->symtab;
  if (symtab == NULL)
    goto beach;

  slide = gum_darwin_module_slide (self);

  if (!gum_darwin_find_linkedit (image->data, image->size, &linkedit))
    goto beach;
  linkedit += slide;

  symbol_size = (self->pointer_size == 8)
      ? sizeof (struct nlist_64)
      : sizeof (struct nlist);

  symbols = gum_darwin_read (self->task, linkedit + symtab->symoff,
      symtab->nsyms * symbol_size, NULL);
  strings = gum_darwin_read (self->task, linkedit + symtab->stroff,
      symtab->strsize, NULL);

  for (symbol_index = 0; symbol_index != symtab->nsyms; symbol_index++)
  {
    GumDarwinSymbolDetails details;
    gboolean carry_on;

    if (self->pointer_size == 8)
    {
      struct nlist_64 * symbol;

      symbol = symbols + (symbol_index * sizeof (struct nlist_64));

      details.name = strings + symbol->n_un.n_strx;
      details.address = symbol->n_value + slide;

      details.type = symbol->n_type;
      details.section = symbol->n_sect;
      details.description = symbol->n_desc;
    }
    else
    {
      struct nlist * symbol;

      symbol = symbols + (symbol_index * sizeof (struct nlist));

      details.name = strings + symbol->n_un.n_strx;
      details.address = symbol->n_value + slide;

      details.type = symbol->n_type;
      details.section = symbol->n_sect;
      details.description = symbol->n_desc;
    }

    carry_on = func (&details, user_data);
    if (!carry_on)
      goto beach;
  }

beach:
  g_free (strings);
  g_free (symbols);
}

GumAddress
gum_darwin_module_slide (GumDarwinModule * self)
{
  return self->base_address - self->preferred_address;
}

const GumDarwinSegment *
gum_darwin_module_segment (GumDarwinModule * self,
                           gsize index)
{
  if (!gum_darwin_module_ensure_image_loaded (self))
    return NULL;

  return &g_array_index (self->segments, GumDarwinSegment, index);
}

void
gum_darwin_module_enumerate_sections (GumDarwinModule * self,
                                      GumDarwinFoundSectionFunc func,
                                      gpointer user_data)
{
  const struct mach_header * header;
  gconstpointer command;
  gsize command_index;
  GumAddress slide;

  if (!gum_darwin_module_ensure_image_loaded (self))
    return;

  header = (struct mach_header *) self->image->data;
  if (header->magic == MH_MAGIC)
    command = self->image->data + sizeof (struct mach_header);
  else
    command = self->image->data + sizeof (struct mach_header_64);
  slide = gum_darwin_module_slide (self);
  for (command_index = 0; command_index != header->ncmds; command_index++)
  {
    const struct load_command * lc = command;

    if (lc->cmd == LC_SEGMENT || lc->cmd == LC_SEGMENT_64)
    {
      gconstpointer sections;
      gsize section_count, section_index;

      if (lc->cmd == LC_SEGMENT)
      {
        const struct segment_command * sc = command;
        sections = sc + 1;
        section_count = sc->nsects;
      }
      else
      {
        const struct segment_command_64 * sc = command;
        sections = sc + 1;
        section_count = sc->nsects;
      }

      for (section_index = 0; section_index != section_count; section_index++)
      {
        GumDarwinSectionDetails details;

        if (lc->cmd == LC_SEGMENT)
        {
          const struct section * s = sections +
              (section_index * sizeof (struct section));
          details.segment_name = s->segname;
          details.section_name = s->sectname;
          details.vm_address = s->addr + (guint32) slide;
          details.size = s->size;
          details.file_offset = s->offset;
          details.flags = s->flags;
        }
        else
        {
          const struct section_64 * s = sections +
              (section_index * sizeof (struct section_64));
          details.segment_name = s->segname;
          details.section_name = s->sectname;
          details.vm_address = s->addr + (guint64) slide;
          details.size = s->size;
          details.file_offset = s->offset;
          details.flags = s->flags;
        }

        if (!func (&details, user_data))
          return;
      }
    }

    command += lc->cmdsize;
  }
}

gboolean
gum_darwin_module_is_address_in_text_section (GumDarwinModule * self,
                                              GumAddress address)
{
  guint i;

  for (i = 0; i != self->text_ranges->len; i++)
  {
    GumMemoryRange * r = &g_array_index (self->text_ranges, GumMemoryRange, i);
    if (GUM_MEMORY_RANGE_INCLUDES (r, address))
      return TRUE;
  }

  return FALSE;
}

void
gum_darwin_module_enumerate_rebases (GumDarwinModule * self,
                                     GumDarwinFoundRebaseFunc func,
                                     gpointer user_data)
{
  const guint8 * start, * end, * p;
  gboolean done;
  GumDarwinRebaseDetails details;
  guint64 max_offset;

  if (!gum_darwin_module_ensure_image_loaded (self))
    return;

  start = self->rebases;
  end = self->rebases_end;
  p = start;
  done = FALSE;

  details.segment = gum_darwin_module_segment (self, 0);
  details.offset = 0;
  details.type = 0;
  details.slide = gum_darwin_module_slide (self);

  max_offset = details.segment->file_size;

  while (!done && p != end)
  {
    guint8 opcode = *p & REBASE_OPCODE_MASK;
    guint8 immediate = *p & REBASE_IMMEDIATE_MASK;

    p++;

    switch (opcode)
    {
      case REBASE_OPCODE_DONE:
        done = TRUE;
        break;
      case REBASE_OPCODE_SET_TYPE_IMM:
        details.type = immediate;
        break;
      case REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB:
      {
        gint segment_index = immediate;
        details.segment = gum_darwin_module_segment (self, segment_index);
        details.offset = gum_read_uleb128 (&p, end);
        max_offset = details.segment->file_size;
        break;
      }
      case REBASE_OPCODE_ADD_ADDR_ULEB:
        details.offset += gum_read_uleb128 (&p, end);
        break;
      case REBASE_OPCODE_ADD_ADDR_IMM_SCALED:
        details.offset += immediate * self->pointer_size;
        break;
      case REBASE_OPCODE_DO_REBASE_IMM_TIMES:
      {
        guint8 i;

        for (i = 0; i != immediate; i++)
        {
          g_assert_cmpuint (details.offset, <, max_offset);
          if (!func (&details, user_data))
            return;
          details.offset += self->pointer_size;
        }

        break;
      }
      case REBASE_OPCODE_DO_REBASE_ULEB_TIMES:
      {
        guint64 count, i;

        count = gum_read_uleb128 (&p, end);
        for (i = 0; i != count; i++)
        {
          g_assert_cmpuint (details.offset, <, max_offset);
          if (!func (&details, user_data))
            return;
          details.offset += self->pointer_size;
        }

        break;
      }
      case REBASE_OPCODE_DO_REBASE_ADD_ADDR_ULEB:
        g_assert_cmpuint (details.offset, <, max_offset);
        if (!func (&details, user_data))
          return;
        details.offset += self->pointer_size + gum_read_uleb128 (&p, end);
        break;
      case REBASE_OPCODE_DO_REBASE_ULEB_TIMES_SKIPPING_ULEB:
      {
        gsize count, skip, i;

        count = gum_read_uleb128 (&p, end);
        skip = gum_read_uleb128 (&p, end);
        for (i = 0; i != count; ++i)
        {
          g_assert_cmpuint (details.offset, <, max_offset);
          if (!func (&details, user_data))
            return;
          details.offset += self->pointer_size + skip;
        }

        break;
      }
      default:
        g_assert_not_reached ();
        break;
    }
  }
}

void
gum_darwin_module_enumerate_binds (GumDarwinModule * self,
                                   GumDarwinFoundBindFunc func,
                                   gpointer user_data)
{
  const guint8 * start, * end, * p;
  gboolean done;
  GumDarwinBindDetails details;
  guint64 max_offset;

  if (!gum_darwin_module_ensure_image_loaded (self))
    return;

  start = self->binds;
  end = self->binds_end;
  p = start;
  done = FALSE;

  details.segment = gum_darwin_module_segment (self, 0);
  details.offset = 0;
  details.type = 0;
  details.library_ordinal = 0;
  details.symbol_name = NULL;
  details.symbol_flags = 0;
  details.addend = 0;

  max_offset = details.segment->file_size;

  while (!done && p != end)
  {
    guint8 opcode = *p & BIND_OPCODE_MASK;
    guint8 immediate = *p & BIND_IMMEDIATE_MASK;

    p++;

    switch (opcode)
    {
      case BIND_OPCODE_DONE:
        done = TRUE;
        break;
      case BIND_OPCODE_SET_DYLIB_ORDINAL_IMM:
        details.library_ordinal = immediate;
        break;
      case BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB:
        details.library_ordinal = gum_read_uleb128 (&p, end);
        break;
      case BIND_OPCODE_SET_DYLIB_SPECIAL_IMM:
        if (immediate == 0)
        {
          details.library_ordinal = 0;
        }
        else
        {
          gint8 value = BIND_OPCODE_MASK | immediate;
          details.library_ordinal = value;
        }
        break;
      case BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM:
        details.symbol_name = (gchar *) p;
        details.symbol_flags = immediate;
        while (*p != '\0')
          p++;
        p++;
        break;
      case BIND_OPCODE_SET_TYPE_IMM:
        details.type = immediate;
        break;
      case BIND_OPCODE_SET_ADDEND_SLEB:
        details.addend = gum_read_sleb128 (&p, end);
        break;
      case BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB:
      {
        gint segment_index = immediate;
        details.segment = gum_darwin_module_segment (self, segment_index);
        details.offset = gum_read_uleb128 (&p, end);
        max_offset = details.segment->file_size;
        break;
      }
      case BIND_OPCODE_ADD_ADDR_ULEB:
        details.offset += gum_read_uleb128 (&p, end);
        break;
      case BIND_OPCODE_DO_BIND:
        g_assert_cmpuint (details.offset, <, max_offset);
        if (!func (&details, user_data))
          return;
        details.offset += self->pointer_size;
        break;
      case BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB:
        g_assert_cmpuint (details.offset, <, max_offset);
        if (!func (&details, user_data))
          return;
        details.offset += self->pointer_size + gum_read_uleb128 (&p, end);
        break;
      case BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED:
        g_assert_cmpuint (details.offset, <, max_offset);
        if (!func (&details, user_data))
          return;
        details.offset += self->pointer_size + (immediate * self->pointer_size);
        break;
      case BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB:
      {
        guint64 count, skip, i;

        count = gum_read_uleb128 (&p, end);
        skip = gum_read_uleb128 (&p, end);
        for (i = 0; i != count; ++i)
        {
          g_assert_cmpuint (details.offset, <, max_offset);
          if (!func (&details, user_data))
            return;
          details.offset += self->pointer_size + skip;
        }

        break;
      }
      default:
        g_assert_not_reached ();
        break;
    }
  }
}

void
gum_darwin_module_enumerate_lazy_binds (GumDarwinModule * self,
                                        GumDarwinFoundBindFunc func,
                                        gpointer user_data)
{
  const guint8 * start, * end, * p;
  GumDarwinBindDetails details;
  guint64 max_offset;

  if (!gum_darwin_module_ensure_image_loaded (self))
    return;

  start = self->lazy_binds;
  end = self->lazy_binds_end;
  p = start;

  details.segment = gum_darwin_module_segment (self, 0);
  details.offset = 0;
  details.type = BIND_TYPE_POINTER;
  details.library_ordinal = 0;
  details.symbol_name = NULL;
  details.symbol_flags = 0;
  details.addend = 0;

  max_offset = details.segment->file_size;

  while (p != end)
  {
    guint8 opcode = *p & BIND_OPCODE_MASK;
    guint8 immediate = *p & BIND_IMMEDIATE_MASK;

    p++;

    switch (opcode)
    {
      case BIND_OPCODE_DONE:
        break;
      case BIND_OPCODE_SET_DYLIB_ORDINAL_IMM:
        details.library_ordinal = immediate;
        break;
      case BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB:
        details.library_ordinal = gum_read_uleb128 (&p, end);
        break;
      case BIND_OPCODE_SET_DYLIB_SPECIAL_IMM:
        if (immediate == 0)
        {
          details.library_ordinal = 0;
        }
        else
        {
          gint8 value = BIND_OPCODE_MASK | immediate;
          details.library_ordinal = value;
        }
        break;
      case BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM:
        details.symbol_name = (gchar *) p;
        details.symbol_flags = immediate;
        while (*p != '\0')
          p++;
        p++;
        break;
      case BIND_OPCODE_SET_TYPE_IMM:
        details.type = immediate;
        break;
      case BIND_OPCODE_SET_ADDEND_SLEB:
        details.addend = gum_read_sleb128 (&p, end);
        break;
      case BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB:
      {
        gint segment_index = immediate;
        details.segment = gum_darwin_module_segment (self, segment_index);
        details.offset = gum_read_uleb128 (&p, end);
        max_offset = details.segment->file_size;
        break;
      }
      case BIND_OPCODE_ADD_ADDR_ULEB:
        details.offset += gum_read_uleb128 (&p, end);
        break;
      case BIND_OPCODE_DO_BIND:
        g_assert_cmpuint (details.offset, <, max_offset);
        if (!func (&details, user_data))
          return;
        details.offset += self->pointer_size;
        break;
      case BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB:
      case BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED:
      case BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB:
      default:
        g_assert_not_reached ();
        break;
    }
  }
}

void
gum_darwin_module_enumerate_init_pointers (GumDarwinModule * self,
                                           GumDarwinFoundInitPointersFunc func,
                                           gpointer user_data)
{
  GumEmitInitPointersContext ctx;
  ctx.func = func;
  ctx.user_data = user_data;
  ctx.pointer_size = self->pointer_size;
  gum_darwin_module_enumerate_sections (self, gum_emit_section_init_pointers,
      &ctx);
}

void
gum_darwin_module_enumerate_term_pointers (GumDarwinModule * self,
                                           GumDarwinFoundTermPointersFunc func,
                                           gpointer user_data)
{
  GumEmitTermPointersContext ctx;
  ctx.func = func;
  ctx.user_data = user_data;
  ctx.pointer_size = self->pointer_size;
  gum_darwin_module_enumerate_sections (self, gum_emit_section_term_pointers,
      &ctx);
}

static gboolean
gum_emit_section_init_pointers (const GumDarwinSectionDetails * details,
                                gpointer user_data)
{
  if ((details->flags & SECTION_TYPE) == S_MOD_INIT_FUNC_POINTERS)
  {
    GumEmitInitPointersContext * ctx = user_data;
    GumDarwinInitPointersDetails d;
    d.address = details->vm_address;
    d.count = details->size / ctx->pointer_size;
    return ctx->func (&d, ctx->user_data);
  }

  return TRUE;
}

static gboolean
gum_emit_section_term_pointers (const GumDarwinSectionDetails * details,
                                gpointer user_data)
{
  if ((details->flags & SECTION_TYPE) == S_MOD_TERM_FUNC_POINTERS)
  {
    GumEmitTermPointersContext * ctx = user_data;
    GumDarwinTermPointersDetails d;
    d.address = details->vm_address;
    d.count = details->size / ctx->pointer_size;
    return ctx->func (&d, ctx->user_data);
  }

  return TRUE;
}

const gchar *
gum_darwin_module_dependency (GumDarwinModule * self,
                              gint ordinal)
{
  const gchar * result;

  g_assert_cmpint (ordinal, >=, 1);

  if (!gum_darwin_module_ensure_image_loaded (self))
    return NULL;

  result = g_ptr_array_index (self->dependencies, ordinal - 1);
  g_assert (result != NULL);

  return result;
}

static gboolean
gum_darwin_module_ensure_image_loaded (GumDarwinModule * self)
{
  if (self->image != NULL)
    return TRUE;
  else
    return gum_darwin_module_load_image_from_memory (self);
}

static gboolean
gum_darwin_module_try_load_image_from_cache (GumDarwinModule * self,
                                             const gchar * name,
                                             GumCpuType cpu_type,
                                             GMappedFile * cache_file)
{
  gpointer cache;
  const GumDyldCacheHeader * header;
  const GumDyldCacheImageInfo * images, * image;
  const GumDyldCacheMappingInfo * mappings, * first_mapping, * second_mapping,
      * last_mapping, * mapping;
  guint64 image_offset, image_size;
  GumDarwinModuleImage * module_image;
  gboolean success;

  cache = g_mapped_file_get_contents (cache_file);
  g_assert (cache != NULL);

  header = cache;
  images = cache + header->images_offset;
  mappings = cache + header->mapping_offset;
  first_mapping = &mappings[0];
  second_mapping = &mappings[1];
  last_mapping = &mappings[header->mapping_count - 1];

  image = gum_dyld_cache_find_image_by_name (name, images,
      header->images_count, cache);
  if (image == NULL)
    return FALSE;

  image_offset = gum_dyld_cache_offset_from_address (image->address, mappings,
      header->mapping_count);
  image_size = gum_dyld_cache_compute_image_size (image, images,
      header->images_count);

  g_assert_cmpint (image_offset, >=, first_mapping->offset);
  g_assert_cmpint (image_offset, <, first_mapping->offset +
      first_mapping->size);

  module_image = gum_darwin_module_image_new ();

  module_image->source_offset = image_offset;
  module_image->source_size = image_size;
  module_image->shared_offset = second_mapping->offset - image_offset;
  module_image->shared_size = (last_mapping->offset + last_mapping->size) -
      second_mapping->offset;
  for (mapping = second_mapping; mapping != last_mapping + 1; mapping++)
  {
    GumDarwinModuleImageSegment segment;
    segment.offset = module_image->shared_offset + (mapping->offset -
        second_mapping->offset);
    segment.size = mapping->size;
    segment.protection = mapping->initial_protection;
    g_array_append_val (module_image->shared_segments, segment);
  }

  module_image->data = cache + image_offset;
  module_image->size = module_image->shared_offset +
      module_image->shared_size;
  module_image->linkedit = cache;

  module_image->bytes = g_mapped_file_get_bytes (cache_file);

  success = gum_darwin_module_take_image (self, module_image);
  g_assert (success);

  return TRUE;
}

static void
gum_darwin_module_load_image_from_filesystem (GumDarwinModule * self,
                                              const gchar * name,
                                              GumCpuType cpu_type)
{
  GMappedFile * file;
  gsize size, size_in_pages, page_size;
  gpointer data;
  GBytes * blob;

  file = g_mapped_file_new (name, FALSE, NULL);
  g_assert (file != NULL);

  size = g_mapped_file_get_length (file);
  page_size = gum_query_page_size ();
  size_in_pages = size / page_size;
  if (size % page_size != 0)
    size_in_pages++;

  data = gum_alloc_n_pages (size_in_pages, GUM_PAGE_RW);
  memcpy (data, g_mapped_file_get_contents (file), size);

  g_clear_pointer (&file, g_mapped_file_unref);

  blob = g_bytes_new_with_free_func (data, size, gum_free_pages, data);

  gum_darwin_module_load_image_from_blob (self, blob);

  g_bytes_unref (blob);
}

static void
gum_darwin_module_load_image_from_blob (GumDarwinModule * self,
                                        GBytes * blob)
{
  GumDarwinModuleImage * image;
  gpointer blob_data;
  gsize blob_size;
  struct fat_header * fat_header;
  struct mach_header * header_32 = NULL;
  struct mach_header_64 * header_64 = NULL;
  gsize size_32 = 0;
  gsize size_64 = 0;
  gboolean success;

  image = gum_darwin_module_image_new ();
  image->bytes = g_bytes_ref (blob);

  blob_data = (gpointer) g_bytes_get_data (blob, &blob_size);

  fat_header = blob_data;
  switch (fat_header->magic)
  {
    case FAT_CIGAM:
    {
      uint32_t count, i;

      count = GUINT32_FROM_BE (fat_header->nfat_arch);
      for (i = 0; i != count; i++)
      {
        struct fat_arch * fat_arch = ((struct fat_arch *) (fat_header + 1)) + i;
        gpointer mach_header = blob_data + GUINT32_FROM_BE (fat_arch->offset);
        switch (((struct mach_header *) mach_header)->magic)
        {
          case MH_MAGIC:
            header_32 = mach_header;
            size_32 = GUINT32_FROM_BE (fat_arch->size);
            break;
          case MH_MAGIC_64:
            header_64 = mach_header;
            size_64 = GUINT32_FROM_BE (fat_arch->size);
            break;
          default:
            g_assert_not_reached ();
            break;
        }
      }

      break;
    }
    case MH_MAGIC:
      header_32 = blob_data;
      size_32 = blob_size;
      break;
    case MH_MAGIC_64:
      header_64 = blob_data;
      size_64 = blob_size;
      break;
    default:
      g_assert_not_reached ();
      break;
  }

  switch (self->cpu_type)
  {
    case GUM_CPU_IA32:
    case GUM_CPU_ARM:
      g_assert (header_32 != NULL);
      image->data = header_32;
      image->size = size_32;
      image->linkedit = header_32;
      break;
    case GUM_CPU_AMD64:
    case GUM_CPU_ARM64:
      g_assert (header_64 != NULL);
      image->data = header_64;
      image->size = size_64;
      image->linkedit = header_64;
      break;
    default:
      g_assert_not_reached ();
      break;
  }

  success = gum_darwin_module_take_image (self, image);
  g_assert (success);
}

static gboolean
gum_darwin_module_load_image_from_memory (GumDarwinModule * self)
{
  gpointer data, malloc_data;
  gsize data_size;
  GumDarwinModuleImage * image;

  g_assert_cmpint (self->base_address, !=, 0);

  if (self->is_local)
  {
    data = GSIZE_TO_POINTER (self->base_address);
    data_size = MAX_METADATA_SIZE;
    malloc_data = NULL;
  }
  else
  {
    data = gum_darwin_read (self->task, self->base_address,
        MAX_METADATA_SIZE, &data_size);
    if (data == NULL)
      return FALSE;
    malloc_data = data;
  }

  image = gum_darwin_module_image_new ();

  image->data = data;
  image->size = data_size;

  image->malloc_data = malloc_data;

  return gum_darwin_module_take_image (self, image);
}

static gboolean
gum_darwin_module_take_image (GumDarwinModule * self,
                              GumDarwinModuleImage * image)
{
  gboolean success = FALSE;
  const struct mach_header * header;
  gconstpointer command;
  gsize command_index;

  g_assert (self->image == NULL);
  self->image = image;

  header = (struct mach_header *) image->data;
  if (header->magic == MH_MAGIC)
    command = image->data + sizeof (struct mach_header);
  else
    command = image->data + sizeof (struct mach_header_64);
  for (command_index = 0; command_index != header->ncmds; command_index++)
  {
    const struct load_command * lc = (struct load_command *) command;

    switch (lc->cmd)
    {
      case LC_SEGMENT:
      case LC_SEGMENT_64:
      {
        GumDarwinSegment segment;

        if (lc->cmd == LC_SEGMENT)
        {
          const struct segment_command * sc = command;
          strcpy (segment.name, sc->segname);
          segment.vm_address = sc->vmaddr;
          segment.vm_size = sc->vmsize;
          segment.file_offset = sc->fileoff;
          segment.file_size = sc->filesize;
          segment.protection = sc->initprot;
        }
        else
        {
          const struct segment_command_64 * sc = command;
          strcpy (segment.name, sc->segname);
          segment.vm_address = sc->vmaddr;
          segment.vm_size = sc->vmsize;
          segment.file_offset = sc->fileoff;
          segment.file_size = sc->filesize;
          segment.protection = sc->initprot;
        }

        g_array_append_val (self->segments, segment);

        if (strcmp (segment.name, "__TEXT") == 0)
        {
          self->preferred_address = segment.vm_address;
        }

        break;
      }
      case LC_LOAD_DYLIB:
      case LC_LOAD_WEAK_DYLIB:
      case LC_REEXPORT_DYLIB:
      case LC_LOAD_UPWARD_DYLIB:
      {
        const struct dylib_command * dc = command;
        const gchar * name;

        name = command + dc->dylib.name.offset;
        g_ptr_array_add (self->dependencies, (gpointer) name);

        if (lc->cmd == LC_REEXPORT_DYLIB)
          g_ptr_array_add (self->reexports, (gpointer) name);

        break;
      }
      case LC_DYLD_INFO_ONLY:
        self->info = command;
        break;
      case LC_SYMTAB:
        self->symtab = command;
        break;
      case LC_DYSYMTAB:
        self->dysymtab = command;
        break;
      default:
        break;
    }

    command += lc->cmdsize;
  }

  gum_darwin_module_enumerate_sections (self,
      gum_add_text_range_if_text_section, self->text_ranges);

  if (self->info == NULL)
  {
    /* This is the case with dyld */
  }
  else if (image->linkedit != NULL)
  {
    self->rebases = image->linkedit + self->info->rebase_off;
    self->rebases_end = self->rebases + self->info->rebase_size;
    self->rebases_malloc_data = NULL;

    self->binds = image->linkedit + self->info->bind_off;
    self->binds_end = self->binds + self->info->bind_size;
    self->binds_malloc_data = NULL;

    self->lazy_binds = image->linkedit + self->info->lazy_bind_off;
    self->lazy_binds_end = self->lazy_binds + self->info->lazy_bind_size;
    self->lazy_binds_malloc_data = NULL;

    self->exports = image->linkedit + self->info->export_off;
    self->exports_end = self->exports + self->info->export_size;
    self->exports_malloc_data = NULL;
  }
  else
  {
    GumAddress linkedit;

    if (!gum_darwin_find_linkedit (image->data, image->size, &linkedit))
      goto beach;
    linkedit += gum_darwin_module_slide (self);

    gum_darwin_module_read_and_assign (self,
        linkedit + self->info->rebase_off,
        self->info->rebase_size,
        &self->rebases,
        &self->rebases_end,
        &self->rebases_malloc_data);

    gum_darwin_module_read_and_assign (self,
        linkedit + self->info->bind_off,
        self->info->bind_size,
        &self->binds,
        &self->binds_end,
        &self->binds_malloc_data);

    gum_darwin_module_read_and_assign (self,
        linkedit + self->info->lazy_bind_off,
        self->info->lazy_bind_size,
        &self->lazy_binds,
        &self->lazy_binds_end,
        &self->lazy_binds_malloc_data);

    gum_darwin_module_read_and_assign (self,
        linkedit + self->info->export_off,
        self->info->export_size,
        &self->exports,
        &self->exports_end,
        &self->exports_malloc_data);
  }

  success = TRUE;

beach:
  if (!success)
  {
    self->image = NULL;
    gum_darwin_module_image_free (image);
  }

  return success;
}

static void
gum_darwin_module_read_and_assign (GumDarwinModule * self,
                                   GumAddress address,
                                   gsize size,
                                   const guint8 ** start,
                                   const guint8 ** end,
                                   gpointer * malloc_data)
{
  if (self->is_local)
  {
    *start = GSIZE_TO_POINTER (address);
    *end = GSIZE_TO_POINTER (address + size);
    *malloc_data = NULL;
  }
  else
  {
    gpointer data;
    gsize n_bytes_read;

    data = gum_darwin_read (self->task, address, size, &n_bytes_read);
    *start = data;
    *end = (data != NULL) ? data + n_bytes_read : NULL;
    *malloc_data = data;
  }
}

static gboolean
gum_add_text_range_if_text_section (const GumDarwinSectionDetails * details,
                                    gpointer user_data)
{
  GArray * ranges = user_data;

  if (gum_section_flags_indicate_text_section (details->flags))
  {
    GumMemoryRange r;
    r.base_address = details->vm_address;
    r.size = details->size;
    g_array_append_val (ranges, r);
  }

  return TRUE;
}

static gboolean
gum_section_flags_indicate_text_section (uint32_t flags)
{
  return (flags & (S_ATTR_PURE_INSTRUCTIONS | S_ATTR_SOME_INSTRUCTIONS)) != 0;
}

GumDarwinModuleImage *
gum_darwin_module_image_new (void)
{
  GumDarwinModuleImage * image;

  image = g_slice_new0 (GumDarwinModuleImage);
  image->shared_segments = g_array_new (FALSE, FALSE,
      sizeof (GumDarwinModuleImageSegment));

  return image;
}

GumDarwinModuleImage *
gum_darwin_module_image_dup (const GumDarwinModuleImage * other)
{
  GumDarwinModuleImage * image;

  image = g_slice_new0 (GumDarwinModuleImage);

  image->size = other->size;

  image->source_offset = other->source_offset;
  image->source_size = other->source_size;
  image->shared_offset = other->shared_offset;
  image->shared_size = other->shared_size;
  image->shared_segments = g_array_ref (other->shared_segments);

  if (other->bytes != NULL)
    image->bytes = g_bytes_ref (other->bytes);

  if (other->shared_segments->len > 0)
  {
    guint i;

    image->malloc_data = g_malloc (other->size);
    image->data = image->malloc_data;

    g_assert (other->source_size != 0);
    memcpy (image->data, other->data, other->source_size);

    for (i = 0; i != other->shared_segments->len; i++)
    {
      GumDarwinModuleImageSegment * s = &g_array_index (other->shared_segments,
          GumDarwinModuleImageSegment, i);
      memcpy (image->data + s->offset, other->data + s->offset, s->size);
    }
  }
  else
  {
    image->malloc_data = g_memdup (other->data, other->size);
    image->data = image->malloc_data;
  }

  if (other->bytes != NULL)
  {
    gconstpointer data;
    gsize size;

    data = g_bytes_get_data (other->bytes, &size);
    if (other->linkedit >= data && other->linkedit < data + size)
      image->linkedit = other->linkedit;
  }

  if (image->linkedit == NULL && other->linkedit != NULL)
  {
    g_assert (other->linkedit >= other->data &&
        other->linkedit < other->data + other->size);
    image->linkedit = image->data + (other->linkedit - other->data);
  }

  return image;
}

void
gum_darwin_module_image_free (GumDarwinModuleImage * image)
{
  g_free (image->malloc_data);
  g_bytes_unref (image->bytes);

  g_array_unref (image->shared_segments);

  g_slice_free (GumDarwinModuleImage, image);
}

static gboolean
gum_exports_trie_find (const guint8 * exports,
                       const guint8 * exports_end,
                       const gchar * name,
                       GumDarwinExportDetails * details)
{
  const gchar * s;
  const guint8 * p;

  if (exports == exports_end)
    return FALSE;

  s = name;
  p = exports;
  while (p != NULL)
  {
    gint64 terminal_size;
    const guint8 * children;
    guint8 child_count, i;
    guint64 node_offset;

    terminal_size = gum_read_uleb128 (&p, exports_end);

    if (*s == '\0' && terminal_size != 0)
    {
      gum_darwin_export_details_init_from_node (details, name, p, exports_end);
      return TRUE;
    }

    children = p + terminal_size;
    child_count = *children++;
    p = children;
    node_offset = 0;
    for (i = 0; i != child_count; i++)
    {
      const gchar * symbol_cur;
      gboolean matching_edge;

      symbol_cur = s;
      matching_edge = TRUE;
      while (*p != '\0')
      {
        if (matching_edge)
        {
          if (*p != *symbol_cur)
            matching_edge = FALSE;
          symbol_cur++;
        }
        p++;
      }
      p++;

      if (matching_edge)
      {
        node_offset = gum_read_uleb128 (&p, exports_end);
        s = symbol_cur;
        break;
      }
      else
      {
        gum_skip_uleb128 (&p);
      }
    }

    if (node_offset != 0)
      p = exports + node_offset;
    else
      p = NULL;
  }

  return FALSE;
}

static gboolean
gum_exports_trie_foreach (const guint8 * exports,
                          const guint8 * exports_end,
                          GumDarwinFoundExportFunc func,
                          gpointer user_data)
{
  GumExportsTrieForeachContext ctx;
  gboolean carry_on;

  if (exports == exports_end)
    return TRUE;

  ctx.func = func;
  ctx.user_data = user_data;

  ctx.prefix = g_string_new ("");
  ctx.exports = exports;
  ctx.exports_end = exports_end;

  carry_on = gum_exports_trie_traverse (exports, &ctx);

  g_string_free (ctx.prefix, TRUE);

  return carry_on;
}

static gboolean
gum_exports_trie_traverse (const guint8 * p,
                           GumExportsTrieForeachContext * ctx)
{
  GString * prefix = ctx->prefix;
  const guint8 * exports = ctx->exports;
  const guint8 * exports_end = ctx->exports_end;
  gboolean carry_on;
  guint64 terminal_size;
  guint8 child_count, i;

  terminal_size = gum_read_uleb128 (&p, exports_end);
  if (terminal_size != 0)
  {
    GumDarwinExportDetails details;

    gum_darwin_export_details_init_from_node (&details, prefix->str, p,
        exports_end);

    carry_on = ctx->func (&details, ctx->user_data);
    if (!carry_on)
      return FALSE;
  }

  p += terminal_size;
  child_count = *p++;
  for (i = 0; i != child_count; i++)
  {
    gsize length = 0;

    while (*p != '\0')
    {
      g_string_append_c (prefix, *p++);
      length++;
    }
    p++;

    carry_on = gum_exports_trie_traverse (
        exports + gum_read_uleb128 (&p, exports_end),
        ctx);
    if (!carry_on)
      return FALSE;

    g_string_truncate (prefix, prefix->len - length);
  }

  return TRUE;
}

static void
gum_darwin_export_details_init_from_node (GumDarwinExportDetails * details,
                                          const gchar * name,
                                          const guint8 * node,
                                          const guint8 * exports_end)
{
  const guint8 * p = node;

  details->name = name;
  details->flags = gum_read_uleb128 (&p, exports_end);
  if ((details->flags & EXPORT_SYMBOL_FLAGS_REEXPORT) != 0)
  {
    details->reexport_library_ordinal = gum_read_uleb128 (&p, exports_end);
    details->reexport_symbol = (*p != '\0') ? (gchar *) p : name;
  }
  else if ((details->flags & EXPORT_SYMBOL_FLAGS_STUB_AND_RESOLVER) != 0)
  {
    details->stub = gum_read_uleb128 (&p, exports_end);
    details->resolver = gum_read_uleb128 (&p, exports_end);
  }
  else
  {
    details->offset = gum_read_uleb128 (&p, exports_end);
  }
}

static const GumDyldCacheImageInfo *
gum_dyld_cache_find_image_by_name (const gchar * name,
                                   const GumDyldCacheImageInfo * images,
                                   gsize image_count,
                                   gconstpointer cache)
{
  gsize i;

  for (i = 0; i != image_count; i++)
  {
    const GumDyldCacheImageInfo * image = &images[i];
    const gchar * current_name;

    current_name = cache + image->name_offset;
    if (strcmp (current_name, name) == 0)
      return image;
  }

  return NULL;
}

static guint64
gum_dyld_cache_compute_image_size (const GumDyldCacheImageInfo * image,
                                   const GumDyldCacheImageInfo * images,
                                   gsize image_count)
{
  const GumDyldCacheImageInfo * next_image;
  gsize i;

  next_image = NULL;
  for (i = 0; i != image_count; i++)
  {
    const GumDyldCacheImageInfo * candidate = &images[i];

    if (candidate->address > image->address && (next_image == NULL ||
        candidate->address < next_image->address))
    {
      next_image = candidate;
    }
  }
  g_assert (next_image != NULL);

  return next_image->address - image->address;
}

static guint64
gum_dyld_cache_offset_from_address (GumAddress address,
                                    const GumDyldCacheMappingInfo * mappings,
                                    gsize mapping_count)
{
  gsize i;

  for (i = 0; i != mapping_count; i++)
  {
    const GumDyldCacheMappingInfo * mapping = &mappings[i];

    if (address >= mapping->address &&
        address < mapping->address + mapping->size)
    {
      return address - mapping->address + mapping->offset;
    }
  }

  g_assert_not_reached ();
}
