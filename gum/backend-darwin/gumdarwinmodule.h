/*
 * Copyright (C) 2015 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_DARWIN_MODULE_H__
#define __GUM_DARWIN_MODULE_H__

#include <gum/gum.h>
#include <mach/mach.h>

#define GUM_DARWIN_EXPORT_SYMBOL_FLAGS_KIND_ABSOLUTE 2

G_BEGIN_DECLS

typedef struct _GumDarwinModule GumDarwinModule;
typedef struct _GumDarwinModuleImage GumDarwinModuleImage;

typedef struct _GumDarwinModuleImageSegment GumDarwinModuleImageSegment;
typedef struct _GumDarwinSectionDetails GumDarwinSectionDetails;
typedef struct _GumDarwinRebaseDetails GumDarwinRebaseDetails;
typedef struct _GumDarwinBindDetails GumDarwinBindDetails;
typedef struct _GumDarwinInitPointersDetails GumDarwinInitPointersDetails;
typedef struct _GumDarwinTermPointersDetails GumDarwinTermPointersDetails;
typedef struct _GumDarwinSegment GumDarwinSegment;
typedef struct _GumDarwinSymbolDetails GumDarwinSymbolDetails;

typedef gboolean (* GumDarwinFoundSymbolFunc) (
    const GumDarwinSymbolDetails * details, gpointer user_data);
typedef gboolean (* GumDarwinFoundSectionFunc) (
    const GumDarwinSectionDetails * details, gpointer user_data);
typedef gboolean (* GumDarwinFoundRebaseFunc) (
    const GumDarwinRebaseDetails * details, gpointer user_data);
typedef gboolean (* GumDarwinFoundBindFunc) (
    const GumDarwinBindDetails * details, gpointer user_data);
typedef gboolean (* GumDarwinFoundInitPointersFunc) (
    const GumDarwinInitPointersDetails * details, gpointer user_data);
typedef gboolean (* GumDarwinFoundTermPointersFunc) (
    const GumDarwinTermPointersDetails * details, gpointer user_data);

struct _GumDarwinModule
{
  gint ref_count;

  gchar * name;

  mach_port_t task;
  gboolean is_local;
  GumCpuType cpu_type;
  gsize pointer_size;
  gsize page_size;
  GumAddress base_address;
  GumMemoryRange text_range;

  GumDarwinModuleImage * image;

  const struct dyld_info_command * info;
  const struct symtab_command * symtab;
  const struct dysymtab_command * dysymtab;

  GumAddress preferred_address;

  GArray * segments;

  guint8 * rebases;
  const guint8 * rebases_end;
  gpointer rebases_malloc_data;

  guint8 * binds;
  const guint8 * binds_end;
  gpointer binds_malloc_data;

  guint8 * lazy_binds;
  const guint8 * lazy_binds_end;
  gpointer lazy_binds_malloc_data;

  guint8 * exports;
  const guint8 * exports_end;
  gpointer exports_malloc_data;

  GPtrArray * dependencies;
};

struct _GumDarwinModuleImage
{
  gpointer data;
  guint64 size;
  gconstpointer linkedit;

  guint64 source_offset;
  guint64 source_size;
  guint64 shared_offset;
  guint64 shared_size;
  GArray * shared_segments;

  GMappedFile * file;
  gpointer malloc_data;
};

struct _GumDarwinModuleImageSegment
{
  guint64 offset;
  guint64 size;
  gint protection;
};

struct _GumDarwinSectionDetails
{
  const gchar * segment_name;
  const gchar * section_name;
  GumAddress vm_address;
  guint64 size;
  guint32 file_offset;
  guint32 flags;
};

struct _GumDarwinRebaseDetails
{
  const GumDarwinSegment * segment;
  guint64 offset;
  guint8 type;
  GumAddress slide;
};

struct _GumDarwinBindDetails
{
  const GumDarwinSegment * segment;
  guint64 offset;
  guint8 type;
  gint library_ordinal;
  const gchar * symbol_name;
  guint8 symbol_flags;
  gint64 addend;
};

struct _GumDarwinInitPointersDetails
{
  GumAddress address;
  guint64 count;
};

struct _GumDarwinTermPointersDetails
{
  GumAddress address;
  guint64 count;
};

struct _GumDarwinSegment
{
  gchar name[16];
  GumAddress vm_address;
  guint64 vm_size;
  guint64 file_offset;
  guint64 file_size;
  vm_prot_t protection;
};

struct _GumDarwinSymbolDetails
{
  const gchar * symbol;
  guint64 flags;

  union
  {
    struct {
      guint64 offset;
    };
    struct {
      guint64 stub;
      guint64 resolver;
    };
    struct {
      gint reexport_library_ordinal;
      const gchar * reexport_symbol;
    };
  };
};

GumDarwinModule * gum_darwin_module_new_from_file (const gchar * name,
    mach_port_t task, GumCpuType cpu_type, GMappedFile * cache_file);
GumDarwinModule * gum_darwin_module_new_from_memory (const gchar * name,
    mach_port_t task, GumCpuType cpu_type, GumAddress base_address);
GumDarwinModule * gum_darwin_module_ref (GumDarwinModule * self);
void gum_darwin_module_unref (GumDarwinModule * self);

void gum_darwin_module_set_base_address (GumDarwinModule * self,
    GumAddress base_address);

gboolean gum_darwin_module_resolve (GumDarwinModule * self,
    const gchar * symbol, GumDarwinSymbolDetails * details);
void gum_darwin_module_enumerate_imports (GumDarwinModule * self,
    GumFoundImportFunc func, gpointer user_data);
void gum_darwin_module_enumerate_exports (GumDarwinModule * self,
    GumDarwinFoundSymbolFunc func, gpointer user_data);
GumAddress gum_darwin_module_slide (GumDarwinModule * self);
const GumDarwinSegment * gum_darwin_module_segment (GumDarwinModule * self,
    gsize index);
void gum_darwin_module_enumerate_sections (GumDarwinModule * self,
    GumDarwinFoundSectionFunc func, gpointer user_data);
void gum_darwin_module_enumerate_rebases (GumDarwinModule * self,
    GumDarwinFoundRebaseFunc func, gpointer user_data);
void gum_darwin_module_enumerate_binds (GumDarwinModule * self,
    GumDarwinFoundBindFunc func, gpointer user_data);
void gum_darwin_module_enumerate_lazy_binds (GumDarwinModule * self,
    GumDarwinFoundBindFunc func, gpointer user_data);
void gum_darwin_module_enumerate_init_pointers (GumDarwinModule * self,
    GumDarwinFoundInitPointersFunc func, gpointer user_data);
void gum_darwin_module_enumerate_term_pointers (GumDarwinModule * self,
    GumDarwinFoundTermPointersFunc func, gpointer user_data);
const gchar * gum_darwin_module_dependency (GumDarwinModule * self,
    gint ordinal);

GumDarwinModuleImage * gum_darwin_module_image_new (void);
GumDarwinModuleImage * gum_darwin_module_image_dup (
    const GumDarwinModuleImage * other);
void gum_darwin_module_image_free (GumDarwinModuleImage * image);

G_END_DECLS

#endif
