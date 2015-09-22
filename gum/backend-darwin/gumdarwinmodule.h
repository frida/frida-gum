/*
 * Copyright (C) 2015 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_DARWIN_MODULE_H__
#define __GUM_DARWIN_MODULE_H__

#include <gum/gum.h>

G_BEGIN_DECLS

typedef struct _GumDarwinModule GumDarwinModule;
typedef struct _GumDarwinModuleImage GumDarwinModuleImage;

typedef struct _GumDarwinSymbolDetails GumDarwinSymbolDetails;
typedef struct _GumDarwinSegment GumDarwinSegment;
typedef struct _GumDarwinSectionDetails GumDarwinSectionDetails;
typedef struct _GumDarwinRebaseDetails GumDarwinRebaseDetails;
typedef struct _GumDarwinBindDetails GumDarwinBindDetails;
typedef struct _GumDarwinInitPointersDetails GumDarwinInitPointersDetails;
typedef struct _GumDarwinTermPointersDetails GumDarwinTermPointersDetails;

typedef void (* GumDarwinFoundSectionFunc) (GumDarwinModule * self,
    const GumDarwinSectionDetails * details, gpointer user_data);
typedef void (* GumDarwinFoundRebaseFunc) (GumDarwinModule * self,
    const GumDarwinRebaseDetails * details, gpointer user_data);
typedef void (* GumDarwinFoundBindFunc) (GumDarwinModule * self,
    const GumDarwinBindDetails * details, gpointer user_data);
typedef void (* GumDarwinFoundInitPointersFunc) (GumDarwinModule * self,
    const GumDarwinInitPointersDetails * details, gpointer user_data);
typedef void (* GumDarwinFoundTermPointersFunc) (GumDarwinModule * self,
    const GumDarwinTermPointersDetails * details, gpointer user_data);

struct _GumDarwinModule
{
  gint ref_count;

  gchar * name;

  mach_port_t task;
  GumCpuType cpu_type;
  gsize pointer_size;
  gsize page_size;
  GumAddress base_address;

  GumDarwinModuleImage * image;
  const struct dyld_info_command * info;
  const struct symtab_command * symtab;
  const struct dysymtab_command * dysymtab;
  GumAddress preferred_address;
  GArray * segments;
  guint8 * exports;
  const guint8 * exports_end;
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

struct _GumDarwinSymbolDetails
{
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

GumDarwinModuleImage * gum_darwin_module_image_dup (
    const GumDarwinModuleImage * other);

G_END_DECLS

#endif
