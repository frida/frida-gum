/*
 * Copyright (C) 2015-2018 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_DARWIN_MODULE_H__
#define __GUM_DARWIN_MODULE_H__

#include <gum/gum.h>
#include <mach-o/nlist.h>
#include <mach/mach.h>

#define GUM_DARWIN_EXPORT_SYMBOL_FLAGS_KIND_ABSOLUTE 2

G_BEGIN_DECLS

#define GUM_DARWIN_TYPE_MODULE (gum_darwin_module_get_type ())
G_DECLARE_FINAL_TYPE (GumDarwinModule, gum_darwin_module, GUM_DARWIN, MODULE,
    GObject)

#define GUM_DARWIN_TYPE_MODULE_FLAGS (gum_darwin_module_flags_get_type ())

typedef enum {
  GUM_DARWIN_MODULE_FLAGS_NONE = 0,
  GUM_DARWIN_MODULE_FLAGS_HEADER_ONLY = (1<<0),
} GumDarwinModuleFlags;

typedef struct _GumDarwinModuleImage GumDarwinModuleImage;

typedef struct _GumDarwinModuleImageSegment GumDarwinModuleImageSegment;
typedef struct _GumDarwinSectionDetails GumDarwinSectionDetails;
typedef struct _GumDarwinRebaseDetails GumDarwinRebaseDetails;
typedef struct _GumDarwinBindDetails GumDarwinBindDetails;
typedef struct _GumDarwinInitPointersDetails GumDarwinInitPointersDetails;
typedef struct _GumDarwinTermPointersDetails GumDarwinTermPointersDetails;
typedef struct _GumDarwinSegment GumDarwinSegment;
typedef struct _GumDarwinExportDetails GumDarwinExportDetails;
typedef struct _GumDarwinSymbolDetails GumDarwinSymbolDetails;

typedef gboolean (* GumDarwinFoundExportFunc) (
    const GumDarwinExportDetails * details, gpointer user_data);
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
typedef gboolean (* GumDarwinFoundDependencyFunc) (const gchar * path,
    gpointer user_data);
typedef gpointer (* GumDarwinModuleResolverFunc) (void);

struct _GumDarwinModule
{
  GObject parent;

  gchar * name;
  gchar * uuid;

  mach_port_t task;
  gboolean is_local;
  gboolean is_kernel;
  GumCpuType cpu_type;
  gsize pointer_size;
  gsize page_size;
  GumAddress base_address;
  gchar * source_path;
  GBytes * source_blob;
  GMappedFile * cache_file;
  GumDarwinModuleFlags flags;

  GumDarwinModuleImage * image;

  const struct dyld_info_command * info;
  const struct symtab_command * symtab;
  const struct dysymtab_command * dysymtab;

  GumAddress preferred_address;

  GArray * segments;
  GArray * text_ranges;

  const guint8 * rebases;
  const guint8 * rebases_end;
  gpointer rebases_malloc_data;

  const guint8 * binds;
  const guint8 * binds_end;
  gpointer binds_malloc_data;

  const guint8 * lazy_binds;
  const guint8 * lazy_binds_end;
  gpointer lazy_binds_malloc_data;

  const guint8 * exports;
  const guint8 * exports_end;
  gpointer exports_malloc_data;

  GPtrArray * dependencies;
  GPtrArray * reexports;
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

  GBytes * bytes;
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
  gchar segment_name[17];
  gchar section_name[17];
  GumAddress vm_address;
  guint64 size;
  vm_prot_t protection;
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
  gchar name[17];
  GumAddress vm_address;
  guint64 vm_size;
  guint64 file_offset;
  guint64 file_size;
  vm_prot_t protection;
};

struct _GumDarwinExportDetails
{
  const gchar * name;
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

struct _GumDarwinSymbolDetails
{
  const gchar * name;
  GumAddress address;

  /* These map 1:1 to their struct nlist / nlist_64 equivalents. */
  guint8 type;
  guint8 section;
  guint16 description;
};

GUM_API GumDarwinModule * gum_darwin_module_new_from_file (const gchar * path,
    mach_port_t task, GumCpuType cpu_type, guint page_size,
    GMappedFile * cache_file, GumDarwinModuleFlags flags, GError ** error);
GUM_API GumDarwinModule * gum_darwin_module_new_from_blob (GBytes * blob,
    mach_port_t task, GumCpuType cpu_type, guint page_size,
    GumDarwinModuleFlags flags, GError ** error);
GUM_API GumDarwinModule * gum_darwin_module_new_from_memory (const gchar * name,
    mach_port_t task, GumCpuType cpu_type, guint page_size,
    GumAddress base_address, GumDarwinModuleFlags flags, GError ** error);

GUM_API gboolean gum_darwin_module_resolve_export (GumDarwinModule * self,
    const gchar * symbol, GumDarwinExportDetails * details);
GUM_API GumAddress gum_darwin_module_resolve_symbol_address (
    GumDarwinModule * self, const gchar * symbol);
GUM_API gboolean gum_darwin_module_get_lacks_exports_for_reexports (
    GumDarwinModule * self);
GUM_API void gum_darwin_module_enumerate_imports (GumDarwinModule * self,
    GumFoundImportFunc func, gpointer user_data);
GUM_API void gum_darwin_module_enumerate_exports (GumDarwinModule * self,
    GumDarwinFoundExportFunc func, gpointer user_data);
GUM_API void gum_darwin_module_enumerate_symbols (GumDarwinModule * self,
    GumDarwinFoundSymbolFunc func, gpointer user_data);
GUM_API GumAddress gum_darwin_module_get_slide (GumDarwinModule * self);
GUM_API const GumDarwinSegment * gum_darwin_module_get_nth_segment (
    GumDarwinModule * self, gsize index);
GUM_API void gum_darwin_module_enumerate_sections (GumDarwinModule * self,
    GumDarwinFoundSectionFunc func, gpointer user_data);
GUM_API gboolean gum_darwin_module_is_address_in_text_section (
    GumDarwinModule * self, GumAddress address);
GUM_API void gum_darwin_module_enumerate_rebases (GumDarwinModule * self,
    GumDarwinFoundRebaseFunc func, gpointer user_data);
GUM_API void gum_darwin_module_enumerate_binds (GumDarwinModule * self,
    GumDarwinFoundBindFunc func, gpointer user_data);
GUM_API void gum_darwin_module_enumerate_lazy_binds (GumDarwinModule * self,
    GumDarwinFoundBindFunc func, gpointer user_data);
GUM_API void gum_darwin_module_enumerate_init_pointers (GumDarwinModule * self,
    GumDarwinFoundInitPointersFunc func, gpointer user_data);
GUM_API void gum_darwin_module_enumerate_term_pointers (GumDarwinModule * self,
    GumDarwinFoundTermPointersFunc func, gpointer user_data);
GUM_API void gum_darwin_module_enumerate_dependencies (GumDarwinModule * self,
    GumDarwinFoundDependencyFunc func, gpointer user_data);
GUM_API const gchar * gum_darwin_module_get_dependency_by_ordinal (
    GumDarwinModule * self, gint ordinal);

GUM_API GumDarwinModuleImage * gum_darwin_module_image_new (void);
GUM_API GumDarwinModuleImage * gum_darwin_module_image_dup (
    const GumDarwinModuleImage * other);
GUM_API void gum_darwin_module_image_free (GumDarwinModuleImage * image);

GUM_API GType gum_darwin_module_flags_get_type (void) G_GNUC_CONST;

G_END_DECLS

#endif
