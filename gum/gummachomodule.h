/*
 * Copyright (C) 2015-2025 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 * Copyright (C) 2023 Fabian Freyer <fabian.freyer@physik.tu-berlin.de>
 * Copyright (C) 2026 Håvard Sørbø <havard@hsorbo.no>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_MACHO_MODULE_H__
#define __GUM_MACHO_MODULE_H__

#include <gum/gum.h>

G_BEGIN_DECLS

#define GUM_TYPE_MACHO_MODULE (gum_macho_module_get_type ())
G_DECLARE_FINAL_TYPE (GumMachoModule, gum_macho_module, GUM, MACHO_MODULE,
                      GObject)

#define GUM_TYPE_MACHO_MODULE_IMAGE (gum_macho_module_image_get_type ())

#define GUM_DARWIN_PORT_NULL 0
#define GUM_MACHO_EXPORT_KIND_MASK 3

typedef guint GumMachoModuleFiletype;
typedef gint GumMachoCpuType;
typedef gint GumMachoCpuSubtype;

typedef struct _GumMachoModuleImage GumMachoModuleImage;

typedef struct _GumMachoModuleImageSegment GumMachoModuleImageSegment;
typedef struct _GumMachoSectionDetails GumMachoSectionDetails;
typedef struct _GumMachoChainedFixupsDetails GumMachoChainedFixupsDetails;
typedef struct _GumMachoRebaseDetails GumMachoRebaseDetails;
typedef struct _GumMachoBindDetails GumMachoBindDetails;
typedef struct _GumMachoThreadedItem GumMachoThreadedItem;
typedef struct _GumMachoTlvParameters GumMachoTlvParameters;
typedef struct _GumMachoTlvDescriptorDetails GumMachoTlvDescriptorDetails;
typedef struct _GumMachoInitPointersDetails GumMachoInitPointersDetails;
typedef struct _GumMachoInitOffsetsDetails GumMachoInitOffsetsDetails;
typedef struct _GumMachoTermPointersDetails GumMachoTermPointersDetails;
typedef struct _GumMachoFunctionStartsDetails GumMachoFunctionStartsDetails;
typedef struct _GumMachoSegment GumMachoSegment;
typedef struct _GumMachoExportDetails GumMachoExportDetails;
typedef struct _GumMachoSymbolDetails GumMachoSymbolDetails;

typedef guint8 GumMachoRebaseType;
typedef guint8 GumMachoBindType;
typedef guint8 GumMachoThreadedItemType;
typedef gint GumMachoBindOrdinal;
typedef guint8 GumMachoBindSymbolFlags;
typedef guint8 GumMachoExportSymbolKind;
typedef guint8 GumMachoExportSymbolFlags;

typedef guint GumDarwinPort;
typedef gint GumDarwinPageProtection;

typedef gboolean (* GumFoundMachoExportFunc) (
    const GumMachoExportDetails * details, gpointer user_data);
typedef gboolean (* GumFoundMachoSymbolFunc) (
    const GumMachoSymbolDetails * details, gpointer user_data);
typedef gboolean (* GumFoundMachoSectionFunc) (
    const GumMachoSectionDetails * details, gpointer user_data);
typedef gboolean (* GumFoundMachoChainedFixupsFunc) (
    const GumMachoChainedFixupsDetails * details, gpointer user_data);
typedef gboolean (* GumFoundMachoRebaseFunc) (
    const GumMachoRebaseDetails * details, gpointer user_data);
typedef gboolean (* GumFoundMachoBindFunc) (
    const GumMachoBindDetails * details, gpointer user_data);

typedef gboolean (* GumFoundMachoTlvDescriptorFunc) (
    const GumMachoTlvDescriptorDetails * details, gpointer user_data);

typedef gboolean (* GumFoundMachoInitPointersFunc) (
    const GumMachoInitPointersDetails * details, gpointer user_data);
typedef gboolean (* GumFoundMachoInitOffsetsFunc) (
    const GumMachoInitOffsetsDetails * details, gpointer user_data);
typedef gboolean (* GumFoundMachoTermPointersFunc) (
    const GumMachoTermPointersDetails * details, gpointer user_data);
typedef gboolean (* GumFoundMachoFunctionStartsFunc) (
    const GumMachoFunctionStartsDetails * details, gpointer user_data);

typedef struct _GumDyldInfoCommand GumDyldInfoCommand;
typedef struct _GumSymtabCommand GumSymtabCommand;
typedef struct _GumDysymtabCommand GumDysymtabCommand;

typedef enum {
  GUM_MACHO_MODULE_FLAGS_NONE        = 0,
  GUM_MACHO_MODULE_FLAGS_HEADER_ONLY = (1 << 0),
} GumMachoModuleFlags;

typedef struct _GumChainedFixupsHeader GumChainedFixupsHeader;
typedef struct _GumChainedStartsInImage GumChainedStartsInImage;
typedef struct _GumChainedStartsInSegment GumChainedStartsInSegment;

typedef guint32 GumChainedImportFormat;
typedef guint32 GumChainedSymbolFormat;
typedef guint16 GumChainedPtrFormat;

typedef struct _GumChainedImport GumChainedImport;
typedef struct _GumChainedImportAddend GumChainedImportAddend;
typedef struct _GumChainedImportAddend64 GumChainedImportAddend64;

typedef struct _GumChainedPtr64Rebase GumChainedPtr64Rebase;
typedef struct _GumChainedPtr64Bind GumChainedPtr64Bind;
typedef struct _GumChainedPtrArm64eRebase GumChainedPtrArm64eRebase;
typedef struct _GumChainedPtrArm64eBind GumChainedPtrArm64eBind;
typedef struct _GumChainedPtrArm64eBind24 GumChainedPtrArm64eBind24;
typedef struct _GumChainedPtrArm64eAuthRebase GumChainedPtrArm64eAuthRebase;
typedef struct _GumChainedPtrArm64eAuthBind GumChainedPtrArm64eAuthBind;
typedef struct _GumChainedPtrArm64eAuthBind24 GumChainedPtrArm64eAuthBind24;

struct _GumMachoModule
{
  GObject parent;

  GumMachoModuleFiletype filetype;
  gchar * name;
  gchar * uuid;
  gchar * source_version;

  GumDarwinPort task;
  gboolean is_local;
  gboolean is_kernel;
  GumCpuType cpu_type;
  GumPtrauthSupport ptrauth_support;
  gsize pointer_size;
  GumAddress base_address;
  gchar * source_path;
  GBytes * source_blob;
  GumMachoModuleFlags flags;

  GumMachoModuleImage * image;

  const GumDyldInfoCommand * info;
  const GumSymtabCommand * symtab;
  const GumDysymtabCommand * dysymtab;

  GumAddress preferred_address;

  GArray * segments;
  GArray * text_ranges;
  gsize text_size;

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

  GArray * dependencies;
  GPtrArray * reexports;
};

enum _GumMachoModuleFiletype
{
  GUM_MACHO_MODULE_FILETYPE_OBJECT = 1,
  GUM_MACHO_MODULE_FILETYPE_EXECUTE,
  GUM_MACHO_MODULE_FILETYPE_FVMLIB,
  GUM_MACHO_MODULE_FILETYPE_CORE,
  GUM_MACHO_MODULE_FILETYPE_PRELOAD,
  GUM_MACHO_MODULE_FILETYPE_DYLIB,
  GUM_MACHO_MODULE_FILETYPE_DYLINKER,
  GUM_MACHO_MODULE_FILETYPE_BUNDLE,
  GUM_MACHO_MODULE_FILETYPE_DYLIB_STUB,
  GUM_MACHO_MODULE_FILETYPE_DSYM,
  GUM_MACHO_MODULE_FILETYPE_KEXT_BUNDLE,
  GUM_MACHO_MODULE_FILETYPE_FILESET,
};

enum _GumMachoCpuArchType
{
  GUM_MACHO_CPU_ARCH_ABI64    = 0x01000000,
  GUM_MACHO_CPU_ARCH_ABI64_32 = 0x02000000,
};

enum _GumMachoCpuType
{
  GUM_MACHO_CPU_X86      =  7,
  GUM_MACHO_CPU_X86_64   =  7 | GUM_MACHO_CPU_ARCH_ABI64,
  GUM_MACHO_CPU_ARM      = 12,
  GUM_MACHO_CPU_ARM64    = 12 | GUM_MACHO_CPU_ARCH_ABI64,
  GUM_MACHO_CPU_ARM64_32 = 12 | GUM_MACHO_CPU_ARCH_ABI64_32,
};

enum _GumMachoCpuSubtype
{
  GUM_MACHO_CPU_SUBTYPE_ARM64E = 2,

  GUM_MACHO_CPU_SUBTYPE_MASK = 0x00ffffff,
};

struct _GumMachoModuleImage
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

struct _GumMachoModuleImageSegment
{
  guint64 offset;
  guint64 size;
  GumDarwinPageProtection protection;
};

struct _GumMachoSectionDetails
{
  gchar segment_name[17];
  gchar section_name[17];
  GumAddress vm_address;
  guint64 size;
  GumDarwinPageProtection protection;
  guint32 file_offset;
  guint32 flags;
};

struct _GumMachoChainedFixupsDetails
{
  GumAddress vm_address;
  guint64 file_offset;
  guint32 size;
};

struct _GumMachoRebaseDetails
{
  const GumMachoSegment * segment;
  guint64 offset;
  GumMachoRebaseType type;
  GumAddress slide;
};

struct _GumMachoBindDetails
{
  const GumMachoSegment * segment;
  guint64 offset;
  GumMachoBindType type;
  GumMachoBindOrdinal library_ordinal;
  const gchar * symbol_name;
  GumMachoBindSymbolFlags symbol_flags;
  gint64 addend;
  guint16 threaded_table_size;
};

struct _GumMachoThreadedItem
{
  gboolean is_authenticated;
  GumMachoThreadedItemType type;
  guint16 delta;
  guint8 key;
  gboolean has_address_diversity;
  guint16 diversity;

  guint16 bind_ordinal;

  GumAddress rebase_address;
};

struct _GumMachoTlvParameters
{
  guint num_descriptors;
  guint descriptors_offset;
  guint data_offset;
  gsize data_size;
  gsize bss_size;
};

struct _GumMachoTlvDescriptorDetails
{
  guint64 file_offset;
  GumAddress thunk;
  guint64 key;
  gsize offset;
};

struct _GumMachoInitPointersDetails
{
  GumAddress address;
  guint64 count;
};

struct _GumMachoInitOffsetsDetails
{
  GumAddress address;
  guint64 count;
};

struct _GumMachoTermPointersDetails
{
  GumAddress address;
  guint64 count;
};

struct _GumMachoFunctionStartsDetails
{
  GumAddress vm_address;
  guint64 file_offset;
  guint32 size;
};

struct _GumMachoSegment
{
  gchar name[17];
  GumAddress vm_address;
  guint64 vm_size;
  guint64 file_offset;
  guint64 file_size;
  GumDarwinPageProtection protection;
};

struct _GumMachoExportDetails
{
  const gchar * name;
  guint64 flags;

  union
  {
    struct
    {
      guint64 offset;
    };

    struct
    {
      guint64 stub;
      guint64 resolver;
    };

    struct
    {
      gint reexport_library_ordinal;
      const gchar * reexport_symbol;
    };
  };
};

struct _GumMachoSymbolDetails
{
  const gchar * name;
  GumAddress address;

  /* These map 1:1 to their struct nlist / nlist_64 equivalents. */
  guint8 type;
  guint8 section;
  guint16 description;
};

enum _GumMachoRebaseType
{
  GUM_MACHO_REBASE_POINTER = 1,
  GUM_MACHO_REBASE_TEXT_ABSOLUTE32,
  GUM_MACHO_REBASE_TEXT_PCREL32,
};

enum _GumMachoBindType
{
  GUM_MACHO_BIND_POINTER = 1,
  GUM_MACHO_BIND_TEXT_ABSOLUTE32,
  GUM_MACHO_BIND_TEXT_PCREL32,
  GUM_MACHO_BIND_THREADED_TABLE,
  GUM_MACHO_BIND_THREADED_ITEMS,
};

enum _GumMachoThreadedItemType
{
  GUM_MACHO_THREADED_REBASE,
  GUM_MACHO_THREADED_BIND
};

enum _GumMachoBindOrdinal
{
  GUM_MACHO_BIND_SELF            =  0,
  GUM_MACHO_BIND_MAIN_EXECUTABLE = -1,
  GUM_MACHO_BIND_FLAT_LOOKUP     = -2,
  GUM_MACHO_BIND_WEAK_LOOKUP     = -3,
};

enum _GumMachoBindSymbolFlags
{
  GUM_MACHO_BIND_WEAK_IMPORT         = 0x1,
  GUM_MACHO_BIND_NON_WEAK_DEFINITION = 0x8,
};

enum _GumMachoExportSymbolKind
{
  GUM_MACHO_EXPORT_REGULAR,
  GUM_MACHO_EXPORT_THREAD_LOCAL,
  GUM_MACHO_EXPORT_ABSOLUTE
};

enum _GumMachoExportSymbolFlags
{
  GUM_MACHO_EXPORT_WEAK_DEFINITION   = 0x04,
  GUM_MACHO_EXPORT_REEXPORT          = 0x08,
  GUM_MACHO_EXPORT_STUB_AND_RESOLVER = 0x10,
};

#ifdef _MSC_VER
# pragma warning (push)
# pragma warning (disable: 4214)
#endif

struct _GumChainedFixupsHeader
{
  guint32 fixups_version;
  guint32 starts_offset;
  guint32 imports_offset;
  guint32 symbols_offset;
  guint32 imports_count;
  GumChainedImportFormat imports_format;
  GumChainedSymbolFormat symbols_format;
};

enum _GumChainedImportFormat
{
  GUM_CHAINED_IMPORT          = 1,
  GUM_CHAINED_IMPORT_ADDEND   = 2,
  GUM_CHAINED_IMPORT_ADDEND64 = 3,
};

struct _GumChainedImport
{
  guint32 lib_ordinal :  8,
          weak_import :  1,
          name_offset : 23;
};

struct _GumChainedImportAddend
{
  guint32 lib_ordinal :  8,
          weak_import :  1,
          name_offset : 23;
  gint32 addend;
};

struct _GumChainedImportAddend64
{
  guint64 lib_ordinal : 16,
          weak_import :  1,
          reserved    : 15,
          name_offset : 32;
  guint64 addend;
};

struct _GumChainedStartsInImage
{
  guint32 seg_count;
  guint32 seg_info_offset[1];
};

struct _GumChainedStartsInSegment
{
  guint32 size;
  guint16 page_size;
  GumChainedPtrFormat pointer_format;
  guint64 segment_offset;
  guint32 max_valid_pointer;
  guint16 page_count;
  guint16 page_start[1];
};

enum _GumChainedPtrStart
{
  GUM_CHAINED_PTR_START_NONE  = 0xffff,
  GUM_CHAINED_PTR_START_MULTI = 0x8000,
  GUM_CHAINED_PTR_START_LAST  = 0x8000,
};

enum _GumChainedPtrFormat
{
  GUM_CHAINED_PTR_ARM64E              =  1,
  GUM_CHAINED_PTR_64                  =  2,
  GUM_CHAINED_PTR_32                  =  3,
  GUM_CHAINED_PTR_32_CACHE            =  4,
  GUM_CHAINED_PTR_32_FIRMWARE         =  5,
  GUM_CHAINED_PTR_64_OFFSET           =  6,
  GUM_CHAINED_PTR_ARM64E_OFFSET       =  7,
  GUM_CHAINED_PTR_ARM64E_KERNEL       =  7,
  GUM_CHAINED_PTR_64_KERNEL_CACHE     =  8,
  GUM_CHAINED_PTR_ARM64E_USERLAND     =  9,
  GUM_CHAINED_PTR_ARM64E_FIRMWARE     = 10,
  GUM_CHAINED_PTR_X86_64_KERNEL_CACHE = 11,
  GUM_CHAINED_PTR_ARM64E_USERLAND24   = 12,
};

struct _GumChainedPtr64Rebase
{
  guint64 target   : 36,
          high8    :  8,
          reserved :  7,
          next     : 12,
          bind     :  1;
};

struct _GumChainedPtr64Bind
{
  guint64 ordinal  : 24,
          addend   :  8,
          reserved : 19,
          next     : 12,
          bind     :  1;
};

struct _GumChainedPtrArm64eRebase
{
  guint64 target : 43,
          high8  :  8,
          next   : 11,
          bind   :  1,
          auth   :  1;
};

struct _GumChainedPtrArm64eBind
{
  guint64 ordinal : 16,
          zero    : 16,
          addend  : 19,
          next    : 11,
          bind    :  1,
          auth    :  1;
};

struct _GumChainedPtrArm64eBind24
{
  guint64 ordinal : 24,
          zero    :  8,
          addend  : 19,
          next    : 11,
          bind    :  1,
          auth    :  1;
};

struct _GumChainedPtrArm64eAuthRebase
{
  guint64 target    : 32,
          diversity : 16,
          addr_div  :  1,
          key       :  2,
          next      : 11,
          bind      :  1,
          auth      :  1;
};

struct _GumChainedPtrArm64eAuthBind
{
  guint64 ordinal   : 16,
          zero      : 16,
          diversity : 16,
          addr_div  :  1,
          key       :  2,
          next      : 11,
          bind      :  1,
          auth      :  1;
};

struct _GumChainedPtrArm64eAuthBind24
{
  guint64 ordinal   : 24,
          zero      :  8,
          diversity : 16,
          addr_div  :  1,
          key       :  2,
          next      : 11,
          bind      :  1,
          auth      :  1;
};

#ifdef _MSC_VER
# pragma warning (pop)
#endif

GUM_API GumMachoModule * gum_macho_module_new_from_file (const gchar * path,
    GumCpuType cpu_type, GumPtrauthSupport ptrauth_support,
    GumMachoModuleFlags flags, GError ** error);
GUM_API GumMachoModule * gum_macho_module_new_from_blob (GBytes * blob,
    GumCpuType cpu_type, GumPtrauthSupport ptrauth_support,
    GumMachoModuleFlags flags, GError ** error);
GUM_API GumMachoModule * gum_macho_module_new_from_memory (const gchar * name,
    GumDarwinPort task, GumAddress base_address, GumMachoModuleFlags flags,
    GError ** error);

GUM_API gboolean gum_macho_module_load (GumMachoModule * self,
    GError ** error);

GUM_API gboolean gum_macho_module_resolve_export (GumMachoModule * self,
    const gchar * symbol, GumMachoExportDetails * details);
GUM_API GumAddress gum_macho_module_resolve_symbol_address (
    GumMachoModule * self, const gchar * symbol);
GUM_API gboolean gum_macho_module_get_lacks_exports_for_reexports (
    GumMachoModule * self);
GUM_API void gum_macho_module_enumerate_imports (GumMachoModule * self,
    GumFoundImportFunc func, GumResolveExportFunc resolver, gpointer user_data);
GUM_API void gum_macho_module_enumerate_exports (GumMachoModule * self,
    GumFoundMachoExportFunc func, gpointer user_data);
GUM_API void gum_macho_module_enumerate_exports_with_prefix (
    GumMachoModule * self, const gchar * prefix,
    GumFoundMachoExportFunc func, gpointer user_data);
GUM_API void gum_macho_module_enumerate_symbols (GumMachoModule * self,
    GumFoundMachoSymbolFunc func, gpointer user_data);
GUM_API GumAddress gum_macho_module_get_slide (GumMachoModule * self);
GUM_API const GumMachoSegment * gum_macho_module_get_nth_segment (
    GumMachoModule * self, gsize index);
GUM_API void gum_macho_module_enumerate_sections (GumMachoModule * self,
    GumFoundMachoSectionFunc func, gpointer user_data);
GUM_API gboolean gum_macho_module_is_address_in_text_section (
    GumMachoModule * self, GumAddress address);
GUM_API void gum_macho_module_enumerate_chained_fixups (GumMachoModule * self,
    GumFoundMachoChainedFixupsFunc func, gpointer user_data);
GUM_API void gum_macho_module_enumerate_rebases (GumMachoModule * self,
    GumFoundMachoRebaseFunc func, gpointer user_data);
GUM_API void gum_macho_module_enumerate_binds (GumMachoModule * self,
    GumFoundMachoBindFunc func, gpointer user_data);
GUM_API void gum_macho_module_enumerate_lazy_binds (GumMachoModule * self,
    GumFoundMachoBindFunc func, gpointer user_data);
GUM_API void gum_macho_module_query_tlv_parameters (GumMachoModule * self,
    GumMachoTlvParameters * params);
GUM_API void gum_macho_module_enumerate_tlv_descriptors (
    GumMachoModule * self, GumFoundMachoTlvDescriptorFunc func,
    gpointer user_data);
GUM_API void gum_macho_module_enumerate_init_pointers (GumMachoModule * self,
    GumFoundMachoInitPointersFunc func, gpointer user_data);
GUM_API void gum_macho_module_enumerate_init_offsets (GumMachoModule * self,
    GumFoundMachoInitOffsetsFunc func, gpointer user_data);
GUM_API void gum_macho_module_enumerate_term_pointers (GumMachoModule * self,
    GumFoundMachoTermPointersFunc func, gpointer user_data);
GUM_API void gum_macho_module_enumerate_dependencies (GumMachoModule * self,
    GumFoundDependencyFunc func, gpointer user_data);
GUM_API void gum_macho_module_enumerate_function_starts (
    GumMachoModule * self, GumFoundMachoFunctionStartsFunc func,
    gpointer user_data);
GUM_API const gchar * gum_macho_module_get_dependency_by_ordinal (
    GumMachoModule * self, gint ordinal);
GUM_API gboolean gum_macho_module_ensure_image_loaded (GumMachoModule * self,
    GError ** error);

GUM_API void gum_macho_threaded_item_parse (guint64 value,
    GumMachoThreadedItem * result);

GUM_API GType gum_macho_module_image_get_type (void) G_GNUC_CONST;
GUM_API GumMachoModuleImage * gum_macho_module_image_new (void);
GUM_API GumMachoModuleImage * gum_macho_module_image_dup (
    const GumMachoModuleImage * other);
GUM_API void gum_macho_module_image_free (GumMachoModuleImage * image);

G_END_DECLS

#endif
