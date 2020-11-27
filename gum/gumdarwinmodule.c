/*
 * Copyright (C) 2015-2020 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumdarwinmodule.h"

#ifdef HAVE_DARWIN
# include "backend-darwin/gumdarwin.h"
#endif
#include "gumleb.h"
#include "gumkernel.h"

#include <gio/gio.h>

#define GUM_FAT_CIGAM_32               0xbebafeca
#define GUM_MH_MAGIC_32                0xfeedface
#define GUM_MH_MAGIC_64                0xfeedfacf
#define GUM_MH_EXECUTE                        0x2
#define GUM_MH_PREBOUND                      0x10

#define GUM_LC_REQ_DYLD                0x80000000

#define GUM_SECTION_TYPE_MASK          0x000000ff

#define GUM_N_EXT                            0x01
#define GUM_N_TYPE                           0x0e
#define GUM_N_SECT                            0xe

#define GUM_REBASE_OPCODE_MASK               0xf0
#define GUM_REBASE_IMMEDIATE_MASK            0x0f

#define GUM_BIND_OPCODE_MASK                 0xf0
#define GUM_BIND_IMMEDIATE_MASK              0x0f

#define GUM_BIND_TYPE_POINTER 1

#define GUM_BIND_SPECIAL_DYLIB_SELF             0
#define GUM_BIND_SPECIAL_DYLIB_MAIN_EXECUTABLE -1
#define GUM_BIND_SPECIAL_DYLIB_FLAT_LOOKUP     -2

#define GUM_MAX_MACHO_METADATA_SIZE   (64 * 1024)

#define GUM_DARWIN_MODULE_HAS_HEADER_ONLY(self) \
    ((self->flags & GUM_DARWIN_MODULE_FLAGS_HEADER_ONLY) != 0)

typedef struct _GumResolveSymbolContext GumResolveSymbolContext;

typedef struct _GumEmitImportContext GumEmitImportContext;
typedef struct _GumEmitExportFromSymbolContext GumEmitExportFromSymbolContext;
typedef struct _GumEmitInitPointersContext GumEmitInitPointersContext;
typedef struct _GumEmitInitOffsetsContext GumEmitInitOffsetsContext;
typedef struct _GumEmitTermPointersContext GumEmitTermPointersContext;

typedef struct _GumExportsTrieForeachContext GumExportsTrieForeachContext;

typedef struct _GumFatHeader GumFatHeader;
typedef struct _GumFatArch32 GumFatArch32;
typedef struct _GumMachHeader32 GumMachHeader32;
typedef struct _GumMachHeader64 GumMachHeader64;
typedef struct _GumLoadCommand GumLoadCommand;
typedef union _GumLcStr GumLcStr;
typedef struct _GumSegmentCommand32 GumSegmentCommand32;
typedef struct _GumSegmentCommand64 GumSegmentCommand64;
typedef struct _GumDylibCommand GumDylibCommand;
typedef struct _GumDylinkerCommand GumDylinkerCommand;
typedef struct _GumUUIDCommand GumUUIDCommand;
typedef struct _GumDylib GumDylib;
typedef struct _GumLinkeditDataCommand GumLinkeditDataCommand;
typedef struct _GumSection32 GumSection32;
typedef struct _GumSection64 GumSection64;
typedef struct _GumNList32 GumNList32;
typedef struct _GumNList64 GumNList64;

enum
{
  PROP_0,
  PROP_NAME,
  PROP_UUID,
  PROP_TASK,
  PROP_CPU_TYPE,
  PROP_PTRAUTH_SUPPORT,
  PROP_BASE_ADDRESS,
  PROP_SOURCE_PATH,
  PROP_SOURCE_BLOB,
  PROP_FLAGS,
};

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
  GArray * threaded_binds;
  const guint8 * source_start;
  const guint8 * source_end;
  GMappedFile * source_file;
  gboolean carry_on;
};

struct _GumEmitExportFromSymbolContext
{
  GumFoundDarwinExportFunc func;
  gpointer user_data;
};

struct _GumEmitInitPointersContext
{
  GumFoundDarwinInitPointersFunc func;
  gpointer user_data;
  gsize pointer_size;
};

struct _GumEmitInitOffsetsContext
{
  GumFoundDarwinInitOffsetsFunc func;
  gpointer user_data;
};

struct _GumEmitTermPointersContext
{
  GumFoundDarwinTermPointersFunc func;
  gpointer user_data;
  gsize pointer_size;
};

struct _GumExportsTrieForeachContext
{
  GumFoundDarwinExportFunc func;
  gpointer user_data;

  GString * prefix;
  const guint8 * exports;
  const guint8 * exports_end;
};

struct _GumFatHeader
{
  guint32 magic;
  guint32 nfat_arch;
};

struct _GumFatArch32
{
  GumDarwinCpuType cputype;
  GumDarwinCpuSubtype cpusubtype;
  guint32 offset;
  guint32 size;
  guint32 align;
};

struct _GumMachHeader32
{
  guint32 magic;
  GumDarwinCpuType cputype;
  GumDarwinCpuSubtype cpusubtype;
  guint32 filetype;
  guint32 ncmds;
  guint32 sizeofcmds;
  guint32 flags;
};

struct _GumMachHeader64
{
  guint32 magic;
  GumDarwinCpuType cputype;
  GumDarwinCpuSubtype cpusubtype;
  guint32 filetype;
  guint32 ncmds;
  guint32 sizeofcmds;
  guint32 flags;
  guint32 reserved;
};

enum _GumLoadCommandType
{
  GUM_LC_SEGMENT_32          = 0x01,
  GUM_LC_SYMTAB              = 0x02,
  GUM_LC_DYSYMTAB            = 0x0b,
  GUM_LC_LOAD_DYLIB          = 0x0c,
  GUM_LC_ID_DYLIB            = 0x0d,
  GUM_LC_ID_DYLINKER         = 0x0f,
  GUM_LC_LOAD_WEAK_DYLIB     = (0x18 | GUM_LC_REQ_DYLD),
  GUM_LC_SEGMENT_64          = 0x19,
  GUM_LC_UUID                = 0x1b,
  GUM_LC_REEXPORT_DYLIB      = (0x1f | GUM_LC_REQ_DYLD),
  GUM_LC_DYLD_INFO_ONLY      = (0x22 | GUM_LC_REQ_DYLD),
  GUM_LC_LOAD_UPWARD_DYLIB   = (0x23 | GUM_LC_REQ_DYLD),
  GUM_LC_DYLD_EXPORTS_TRIE   = (0x33 | GUM_LC_REQ_DYLD),
  GUM_LC_DYLD_CHAINED_FIXUPS = (0x34 | GUM_LC_REQ_DYLD),
};

struct _GumLoadCommand
{
  guint32 cmd;
  guint32 cmdsize;
};

union _GumLcStr
{
  guint32 offset;
};

struct _GumSegmentCommand32
{
  guint32 cmd;
  guint32 cmdsize;

  gchar segname[16];

  guint32 vmaddr;
  guint32 vmsize;

  guint32 fileoff;
  guint32 filesize;

  GumDarwinPageProtection maxprot;
  GumDarwinPageProtection initprot;

  guint32 nsects;

  guint32 flags;
};

struct _GumSegmentCommand64
{
  guint32 cmd;
  guint32 cmdsize;

  gchar segname[16];

  guint64 vmaddr;
  guint64 vmsize;

  guint64 fileoff;
  guint64 filesize;

  GumDarwinPageProtection maxprot;
  GumDarwinPageProtection initprot;

  guint32 nsects;

  guint32 flags;
};

struct _GumDylib
{
  GumLcStr name;
  guint32 timestamp;
  guint32 current_version;
  guint32 compatibility_version;
};

struct _GumDylibCommand
{
  guint32 cmd;
  guint32 cmdsize;

  GumDylib dylib;
};

struct _GumDylinkerCommand
{
  guint32 cmd;
  guint32 cmdsize;

  GumLcStr name;
};

struct _GumUUIDCommand
{
  guint32 cmd;
  guint32 cmdsize;

  guint8 uuid[16];
};

struct _GumDyldInfoCommand
{
  guint32 cmd;
  guint32 cmdsize;

  guint32 rebase_off;
  guint32 rebase_size;

  guint32 bind_off;
  guint32 bind_size;

  guint32 weak_bind_off;
  guint32 weak_bind_size;

  guint32 lazy_bind_off;
  guint32 lazy_bind_size;

  guint32 export_off;
  guint32 export_size;
};

struct _GumSymtabCommand
{
  guint32 cmd;
  guint32 cmdsize;

  guint32 symoff;
  guint32 nsyms;

  guint32 stroff;
  guint32 strsize;
};

struct _GumDysymtabCommand
{
  guint32 cmd;
  guint32 cmdsize;

  guint32 ilocalsym;
  guint32 nlocalsym;

  guint32 iextdefsym;
  guint32 nextdefsym;

  guint32 iundefsym;
  guint32 nundefsym;

  guint32 tocoff;
  guint32 ntoc;

  guint32 modtaboff;
  guint32 nmodtab;

  guint32 extrefsymoff;
  guint32 nextrefsyms;

  guint32 indirectsymoff;
  guint32 nindirectsyms;

  guint32 extreloff;
  guint32 nextrel;

  guint32 locreloff;
  guint32 nlocrel;
};

struct _GumLinkeditDataCommand
{
  guint32 cmd;
  guint32 cmdsize;

  guint32 dataoff;
  guint32 datasize;
};

enum _GumSectionType
{
  GUM_S_MOD_INIT_FUNC_POINTERS = 0x09,
  GUM_S_MOD_TERM_FUNC_POINTERS = 0x0a,
  GUM_S_INIT_FUNC_OFFSETS      = 0x16,
};

enum _GumSectionAttributes
{
  GUM_S_ATTR_SOME_INSTRUCTIONS = 0x00000400,
  GUM_S_ATTR_PURE_INSTRUCTIONS = 0x80000000,
};

struct _GumSection32
{
  gchar sectname[16];
  gchar segname[16];
  guint32 addr;
  guint32 size;
  guint32 offset;
  guint32 align;
  guint32 reloff;
  guint32 nreloc;
  guint32 flags;
  guint32 reserved1;
  guint32 reserved2;
};

struct _GumSection64
{
  gchar sectname[16];
  gchar segname[16];
  guint64 addr;
  guint64 size;
  guint32 offset;
  guint32 align;
  guint32 reloff;
  guint32 nreloc;
  guint32 flags;
  guint32 reserved1;
  guint32 reserved2;
  guint32 reserved3;
};

struct _GumNList32
{
  guint32 n_strx;
  guint8 n_type;
  guint8 n_sect;
  gint16 n_desc;
  guint32 n_value;
};

struct _GumNList64
{
  guint32 n_strx;
  guint8 n_type;
  guint8 n_sect;
  guint16 n_desc;
  guint64 n_value;
};

enum _GumRebaseOpcode
{
  GUM_REBASE_OPCODE_DONE                               = 0x00,
  GUM_REBASE_OPCODE_SET_TYPE_IMM                       = 0x10,
  GUM_REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB        = 0x20,
  GUM_REBASE_OPCODE_ADD_ADDR_ULEB                      = 0x30,
  GUM_REBASE_OPCODE_ADD_ADDR_IMM_SCALED                = 0x40,
  GUM_REBASE_OPCODE_DO_REBASE_IMM_TIMES                = 0x50,
  GUM_REBASE_OPCODE_DO_REBASE_ULEB_TIMES               = 0x60,
  GUM_REBASE_OPCODE_DO_REBASE_ADD_ADDR_ULEB            = 0x70,
  GUM_REBASE_OPCODE_DO_REBASE_ULEB_TIMES_SKIPPING_ULEB = 0x80,
};

enum _GumBindOpcode
{
  GUM_BIND_OPCODE_DONE                                 = 0x00,
  GUM_BIND_OPCODE_SET_DYLIB_ORDINAL_IMM                = 0x10,
  GUM_BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB               = 0x20,
  GUM_BIND_OPCODE_SET_DYLIB_SPECIAL_IMM                = 0x30,
  GUM_BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM        = 0x40,
  GUM_BIND_OPCODE_SET_TYPE_IMM                         = 0x50,
  GUM_BIND_OPCODE_SET_ADDEND_SLEB                      = 0x60,
  GUM_BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB          = 0x70,
  GUM_BIND_OPCODE_ADD_ADDR_ULEB                        = 0x80,
  GUM_BIND_OPCODE_DO_BIND                              = 0x90,
  GUM_BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB                = 0xa0,
  GUM_BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED          = 0xb0,
  GUM_BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB     = 0xc0,
  GUM_BIND_OPCODE_THREADED                             = 0xd0,
};

enum _GumBindSubopcode
{
  GUM_BIND_SUBOPCODE_THREADED_SET_BIND_ORDINAL_TABLE_SIZE_ULEB = 0x00,
  GUM_BIND_SUBOPCODE_THREADED_APPLY                            = 0x01,
};

enum _GumExportSymbolFlags
{
  GUM_EXPORT_SYMBOL_FLAGS_REEXPORT                     = 0x08,
  GUM_EXPORT_SYMBOL_FLAGS_STUB_AND_RESOLVER            = 0x10,
};

static void gum_darwin_module_initable_iface_init (gpointer g_iface,
    gpointer iface_data);
static void gum_darwin_module_constructed (GObject * object);
static gboolean gum_darwin_module_initable_init (GInitable * initable,
    GCancellable * cancellable, GError ** error);
static void gum_darwin_module_finalize (GObject * object);
static void gum_darwin_module_get_property (GObject * object,
    guint property_id, GValue * value, GParamSpec * pspec);
static void gum_darwin_module_set_property (GObject * object,
    guint property_id, const GValue * value, GParamSpec * pspec);

static gboolean gum_store_address_if_name_matches (
    const GumDarwinSymbolDetails * details, gpointer user_data);
static gboolean gum_emit_import (const GumDarwinBindDetails * details,
    gpointer user_data);
static gboolean gum_emit_export_from_symbol (
    const GumDarwinSymbolDetails * details, gpointer user_data);
static gboolean gum_emit_section_init_pointers (
    const GumDarwinSectionDetails * details, gpointer user_data);
static gboolean gum_emit_section_init_offsets (
    const GumDarwinSectionDetails * details, gpointer user_data);
static gboolean gum_emit_section_term_pointers (
    const GumDarwinSectionDetails * details, gpointer user_data);
static gboolean gum_darwin_module_ensure_image_loaded (GumDarwinModule * self,
    GError ** error);
static gboolean gum_darwin_module_load_image_from_filesystem (
    GumDarwinModule * self, const gchar * path, GError ** error);
static gboolean gum_darwin_module_load_image_header_from_filesystem (
    GumDarwinModule * self, const gchar * path, GError ** error);
static gboolean gum_darwin_module_load_image_from_blob (GumDarwinModule * self,
    GBytes * blob, GError ** error);
static gboolean gum_darwin_module_load_image_from_memory (
    GumDarwinModule * self, GError ** error);
static gboolean gum_darwin_module_can_load (GumDarwinModule * self,
    GumDarwinCpuType cpu_type, GumDarwinCpuSubtype cpu_subtype);
static gboolean gum_darwin_module_take_image (GumDarwinModule * self,
    GumDarwinModuleImage * image, GError ** error);
static gboolean gum_darwin_module_get_header_offset_size (
    GumDarwinModule * self, gpointer data, gsize data_size, gsize * out_offset,
    gsize * out_size, GError ** error);
static void gum_darwin_module_read_and_assign (GumDarwinModule * self,
    GumAddress address, gsize size, const guint8 ** start, const guint8 ** end,
    gpointer * malloc_data);
static gboolean gum_find_linkedit (const guint8 * module, gsize module_size,
    GumAddress * linkedit);
static gboolean gum_add_text_range_if_text_section (
    const GumDarwinSectionDetails * details, gpointer user_data);
static gboolean gum_section_flags_indicate_text_section (guint32 flags);

static gboolean gum_exports_trie_find (const guint8 * exports,
    const guint8 * exports_end, const gchar * name,
    GumDarwinExportDetails * details);
static gboolean gum_exports_trie_foreach (const guint8 * exports,
    const guint8 * exports_end, GumFoundDarwinExportFunc func,
    gpointer user_data);
static gboolean gum_exports_trie_traverse (const guint8 * p,
    GumExportsTrieForeachContext * ctx);

static void gum_darwin_export_details_init_from_node (
    GumDarwinExportDetails * details, const gchar * name, const guint8 * node,
    const guint8 * exports_end);

static GumCpuType gum_cpu_type_from_darwin (GumDarwinCpuType cpu_type);
static GumPtrauthSupport gum_ptrauth_support_from_darwin (
    GumDarwinCpuType cpu_type, GumDarwinCpuSubtype cpu_subtype);
static guint gum_pointer_size_from_cpu_type (GumDarwinCpuType cpu_type);

G_DEFINE_TYPE_EXTENDED (GumDarwinModule,
                        gum_darwin_module,
                        G_TYPE_OBJECT,
                        0,
                        G_IMPLEMENT_INTERFACE (G_TYPE_INITABLE,
                            gum_darwin_module_initable_iface_init))

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
  g_object_class_install_property (object_class, PROP_UUID,
      g_param_spec_string ("uuid", "UUID", "UUID", NULL,
      G_PARAM_READABLE | G_PARAM_STATIC_STRINGS));
  g_object_class_install_property (object_class, PROP_TASK,
      g_param_spec_uint ("task", "Task", "Mach task", 0, G_MAXUINT,
      GUM_DARWIN_PORT_NULL, G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY |
      G_PARAM_STATIC_STRINGS));
  g_object_class_install_property (object_class, PROP_CPU_TYPE,
      g_param_spec_uint ("cpu-type", "CpuType", "CPU type", 0, G_MAXUINT,
      GUM_CPU_INVALID, G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY |
      G_PARAM_STATIC_STRINGS));
  g_object_class_install_property (object_class, PROP_PTRAUTH_SUPPORT,
      g_param_spec_uint ("ptrauth-support", "PtrauthSupport",
      "Pointer authentication support", 0, G_MAXUINT, GUM_PTRAUTH_INVALID,
      G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY | G_PARAM_STATIC_STRINGS));
  g_object_class_install_property (object_class, PROP_BASE_ADDRESS,
      g_param_spec_uint64 ("base-address", "BaseAddress", "Base address", 0,
      G_MAXUINT64, 0, G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS));
  g_object_class_install_property (object_class, PROP_SOURCE_PATH,
      g_param_spec_string ("source-path", "SourcePath", "Source path", NULL,
      G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY | G_PARAM_STATIC_STRINGS));
  g_object_class_install_property (object_class, PROP_SOURCE_BLOB,
      g_param_spec_boxed ("source-blob", "SourceBlob", "Source blob",
      G_TYPE_BYTES,
      G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY | G_PARAM_STATIC_STRINGS));
  g_object_class_install_property (object_class, PROP_FLAGS,
      g_param_spec_flags ("flags", "Flags", "Optional flags",
      GUM_TYPE_DARWIN_MODULE_FLAGS, GUM_DARWIN_MODULE_FLAGS_NONE,
      G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY | G_PARAM_STATIC_STRINGS));
}

static void
gum_darwin_module_initable_iface_init (gpointer g_iface,
                                       gpointer iface_data)
{
  GInitableIface * iface = g_iface;

  iface->init = gum_darwin_module_initable_init;
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
#ifdef HAVE_DARWIN
  GumDarwinModule * self = GUM_DARWIN_MODULE (object);

  if (self->task != GUM_DARWIN_PORT_NULL)
  {
    self->is_local = self->task == mach_task_self ();
    self->is_kernel = self->task == gum_kernel_get_task ();
  }
#endif
}

static gboolean
gum_darwin_module_initable_init (GInitable * initable,
                                 GCancellable * cancellable,
                                 GError ** error)
{
  GumDarwinModule * self = GUM_DARWIN_MODULE (initable);

  if (self->source_path != NULL)
  {
    if (GUM_DARWIN_MODULE_HAS_HEADER_ONLY (self))
    {
      if (!gum_darwin_module_load_image_header_from_filesystem (self,
          self->source_path, error))
      {
        return FALSE;
      }
    }
    else
    {
      if (!gum_darwin_module_load_image_from_filesystem (self,
          self->source_path, error))
      {
        return FALSE;
      }
    }
  }
  else if (self->source_blob != NULL)
  {
    if (!gum_darwin_module_load_image_from_blob (self, self->source_blob,
        error))
    {
      return FALSE;
    }
  }

  if (self->name == NULL)
    return gum_darwin_module_ensure_image_loaded (self, error);

  return TRUE;
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

  g_free (self->source_path);
  g_bytes_unref (self->source_blob);

  g_free (self->name);
  g_free (self->uuid);

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
    case PROP_UUID:
      if (self->uuid == NULL)
        gum_darwin_module_ensure_image_loaded (self, NULL);
      g_value_set_string (value, self->uuid);
      break;
    case PROP_TASK:
      g_value_set_uint (value, self->task);
      break;
    case PROP_CPU_TYPE:
      g_value_set_uint (value, self->cpu_type);
      break;
    case PROP_PTRAUTH_SUPPORT:
      g_value_set_uint (value, self->ptrauth_support);
      break;
    case PROP_BASE_ADDRESS:
      g_value_set_uint64 (value, self->base_address);
      break;
    case PROP_SOURCE_PATH:
      g_value_set_string (value, self->source_path);
      break;
    case PROP_SOURCE_BLOB:
      g_value_set_boxed (value, self->source_blob);
      break;
    case PROP_FLAGS:
      g_value_set_flags (value, self->flags);
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
    case PROP_PTRAUTH_SUPPORT:
      self->ptrauth_support = g_value_get_uint (value);
      break;
    case PROP_BASE_ADDRESS:
      self->base_address = g_value_get_uint64 (value);
      break;
    case PROP_SOURCE_PATH:
      g_free (self->source_path);
      self->source_path = g_value_dup_string (value);
      break;
    case PROP_SOURCE_BLOB:
      g_clear_pointer (&self->source_blob, g_bytes_unref);
      self->source_blob = g_value_dup_boxed (value);
      break;
    case PROP_FLAGS:
      self->flags = g_value_get_flags (value);
      break;
    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, property_id, pspec);
  }
}

GumDarwinModule *
gum_darwin_module_new_from_file (const gchar * path,
                                 GumCpuType cpu_type,
                                 GumPtrauthSupport ptrauth_support,
                                 GumDarwinModuleFlags flags,
                                 GError ** error)
{
  return g_initable_new (GUM_TYPE_DARWIN_MODULE, NULL, error,
      "cpu-type", cpu_type,
      "ptrauth-support", ptrauth_support,
      "source-path", path,
      "flags", flags,
      NULL);
}

GumDarwinModule *
gum_darwin_module_new_from_blob (GBytes * blob,
                                 GumCpuType cpu_type,
                                 GumPtrauthSupport ptrauth_support,
                                 GumDarwinModuleFlags flags,
                                 GError ** error)
{
  return g_initable_new (GUM_TYPE_DARWIN_MODULE, NULL, error,
      "cpu-type", cpu_type,
      "ptrauth-support", ptrauth_support,
      "source-blob", blob,
      "flags", flags,
      NULL);
}

GumDarwinModule *
gum_darwin_module_new_from_memory (const gchar * name,
                                   GumDarwinPort task,
                                   GumAddress base_address,
                                   GumDarwinModuleFlags flags,
                                   GError ** error)
{
  return g_initable_new (GUM_TYPE_DARWIN_MODULE, NULL, error,
      "name", name,
      "task", task,
      "base-address", base_address,
      "flags", flags,
      NULL);
}

static guint8 *
gum_darwin_module_read_from_task (GumDarwinModule * self,
                                  GumAddress address,
                                  gsize len,
                                  gsize * n_bytes_read)
{
#ifdef HAVE_DARWIN
  return self->is_kernel
      ? gum_kernel_read (address, len, n_bytes_read)
      : gum_darwin_read (self->task, address, len, n_bytes_read);
#else
  return NULL;
#endif
}

gboolean
gum_darwin_module_resolve_export (GumDarwinModule * self,
                                  const gchar * name,
                                  GumDarwinExportDetails * details)
{
  if (!gum_darwin_module_ensure_image_loaded (self, NULL))
    return FALSE;

  if (self->exports != NULL)
  {
    return gum_exports_trie_find (self->exports, self->exports_end, name,
        details);
  }
  else if (self->filetype == GUM_DARWIN_MODULE_FILETYPE_DYLINKER)
  {
    GumAddress address;

    address = gum_darwin_module_resolve_symbol_address (self, name);
    if (address == 0)
      return FALSE;

    details->name = name;
    details->flags = GUM_DARWIN_EXPORT_SYMBOL_FLAGS_KIND_ABSOLUTE;
    details->offset = address;

    return TRUE;
  }

  return FALSE;
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
gum_darwin_module_get_lacks_exports_for_reexports (GumDarwinModule * self)
{
  guint32 flags;

  if (!gum_darwin_module_ensure_image_loaded (self, NULL))
    return FALSE;

  /*
   * FIXME: There must be a better way to detect this behavioral change
   *        introduced in macOS 10.11 and iOS 9.0, but this will have to
   *        do for now.
   */
  flags = ((GumMachHeader32 *) self->image->data)->flags;

  return (flags & GUM_MH_PREBOUND) == 0;
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
  ctx.threaded_binds = NULL;
  ctx.source_start = NULL;
  ctx.source_end = NULL;
  ctx.source_file = NULL;
  ctx.carry_on = TRUE;

  gum_darwin_module_enumerate_binds (self, gum_emit_import, &ctx);
  if (ctx.carry_on)
    gum_darwin_module_enumerate_lazy_binds (self, gum_emit_import, &ctx);

  g_clear_pointer (&ctx.source_file, g_mapped_file_unref);
  g_clear_pointer (&ctx.threaded_binds, g_array_unref);
}

static gboolean
gum_emit_import (const GumDarwinBindDetails * details,
                 gpointer user_data)
{
  GumEmitImportContext * ctx = user_data;
  GumDarwinModule * self = ctx->module;
  const GumDarwinSegment * segment = details->segment;
  GumAddress vm_base;

  vm_base = segment->vm_address + gum_darwin_module_get_slide (self);

  switch (details->type)
  {
    case GUM_DARWIN_BIND_POINTER:
    {
      GumImportDetails d;

      d.type = GUM_IMPORT_UNKNOWN;
      d.name = details->symbol_name;
      switch (details->library_ordinal)
      {
        case GUM_BIND_SPECIAL_DYLIB_MAIN_EXECUTABLE:
        case GUM_BIND_SPECIAL_DYLIB_SELF:
          return TRUE;
        case GUM_BIND_SPECIAL_DYLIB_FLAT_LOOKUP:
        {
          d.module = NULL;
          break;
        }
        default:
          d.module = gum_darwin_module_get_dependency_by_ordinal (self,
              details->library_ordinal);
          break;
      }
      d.address = 0;
      d.slot = vm_base + details->offset;

      if (ctx->threaded_binds != NULL)
        g_array_append_val (ctx->threaded_binds, d);
      else
        ctx->carry_on = ctx->func (&d, ctx->user_data);

      break;
    }
    case GUM_DARWIN_BIND_THREADED_TABLE:
    {
      g_clear_pointer (&ctx->threaded_binds, g_array_unref);
      ctx->threaded_binds = g_array_sized_new (FALSE, FALSE,
          sizeof (GumImportDetails), details->threaded_table_size);

      break;
    }
    case GUM_DARWIN_BIND_THREADED_ITEMS:
    {
      GArray * threaded_binds = ctx->threaded_binds;
      guint64 cursor;
      GumDarwinThreadedItem item;

      if (threaded_binds == NULL)
        return TRUE;

      if (ctx->source_start == NULL)
      {
        gchar * source_path = NULL;
        GMappedFile * file;

#ifdef HAVE_DARWIN
        if (self->task != GUM_DARWIN_PORT_NULL)
        {
          GumDarwinMappingDetails mapping;
          if (gum_darwin_query_mapped_address (self->task, vm_base, &mapping))
            source_path = g_strdup (mapping.path);
        }
#endif
        if (source_path == NULL)
        {
          source_path = g_strdup (self->name);
          if (source_path == NULL)
            return TRUE;
        }
        file = g_mapped_file_new (source_path, FALSE, NULL);
        g_free (source_path);
        if (file == NULL)
          return TRUE;

        ctx->source_start = (const guint8 *) g_mapped_file_get_contents (file);
        ctx->source_end = ctx->source_start + g_mapped_file_get_length (file);
        ctx->source_file = file;
      }

      cursor = details->offset;

      do
      {
        const guint8 * raw_slot;

        raw_slot = ctx->source_start + segment->file_offset + cursor;
        if (raw_slot < ctx->source_start ||
            raw_slot + sizeof (guint64) > ctx->source_end)
        {
          return FALSE;
        }

        gum_darwin_threaded_item_parse (*((const guint64 *) raw_slot), &item);

        if (item.type == GUM_DARWIN_THREADED_BIND)
        {
          guint ordinal = item.bind_ordinal;
          GumImportDetails * d;

          if (ordinal >= threaded_binds->len)
            return TRUE;
          d = &g_array_index (threaded_binds, GumImportDetails, ordinal);
          d->slot = vm_base + cursor;

          ctx->carry_on = ctx->func (d, ctx->user_data);
        }

        cursor += item.delta * sizeof (guint64);
      }
      while (item.delta != 0 && ctx->carry_on);

      break;
    }
    default:
      g_assert_not_reached ();
  }

  return ctx->carry_on;
}

void
gum_darwin_module_enumerate_exports (GumDarwinModule * self,
                                     GumFoundDarwinExportFunc func,
                                     gpointer user_data)
{
  if (!gum_darwin_module_ensure_image_loaded (self, NULL))
    return;

  if (self->exports != NULL)
  {
    gum_exports_trie_foreach (self->exports, self->exports_end, func,
        user_data);
  }
  else if (self->filetype == GUM_DARWIN_MODULE_FILETYPE_DYLINKER)
  {
    GumEmitExportFromSymbolContext ctx;

    ctx.func = func;
    ctx.user_data = user_data;

    gum_darwin_module_enumerate_symbols (self, gum_emit_export_from_symbol,
        &ctx);
  }
}

static gboolean
gum_emit_export_from_symbol (const GumDarwinSymbolDetails * details,
                             gpointer user_data)
{
  GumEmitExportFromSymbolContext * ctx = user_data;
  GumDarwinExportDetails d;

  if ((details->type & GUM_N_EXT) == 0)
    return TRUE;

  if ((details->type & GUM_N_TYPE) != GUM_N_SECT)
    return TRUE;

  d.name = details->name;
  d.flags = GUM_DARWIN_EXPORT_SYMBOL_FLAGS_KIND_ABSOLUTE;
  d.offset = details->address;

  return ctx->func (&d, ctx->user_data);
}

void
gum_darwin_module_enumerate_symbols (GumDarwinModule * self,
                                     GumFoundDarwinSymbolFunc func,
                                     gpointer user_data)
{
  GumDarwinModuleImage * image;
  const GumSymtabCommand * symtab;
  GumAddress slide;
  const guint8 * symbols, * strings;
  gpointer symbols_malloc_data = NULL;
  gpointer strings_malloc_data = NULL;
  gsize symbol_index;

  if (GUM_DARWIN_MODULE_HAS_HEADER_ONLY (self) ||
      !gum_darwin_module_ensure_image_loaded (self, NULL))
  {
    goto beach;
  }

  image = self->image;

  symtab = self->symtab;
  if (symtab == NULL)
    goto beach;

  slide = gum_darwin_module_get_slide (self);

  if (image->linkedit != NULL)
  {
    symbols = (guint8 *) image->linkedit + symtab->symoff;
    strings = (guint8 *) image->linkedit + symtab->stroff;
  }
  else
  {
    GumAddress linkedit;
    gsize symbol_size;

    if (!gum_find_linkedit (image->data, image->size, &linkedit))
      goto beach;
    linkedit += slide;

    symbol_size = (self->pointer_size == 8)
        ? sizeof (GumNList64)
        : sizeof (GumNList32);

    gum_darwin_module_read_and_assign (self, linkedit + symtab->symoff,
        symtab->nsyms * symbol_size, &symbols, NULL, &symbols_malloc_data);
    gum_darwin_module_read_and_assign (self, linkedit + symtab->stroff,
        symtab->strsize, &strings, NULL, &strings_malloc_data);
    if (symbols == NULL || strings == NULL)
      goto beach;
  }

  for (symbol_index = 0; symbol_index != symtab->nsyms; symbol_index++)
  {
    GumDarwinSymbolDetails details;
    gboolean carry_on;

    if (self->pointer_size == 8)
    {
      const GumNList64 * symbol;

      symbol = (GumNList64 *) (symbols + (symbol_index * sizeof (GumNList64)));

      details.name = (const gchar *) (strings + symbol->n_strx);
      details.address = (symbol->n_value != 0) ? symbol->n_value + slide : 0;

      details.type = symbol->n_type;
      details.section = symbol->n_sect;
      details.description = symbol->n_desc;
    }
    else
    {
      const GumNList32 * symbol;

      symbol = (GumNList32 *) (symbols + (symbol_index * sizeof (GumNList32)));

      details.name = (const gchar *) (strings + symbol->n_strx);
      details.address = (symbol->n_value != 0) ? symbol->n_value + slide : 0;

      details.type = symbol->n_type;
      details.section = symbol->n_sect;
      details.description = symbol->n_desc;
    }

    carry_on = func (&details, user_data);
    if (!carry_on)
      goto beach;
  }

beach:
  g_free (strings_malloc_data);
  g_free (symbols_malloc_data);
}

GumAddress
gum_darwin_module_get_slide (GumDarwinModule * self)
{
  return self->base_address - self->preferred_address;
}

const GumDarwinSegment *
gum_darwin_module_get_nth_segment (GumDarwinModule * self,
                                   gsize index)
{
  if (!gum_darwin_module_ensure_image_loaded (self, NULL))
    return NULL;

  if (index >= self->segments->len)
    return NULL;

  return &g_array_index (self->segments, GumDarwinSegment, index);
}

void
gum_darwin_module_enumerate_sections (GumDarwinModule * self,
                                      GumFoundDarwinSectionFunc func,
                                      gpointer user_data)
{
  const GumMachHeader32 * header;
  gconstpointer command;
  gsize command_index;
  GumAddress slide;

  if (!gum_darwin_module_ensure_image_loaded (self, NULL))
    return;

  header = (GumMachHeader32 *) self->image->data;
  if (header->magic == GUM_MH_MAGIC_32)
    command = (GumMachHeader32 *) self->image->data + 1;
  else
    command = (GumMachHeader64 *) self->image->data + 1;
  slide = gum_darwin_module_get_slide (self);
  for (command_index = 0; command_index != header->ncmds; command_index++)
  {
    const GumLoadCommand * lc = command;

    if (lc->cmd == GUM_LC_SEGMENT_32 || lc->cmd == GUM_LC_SEGMENT_64)
    {
      GumDarwinSectionDetails details;
      const guint8 * sections;
      gsize section_count, section_index;

      if (lc->cmd == GUM_LC_SEGMENT_32)
      {
        const GumSegmentCommand32 * sc = command;

        details.protection = sc->initprot;

        sections = (const guint8 *) (sc + 1);
        section_count = sc->nsects;
      }
      else
      {
        const GumSegmentCommand64 * sc = command;

        details.protection = sc->initprot;

        sections = (const guint8 *) (sc + 1);
        section_count = sc->nsects;
      }

      for (section_index = 0; section_index != section_count; section_index++)
      {
        if (lc->cmd == GUM_LC_SEGMENT_32)
        {
          const GumSection32 * s =
              (const GumSection32 *) sections + section_index;

          g_strlcpy (details.segment_name, s->segname,
              sizeof (details.segment_name));
          g_strlcpy (details.section_name, s->sectname,
              sizeof (details.section_name));

          details.vm_address = s->addr + (guint32) slide;
          details.size = s->size;
          details.file_offset = s->offset;
          details.flags = s->flags;
        }
        else
        {
          const GumSection64 * s =
              (const GumSection64 *) sections + section_index;

          g_strlcpy (details.segment_name, s->segname,
              sizeof (details.segment_name));
          g_strlcpy (details.section_name, s->sectname,
              sizeof (details.section_name));

          details.vm_address = s->addr + (guint64) slide;
          details.size = s->size;
          details.file_offset = s->offset;
          details.flags = s->flags;
        }

        if (!func (&details, user_data))
          return;
      }
    }

    command = (const guint8 *) command + lc->cmdsize;
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
gum_darwin_module_enumerate_chained_fixups (
    GumDarwinModule * self,
    GumFoundDarwinChainedFixupsFunc func,
    gpointer user_data)
{
  GumDarwinModuleImage * image;
  const GumMachHeader32 * header;
  gconstpointer command;
  gsize command_index;

  if (!gum_darwin_module_ensure_image_loaded (self, NULL))
    return;

  image = self->image;

  header = image->data;
  if (header->magic == GUM_MH_MAGIC_32)
    command = (GumMachHeader32 *) image->data + 1;
  else
    command = (GumMachHeader64 *) image->data + 1;
  for (command_index = 0; command_index != header->ncmds; command_index++)
  {
    const GumLoadCommand * lc = command;

    if (lc->cmd == GUM_LC_DYLD_CHAINED_FIXUPS)
    {
      const GumLinkeditDataCommand * fixups = command;
      GumAddress linkedit;
      GumDarwinChainedFixupsDetails details;

      if (!gum_find_linkedit (image->data, image->size, &linkedit))
        return;

      linkedit += gum_darwin_module_get_slide (self);

      details.vm_address = linkedit + fixups->dataoff;
      details.file_offset = fixups->dataoff;
      details.size = fixups->datasize;

      if (!func (&details, user_data))
        return;
    }

    command = (const guint8 *) command + lc->cmdsize;
  }
}

void
gum_darwin_module_enumerate_rebases (GumDarwinModule * self,
                                     GumFoundDarwinRebaseFunc func,
                                     gpointer user_data)
{
  const guint8 * start, * end, * p;
  gboolean done;
  GumDarwinRebaseDetails details;

  if (GUM_DARWIN_MODULE_HAS_HEADER_ONLY (self) ||
      !gum_darwin_module_ensure_image_loaded (self, NULL))
  {
    return;
  }

  start = self->rebases;
  end = self->rebases_end;
  p = start;
  done = FALSE;

  details.segment = gum_darwin_module_get_nth_segment (self, 0);
  details.offset = 0;
  details.type = 0;
  details.slide = gum_darwin_module_get_slide (self);

  while (!done && p != end)
  {
    guint8 opcode = *p & GUM_REBASE_OPCODE_MASK;
    guint8 immediate = *p & GUM_REBASE_IMMEDIATE_MASK;

    p++;

    switch (opcode)
    {
      case GUM_REBASE_OPCODE_DONE:
        done = TRUE;
        break;
      case GUM_REBASE_OPCODE_SET_TYPE_IMM:
        details.type = immediate;
        break;
      case GUM_REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB:
      {
        gint segment_index = immediate;
        details.segment =
            gum_darwin_module_get_nth_segment (self, segment_index);
        if (details.segment == NULL)
          return;
        details.offset = gum_read_uleb128 (&p, end);
        break;
      }
      case GUM_REBASE_OPCODE_ADD_ADDR_ULEB:
        details.offset += gum_read_uleb128 (&p, end);
        break;
      case GUM_REBASE_OPCODE_ADD_ADDR_IMM_SCALED:
        details.offset += immediate * self->pointer_size;
        break;
      case GUM_REBASE_OPCODE_DO_REBASE_IMM_TIMES:
      {
        guint8 i;

        for (i = 0; i != immediate; i++)
        {
          if (!func (&details, user_data))
            return;
          details.offset += self->pointer_size;
        }

        break;
      }
      case GUM_REBASE_OPCODE_DO_REBASE_ULEB_TIMES:
      {
        guint64 count, i;

        count = gum_read_uleb128 (&p, end);
        for (i = 0; i != count; i++)
        {
          if (!func (&details, user_data))
            return;
          details.offset += self->pointer_size;
        }

        break;
      }
      case GUM_REBASE_OPCODE_DO_REBASE_ADD_ADDR_ULEB:
        if (!func (&details, user_data))
          return;
        details.offset += self->pointer_size + gum_read_uleb128 (&p, end);
        break;
      case GUM_REBASE_OPCODE_DO_REBASE_ULEB_TIMES_SKIPPING_ULEB:
      {
        gsize count, skip, i;

        count = gum_read_uleb128 (&p, end);
        skip = gum_read_uleb128 (&p, end);
        for (i = 0; i != count; ++i)
        {
          if (!func (&details, user_data))
            return;
          details.offset += self->pointer_size + skip;
        }

        break;
      }
      default:
        return;
    }
  }
}

void
gum_darwin_module_enumerate_binds (GumDarwinModule * self,
                                   GumFoundDarwinBindFunc func,
                                   gpointer user_data)
{
  const guint8 * start, * end, * p;
  gboolean done;
  GumDarwinBindDetails details;

  if (GUM_DARWIN_MODULE_HAS_HEADER_ONLY (self) ||
      !gum_darwin_module_ensure_image_loaded (self, NULL))
  {
    return;
  }

  start = self->binds;
  end = self->binds_end;
  p = start;
  done = FALSE;

  details.segment = gum_darwin_module_get_nth_segment (self, 0);
  details.offset = 0;
  details.type = 0;
  details.library_ordinal = 0;
  details.symbol_name = NULL;
  details.symbol_flags = 0;
  details.addend = 0;
  details.threaded_table_size = 0;

  while (!done && p != end)
  {
    guint8 opcode = *p & GUM_BIND_OPCODE_MASK;
    guint8 immediate = *p & GUM_BIND_IMMEDIATE_MASK;

    p++;

    switch (opcode)
    {
      case GUM_BIND_OPCODE_DONE:
        done = TRUE;
        break;
      case GUM_BIND_OPCODE_SET_DYLIB_ORDINAL_IMM:
        details.library_ordinal = immediate;
        break;
      case GUM_BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB:
        details.library_ordinal = gum_read_uleb128 (&p, end);
        break;
      case GUM_BIND_OPCODE_SET_DYLIB_SPECIAL_IMM:
        if (immediate == 0)
        {
          details.library_ordinal = 0;
        }
        else
        {
          gint8 value = GUM_BIND_OPCODE_MASK | immediate;
          details.library_ordinal = value;
        }
        break;
      case GUM_BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM:
        details.symbol_name = (gchar *) p;
        details.symbol_flags = immediate;
        while (*p != '\0')
          p++;
        p++;
        break;
      case GUM_BIND_OPCODE_SET_TYPE_IMM:
        details.type = immediate;
        break;
      case GUM_BIND_OPCODE_SET_ADDEND_SLEB:
        details.addend = gum_read_sleb128 (&p, end);
        break;
      case GUM_BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB:
      {
        gint segment_index = immediate;
        details.segment =
            gum_darwin_module_get_nth_segment (self, segment_index);
        if (details.segment == NULL)
          return;
        details.offset = gum_read_uleb128 (&p, end);
        break;
      }
      case GUM_BIND_OPCODE_ADD_ADDR_ULEB:
        details.offset += gum_read_uleb128 (&p, end);
        break;
      case GUM_BIND_OPCODE_DO_BIND:
        if (!func (&details, user_data))
          return;
        details.offset += self->pointer_size;
        break;
      case GUM_BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB:
        if (!func (&details, user_data))
          return;
        details.offset += self->pointer_size + gum_read_uleb128 (&p, end);
        break;
      case GUM_BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED:
        if (!func (&details, user_data))
          return;
        details.offset += self->pointer_size + (immediate * self->pointer_size);
        break;
      case GUM_BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB:
      {
        guint64 count, skip, i;

        count = gum_read_uleb128 (&p, end);
        skip = gum_read_uleb128 (&p, end);
        for (i = 0; i != count; ++i)
        {
          if (!func (&details, user_data))
            return;
          details.offset += self->pointer_size + skip;
        }

        break;
      }
      case GUM_BIND_OPCODE_THREADED:
      {
        switch (immediate)
        {
          case GUM_BIND_SUBOPCODE_THREADED_SET_BIND_ORDINAL_TABLE_SIZE_ULEB:
          {
            guint64 size;

            size = gum_read_uleb128 (&p, end);
            if (size > G_MAXUINT16)
              return;

            details.type = GUM_DARWIN_BIND_THREADED_TABLE;
            details.threaded_table_size = size;

            if (!func (&details, user_data))
              return;

            break;
          }
          case GUM_BIND_SUBOPCODE_THREADED_APPLY:
          {
            details.type = GUM_DARWIN_BIND_THREADED_ITEMS;

            if (!func (&details, user_data))
              return;

            break;
          }
          default:
            return;
        }

        break;
      }
      default:
        return;
    }
  }
}

void
gum_darwin_module_enumerate_lazy_binds (GumDarwinModule * self,
                                        GumFoundDarwinBindFunc func,
                                        gpointer user_data)
{
  const guint8 * start, * end, * p;
  GumDarwinBindDetails details;

  if (GUM_DARWIN_MODULE_HAS_HEADER_ONLY (self) ||
      !gum_darwin_module_ensure_image_loaded (self, NULL))
  {
    return;
  }

  start = self->lazy_binds;
  end = self->lazy_binds_end;
  p = start;

  details.segment = gum_darwin_module_get_nth_segment (self, 0);
  details.offset = 0;
  details.type = GUM_DARWIN_BIND_POINTER;
  details.library_ordinal = 0;
  details.symbol_name = NULL;
  details.symbol_flags = 0;
  details.addend = 0;

  while (p != end)
  {
    guint8 opcode = *p & GUM_BIND_OPCODE_MASK;
    guint8 immediate = *p & GUM_BIND_IMMEDIATE_MASK;

    p++;

    switch (opcode)
    {
      case GUM_BIND_OPCODE_DONE:
        break;
      case GUM_BIND_OPCODE_SET_DYLIB_ORDINAL_IMM:
        details.library_ordinal = immediate;
        break;
      case GUM_BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB:
        details.library_ordinal = gum_read_uleb128 (&p, end);
        break;
      case GUM_BIND_OPCODE_SET_DYLIB_SPECIAL_IMM:
        if (immediate == 0)
        {
          details.library_ordinal = 0;
        }
        else
        {
          gint8 value = GUM_BIND_OPCODE_MASK | immediate;
          details.library_ordinal = value;
        }
        break;
      case GUM_BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM:
        details.symbol_name = (gchar *) p;
        details.symbol_flags = immediate;
        while (*p != '\0')
          p++;
        p++;
        break;
      case GUM_BIND_OPCODE_SET_TYPE_IMM:
        details.type = immediate;
        break;
      case GUM_BIND_OPCODE_SET_ADDEND_SLEB:
        details.addend = gum_read_sleb128 (&p, end);
        break;
      case GUM_BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB:
      {
        gint segment_index = immediate;
        details.segment =
            gum_darwin_module_get_nth_segment (self, segment_index);
        if (details.segment == NULL)
          return;
        details.offset = gum_read_uleb128 (&p, end);
        break;
      }
      case GUM_BIND_OPCODE_ADD_ADDR_ULEB:
        details.offset += gum_read_uleb128 (&p, end);
        break;
      case GUM_BIND_OPCODE_DO_BIND:
        if (!func (&details, user_data))
          return;
        details.offset += self->pointer_size;
        break;
      case GUM_BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB:
      case GUM_BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED:
      case GUM_BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB:
      default:
        return;
    }
  }
}

void
gum_darwin_module_enumerate_init_pointers (GumDarwinModule * self,
                                           GumFoundDarwinInitPointersFunc func,
                                           gpointer user_data)
{
  GumEmitInitPointersContext ctx;

  if (GUM_DARWIN_MODULE_HAS_HEADER_ONLY (self) ||
      !gum_darwin_module_ensure_image_loaded (self, NULL))
  {
    return;
  }

  ctx.func = func;
  ctx.user_data = user_data;
  ctx.pointer_size = self->pointer_size;
  gum_darwin_module_enumerate_sections (self, gum_emit_section_init_pointers,
      &ctx);
}

void
gum_darwin_module_enumerate_init_offsets (GumDarwinModule * self,
                                          GumFoundDarwinInitOffsetsFunc func,
                                          gpointer user_data)
{
  GumEmitInitOffsetsContext ctx;

  if (GUM_DARWIN_MODULE_HAS_HEADER_ONLY (self) ||
      !gum_darwin_module_ensure_image_loaded (self, NULL))
  {
    return;
  }

  ctx.func = func;
  ctx.user_data = user_data;
  gum_darwin_module_enumerate_sections (self, gum_emit_section_init_offsets,
      &ctx);
}

void
gum_darwin_module_enumerate_term_pointers (GumDarwinModule * self,
                                           GumFoundDarwinTermPointersFunc func,
                                           gpointer user_data)
{
  GumEmitTermPointersContext ctx;

  if (GUM_DARWIN_MODULE_HAS_HEADER_ONLY (self) ||
      !gum_darwin_module_ensure_image_loaded (self, NULL))
  {
    return;
  }

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
  if ((details->flags & GUM_SECTION_TYPE_MASK) == GUM_S_MOD_INIT_FUNC_POINTERS)
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
gum_emit_section_init_offsets (const GumDarwinSectionDetails * details,
                               gpointer user_data)
{
  if ((details->flags & GUM_SECTION_TYPE_MASK) == GUM_S_INIT_FUNC_OFFSETS)
  {
    GumEmitInitOffsetsContext * ctx = user_data;
    GumDarwinInitOffsetsDetails d;

    d.address = details->vm_address;
    d.count = details->size / sizeof (guint32);

    return ctx->func (&d, ctx->user_data);
  }

  return TRUE;
}

static gboolean
gum_emit_section_term_pointers (const GumDarwinSectionDetails * details,
                                gpointer user_data)
{
  if ((details->flags & GUM_SECTION_TYPE_MASK) == GUM_S_MOD_TERM_FUNC_POINTERS)
  {
    GumEmitTermPointersContext * ctx = user_data;
    GumDarwinTermPointersDetails d;

    d.address = details->vm_address;
    d.count = details->size / ctx->pointer_size;

    return ctx->func (&d, ctx->user_data);
  }

  return TRUE;
}

void
gum_darwin_module_enumerate_dependencies (GumDarwinModule * self,
                                          GumFoundDarwinDependencyFunc func,
                                          gpointer user_data)
{
  guint i;

  if (!gum_darwin_module_ensure_image_loaded (self, NULL))
    return;

  for (i = 0; i < self->dependencies->len; i++)
  {
    const gchar * path;

    path = g_ptr_array_index (self->dependencies, i);
    if (path == NULL)
      continue;

    if (!func (path, user_data))
      return;
  }
}

const gchar *
gum_darwin_module_get_dependency_by_ordinal (GumDarwinModule * self,
                                             gint ordinal)
{
  gint i = ordinal - 1;

  if (!gum_darwin_module_ensure_image_loaded (self, NULL))
    return NULL;

  if (i < 0 || i >= (gint) self->dependencies->len)
    return NULL;

  return g_ptr_array_index (self->dependencies, i);
}

void
gum_darwin_threaded_item_parse (guint64 value,
                                GumDarwinThreadedItem * result)
{
  result->is_authenticated      = (value >> 63) & 1;
  result->type                  = (value >> 62) & 1;
  result->delta                 = (value >> 51) & GUM_INT11_MASK;
  result->key                   = (value >> 49) & GUM_INT2_MASK;
  result->has_address_diversity = (value >> 48) & 1;
  result->diversity             = (value >> 32) & GUM_INT16_MASK;

  if (result->type == GUM_DARWIN_THREADED_BIND)
  {
    result->bind_ordinal = value & GUM_INT16_MASK;
  }
  else if (result->type == GUM_DARWIN_THREADED_REBASE)
  {
    if (result->is_authenticated)
    {
      result->rebase_address = value & GUM_INT32_MASK;
    }
    else
    {
      guint64 top_8_bits, bottom_43_bits, sign_bits;
      gboolean sign_bit_set;

      top_8_bits = (value << 13) & G_GUINT64_CONSTANT (0xff00000000000000);
      bottom_43_bits = value     & G_GUINT64_CONSTANT (0x000007ffffffffff);

      sign_bit_set = (value >> 42) & 1;
      if (sign_bit_set)
        sign_bits = G_GUINT64_CONSTANT (0x00fff80000000000);
      else
        sign_bits = 0;

      result->rebase_address = top_8_bits | sign_bits | bottom_43_bits;
    }
  }
}

static gboolean
gum_darwin_module_ensure_image_loaded (GumDarwinModule * self,
                                       GError ** error)
{
  if (self->image != NULL)
    return TRUE;

  return gum_darwin_module_load_image_from_memory (self, error);
}

static gboolean
gum_darwin_module_load_image_from_filesystem (GumDarwinModule * self,
                                              const gchar * path,
                                              GError ** error)
{
  gboolean success;
  GMappedFile * file;
  gsize size, size_in_pages, page_size;
  gpointer data;
  GBytes * blob;

  file = g_mapped_file_new (path, FALSE, error);
  if (file == NULL)
    return FALSE;

  size = g_mapped_file_get_length (file);
  page_size = gum_query_page_size ();
  size_in_pages = size / page_size;
  if (size % page_size != 0)
    size_in_pages++;

  data = gum_alloc_n_pages (size_in_pages, GUM_PAGE_RW);
  memcpy (data, g_mapped_file_get_contents (file), size);

  g_clear_pointer (&file, g_mapped_file_unref);

  blob = g_bytes_new_with_free_func (data, size, gum_free_pages, data);

  success = gum_darwin_module_load_image_from_blob (self, blob, error);

  g_bytes_unref (blob);

  return success;
}

static gboolean
gum_darwin_module_load_image_header_from_filesystem (GumDarwinModule * self,
                                                     const gchar * path,
                                                     GError ** error)
{
  gboolean success;
  GMappedFile * file;
  gsize page_size, size, size_in_pages;
  gpointer data;
  GBytes * blob;
  gsize header_size, cursor;
  gboolean is_fat;

  file = g_mapped_file_new (path, FALSE, error);
  if (file == NULL)
    return FALSE;

  page_size = gum_query_page_size ();
  data = gum_alloc_n_pages (1, GUM_PAGE_RW);
  size = page_size;

  cursor = 0;
  do
  {
    gsize header_offset;

    memcpy (data, g_mapped_file_get_contents (file) + cursor, size);
    if (!gum_darwin_module_get_header_offset_size (self, data, size,
        &header_offset, &header_size, error))
    {
      gum_free_pages (data);
      g_clear_pointer (&file, g_mapped_file_unref);
      return FALSE;
    }

    cursor += header_offset;
    is_fat = header_offset > 0;
  }
  while (is_fat);

  size_in_pages = header_size / page_size;
  if (header_size % page_size != 0)
    size_in_pages++;

  if (size_in_pages != 1)
  {
    gum_free_pages (data);
    data = gum_alloc_n_pages (size_in_pages, GUM_PAGE_RW);
  }

  memcpy (data, g_mapped_file_get_contents (file) + cursor, header_size);

  g_clear_pointer (&file, g_mapped_file_unref);

  blob = g_bytes_new_with_free_func (data, header_size, gum_free_pages, data);

  success = gum_darwin_module_load_image_from_blob (self, blob, error);

  g_bytes_unref (blob);

  return success;
}

static gboolean
gum_darwin_module_get_header_offset_size (GumDarwinModule * self,
                                          gpointer data,
                                          gsize data_size,
                                          gsize * out_offset,
                                          gsize * out_size,
                                          GError ** error)
{
  GumFatHeader * fat_header;
  gpointer data_end;
  gboolean found;

  fat_header = data;
  data_end = (guint8 *) data + data_size;

  found = FALSE;
  switch (fat_header->magic)
  {
    case GUM_FAT_CIGAM_32:
    {
      guint32 count, i;

      count = GUINT32_FROM_BE (fat_header->nfat_arch);
      for (i = 0; i != count && !found; i++)
      {
        GumFatArch32 * fat_arch;
        guint32 offset;
        GumDarwinCpuType cpu_type;
        GumDarwinCpuSubtype cpu_subtype;

        fat_arch = ((GumFatArch32 *) (fat_header + 1)) + i;
        if ((gpointer) (fat_arch + 1) > data_end)
          goto invalid_blob;

        offset = GUINT32_FROM_BE (fat_arch->offset);
        cpu_type = GUINT32_FROM_BE (fat_arch->cputype);
        cpu_subtype = GUINT32_FROM_BE (fat_arch->cpusubtype);

        found = gum_darwin_module_can_load (self, cpu_type, cpu_subtype);
        if (found)
        {
          *out_offset = offset;
          *out_size = (gum_pointer_size_from_cpu_type (cpu_type) == 8)
              ? sizeof (GumMachHeader64)
              : sizeof (GumMachHeader32);
        }
      }

      break;
    }
    case GUM_MH_MAGIC_32:
    {
      GumMachHeader32 * header = data;

      if ((gpointer) (header + 1) > data_end)
        goto invalid_blob;

      found = gum_darwin_module_can_load (self, header->cputype,
          header->cpusubtype);
      if (found)
      {
        *out_offset = 0;
        *out_size = sizeof (GumMachHeader32) + header->sizeofcmds;
      }

      break;
    }
    case GUM_MH_MAGIC_64:
    {
      GumMachHeader64 * header = data;

      if ((gpointer) (header + 1) > data_end)
        goto invalid_blob;

      found = gum_darwin_module_can_load (self, header->cputype,
          header->cpusubtype);
      if (found)
      {
        *out_offset = 0;
        *out_size = sizeof (GumMachHeader64) + header->sizeofcmds;
      }

      break;
    }
    default:
      goto invalid_blob;
  }

  if (!found)
    goto incompatible_image;

  return TRUE;

invalid_blob:
  {
    g_set_error (error, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT,
        "Invalid Mach-O image");
    return FALSE;
  }
incompatible_image:
  {
    g_set_error (error, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT,
        "Incompatible Mach-O image");
    return FALSE;
  }
}

static gboolean
gum_darwin_module_load_image_from_blob (GumDarwinModule * self,
                                        GBytes * blob,
                                        GError ** error)
{
  GumDarwinModuleImage * image;
  guint8 * blob_start, * blob_end;
  gsize blob_size;
  gpointer data;
  gsize size;
  guint32 magic;

  image = gum_darwin_module_image_new ();
  image->bytes = g_bytes_ref (blob);

  blob_start = (guint8 *) g_bytes_get_data (blob, &blob_size);
  blob_end = blob_start + blob_size;

  data = blob_start;
  size = blob_size;

  if (blob_size < 4)
    goto invalid_blob;
  magic = *((guint32 *) data);

  if (magic == GUM_FAT_CIGAM_32)
  {
    GumFatHeader * fat_header;
    guint32 count, i;
    gboolean found;

    fat_header = (GumFatHeader *) blob_start;

    count = GUINT32_FROM_BE (fat_header->nfat_arch);
    found = FALSE;
    for (i = 0; i != count && !found; i++)
    {
      GumFatArch32 * fat_arch;
      GumDarwinCpuType cpu_type;
      GumDarwinCpuSubtype cpu_subtype;

      fat_arch = ((GumFatArch32 *) (fat_header + 1)) + i;
      if ((guint8 *) (fat_arch + 1) > blob_end)
        goto invalid_blob;

      cpu_type = GUINT32_FROM_BE (fat_arch->cputype);
      cpu_subtype = GUINT32_FROM_BE (fat_arch->cpusubtype);

      found = gum_darwin_module_can_load (self, cpu_type, cpu_subtype);
      if (found)
      {
        data = blob_start + GUINT32_FROM_BE (fat_arch->offset);
        size = GUINT32_FROM_BE (fat_arch->size);
      }
    }

    if (!found)
      goto incompatible_image;

    if ((guint8 *) data + 4 > blob_end)
      goto invalid_blob;
    magic = *((guint32 *) data);
  }

  switch (magic)
  {
    case GUM_MH_MAGIC_32:
    {
      GumMachHeader32 * header = data;

      if ((guint8 *) (header + 1) > blob_end)
        goto invalid_blob;

      if (!gum_darwin_module_can_load (self, header->cputype,
          header->cpusubtype))
      {
        goto incompatible_image;
      }

      break;
    }
    case GUM_MH_MAGIC_64:
    {
      GumMachHeader64 * header = data;

      if ((guint8 *) (header + 1) > blob_end)
        goto invalid_blob;

      if (!gum_darwin_module_can_load (self, header->cputype,
          header->cpusubtype))
      {
        goto incompatible_image;
      }

      break;
    }
    default:
      goto invalid_blob;
  }

  image->data = data;
  image->size = size;
  image->linkedit = data;

  return gum_darwin_module_take_image (self, image, error);

invalid_blob:
  {
    gum_darwin_module_image_free (image);

    g_set_error (error, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT,
        "Invalid Mach-O image");
    return FALSE;
  }
incompatible_image:
  {
    gum_darwin_module_image_free (image);

    g_set_error (error, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT,
        "Incompatible Mach-O image");
    return FALSE;
  }
}

static gboolean
gum_darwin_module_load_image_from_memory (GumDarwinModule * self,
                                          GError ** error)
{
  guint8 * start, * end;
  gpointer malloc_data;
  GumDarwinModuleImage * image;

  g_assert (self->base_address != 0);

  gum_darwin_module_read_and_assign (self, self->base_address,
      GUM_MAX_MACHO_METADATA_SIZE, (const guint8 **) &start,
      (const guint8 **) &end, &malloc_data);
  if (start == NULL)
    goto invalid_task;

  image = gum_darwin_module_image_new ();

  image->data = start;
  image->size = end - start;

  image->malloc_data = malloc_data;

  return gum_darwin_module_take_image (self, image, error);

invalid_task:
  {
    g_set_error (error, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT,
        "Process is dead");
    return FALSE;
  }
}

static gboolean
gum_darwin_module_can_load (GumDarwinModule * self,
                            GumDarwinCpuType cpu_type,
                            GumDarwinCpuSubtype cpu_subtype)
{
  GumCpuType canonical_cpu_type;
  gboolean allow_any_cpu, allow_any_ptrauth;

  canonical_cpu_type = gum_cpu_type_from_darwin (cpu_type);

  allow_any_cpu = self->cpu_type == GUM_CPU_INVALID;
  if (allow_any_cpu)
  {
    gboolean is_supported = canonical_cpu_type != GUM_CPU_INVALID;
    if (!is_supported)
      return FALSE;
  }
  else
  {
    gboolean matches_selected_cpu = canonical_cpu_type == self->cpu_type;
    if (!matches_selected_cpu)
      return FALSE;
  }

  allow_any_ptrauth = self->ptrauth_support == GUM_PTRAUTH_INVALID;
  if (!allow_any_ptrauth)
  {
    gboolean matches_selected_ptrauth =
        gum_ptrauth_support_from_darwin (cpu_type, cpu_subtype)
        == self->ptrauth_support;
    if (!matches_selected_ptrauth)
      return FALSE;
  }

  return TRUE;
}

static gboolean
gum_darwin_module_take_image (GumDarwinModule * self,
                              GumDarwinModuleImage * image,
                              GError ** error)
{
  gboolean success = FALSE;
  const GumMachHeader32 * header;
  gconstpointer command;
  gsize command_index;
  const GumLinkeditDataCommand * exports_trie = NULL;

  g_assert (self->image == NULL);
  self->image = image;

  header = (GumMachHeader32 *) image->data;

  self->filetype = header->filetype;

  if (self->cpu_type == GUM_CPU_INVALID)
    self->cpu_type = gum_cpu_type_from_darwin (header->cputype);

  if (self->ptrauth_support == GUM_PTRAUTH_INVALID)
  {
    self->ptrauth_support =
        gum_ptrauth_support_from_darwin (header->cputype, header->cpusubtype);
  }

  self->pointer_size = gum_pointer_size_from_cpu_type (header->cputype);

  if (header->magic == GUM_MH_MAGIC_32)
    command = (GumMachHeader32 *) image->data + 1;
  else
    command = (GumMachHeader64 *) image->data + 1;
  for (command_index = 0; command_index != header->ncmds; command_index++)
  {
    const GumLoadCommand * lc = (GumLoadCommand *) command;

    switch (lc->cmd)
    {
      case GUM_LC_ID_DYLIB:
      {
        if (self->name == NULL)
        {
          const GumDylib * dl = &((GumDylibCommand *) lc)->dylib;
          const gchar * raw_path;
          guint raw_path_len;

          raw_path = (const gchar *) command + dl->name.offset;
          raw_path_len = lc->cmdsize - sizeof (GumDylibCommand);

          self->name = g_strndup (raw_path, raw_path_len);
        }

        break;
      }
      case GUM_LC_ID_DYLINKER:
      {
        if (self->name == NULL)
        {
          const GumDylinkerCommand * dl = (const GumDylinkerCommand *) lc;
          const gchar * raw_path;
          guint raw_path_len;

          raw_path = (const gchar *) command + dl->name.offset;
          raw_path_len = lc->cmdsize - sizeof (GumDylinkerCommand);

          self->name = g_strndup (raw_path, raw_path_len);
        }

        break;
      }
      case GUM_LC_UUID:
      {
        if (self->uuid == NULL)
        {
          const GumUUIDCommand * uc = command;
          const uint8_t * u = uc->uuid;

          self->uuid = g_strdup_printf ("%02X%02X%02X%02X-%02X%02X-%02X%02X-"
              "%02X%02X-%02X%02X%02X%02X%02X%02X", u[0], u[1], u[2], u[3],
              u[4], u[5], u[6], u[7], u[8], u[9], u[10], u[11], u[12], u[13],
              u[14], u[15]);
        }

        break;
      }
      case GUM_LC_SEGMENT_32:
      case GUM_LC_SEGMENT_64:
      {
        GumDarwinSegment segment;

        if (lc->cmd == GUM_LC_SEGMENT_32)
        {
          const GumSegmentCommand32 * sc = command;

          g_strlcpy (segment.name, sc->segname, sizeof (segment.name));
          segment.vm_address = sc->vmaddr;
          segment.vm_size = sc->vmsize;
          segment.file_offset = sc->fileoff;
          segment.file_size = sc->filesize;
          segment.protection = sc->initprot;
        }
        else
        {
          const GumSegmentCommand64 * sc = command;

          g_strlcpy (segment.name, sc->segname, sizeof (segment.name));
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
      case GUM_LC_LOAD_DYLIB:
      case GUM_LC_LOAD_WEAK_DYLIB:
      case GUM_LC_REEXPORT_DYLIB:
      case GUM_LC_LOAD_UPWARD_DYLIB:
      {
        const GumDylibCommand * dc = command;
        const gchar * name;

        name = (const gchar *) command + dc->dylib.name.offset;
        g_ptr_array_add (self->dependencies, (gpointer) name);

        if (lc->cmd == GUM_LC_REEXPORT_DYLIB)
          g_ptr_array_add (self->reexports, (gpointer) name);

        break;
      }
      case GUM_LC_DYLD_INFO_ONLY:
        self->info = command;
        break;
      case GUM_LC_DYLD_EXPORTS_TRIE:
        exports_trie = command;
        break;
      case GUM_LC_SYMTAB:
        self->symtab = command;
        break;
      case GUM_LC_DYSYMTAB:
        self->dysymtab = command;
        break;
      default:
        break;
    }

    command = (const guint8 *) command + lc->cmdsize;
  }

  gum_darwin_module_enumerate_sections (self,
      gum_add_text_range_if_text_section, self->text_ranges);

  if (self->info == NULL)
  {
    if (exports_trie != NULL)
    {
      if (image->linkedit != NULL)
      {
        self->exports =
            (const guint8 *) image->linkedit + exports_trie->dataoff;
        self->exports_end = self->exports + exports_trie->datasize;
        self->exports_malloc_data = NULL;
      }
      else
      {
        GumAddress linkedit;

        if (!gum_find_linkedit (image->data, image->size, &linkedit))
          goto beach;
        linkedit += gum_darwin_module_get_slide (self);

        gum_darwin_module_read_and_assign (self,
            linkedit + exports_trie->dataoff,
            exports_trie->datasize,
            &self->exports,
            &self->exports_end,
            &self->exports_malloc_data);
      }
    }
  }
  else if (image->linkedit != NULL)
  {
    self->rebases = (const guint8 *) image->linkedit + self->info->rebase_off;
    self->rebases_end = self->rebases + self->info->rebase_size;
    self->rebases_malloc_data = NULL;

    self->binds = (const guint8 *) image->linkedit + self->info->bind_off;
    self->binds_end = self->binds + self->info->bind_size;
    self->binds_malloc_data = NULL;

    self->lazy_binds =
        (const guint8 *) image->linkedit + self->info->lazy_bind_off;
    self->lazy_binds_end = self->lazy_binds + self->info->lazy_bind_size;
    self->lazy_binds_malloc_data = NULL;

    self->exports = (const guint8 *) image->linkedit + self->info->export_off;
    self->exports_end = self->exports + self->info->export_size;
    self->exports_malloc_data = NULL;
  }
  else
  {
    GumAddress linkedit;

    if (!gum_find_linkedit (image->data, image->size, &linkedit))
      goto beach;
    linkedit += gum_darwin_module_get_slide (self);

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

  success = self->segments->len != 0;

beach:
  if (!success)
  {
    self->image = NULL;
    gum_darwin_module_image_free (image);

    g_set_error (error, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT,
        "Invalid Mach-O image");
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
  guint8 * data;

  if (size == 0)
    goto empty_read;

  if (self->is_local)
  {
    *start = GSIZE_TO_POINTER (address);
    if (end != NULL)
      *end = GSIZE_TO_POINTER (address + size);

    *malloc_data = NULL;
  }
  else
  {
    gsize n_bytes_read;

    n_bytes_read = 0;
    data = gum_darwin_module_read_from_task (self, address, size,
        &n_bytes_read);

    *start = data;
    if (end != NULL)
      *end = (data != NULL) ? data + n_bytes_read : NULL;
    else if (n_bytes_read != size)
      goto short_read;

    *malloc_data = data;
  }

  return;

empty_read:
  {
    *start = NULL;
    if (end != NULL)
      *end = NULL;

    *malloc_data = NULL;

    return;
  }
short_read:
  {
    g_free (data);
    *start = NULL;

    *malloc_data = NULL;

    return;
  }
}

static gboolean
gum_find_linkedit (const guint8 * module,
                   gsize module_size,
                   GumAddress * linkedit)
{
  GumMachHeader32 * header;
  const guint8 * p;
  guint cmd_index;

  header = (GumMachHeader32 *) module;
  if (header->magic == GUM_MH_MAGIC_32)
    p = module + sizeof (GumMachHeader32);
  else
    p = module + sizeof (GumMachHeader64);
  for (cmd_index = 0; cmd_index != header->ncmds; cmd_index++)
  {
    GumLoadCommand * lc = (GumLoadCommand *) p;

    if (lc->cmd == GUM_LC_SEGMENT_32 || lc->cmd == GUM_LC_SEGMENT_64)
    {
      GumSegmentCommand32 * sc32 = (GumSegmentCommand32 *) lc;
      GumSegmentCommand64 * sc64 = (GumSegmentCommand64 *) lc;
      if (strncmp (sc32->segname, "__LINKEDIT", 10) == 0)
      {
        if (header->magic == GUM_MH_MAGIC_32)
          *linkedit = sc32->vmaddr - sc32->fileoff;
        else
          *linkedit = sc64->vmaddr - sc64->fileoff;
        return TRUE;
      }
    }

    p += lc->cmdsize;
  }

  return FALSE;
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
gum_section_flags_indicate_text_section (guint32 flags)
{
  return (flags & (GUM_S_ATTR_PURE_INSTRUCTIONS | GUM_S_ATTR_SOME_INSTRUCTIONS))
      != 0;
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
      memcpy ((guint8 *) image->data + s->offset,
          (const guint8 *) other->data + s->offset, s->size);
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
    if (other->linkedit >= data &&
        other->linkedit < (gconstpointer) ((const guint8 *) data + size))
    {
      image->linkedit = other->linkedit;
    }
  }

  if (image->linkedit == NULL && other->linkedit != NULL)
  {
    g_assert (other->linkedit >= other->data && other->linkedit <
        (gconstpointer) ((guint8 *) other->data + other->size));
    image->linkedit = (guint8 *) image->data +
        ((guint8 *) other->linkedit - (guint8 *) other->data);
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
        gum_skip_uleb128 (&p, exports_end);
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
                          GumFoundDarwinExportFunc func,
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
  if ((details->flags & GUM_EXPORT_SYMBOL_FLAGS_REEXPORT) != 0)
  {
    details->reexport_library_ordinal = gum_read_uleb128 (&p, exports_end);
    details->reexport_symbol = (*p != '\0') ? (gchar *) p : name;
  }
  else if ((details->flags & GUM_EXPORT_SYMBOL_FLAGS_STUB_AND_RESOLVER) != 0)
  {
    details->stub = gum_read_uleb128 (&p, exports_end);
    details->resolver = gum_read_uleb128 (&p, exports_end);
  }
  else
  {
    details->offset = gum_read_uleb128 (&p, exports_end);
  }
}

static GumCpuType
gum_cpu_type_from_darwin (GumDarwinCpuType cpu_type)
{
  switch (cpu_type)
  {
    case GUM_DARWIN_CPU_X86:
      return GUM_CPU_IA32;
    case GUM_DARWIN_CPU_X86_64:
      return GUM_CPU_AMD64;
    case GUM_DARWIN_CPU_ARM:
      return GUM_CPU_ARM;
    case GUM_DARWIN_CPU_ARM64:
      return GUM_CPU_ARM64;
    default:
      return GUM_CPU_INVALID;
  }
}

static GumPtrauthSupport
gum_ptrauth_support_from_darwin (GumDarwinCpuType cpu_type,
                                 GumDarwinCpuSubtype cpu_subtype)
{
  if (cpu_type == GUM_DARWIN_CPU_ARM64)
  {
    return ((cpu_subtype & GUM_DARWIN_CPU_SUBTYPE_MASK) ==
            GUM_DARWIN_CPU_SUBTYPE_ARM64E)
        ? GUM_PTRAUTH_SUPPORTED
        : GUM_PTRAUTH_UNSUPPORTED;
  }

  return GUM_PTRAUTH_UNSUPPORTED;
}

static guint
gum_pointer_size_from_cpu_type (GumDarwinCpuType cpu_type)
{
  switch (cpu_type)
  {
    case GUM_DARWIN_CPU_X86:
    case GUM_DARWIN_CPU_ARM:
      return 4;
    case GUM_DARWIN_CPU_X86_64:
    case GUM_DARWIN_CPU_ARM64:
      return 8;
    default:
      return 0;
  }
}
