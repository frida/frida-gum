/*
 * Copyright (C) 2026 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gummapper.h"
#include "gummemory-priv.h"
#include "gummodule-windows.h"
#include "gumnativeprocessmemory.h"
#include "gumpemodule.h"
#include "gum/gumwindows.h"
#if defined (HAVE_I386)
# include "gumx86writer.h"
#elif defined (HAVE_ARM64)
# include "gumarm64writer.h"
#endif

#include <capstone.h>
#include <gio/gio.h>

#define GUM_PE_MAPPER_CODE_BASE_SIZE 512
#define GUM_PE_MAPPER_TLS_CALL_SIZE 128
#define GUM_PE_MAPPER_UNWIND_SIZE 128
#define GUM_PE_MAPPER_ENTRY_CALL_SIZE 128

#define GUM_PE_TLS_THUNK_PATCH_SIZE 5
#define GUM_PE_TLS_HOOK_MAX_DISTANCE 0x70000000
#define GUM_PE_TLS_HOOK_CODE_SIZE 512
#define GUM_PE_TLS_SHARED_SIZE 0x2000
#define GUM_PE_TLS_SHARED_MAGIC G_GUINT64_CONSTANT (0x4750655f544c5301)
#define GUM_PE_TLS_HANDLER_OFFSET 0x1000
#define GUM_PE_TLS_ENTRIES_OFFSET 24
#define GUM_PE_TLS_ENTRY_CAPACITY \
    ((GUM_PE_TLS_HANDLER_OFFSET - GUM_PE_TLS_ENTRIES_OFFSET) / \
        sizeof (GumPeTlsEntry))

#define GUM_ARM64_MOV_X1_XZR 0xaa1f03e1
#define GUM_ARM64_LDR_X16_PC_PLUS_12 0x58000070
#define GUM_ARM64_BR_X16 0xd61f0200
#define GUM_ARM64_RET 0xd65f03c0
#define GUM_ARM64_MOV_W2_TLS_DIRECTORY 0x52800122

#define GUM_PE_DLL_PROCESS_DETACH 0
#define GUM_PE_DLL_PROCESS_ATTACH 1

#define GUM_PE_DEFAULT_COOKIE_32 0xbb40e64e
#define GUM_PE_DEFAULT_COOKIE_64 G_GUINT64_CONSTANT (0x00002b992ddfa232)
#define GUM_PE_COOKIE_MASK_64 G_GUINT64_CONSTANT (0x0000ffffffffffff)

#define GUM_PE_VIEW_UNMAP 2
#define GUM_PE_ALLOCATION_GRANULARITY 0x10000
#define GUM_PE_MAX_PLACEMENT_ATTEMPTS 3

#define GUM_PE_STAGED(self, address) \
    ((self)->staging + ((address) - (self)->image_address))

#if GLIB_SIZEOF_VOID_P == 8
# define GUM_PE_LOADER_ENTRY_SIZE 0x200
# define GUM_PE_LOADER_ENTRY_DLL_BASE_OFFSET 0x30
# define GUM_PE_LDR_TLS_FLAGS_FIELD 0x10c
#else
# define GUM_PE_LOADER_ENTRY_SIZE 0x100
# define GUM_PE_LOADER_ENTRY_DLL_BASE_OFFSET 0x18
# define GUM_PE_LDR_TLS_FLAGS_FIELD 0x94
#endif

#if defined (HAVE_I386) && GLIB_SIZEOF_VOID_P == 4
# define GUM_PE_TLS_ENTRY_REG X86_REG_ECX
# define GUM_PE_TLS_FLAGS_REG X86_REG_EDX
#elif defined (HAVE_I386)
# define GUM_PE_TLS_ENTRY_REG X86_REG_RCX
# define GUM_PE_TLS_FLAGS_REG X86_REG_RDX
#endif

#define GUM_TYPE_PE_MAPPER (gum_pe_mapper_get_type ())
G_DECLARE_FINAL_TYPE (GumPeMapper, gum_pe_mapper, GUM, PE_MAPPER, GObject)

typedef struct _GumPeResolveContext GumPeResolveContext;
typedef struct _GumPeFindWritableContext GumPeFindWritableContext;
typedef struct _GumPeTlsCollectContext GumPeTlsCollectContext;
typedef struct _GumPeEnumerateExportsContext GumPeEnumerateExportsContext;
typedef struct _GumPeMatchOrdinalContext GumPeMatchOrdinalContext;
typedef struct _GumPeFindSectionContext GumPeFindSectionContext;
#if defined (HAVE_I386) && GLIB_SIZEOF_VOID_P == 4
typedef struct _GumPeChpeMetadataX86 GumPeChpeMetadataX86;
#endif
#if GLIB_SIZEOF_VOID_P == 8 && !defined (HAVE_ARM64)
typedef struct _GumPeX64TlsScanContext GumPeX64TlsScanContext;
typedef struct _GumPeTlsShared GumPeTlsShared;
typedef struct _GumPeTlsEntry GumPeTlsEntry;
typedef struct _GumPeArm64Thunk GumPeArm64Thunk;
typedef struct _GumPeTlsThunks GumPeTlsThunks;
#endif

#if defined (HAVE_I386) && GLIB_SIZEOF_VOID_P == 4
typedef void (__fastcall * GumLdrHandleTlsDataFunc) (gpointer entry);
typedef void (__fastcall * GumLdrReleaseTlsEntryFunc) (gpointer entry,
    gsize flags);
#else
typedef void (* GumLdrHandleTlsDataFunc) (gpointer entry);
typedef void (* GumLdrReleaseTlsEntryFunc) (gpointer entry, gsize flags);
#endif
typedef LONG (NTAPI * GumNtMapViewOfSectionFunc) (HANDLE section_handle,
    HANDLE process_handle, PVOID * base_address, ULONG_PTR zero_bits,
    SIZE_T commit_size, PLARGE_INTEGER section_offset, PSIZE_T view_size,
    DWORD inherit_disposition, ULONG allocation_type, ULONG win32_protect);
typedef LONG (NTAPI * GumNtUnmapViewOfSectionFunc) (HANDLE process_handle,
    PVOID base_address);
#if !defined (HAVE_ARM64)
typedef BOOL (WINAPI * GumIsWow64Process2Func) (HANDLE process,
    USHORT * process_machine, USHORT * native_machine);
#endif
#if GLIB_SIZEOF_VOID_P == 8 && !defined (HAVE_ARM64)
typedef PVOID (WINAPI * GumVirtualAlloc2Func) (HANDLE process,
    PVOID base_address, SIZE_T size, ULONG allocation_type,
    ULONG page_protection, MEM_EXTENDED_PARAMETER * extended_parameters,
    ULONG parameter_count);
#endif

struct _GumPeMapper
{
  GObject parent;

  gchar * name;
  gchar * path;
  GBytes * blob;
  GumPeModule * module;
  GumModuleResolver * resolver;
  GumProcessMemory * target;
  GumMemoryRange range;
  HANDLE section;
  guint64 section_offset;
  GumMemoryRange shared_range;

  GumCpuType cpu_type;
  guint pointer_size;

  gsize vm_size;
  gsize runtime_vm_size;
  gsize runtime_file_size;
  guint tls_callback_count;
  gboolean has_exception_table;

  gpointer runtime;
  guint8 * staging;
  GumAddress runtime_address;
  GumAddress image_address;
  gsize constructor_offset;
  gsize destructor_offset;

  GumAddress entrypoint;
  GArray * tls_callbacks;
  GumAddress function_table;
  guint function_table_count;
  GumAddress add_function_table;
  GumAddress delete_function_table;

  gboolean has_static_tls;
  gboolean tls_via_thread;
  gboolean tls_via_run_once;
  GumAddress tls_entry;
  GumAddress tls_handle;
  GumAddress tls_release;
  GumAddress tls_thunk;
  GumAddress tls_shared_region;
  GumAddress tls_shared_entry;
  GumAddress create_thread;
  GumAddress wait_for_single_object;
  GumAddress close_handle;
  GumAddress tls_thunks;
  GumAddress run_once_execute_once;
  GumAddress virtual_protect;
};

enum
{
  PROP_0,
  PROP_NAME,
  PROP_PATH,
  PROP_BLOB,
  PROP_RESOLVER
};

struct _GumPeResolveContext
{
  GumPeMapper * mapper;
  GHashTable * modules;
  gboolean success;
  GError ** error;
};

struct _GumPeFindWritableContext
{
  guint32 rva;
};

struct _GumPeTlsCollectContext
{
  GumPeMapper * mapper;
  GArray * callbacks;
};

struct _GumPeEnumerateExportsContext
{
  GumFoundExportFunc func;
  gpointer user_data;

  GumPeMapper * mapper;
};

struct _GumPeMatchOrdinalContext
{
  guint16 ordinal;
  guint32 rva;
  gboolean found;
};

struct _GumPeFindSectionContext
{
  guint32 rva;
  GumPageProtection protection;
};

#if defined (HAVE_I386) && GLIB_SIZEOF_VOID_P == 4
struct _GumPeChpeMetadataX86
{
  guint32 version;
  guint32 code_address_range_offset;
  guint32 code_address_range_count;
  guint32 exception_handler_function_pointer;
  guint32 dispatch_call_function_pointer;
  guint32 dispatch_indirect_call_function_pointer;
  guint32 dispatch_indirect_call_cfg_function_pointer;
};
#endif

#if GLIB_SIZEOF_VOID_P == 8 && !defined (HAVE_ARM64)
struct _GumPeX64TlsScanContext
{
  csh cs;
  GumAddress base;
  GumAddress limit;
  GumAddress * handle;
  GumAddress * release;
};

struct _GumPeTlsShared
{
  guint64 magic;
  guint32 used;
  guint32 live;
  guint8 orig[8];
};

struct _GumPeTlsEntry
{
  GumAddress index_slot;
  GumAddress template_start;
  GumAddress template_size;
};

struct _GumPeArm64Thunk
{
  guint32 code[4];
  guint64 target;
};

struct _GumPeTlsThunks
{
  GumPeArm64Thunk handle;
  GumPeArm64Thunk release;
};
#endif

static void gum_pe_mapper_initable_iface_init (gpointer g_iface,
    gpointer iface_data);
static void gum_pe_mapper_iface_init (gpointer g_iface, gpointer iface_data);
static void gum_pe_mapper_dispose (GObject * object);
static void gum_pe_mapper_finalize (GObject * object);
static void gum_pe_mapper_get_property (GObject * object, guint property_id,
    GValue * value, GParamSpec * pspec);
static void gum_pe_mapper_set_property (GObject * object, guint property_id,
    const GValue * value, GParamSpec * pspec);

static gboolean gum_pe_mapper_initable_init (GInitable * initable,
    GCancellable * cancellable, GError ** error);
static void gum_pe_mapper_set_target (GumMapper * mapper,
    GumProcessMemory * target);
static gboolean gum_pe_mapper_map (GumMapper * mapper, gsize extra_size,
    GumAddress * extra_address, GError ** error);
static void gum_pe_mapper_unmap (GumMapper * mapper);
static const GumMemoryRange * gum_pe_mapper_get_range (GumMapper * mapper);
static GumAddress gum_pe_mapper_constructor (GumMapper * mapper);
static GumAddress gum_pe_mapper_destructor (GumMapper * mapper);
static GumAddress gum_pe_mapper_resolve (GumMapper * mapper,
    const gchar * symbol);
static void gum_pe_mapper_enumerate_exports (GumMapper * mapper,
    GumFoundExportFunc func, gpointer user_data);
static void gum_pe_mapper_init_footprint_budget (GumPeMapper * self);
static gboolean gum_count_tls_callback (GumAddress rva, gpointer user_data);
static gboolean gum_pe_mapper_map_shared (GumPeMapper * self,
    gsize extra_vm_size);
static gsize gum_pe_mapper_compute_shareable_size (GumPeMapper * self);
static gboolean gum_find_first_writable_section (
    const GumPeSectionDetails * details, gpointer user_data);
static GumAddress gum_pe_mapper_find_free_range (GumPeMapper * self,
    HANDLE process, gsize size);
static gboolean gum_pe_mapper_try_map_shared_at (GumPeMapper * self,
    HANDLE process, GumAddress base, gsize total_size);
static gboolean gum_pe_mapper_map_private (GumPeMapper * self,
    gsize extra_vm_size);
static void gum_pe_mapper_copy_image (GumPeMapper * self);
static gboolean gum_copy_section (const GumPeSectionDetails * details,
    gpointer user_data);
static gboolean gum_apply_relocation (const GumPeRelocationDetails * details,
    gpointer user_data);
static gboolean gum_resolve_import (const GumPeImportDetails * details,
    gpointer user_data);
static GumAddress gum_pe_mapper_resolve_ordinal (GumPeMapper * self,
    GumModule * module, guint16 ordinal);
static gboolean gum_match_ordinal (const GumPeExportDetails * details,
    gpointer user_data);
static void gum_pe_mapper_init_security_cookie (GumPeMapper * self);
static guint64 gum_generate_security_cookie_64 (void);
static guint32 gum_generate_security_cookie_32 (void);
static gboolean gum_collect_tls_callback (GumAddress rva, gpointer user_data);
static void gum_pe_mapper_prepare_tls (GumPeMapper * self);
static void gum_resolve_loader_tls (void);
#if defined (HAVE_ARM64)
static void gum_resolve_arm64_tls (GumModule * ntdll, GumAddress base,
    GumAddress limit, GumAddress * handle, GumAddress * release);
static gboolean gum_arm64_is_handle_tls_data (cs_insn * insns, size_t count);
static gboolean gum_arm64_is_release_tls_entry (cs_insn * insns, size_t count);
#else
static gboolean gum_is_emulated (void);
static void gum_resolve_arm64_tls_emulated (GumModule * ntdll, GumAddress base,
    GumAddress limit, GumAddress * handle, GumAddress * release);
static gpointer gum_follow_x86_thunk (gpointer fn);
static guint gum_arm64_raw_count_until_exit (const guint32 * code, guint n);
static gboolean gum_arm64_raw_is_handle_tls_data (const guint32 * code,
    guint n);
static gboolean gum_arm64_raw_is_release_tls_entry (const guint32 * code,
    guint n);
static gboolean gum_arm64_raw_parse_mov_reg (guint32 insn, guint * rd,
    guint * rm);
static gboolean gum_arm64_raw_accesses_entry_field (guint32 insn,
    guint32 entry_regs, guint offset);
# if GLIB_SIZEOF_VOID_P == 8
static void gum_resolve_x64_tls (GumPeModule * ntdll, GumAddress base,
    GumAddress limit, GumAddress * handle, GumAddress * release);
static gboolean gum_scan_x64_function (GumAddress rva, gpointer user_data);
# else
static void gum_resolve_wowa64_dispatch_slots (GumPeModule * ntdll,
    GumAddress base);
static void gum_resolve_x86_tls (GumAddress base, GumAddress limit,
    GumAddress * handle, GumAddress * release);
# endif
#endif
#if defined (HAVE_I386)
static gboolean gum_function_is_ldr_handle_tls_data (cs_insn * insns,
    size_t count);
static gboolean gum_function_is_ldr_release_tls_entry (cs_insn * insns,
    size_t count);
# if GLIB_SIZEOF_VOID_P == 4
static void gum_reg_set_update (x86_reg * regs, guint * n, x86_reg dst,
    x86_reg src);
# endif
static gboolean gum_reg_set_contains (const x86_reg * regs, guint n,
    x86_reg reg);
#endif
#if GLIB_SIZEOF_VOID_P == 8 && !defined (HAVE_ARM64)
static GumAddress gum_pe_mapper_emit_tls_thunks (GumPeMapper * self);
static void gum_init_arm64_thunk (GumPeArm64Thunk * thunk, GumAddress target);
static void gum_pe_mapper_install_thread_init_hook (GumPeMapper * self);
static GumAddress gum_pe_mapper_resolve_shared_region (GumPeMapper * self);
static gsize gum_emit_shared_hook (GumPeMapper * self, GumAddress code_address,
    gpointer output);
static void gum_pe_mapper_add_tls_entry (GumPeMapper * self);
static void gum_pe_mapper_restore_thread_init_hook (GumPeMapper * self);
static void gum_pe_mapper_remove_tls_entry (GumPeMapper * self);
static void gum_pe_mapper_patch_target_code (GumPeMapper * self,
    GumAddress address, gconstpointer data, gsize size);
#endif
static void gum_pe_mapper_alloc_and_emit_runtime (GumPeMapper * self);
static void gum_emit_runtime (GumPeMapper * self, gpointer output_buffer,
    GumAddress pc, gsize * size);
#if defined (HAVE_I386) && GLIB_SIZEOF_VOID_P == 8
static void gum_emit_tls_thread_init (GumPeMapper * self, GumX86Writer * cw);
static void gum_emit_tls_thread_release (GumPeMapper * self,
    GumX86Writer * cw);
static void gum_emit_call_on_new_thread (GumPeMapper * self, GumX86Writer * cw,
    GumAddress start, GumAddress parameter);
#elif defined (HAVE_I386)
static void gum_emit_call_via_run_once (GumPeMapper * self,
    GumX86Writer * cw, GumAddress routine);
#endif
static void gum_pe_mapper_commit_image (GumPeMapper * self);
static gboolean gum_protect_section (const GumPeSectionDetails * details,
    gpointer user_data);
#if GLIB_SIZEOF_VOID_P == 8 && !defined (HAVE_ARM64)
static void gum_pe_mapper_get_tls_entry (GumPeMapper * self,
    GumPeTlsEntry * entry);
#endif
static gboolean gum_emit_export (const GumPeExportDetails * details,
    gpointer user_data);
static GumExportType gum_pe_mapper_classify_export (GumPeMapper * self,
    const GumPeExportDetails * details);
static gboolean gum_match_section (const GumPeSectionDetails * details,
    gpointer user_data);
static GumAddress gum_pe_mapper_resolve_export (GumPeMapper * self,
    const GumPeExportDetails * details);

static HANDLE gum_pe_mapper_get_process_handle (GumPeMapper * self);
static void gum_resolve_section_api (void);

static GumCpuType gum_cpu_type_from_pe (GumPeMachine machine);

G_DEFINE_TYPE_WITH_CODE (GumPeMapper,
                         gum_pe_mapper,
                         G_TYPE_OBJECT,
                         G_IMPLEMENT_INTERFACE (G_TYPE_INITABLE,
                             gum_pe_mapper_initable_iface_init)
                         G_IMPLEMENT_INTERFACE (GUM_TYPE_MAPPER,
                             gum_pe_mapper_iface_init))

static GumLdrHandleTlsDataFunc gum_ldr_handle_tls_data;
static GumLdrReleaseTlsEntryFunc gum_ldr_release_tls_entry;
#if defined (HAVE_I386) && GLIB_SIZEOF_VOID_P == 4
static GumAddress gum_dispatch_icall_slot;
static GumAddress gum_dispatch_icall_cfg_slot;
#endif

static GumNtMapViewOfSectionFunc gum_nt_map_view_of_section;
static GumNtUnmapViewOfSectionFunc gum_nt_unmap_view_of_section;

static void
gum_pe_mapper_class_init (GumPeMapperClass * klass)
{
  GObjectClass * object_class = G_OBJECT_CLASS (klass);

  object_class->dispose = gum_pe_mapper_dispose;
  object_class->finalize = gum_pe_mapper_finalize;
  object_class->get_property = gum_pe_mapper_get_property;
  object_class->set_property = gum_pe_mapper_set_property;

  g_object_class_install_property (object_class, PROP_NAME,
      g_param_spec_string ("name", "Name", "Name", NULL,
      G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY | G_PARAM_STATIC_STRINGS));
  g_object_class_install_property (object_class, PROP_PATH,
      g_param_spec_string ("path", "Path", "Path", NULL,
      G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY | G_PARAM_STATIC_STRINGS));
  g_object_class_install_property (object_class, PROP_BLOB,
      g_param_spec_boxed ("blob", "Blob", "Blob", G_TYPE_BYTES,
      G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY | G_PARAM_STATIC_STRINGS));
  g_object_class_install_property (object_class, PROP_RESOLVER,
      g_param_spec_object ("resolver", "Resolver", "Module resolver",
      GUM_TYPE_MODULE_RESOLVER, G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY |
      G_PARAM_STATIC_STRINGS));
}

static void
gum_pe_mapper_initable_iface_init (gpointer g_iface,
                                   gpointer iface_data)
{
  GInitableIface * iface = g_iface;

  iface->init = gum_pe_mapper_initable_init;
}

static void
gum_pe_mapper_iface_init (gpointer g_iface,
                          gpointer iface_data)
{
  GumMapperInterface * iface = g_iface;

  iface->set_target = gum_pe_mapper_set_target;
  iface->map = gum_pe_mapper_map;
  iface->unmap = gum_pe_mapper_unmap;
  iface->get_range = gum_pe_mapper_get_range;
  iface->constructor = gum_pe_mapper_constructor;
  iface->destructor = gum_pe_mapper_destructor;
  iface->resolve = gum_pe_mapper_resolve;
  iface->enumerate_exports = gum_pe_mapper_enumerate_exports;
}

static void
gum_pe_mapper_init (GumPeMapper * self)
{
  self->tls_callbacks = g_array_new (FALSE, FALSE, sizeof (GumAddress));
  self->target =
      GUM_PROCESS_MEMORY (gum_native_process_memory_new_local ());
}

static void
gum_pe_mapper_dispose (GObject * object)
{
  GumPeMapper * self = GUM_PE_MAPPER (object);

  g_clear_object (&self->target);
  g_clear_object (&self->resolver);
  g_clear_object (&self->module);

  G_OBJECT_CLASS (gum_pe_mapper_parent_class)->dispose (object);
}

static void
gum_pe_mapper_finalize (GObject * object)
{
  GumPeMapper * self = GUM_PE_MAPPER (object);

  g_array_unref (self->tls_callbacks);
  g_free (self->staging);
  g_free (self->runtime);
  g_clear_pointer (&self->blob, g_bytes_unref);
  g_free (self->path);
  g_free (self->name);

  G_OBJECT_CLASS (gum_pe_mapper_parent_class)->finalize (object);
}

static void
gum_pe_mapper_get_property (GObject * object,
                            guint property_id,
                            GValue * value,
                            GParamSpec * pspec)
{
  GumPeMapper * self = GUM_PE_MAPPER (object);

  switch (property_id)
  {
    case PROP_NAME:
      g_value_set_string (value, self->name);
      break;
    case PROP_PATH:
      g_value_set_string (value, self->path);
      break;
    case PROP_BLOB:
      g_value_set_boxed (value, self->blob);
      break;
    case PROP_RESOLVER:
      g_value_set_object (value, self->resolver);
      break;
    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, property_id, pspec);
  }
}

static void
gum_pe_mapper_set_property (GObject * object,
                            guint property_id,
                            const GValue * value,
                            GParamSpec * pspec)
{
  GumPeMapper * self = GUM_PE_MAPPER (object);

  switch (property_id)
  {
    case PROP_NAME:
      g_free (self->name);
      self->name = g_value_dup_string (value);
      break;
    case PROP_PATH:
      g_free (self->path);
      self->path = g_value_dup_string (value);
      break;
    case PROP_BLOB:
      g_clear_pointer (&self->blob, g_bytes_unref);
      self->blob = g_value_dup_boxed (value);
      break;
    case PROP_RESOLVER:
      g_clear_object (&self->resolver);
      self->resolver = g_value_dup_object (value);
      break;
    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, property_id, pspec);
  }
}

GumMapper *
gum_mapper_new_from_file (const gchar * path,
                          GumModuleResolver * resolver,
                          GError ** error)
{
  return g_initable_new (GUM_TYPE_PE_MAPPER, NULL, error,
      "name", path,
      "path", path,
      "resolver", resolver,
      NULL);
}

GumMapper *
gum_mapper_new_take_blob (const gchar * name,
                          GBytes * blob,
                          GumModuleResolver * resolver,
                          GError ** error)
{
  GumMapper * mapper;

  mapper = g_initable_new (GUM_TYPE_PE_MAPPER, NULL, error,
      "name", name,
      "blob", blob,
      "resolver", resolver,
      NULL);
  g_bytes_unref (blob);

  return mapper;
}

static gboolean
gum_pe_mapper_initable_init (GInitable * initable,
                             GCancellable * cancellable,
                             GError ** error)
{
  GumPeMapper * self = GUM_PE_MAPPER (initable);

  self->module = (self->path != NULL)
      ? gum_pe_module_new_from_file (self->path, error)
      : gum_pe_module_new_from_blob (self->blob, error);
  if (self->module == NULL)
    return FALSE;

  self->cpu_type =
      gum_cpu_type_from_pe (gum_pe_module_get_machine (self->module));
  self->pointer_size = gum_pe_module_get_pointer_size (self->module);

  return TRUE;
}

static void
gum_pe_mapper_set_target (GumMapper * mapper,
                          GumProcessMemory * target)
{
  GumPeMapper * self = GUM_PE_MAPPER (mapper);

  g_set_object (&self->target, target);
}

static gboolean
gum_pe_mapper_map (GumMapper * mapper,
                   gsize extra_size,
                   GumAddress * extra_address,
                   GError ** error)
{
  GumPeMapper * self = GUM_PE_MAPPER (mapper);
  GumPeModule * module = self->module;
  gsize extra_vm_size;
  gboolean shared;
  GumPeResolveContext ctx;
  guint32 entrypoint_rva;
  GumPeTlsCollectContext tls_ctx;
  const GumPeDataDirectory * exception;

  gum_pe_mapper_init_footprint_budget (self);

  extra_vm_size = GUM_ALIGN_SIZE (extra_size, gum_query_page_size ());

  shared = GUM_IS_NATIVE_PROCESS_MEMORY (self->target) &&
      gum_pe_mapper_map_shared (self, extra_vm_size);
  if (!shared && !gum_pe_mapper_map_private (self, extra_vm_size))
    goto alloc_failed;
  if (extra_address != NULL)
    *extra_address = self->runtime_address + self->runtime_vm_size;

  self->staging = g_malloc0 (self->vm_size);

  gum_pe_mapper_copy_image (self);

  gum_pe_module_enumerate_relocations (module, gum_apply_relocation, self);

  ctx.mapper = self;
  ctx.modules = g_hash_table_new_full (g_str_hash, g_str_equal, g_free,
      g_object_unref);
  ctx.success = TRUE;
  ctx.error = error;
  gum_pe_module_enumerate_imports (module, gum_resolve_import, &ctx);
  g_hash_table_unref (ctx.modules);
  if (!ctx.success)
    goto import_failed;

  gum_pe_mapper_init_security_cookie (self);

  entrypoint_rva = gum_pe_module_get_entrypoint (module);
  self->entrypoint = (entrypoint_rva != 0)
      ? self->image_address + entrypoint_rva
      : 0;

  tls_ctx.mapper = self;
  tls_ctx.callbacks = self->tls_callbacks;
  gum_pe_module_enumerate_tls_callbacks (module, gum_collect_tls_callback,
      &tls_ctx);

  exception = gum_pe_module_get_directory (module, GUM_PE_DIRECTORY_EXCEPTION);
  if (exception->size != 0 && self->pointer_size == 8)
  {
    self->function_table = self->image_address + exception->rva;
    self->function_table_count = gum_pe_module_get_function_count (module);
    self->add_function_table = gum_module_resolver_find_dynamic_address (
        self->resolver, "RtlAddFunctionTable");
    self->delete_function_table = gum_module_resolver_find_dynamic_address (
        self->resolver, "RtlDeleteFunctionTable");
  }

  gum_pe_mapper_prepare_tls (self);
#if GLIB_SIZEOF_VOID_P == 8 && !defined (HAVE_ARM64)
  if (self->tls_via_thread)
    gum_pe_mapper_install_thread_init_hook (self);
#endif

  gum_pe_mapper_alloc_and_emit_runtime (self);

  memcpy (GUM_PE_STAGED (self, self->runtime_address), self->runtime,
      self->runtime_file_size);

  gum_process_memory_write (self->target, self->runtime_address,
      GUM_PE_STAGED (self, self->runtime_address), self->runtime_vm_size);
  gum_pe_mapper_commit_image (self);

  gum_pe_module_enumerate_sections (module, gum_protect_section, self);

  gum_process_memory_mark_code (self->target, self->runtime_address,
      self->runtime_vm_size);

  g_clear_pointer (&self->staging, g_free);

  return TRUE;

alloc_failed:
  {
    g_set_error (error, GUM_ERROR, GUM_ERROR_FAILED,
        "Unable to allocate target memory");
    return FALSE;
  }
import_failed:
  {
    g_clear_pointer (&self->staging, g_free);
    gum_pe_mapper_unmap (GUM_MAPPER (self));
    return FALSE;
  }
}

static void
gum_pe_mapper_unmap (GumMapper * mapper)
{
  GumPeMapper * self = GUM_PE_MAPPER (mapper);

#if GLIB_SIZEOF_VOID_P == 8 && !defined (HAVE_ARM64)
  if (self->tls_via_thread)
  {
    gum_pe_mapper_restore_thread_init_hook (self);
    gum_process_memory_free (self->target, self->tls_thunks,
        gum_query_page_size ());
  }
#endif

  gum_process_memory_free (self->target, self->tls_entry,
      GUM_PE_LOADER_ENTRY_SIZE);
  self->tls_entry = 0;

  if (self->shared_range.size != 0)
  {
    HANDLE process = gum_pe_mapper_get_process_handle (self);

    gum_nt_unmap_view_of_section (process,
        GSIZE_TO_POINTER (self->shared_range.base_address));
    VirtualFreeEx (process, GSIZE_TO_POINTER (self->shared_range.base_address +
        self->shared_range.size), 0, MEM_RELEASE);

    self->shared_range.base_address = 0;
    self->shared_range.size = 0;
  }
  else
  {
    gum_process_memory_free (self->target, self->range.base_address,
        self->range.size);
  }
  self->range.base_address = 0;
  self->range.size = 0;
}

static const GumMemoryRange *
gum_pe_mapper_get_range (GumMapper * mapper)
{
  GumPeMapper * self = GUM_PE_MAPPER (mapper);

  return &self->range;
}

static GumAddress
gum_pe_mapper_constructor (GumMapper * mapper)
{
  GumPeMapper * self = GUM_PE_MAPPER (mapper);

  return self->runtime_address + self->constructor_offset;
}

static GumAddress
gum_pe_mapper_destructor (GumMapper * mapper)
{
  GumPeMapper * self = GUM_PE_MAPPER (mapper);

  return self->runtime_address + self->destructor_offset;
}

static GumAddress
gum_pe_mapper_resolve (GumMapper * mapper,
                       const gchar * symbol)
{
  GumPeMapper * self = GUM_PE_MAPPER (mapper);
  GumPeExportDetails details;

  if (!gum_pe_module_find_export_by_name (self->module, symbol, &details))
    return 0;

  return gum_pe_mapper_resolve_export (self, &details);
}

static void
gum_pe_mapper_enumerate_exports (GumMapper * mapper,
                                 GumFoundExportFunc func,
                                 gpointer user_data)
{
  GumPeMapper * self = GUM_PE_MAPPER (mapper);
  GumPeEnumerateExportsContext ctx;

  ctx.func = func;
  ctx.user_data = user_data;
  ctx.mapper = self;

  gum_pe_module_enumerate_exports (self->module, gum_emit_export, &ctx);
}

static void
gum_pe_mapper_init_footprint_budget (GumPeMapper * self)
{
  GumPeModule * module = self->module;
  guint page_size = gum_query_page_size ();
  gsize image_vm_size;
  gsize runtime_size;

  image_vm_size =
      GUM_ALIGN_SIZE (gum_pe_module_get_size_of_image (module), page_size);

  self->tls_callback_count = 0;
  gum_pe_module_enumerate_tls_callbacks (module, gum_count_tls_callback, self);

  self->has_exception_table =
      gum_pe_module_get_directory (module, GUM_PE_DIRECTORY_EXCEPTION)->size
      != 0;

  self->has_static_tls =
      gum_pe_module_get_directory (module, GUM_PE_DIRECTORY_TLS)->size != 0;

  runtime_size = GUM_PE_MAPPER_CODE_BASE_SIZE +
      (2 * self->tls_callback_count * GUM_PE_MAPPER_TLS_CALL_SIZE) +
      GUM_PE_MAPPER_ENTRY_CALL_SIZE;
  if (self->has_exception_table && self->pointer_size == 8)
    runtime_size += 2 * GUM_PE_MAPPER_UNWIND_SIZE;
  if (self->has_static_tls)
    runtime_size += 4 * GUM_PE_MAPPER_TLS_CALL_SIZE;

  self->runtime_file_size = runtime_size;
  self->runtime_vm_size = GUM_ALIGN_SIZE (runtime_size, page_size);

  self->vm_size = image_vm_size + self->runtime_vm_size;
}

static gboolean
gum_count_tls_callback (GumAddress rva,
                        gpointer user_data)
{
  GumPeMapper * self = user_data;

  self->tls_callback_count++;

  return TRUE;
}

static gboolean
gum_pe_mapper_map_shared (GumPeMapper * self,
                          gsize extra_vm_size)
{
  gconstpointer data;
  gsize blob_size, shared_size, total_size;
  HANDLE process;
  guint attempt;

  data = g_bytes_get_data (gum_pe_module_get_source_blob (self->module),
      &blob_size);
  if (!_gum_windows_find_section_view (data, &self->section,
      &self->section_offset))
  {
    return FALSE;
  }
  if (self->section_offset % GUM_PE_ALLOCATION_GRANULARITY != 0)
    return FALSE;

  shared_size = MIN (gum_pe_mapper_compute_shareable_size (self),
      blob_size & ~(GUM_PE_ALLOCATION_GRANULARITY - 1));
  if (shared_size == 0)
    return FALSE;
  self->shared_range.size = shared_size;

  total_size = self->vm_size + extra_vm_size;

  gum_resolve_section_api ();

  process = gum_pe_mapper_get_process_handle (self);

  if (gum_pe_mapper_try_map_shared_at (self, process,
      gum_pe_module_get_image_base (self->module), total_size))
  {
    return TRUE;
  }

  for (attempt = 0; attempt != GUM_PE_MAX_PLACEMENT_ATTEMPTS; attempt++)
  {
    GumAddress base;

    base = gum_pe_mapper_find_free_range (self, process, total_size);
    if (base == 0)
      break;

    if (gum_pe_mapper_try_map_shared_at (self, process, base, total_size))
      return TRUE;
  }

  self->shared_range.size = 0;

  return FALSE;
}

static gsize
gum_pe_mapper_compute_shareable_size (GumPeMapper * self)
{
  GumPeFindWritableContext ctx;

  ctx.rva = G_MAXUINT32;
  gum_pe_module_enumerate_sections (self->module,
      gum_find_first_writable_section, &ctx);

  return MIN (ctx.rva, self->vm_size - self->runtime_vm_size) &
      ~(GUM_PE_ALLOCATION_GRANULARITY - 1);
}

static gboolean
gum_find_first_writable_section (const GumPeSectionDetails * details,
                                 gpointer user_data)
{
  GumPeFindWritableContext * ctx = user_data;

  if ((details->protection & GUM_PAGE_WRITE) != 0)
    ctx->rva = MIN (ctx->rva, details->virtual_address);

  return TRUE;
}

static GumAddress
gum_pe_mapper_find_free_range (GumPeMapper * self,
                               HANDLE process,
                               gsize size)
{
  gpointer base;

  base = VirtualAllocEx (process, NULL, size, MEM_RESERVE, PAGE_NOACCESS);
  if (base == NULL)
    return 0;

  VirtualFreeEx (process, base, 0, MEM_RELEASE);

  return GUM_ADDRESS (base);
}

static gboolean
gum_pe_mapper_try_map_shared_at (GumPeMapper * self,
                                 HANDLE process,
                                 GumAddress base,
                                 gsize total_size)
{
  gsize shared_size = self->shared_range.size;
  PVOID view;
  LARGE_INTEGER offset;
  SIZE_T view_size;

  view = GSIZE_TO_POINTER (base);
  offset.QuadPart = self->section_offset;
  view_size = shared_size;
  if (gum_nt_map_view_of_section (self->section, process, &view, 0, 0,
      &offset, &view_size, GUM_PE_VIEW_UNMAP, 0, PAGE_EXECUTE_WRITECOPY) < 0)
  {
    return FALSE;
  }

  if (VirtualAllocEx (process, GSIZE_TO_POINTER (base + shared_size),
      total_size - shared_size, MEM_RESERVE | MEM_COMMIT,
      PAGE_READWRITE) == NULL)
  {
    gum_nt_unmap_view_of_section (process, view);
    return FALSE;
  }

  self->range.base_address = base;
  self->range.size = total_size;
  self->shared_range.base_address = base;
  self->image_address = base;
  self->runtime_address = base + (self->vm_size - self->runtime_vm_size);

  return TRUE;
}

static gboolean
gum_pe_mapper_map_private (GumPeMapper * self,
                           gsize extra_vm_size)
{
  GumAddress base_address;

  base_address = gum_process_memory_alloc (self->target,
      self->vm_size + extra_vm_size, gum_query_page_size ());
  if (base_address == 0)
    return FALSE;

  self->range.base_address = base_address;
  self->range.size = self->vm_size + extra_vm_size;
  self->image_address = base_address;
  self->runtime_address = base_address +
      (self->vm_size - self->runtime_vm_size);

  return TRUE;
}

static void
gum_pe_mapper_copy_image (GumPeMapper * self)
{
  GumPeModule * module = self->module;
  guint8 * image = GUM_PE_STAGED (self, self->image_address);

  memcpy (image, gum_pe_module_get_data_at_rva (module, 0),
      gum_pe_module_get_size_of_headers (module));

  gum_pe_module_enumerate_sections (module, gum_copy_section, self);
}

static gboolean
gum_copy_section (const GumPeSectionDetails * details,
                  gpointer user_data)
{
  GumPeMapper * self = user_data;
  gconstpointer source;
  guint8 * image = GUM_PE_STAGED (self, self->image_address);

  if (details->raw_data_size == 0)
    return TRUE;

  source = gum_pe_module_get_data_at_rva (self->module,
      details->virtual_address);
  memcpy (image + details->virtual_address, source, details->raw_data_size);

  return TRUE;
}

static gboolean
gum_apply_relocation (const GumPeRelocationDetails * details,
                      gpointer user_data)
{
  GumPeMapper * self = user_data;
  guint64 delta = self->image_address - gum_pe_module_get_image_base (
      self->module);
  guint8 * target = GUM_PE_STAGED (self, self->image_address + details->rva);

  switch (details->type)
  {
    case GUM_PE_RELOCATION_DIR64:
      *((guint64 *) target) += delta;
      break;
    case GUM_PE_RELOCATION_HIGHLOW:
      *((guint32 *) target) += delta;
      break;
    case GUM_PE_RELOCATION_HIGH:
      *((guint16 *) target) += delta >> 16;
      break;
    case GUM_PE_RELOCATION_LOW:
      *((guint16 *) target) += delta & 0xffff;
      break;
    default:
      break;
  }

  return TRUE;
}

static gboolean
gum_resolve_import (const GumPeImportDetails * details,
                    gpointer user_data)
{
  GumPeResolveContext * ctx = user_data;
  GumModule * module;
  GumPeMapper * self = ctx->mapper;
  GumAddress address;

  module = g_hash_table_lookup (ctx->modules, details->module_name);
  if (module == NULL)
  {
    module = gum_module_resolver_find_module_by_name (self->resolver,
        details->module_name);
    if (module != NULL)
    {
      g_hash_table_insert (ctx->modules, g_strdup (details->module_name),
          module);
    }
  }

  address = 0;
  if (module != NULL)
  {
    address = (details->type == GUM_PE_IMPORT_BY_NAME)
        ? gum_module_find_export_by_name (module, details->name)
        : gum_pe_mapper_resolve_ordinal (self, module, details->ordinal);
  }

  if (address == 0 && details->type == GUM_PE_IMPORT_BY_NAME)
  {
    address = gum_module_resolver_find_dynamic_address (self->resolver,
        details->name);
  }

  if (address == 0)
    goto missing_symbol;

  if (self->pointer_size == 8)
  {
    *((guint64 *) GUM_PE_STAGED (self, self->image_address + details->slot_rva))
        = address;
  }
  else
  {
    *((guint32 *) GUM_PE_STAGED (self, self->image_address + details->slot_rva))
        = address;
  }

  return TRUE;

missing_symbol:
  {
    if (details->type == GUM_PE_IMPORT_BY_NAME)
    {
      g_set_error (ctx->error, GUM_ERROR, GUM_ERROR_NOT_FOUND,
          "Unable to resolve “%s” from “%s”", details->name,
          details->module_name);
    }
    else
    {
      g_set_error (ctx->error, GUM_ERROR, GUM_ERROR_NOT_FOUND,
          "Unable to resolve ordinal %u from “%s”", details->ordinal,
          details->module_name);
    }
    ctx->success = FALSE;
    return FALSE;
  }
}

static GumAddress
gum_pe_mapper_resolve_ordinal (GumPeMapper * self,
                               GumModule * module,
                               guint16 ordinal)
{
  GumAddress result = 0;
  const GumMemoryRange * range = gum_module_get_range (module);
  GumPeModule * dependency;
  GumPeMatchOrdinalContext ctx;

  dependency = gum_pe_module_new_from_memory (range->base_address, NULL);
  if (dependency == NULL)
    return 0;

  ctx.ordinal = ordinal;
  ctx.rva = 0;
  ctx.found = FALSE;
  gum_pe_module_enumerate_exports (dependency, gum_match_ordinal, &ctx);

  if (ctx.found)
    result = range->base_address + ctx.rva;

  g_object_unref (dependency);

  return result;
}

static gboolean
gum_match_ordinal (const GumPeExportDetails * details,
                   gpointer user_data)
{
  GumPeMatchOrdinalContext * ctx = user_data;

  if (details->type != GUM_PE_EXPORT_REGULAR ||
      details->ordinal != ctx->ordinal)
    return TRUE;

  ctx->rva = details->rva;
  ctx->found = TRUE;

  return FALSE;
}

static void
gum_pe_mapper_init_security_cookie (GumPeMapper * self)
{
  guint32 rva;
  gpointer cookie;

  rva = gum_pe_module_get_security_cookie_rva (self->module);
  if (rva == 0)
    return;

  cookie = GUM_PE_STAGED (self, self->image_address + rva);
  if (self->pointer_size == 8)
    *((guint64 *) cookie) = gum_generate_security_cookie_64 ();
  else
    *((guint32 *) cookie) = gum_generate_security_cookie_32 ();
}

static guint64
gum_generate_security_cookie_64 (void)
{
  guint64 cookie;

  do
  {
    cookie = (((guint64) g_random_int () << 32) | g_random_int ()) &
        GUM_PE_COOKIE_MASK_64;
  }
  while (cookie == 0 || cookie == GUM_PE_DEFAULT_COOKIE_64);

  return cookie;
}

static guint32
gum_generate_security_cookie_32 (void)
{
  guint32 cookie;

  do
  {
    cookie = g_random_int ();
  }
  while ((cookie & 0xffff0000) == 0 ||
      cookie == GUM_PE_DEFAULT_COOKIE_32);

  return cookie;
}

static gboolean
gum_collect_tls_callback (GumAddress rva,
                          gpointer user_data)
{
  GumPeTlsCollectContext * ctx = user_data;
  GumAddress address = ctx->mapper->image_address + rva;

  g_array_append_val (ctx->callbacks, address);

  return TRUE;
}

static void
gum_pe_mapper_prepare_tls (GumPeMapper * self)
{
  const GumPeDataDirectory * tls =
      gum_pe_module_get_directory (self->module, GUM_PE_DIRECTORY_TLS);
  GumAddress dll_base;

  if (tls->size == 0)
    return;

  gum_resolve_loader_tls ();

  self->has_static_tls = TRUE;
  self->tls_handle = GUM_ADDRESS (gum_ldr_handle_tls_data);
  self->tls_release = GUM_ADDRESS (gum_ldr_release_tls_entry);
#if GLIB_SIZEOF_VOID_P == 8 && !defined (HAVE_ARM64)
  self->tls_via_thread = gum_is_emulated ();
  if (self->tls_via_thread)
  {
    self->create_thread = gum_module_resolver_find_dynamic_address (
        self->resolver, "CreateThread");
    self->wait_for_single_object = gum_module_resolver_find_dynamic_address (
        self->resolver, "WaitForSingleObject");
    self->close_handle = gum_module_resolver_find_dynamic_address (
        self->resolver, "CloseHandle");
    self->tls_thunks = gum_pe_mapper_emit_tls_thunks (self);
  }
#elif defined (HAVE_I386)
  self->tls_via_run_once = gum_is_emulated ();
  if (self->tls_via_run_once)
  {
    self->run_once_execute_once = gum_module_resolver_find_dynamic_address (
        self->resolver, "RtlRunOnceExecuteOnce");
    self->virtual_protect = gum_module_resolver_find_dynamic_address (
        self->resolver, "VirtualProtect");
  }
#else
  self->tls_via_thread = FALSE;
#endif
  self->tls_entry = gum_process_memory_alloc (self->target,
      GUM_PE_LOADER_ENTRY_SIZE, gum_query_page_size ());

  dll_base = self->image_address;
  gum_process_memory_write (self->target,
      self->tls_entry + GUM_PE_LOADER_ENTRY_DLL_BASE_OFFSET, &dll_base,
      self->pointer_size);
}

static void
gum_resolve_loader_tls (void)
{
  static gsize initialized = 0;

  if (g_once_init_enter (&initialized))
  {
    GumNativeModule * ntdll;
    const GumMemoryRange * range;
    GumAddress base, limit, handle = 0, release = 0;

    ntdll = _gum_native_module_make (GetModuleHandleW (L"ntdll.dll"));
    range = gum_module_get_range (GUM_MODULE (ntdll));
    base = range->base_address;
    limit = base + range->size;

#if defined (HAVE_ARM64)
    gum_resolve_arm64_tls (GUM_MODULE (ntdll), base, limit, &handle, &release);
#else
    if (gum_is_emulated ())
    {
      gum_resolve_arm64_tls_emulated (GUM_MODULE (ntdll), base, limit, &handle,
          &release);
# if GLIB_SIZEOF_VOID_P == 4
      gum_resolve_wowa64_dispatch_slots (
          _gum_native_module_get_pe_module (ntdll), base);
# endif
    }
    else
    {
# if GLIB_SIZEOF_VOID_P == 8
      gum_resolve_x64_tls (_gum_native_module_get_pe_module (ntdll), base,
          limit, &handle, &release);
# else
      gum_resolve_x86_tls (base, limit, &handle, &release);
# endif
    }
#endif

    g_object_unref (ntdll);

    if (handle == 0 || release == 0)
      g_error ("Unable to locate the ntdll loader TLS routines");
    gum_ldr_handle_tls_data = GSIZE_TO_POINTER (handle);
    gum_ldr_release_tls_entry = GSIZE_TO_POINTER (release);

    g_once_init_leave (&initialized, 1);
  }
}

#if defined (HAVE_ARM64)

static void
gum_resolve_arm64_tls (GumModule * ntdll,
                       GumAddress base,
                       GumAddress limit,
                       GumAddress * handle,
                       GumAddress * release)
{
  csh cs;
  GHashTable * visited;
  guint i;
  const gchar * anchors[] = { "LdrLoadDll", "LdrUnloadDll" };
  GQueue queue = G_QUEUE_INIT;
  guint budget = 0;

  cs_arch_register_arm64 ();
  cs_open (CS_ARCH_ARM64, GUM_DEFAULT_CS_ENDIAN, &cs);
  cs_option (cs, CS_OPT_DETAIL, CS_OPT_ON);
  cs_option (cs, CS_OPT_SKIPDATA, CS_OPT_ON);

  visited = g_hash_table_new (NULL, NULL);
  for (i = 0; i != G_N_ELEMENTS (anchors); i++)
  {
    gpointer a = GSIZE_TO_POINTER (
        gum_module_find_export_by_name (ntdll, anchors[i]));

    g_hash_table_add (visited, a);
    g_queue_push_tail (&queue, a);
  }

  while (!g_queue_is_empty (&queue) && (*handle == 0 || *release == 0) &&
      budget++ != 100000)
  {
    GumAddress fn = GPOINTER_TO_SIZE (g_queue_pop_head (&queue));
    cs_insn * insns;
    size_t n, scan, j;

    n = cs_disasm (cs, GSIZE_TO_POINTER (fn), MIN (1024, limit - fn), fn, 0,
        &insns);
    if (n == 0)
      continue;

    scan = MIN (n, 48);
    if (*handle == 0 && gum_arm64_is_handle_tls_data (insns, scan))
      *handle = fn;
    if (*release == 0 && gum_arm64_is_release_tls_entry (insns, scan))
      *release = fn;

    for (j = 0; j != n; j++)
    {
      cs_insn * in = &insns[j];
      GumAddress target;

      if (in->id != ARM64_INS_BL)
        continue;
      target = in->detail->arm64.operands[0].imm;
      if (target < base || target >= limit)
        continue;
      if (g_hash_table_add (visited, GSIZE_TO_POINTER (target)))
        g_queue_push_tail (&queue, GSIZE_TO_POINTER (target));
    }

    cs_free (insns, n);
  }

  g_hash_table_unref (visited);
  g_queue_clear (&queue);
  cs_close (&cs);
}

static gboolean
gum_arm64_is_handle_tls_data (cs_insn * insns,
                              size_t count)
{
  size_t i;
  gboolean checked_flag = FALSE, read_dll_base = FALSE;

  for (i = 0; i != count; i++)
  {
    cs_arm64 * d = &insns[i].detail->arm64;
    size_t k;

    if (!(insns[i].id == ARM64_INS_LDR && d->op_count >= 2 &&
        d->operands[1].type == ARM64_OP_MEM &&
        d->operands[1].mem.base == ARM64_REG_X0))
    {
      continue;
    }

    if (d->operands[1].mem.disp == GUM_PE_LOADER_ENTRY_DLL_BASE_OFFSET)
      read_dll_base = TRUE;

    if (d->operands[1].mem.disp != GUM_PE_LDR_TLS_FLAGS_FIELD)
      continue;

    for (k = i + 1; k != count && k != i + 6; k++)
    {
      cs_arm64 * c = &insns[k].detail->arm64;
      cs_arm64_op * last;

      if (insns[k].id != ARM64_INS_CMP && insns[k].id != ARM64_INS_SUBS)
        continue;
      if (c->op_count < 2)
        continue;

      last = &c->operands[c->op_count - 1];
      if (last->type == ARM64_OP_IMM && last->imm == 9)
        checked_flag = TRUE;
    }
  }

  return checked_flag && read_dll_base;
}

static gboolean
gum_arm64_is_release_tls_entry (cs_insn * insns,
                                size_t count)
{
  size_t i;
  gboolean saved_entry = FALSE, saved_flags = FALSE, branches_on_flags = FALSE;

  for (i = 0; i != count; i++)
  {
    cs_arm64 * d = &insns[i].detail->arm64;

    if (insns[i].id == ARM64_INS_MOV && d->op_count == 2 &&
        d->operands[0].type == ARM64_OP_REG &&
        d->operands[1].type == ARM64_OP_REG)
    {
      if (d->operands[0].reg == ARM64_REG_X19 &&
          d->operands[1].reg == ARM64_REG_X0)
        saved_entry = TRUE;
      if (d->operands[0].reg == ARM64_REG_X20 &&
          d->operands[1].reg == ARM64_REG_X1)
        saved_flags = TRUE;
    }

    if (insns[i].id == ARM64_INS_CBNZ && d->op_count >= 1 &&
        d->operands[0].type == ARM64_OP_REG &&
        d->operands[0].reg == ARM64_REG_X20)
      branches_on_flags = TRUE;
  }

  return saved_entry && saved_flags && branches_on_flags;
}

#else

static gboolean
gum_is_emulated (void)
{
  GumIsWow64Process2Func is_wow64_process2;
  USHORT process_machine = 0, native_machine = 0;

  is_wow64_process2 = (GumIsWow64Process2Func) GetProcAddress (
      GetModuleHandleW (L"kernel32.dll"), "IsWow64Process2");
  if (is_wow64_process2 == NULL)
    return FALSE;

  if (!is_wow64_process2 (GetCurrentProcess (), &process_machine,
      &native_machine))
    return FALSE;

  return native_machine == IMAGE_FILE_MACHINE_ARM64;
}

static void
gum_resolve_arm64_tls_emulated (GumModule * ntdll,
                                GumAddress base,
                                GumAddress limit,
                                GumAddress * handle,
                                GumAddress * release)
{
  GHashTable * visited;
  guint i;
  const gchar * anchors[] = { "LdrLoadDll", "LdrUnloadDll" };
  GQueue queue = G_QUEUE_INIT;
  guint budget = 0;

  visited = g_hash_table_new (NULL, NULL);
  for (i = 0; i != G_N_ELEMENTS (anchors); i++)
  {
    gpointer a = gum_follow_x86_thunk (GSIZE_TO_POINTER (
        gum_module_find_export_by_name (ntdll, anchors[i])));

    g_hash_table_add (visited, a);
    g_queue_push_tail (&queue, a);
  }

  while (!g_queue_is_empty (&queue) && (*handle == 0 || *release == 0) &&
      budget++ != 100000)
  {
    GumAddress fn = GPOINTER_TO_SIZE (g_queue_pop_head (&queue));
    guint n, scan, j;
    const guint32 * code = GSIZE_TO_POINTER (fn);

    if (fn < base || fn >= limit)
      continue;

    n = MIN (1024, (guint) ((limit - fn) / sizeof (guint32)));
    scan = gum_arm64_raw_count_until_exit (code, MIN (n, 48));

    if (*handle == 0 && gum_arm64_raw_is_handle_tls_data (code, scan))
      *handle = fn;
    if (*release == 0 && gum_arm64_raw_is_release_tls_entry (code, scan))
      *release = fn;

    for (j = 0; j != n; j++)
    {
      guint32 insn = code[j];
      gint64 imm;
      GumAddress target;

      if ((insn & 0xfc000000) != 0x94000000)
        continue;

      imm = insn & 0x3ffffff;
      if ((imm & 0x2000000) != 0)
        imm |= ~((gint64) 0x3ffffff);
      target = fn + (j * sizeof (guint32)) + (imm * 4);
      if (target < base || target >= limit)
        continue;
      if (g_hash_table_add (visited, GSIZE_TO_POINTER (target)))
        g_queue_push_tail (&queue, GSIZE_TO_POINTER (target));
    }
  }

  g_hash_table_unref (visited);
  g_queue_clear (&queue);
}

static gpointer
gum_follow_x86_thunk (gpointer fn)
{
  guint8 * p = fn;
  guint i;

  for (i = 0; i != 24; i++)
  {
    if (p[i] == 0xe9)
    {
      gint32 rel = *((gint32 *) (p + i + 1));

      return p + i + 5 + rel;
    }
  }

  return fn;
}

static guint
gum_arm64_raw_count_until_exit (const guint32 * code,
                                guint n)
{
  guint i;

  for (i = 0; i != n; i++)
  {
    if (code[i] == GUM_ARM64_RET || (code[i] & 0xfc000000) == 0x14000000)
      return i + 1;
  }

  return n;
}

static gboolean
gum_arm64_raw_is_handle_tls_data (const guint32 * code,
                                  guint n)
{
  guint i;
  guint32 entry_regs = 1 << 0;
  gboolean checked_flag = FALSE, read_dll_base = FALSE,
      queries_tls_directory = FALSE;

  for (i = 0; i != n; i++)
  {
    guint rd, rm, k;

    if (gum_arm64_raw_parse_mov_reg (code[i], &rd, &rm) &&
        (entry_regs & (1 << rm)) != 0)
      entry_regs |= 1 << rd;

    if (code[i] == GUM_ARM64_MOV_W2_TLS_DIRECTORY)
      queries_tls_directory = TRUE;

    if (gum_arm64_raw_accesses_entry_field (code[i], entry_regs,
        GUM_PE_LOADER_ENTRY_DLL_BASE_OFFSET))
      read_dll_base = TRUE;

    if (!gum_arm64_raw_accesses_entry_field (code[i], entry_regs,
        GUM_PE_LDR_TLS_FLAGS_FIELD))
      continue;

    for (k = i + 1; k != n && k != i + 6; k++)
    {
      if ((code[k] & 0x7f000000) == 0x71000000 &&
          ((code[k] >> 10) & 0xfff) == 9)
        checked_flag = TRUE;
    }
  }

  return checked_flag && read_dll_base && queries_tls_directory;
}

static gboolean
gum_arm64_raw_is_release_tls_entry (const guint32 * code,
                                    guint n)
{
  guint i;
  gboolean saved_entry = FALSE, saved_flags = FALSE, branches_on_flags = FALSE;

  for (i = 0; i != n; i++)
  {
    guint32 insn = code[i];
    guint rd, rm;

    if ((insn & 0xfc000000) == 0x94000000)
      break;

    if (gum_arm64_raw_parse_mov_reg (insn, &rd, &rm))
    {
      if (rd == 19 && rm == 0)
        saved_entry = TRUE;
      if (rd == 20 && rm == 1)
        saved_flags = TRUE;
    }

    if ((insn & 0x7f000000) == 0x35000000 && (insn & 0x1f) == 20)
      branches_on_flags = TRUE;
  }

  return saved_entry && saved_flags && branches_on_flags;
}

static gboolean
gum_arm64_raw_parse_mov_reg (guint32 insn,
                             guint * rd,
                             guint * rm)
{
  if ((insn & 0x7fe0ffe0) != 0x2a0003e0)
    return FALSE;

  *rd = insn & 0x1f;
  *rm = (insn >> 16) & 0x1f;

  return TRUE;
}

static gboolean
gum_arm64_raw_accesses_entry_field (guint32 insn,
                                    guint32 entry_regs,
                                    guint offset)
{
  guint base = (insn >> 5) & 0x1f;
  guint imm12 = (insn >> 10) & 0xfff;

  if ((entry_regs & (1 << base)) == 0)
    return FALSE;

#if GLIB_SIZEOF_VOID_P == 8
  if ((insn & 0xffc00000) == 0xb9400000)
    return imm12 * 4 == offset;
  if ((insn & 0xffc00000) == 0xf9400000)
    return imm12 * 8 == offset;
  return FALSE;
#else
  return (insn & 0xffc00000) == 0x11000000 && imm12 == offset;
#endif
}

# if GLIB_SIZEOF_VOID_P == 8

static void
gum_resolve_x64_tls (GumPeModule * ntdll,
                     GumAddress base,
                     GumAddress limit,
                     GumAddress * handle,
                     GumAddress * release)
{
  GumPeX64TlsScanContext ctx;

  cs_arch_register_x86 ();
  cs_open (CS_ARCH_X86, CS_MODE_64, &ctx.cs);
  cs_option (ctx.cs, CS_OPT_DETAIL, CS_OPT_ON);
  cs_option (ctx.cs, CS_OPT_SKIPDATA, CS_OPT_ON);
  ctx.base = base;
  ctx.limit = limit;
  ctx.handle = handle;
  ctx.release = release;

  gum_pe_module_enumerate_function_starts (ntdll, gum_scan_x64_function, &ctx);

  cs_close (&ctx.cs);
}

static gboolean
gum_scan_x64_function (GumAddress rva,
                       gpointer user_data)
{
  GumPeX64TlsScanContext * ctx = user_data;
  GumAddress fn = ctx->base + rva;
  cs_insn * insns;
  size_t n, scan;

  n = cs_disasm (ctx->cs, GSIZE_TO_POINTER (fn), MIN (1024, ctx->limit - fn),
      fn, 0, &insns);
  if (n == 0)
    return TRUE;

  scan = MIN (n, 48);
  if (*ctx->handle == 0 &&
      gum_function_is_ldr_handle_tls_data (insns, scan))
    *ctx->handle = fn;
  if (*ctx->release == 0 &&
      gum_function_is_ldr_release_tls_entry (insns, scan))
    *ctx->release = fn;

  cs_free (insns, n);

  return *ctx->handle == 0 || *ctx->release == 0;
}

# else

static void
gum_resolve_wowa64_dispatch_slots (GumPeModule * ntdll,
                                   GumAddress base)
{
  const GumPeChpeMetadataX86 * metadata;

  metadata = gum_pe_module_get_data_at_rva (ntdll,
      gum_pe_module_get_chpe_metadata_rva (ntdll));

  gum_dispatch_icall_slot =
      base + metadata->dispatch_indirect_call_function_pointer;
  gum_dispatch_icall_cfg_slot =
      base + metadata->dispatch_indirect_call_cfg_function_pointer;
}

static void
gum_resolve_x86_tls (GumAddress base,
                     GumAddress limit,
                     GumAddress * handle,
                     GumAddress * release)
{
  const uint8_t * code = GSIZE_TO_POINTER (base);
  uint64_t address = base;
  csh cs, scan;
  cs_insn * insn;
  size_t code_size = limit - base;
  gboolean at_boundary = TRUE;

  cs_arch_register_x86 ();
  cs_open (CS_ARCH_X86, CS_MODE_32, &cs);
  cs_option (cs, CS_OPT_DETAIL, CS_OPT_ON);
  cs_option (cs, CS_OPT_SKIPDATA, CS_OPT_ON);

  cs_open (CS_ARCH_X86, CS_MODE_32, &scan);
  cs_option (scan, CS_OPT_DETAIL, CS_OPT_ON);
  cs_option (scan, CS_OPT_SKIPDATA, CS_OPT_ON);
  insn = cs_malloc (cs);

  while ((*handle == 0 || *release == 0) &&
      cs_disasm_iter (cs, &code, &code_size, &address, insn))
  {
    if (at_boundary && insn->id != X86_INS_INT3 && insn->id != X86_INS_NOP)
    {
      GumAddress fn = insn->address;
      cs_insn * insns;
      size_t n;

      n = cs_disasm (scan, GSIZE_TO_POINTER (fn), MIN (1024, limit - fn),
          fn, 0, &insns);
      if (n != 0)
      {
        size_t m;
        size_t count = MIN (n, 48);

        for (m = 0; m != count; m++)
        {
          if (insns[m].id == X86_INS_RET || insns[m].id == X86_INS_JMP)
          {
            count = m + 1;
            break;
          }
        }

        if (*handle == 0 &&
            gum_function_is_ldr_handle_tls_data (insns, count))
          *handle = fn;
        if (*release == 0 &&
            gum_function_is_ldr_release_tls_entry (insns, count))
          *release = fn;
        cs_free (insns, n);
      }

      at_boundary = FALSE;
    }

    if (insn->id == X86_INS_RET || insn->id == X86_INS_JMP)
      at_boundary = TRUE;
  }

  cs_free (insn, 1);
  cs_close (&scan);
  cs_close (&cs);
}

# endif

#endif

#if defined (HAVE_I386)

static gboolean
gum_function_is_ldr_handle_tls_data (cs_insn * insns,
                                     size_t count)
{
  x86_reg entry_regs[8];
  size_t i;
  guint num_entry_regs = 1;
  gboolean checked_flag = FALSE, read_dll_base = FALSE;

  entry_regs[0] = GUM_PE_TLS_ENTRY_REG;

  for (i = 0; i != count; i++)
  {
    cs_x86 * d = &insns[i].detail->x86;

#if GLIB_SIZEOF_VOID_P == 4
    if (insns[i].id == X86_INS_MOV && d->op_count == 2 &&
        d->operands[0].type == X86_OP_REG &&
        d->operands[1].type == X86_OP_REG)
      gum_reg_set_update (entry_regs, &num_entry_regs, d->operands[0].reg,
          d->operands[1].reg);
#endif

    if (insns[i].id == X86_INS_CMP && d->op_count == 2 &&
        d->operands[0].type == X86_OP_MEM &&
        gum_reg_set_contains (entry_regs, num_entry_regs,
            d->operands[0].mem.base) &&
        d->operands[0].mem.disp == GUM_PE_LDR_TLS_FLAGS_FIELD &&
        d->operands[1].type == X86_OP_IMM &&
        d->operands[1].imm == 9)
      checked_flag = TRUE;

    if (insns[i].id == X86_INS_MOV && d->op_count == 2 &&
        d->operands[1].type == X86_OP_MEM &&
        gum_reg_set_contains (entry_regs, num_entry_regs,
            d->operands[1].mem.base) &&
        d->operands[1].mem.disp == GUM_PE_LOADER_ENTRY_DLL_BASE_OFFSET)
      read_dll_base = TRUE;
  }

  return checked_flag && read_dll_base;
}

static gboolean
gum_function_is_ldr_release_tls_entry (cs_insn * insns,
                                       size_t count)
{
  x86_reg flags_regs[8];
  size_t i;
  gboolean saved_entry = FALSE, tested_flags = FALSE, frees_bit = FALSE;
  guint num_flags_regs = 1;

  flags_regs[0] = GUM_PE_TLS_FLAGS_REG;

  for (i = 0; i != count; i++)
  {
    cs_x86 * d = &insns[i].detail->x86;

    if (insns[i].id == X86_INS_MOV && d->op_count == 2 &&
        d->operands[0].type == X86_OP_REG &&
        d->operands[1].type == X86_OP_REG)
    {
      if (d->operands[1].reg == GUM_PE_TLS_ENTRY_REG)
        saved_entry = TRUE;
#if GLIB_SIZEOF_VOID_P == 4
      gum_reg_set_update (flags_regs, &num_flags_regs, d->operands[0].reg,
          d->operands[1].reg);
#endif
    }

    if (insns[i].id == X86_INS_TEST && d->op_count == 2 &&
        d->operands[0].type == X86_OP_REG &&
        d->operands[1].type == X86_OP_REG &&
        d->operands[0].reg == d->operands[1].reg &&
        gum_reg_set_contains (flags_regs, num_flags_regs, d->operands[0].reg))
      tested_flags = TRUE;

    if (insns[i].id == X86_INS_BTR && d->op_count == 2 &&
        d->operands[0].type == X86_OP_REG &&
        d->operands[1].type == X86_OP_REG)
      frees_bit = TRUE;
  }

  return saved_entry && tested_flags && frees_bit;
}

#if GLIB_SIZEOF_VOID_P == 4

static void
gum_reg_set_update (x86_reg * regs,
                    guint * n,
                    x86_reg dst,
                    x86_reg src)
{
  guint i;

  if (gum_reg_set_contains (regs, *n, src))
  {
    if (!gum_reg_set_contains (regs, *n, dst) && *n != 8)
      regs[(*n)++] = dst;
    return;
  }

  for (i = 0; i != *n; i++)
  {
    if (regs[i] == dst)
    {
      regs[i] = regs[*n - 1];
      (*n)--;
      return;
    }
  }
}

#endif

static gboolean
gum_reg_set_contains (const x86_reg * regs,
                      guint n,
                      x86_reg reg)
{
  guint i;

  if (reg == X86_REG_INVALID)
    return FALSE;

  for (i = 0; i != n; i++)
  {
    if (regs[i] == reg)
      return TRUE;
  }

  return FALSE;
}

#endif

#if GLIB_SIZEOF_VOID_P == 8 && !defined (HAVE_ARM64)

static GumAddress
gum_pe_mapper_emit_tls_thunks (GumPeMapper * self)
{
  GumVirtualAlloc2Func virtual_alloc2;
  MEM_EXTENDED_PARAMETER ec_code = { 0, };
  gpointer address;
  GumPeTlsThunks thunks;

  virtual_alloc2 = (GumVirtualAlloc2Func) GetProcAddress (
      GetModuleHandleW (L"kernelbase.dll"), "VirtualAlloc2");

  ec_code.Type = MemExtendedParameterAttributeFlags;
  ec_code.ULong64 = MEM_EXTENDED_PARAMETER_EC_CODE;
  address = virtual_alloc2 (gum_pe_mapper_get_process_handle (self), NULL,
      gum_query_page_size (), MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE,
      &ec_code, 1);

  gum_init_arm64_thunk (&thunks.handle, self->tls_handle);
  gum_init_arm64_thunk (&thunks.release, self->tls_release);
  gum_process_memory_write (self->target, GUM_ADDRESS (address), &thunks,
      sizeof (thunks));
  gum_process_memory_mark_code (self->target, GUM_ADDRESS (address),
      sizeof (thunks));

  return GUM_ADDRESS (address);
}

static void
gum_init_arm64_thunk (GumPeArm64Thunk * thunk,
                      GumAddress target)
{
  thunk->code[0] = GUM_ARM64_MOV_X1_XZR;
  thunk->code[1] = GUM_ARM64_LDR_X16_PC_PLUS_12;
  thunk->code[2] = GUM_ARM64_BR_X16;
  thunk->code[3] = 0;
  thunk->target = target;
}

static void
gum_pe_mapper_install_thread_init_hook (GumPeMapper * self)
{
  self->tls_thunk = GUM_ADDRESS (GetProcAddress (
      GetModuleHandleW (L"kernel32.dll"), "BaseThreadInitThunk"));
  self->tls_shared_region = gum_pe_mapper_resolve_shared_region (self);

  gum_pe_mapper_add_tls_entry (self);
}

static GumAddress
gum_pe_mapper_resolve_shared_region (GumPeMapper * self)
{
  GumAddress region;
  guint8 head[GUM_PE_TLS_THUNK_PATCH_SIZE];
  GumPeTlsShared shared = { 0, };
  guint8 code[GUM_PE_TLS_HOOK_CODE_SIZE];
  gsize code_size;
  guint8 patch[GUM_PE_TLS_THUNK_PATCH_SIZE];

  gum_process_memory_read (self->target, self->tls_thunk, head, sizeof (head));

  if (head[0] == 0xe9)
  {
    region = self->tls_thunk + 5 + *((gint32 *) (head + 1)) -
        GUM_PE_TLS_HANDLER_OFFSET;

    gum_process_memory_read (self->target, region, &shared, sizeof (shared));
    if (shared.magic != GUM_PE_TLS_SHARED_MAGIC)
      g_error ("BaseThreadInitThunk already hooked by someone else");

    return region;
  }

  if (!(head[0] == 0x48 && head[1] == 0x8b && head[2] == 0xc4))
    g_error ("Unexpected BaseThreadInitThunk shape");

  region = gum_process_memory_alloc_near (self->target, self->tls_thunk,
      GUM_PE_TLS_HOOK_MAX_DISTANCE, GUM_PE_TLS_SHARED_SIZE,
      gum_query_page_size ());
  if (region == 0)
    g_error ("Unable to allocate thread-init hook near kernel32");

  shared.magic = GUM_PE_TLS_SHARED_MAGIC;
  memcpy (shared.orig, head, sizeof (head));
  gum_process_memory_write (self->target, region, &shared, sizeof (shared));

  code_size = gum_emit_shared_hook (self, region + GUM_PE_TLS_HANDLER_OFFSET,
      code);
  gum_pe_mapper_patch_target_code (self, region + GUM_PE_TLS_HANDLER_OFFSET,
      code, code_size);

  patch[0] = 0xe9;
  *((gint32 *) (patch + 1)) =
      (gint32) (region + GUM_PE_TLS_HANDLER_OFFSET - (self->tls_thunk + 5));
  gum_pe_mapper_patch_target_code (self, self->tls_thunk, patch,
      sizeof (patch));

  return region;
}

static gsize
gum_emit_shared_hook (GumPeMapper * self,
                      GumAddress code_address,
                      gpointer output)
{
  gsize size;
  GumX86Writer cw;
  GumAddress region = code_address - GUM_PE_TLS_HANDLER_OFFSET;
  const guint8 rep_movsb[] = { 0xf3, 0xa4 };

  gum_x86_writer_init (&cw, output);
  cw.pc = code_address;
  gum_x86_writer_set_target_cpu (&cw, GUM_CPU_AMD64);

  gum_x86_writer_put_pushfx (&cw);
  gum_x86_writer_put_push_reg (&cw, GUM_X86_RAX);
  gum_x86_writer_put_push_reg (&cw, GUM_X86_RBX);
  gum_x86_writer_put_push_reg (&cw, GUM_X86_RCX);
  gum_x86_writer_put_push_reg (&cw, GUM_X86_RDX);
  gum_x86_writer_put_push_reg (&cw, GUM_X86_RSI);
  gum_x86_writer_put_push_reg (&cw, GUM_X86_RDI);
  gum_x86_writer_put_push_reg (&cw, GUM_X86_RBP);

  gum_x86_writer_put_mov_reg_address (&cw, GUM_X86_RAX, region + 8);
  gum_x86_writer_put_mov_reg_reg_offset_ptr (&cw, GUM_X86_EBP, GUM_X86_RAX, 0);
  gum_x86_writer_put_mov_reg_address (&cw, GUM_X86_RBX,
      region + GUM_PE_TLS_ENTRIES_OFFSET);
  gum_x86_writer_put_cld (&cw);

  gum_x86_writer_put_label (&cw, "loop");
  gum_x86_writer_put_test_reg_reg (&cw, GUM_X86_RBP, GUM_X86_RBP);
  gum_x86_writer_put_jcc_near_label (&cw, X86_INS_JE, "done", GUM_NO_HINT);
  gum_x86_writer_put_mov_reg_reg_offset_ptr (&cw, GUM_X86_RAX, GUM_X86_RBX, 0);
  gum_x86_writer_put_test_reg_reg (&cw, GUM_X86_RAX, GUM_X86_RAX);
  gum_x86_writer_put_jcc_near_label (&cw, X86_INS_JE, "skip", GUM_NO_HINT);
  gum_x86_writer_put_mov_reg_reg_offset_ptr (&cw, GUM_X86_EAX, GUM_X86_RAX, 0);
  gum_x86_writer_put_mov_reg_gs_u32_ptr (&cw, GUM_X86_RDX, 0x58);
  gum_x86_writer_put_mov_reg_base_index_scale_offset_ptr (&cw, GUM_X86_RDX,
      GUM_X86_RDX, GUM_X86_RAX, 8, 0);
  gum_x86_writer_put_mov_reg_reg_offset_ptr (&cw, GUM_X86_RSI, GUM_X86_RBX, 8);
  gum_x86_writer_put_mov_reg_reg (&cw, GUM_X86_RDI, GUM_X86_RDX);
  gum_x86_writer_put_mov_reg_reg_offset_ptr (&cw, GUM_X86_RCX, GUM_X86_RBX, 16);
  gum_x86_writer_put_bytes (&cw, rep_movsb, sizeof (rep_movsb));

  gum_x86_writer_put_label (&cw, "skip");
  gum_x86_writer_put_add_reg_imm (&cw, GUM_X86_RBX, sizeof (GumPeTlsEntry));
  gum_x86_writer_put_dec_reg (&cw, GUM_X86_RBP);
  gum_x86_writer_put_jmp_near_label (&cw, "loop");

  gum_x86_writer_put_label (&cw, "done");
  gum_x86_writer_put_pop_reg (&cw, GUM_X86_RBP);
  gum_x86_writer_put_pop_reg (&cw, GUM_X86_RDI);
  gum_x86_writer_put_pop_reg (&cw, GUM_X86_RSI);
  gum_x86_writer_put_pop_reg (&cw, GUM_X86_RDX);
  gum_x86_writer_put_pop_reg (&cw, GUM_X86_RCX);
  gum_x86_writer_put_pop_reg (&cw, GUM_X86_RBX);
  gum_x86_writer_put_pop_reg (&cw, GUM_X86_RAX);
  gum_x86_writer_put_popfx (&cw);

  gum_x86_writer_put_mov_reg_reg (&cw, GUM_X86_RAX, GUM_X86_RSP);
  gum_x86_writer_put_mov_reg_offset_ptr_reg (&cw, GUM_X86_RAX, 0x20,
      GUM_X86_RBX);
  gum_x86_writer_put_jmp_address (&cw, self->tls_thunk + 7);

  gum_x86_writer_flush (&cw);
  size = gum_x86_writer_offset (&cw);
  gum_x86_writer_clear (&cw);

  return size;
}

static void
gum_pe_mapper_add_tls_entry (GumPeMapper * self)
{
  GumAddress region = self->tls_shared_region;
  GumPeTlsShared shared;
  guint slot;
  GumPeTlsEntry entry;

  gum_process_memory_read (self->target, region, &shared, sizeof (shared));

  for (slot = 0; slot != shared.used; slot++)
  {
    GumAddress template_start;

    gum_process_memory_read (self->target,
        region + GUM_PE_TLS_ENTRIES_OFFSET + (slot * sizeof (GumPeTlsEntry)) +
          G_STRUCT_OFFSET (GumPeTlsEntry, template_start),
        &template_start, sizeof (template_start));
    if (template_start == 0)
      break;
  }

  if (slot == shared.used)
  {
    if (shared.used == GUM_PE_TLS_ENTRY_CAPACITY)
      g_error ("Too many static-TLS modules mapped into the target");
    shared.used++;
  }

  self->tls_shared_entry =
      region + GUM_PE_TLS_ENTRIES_OFFSET + (slot * sizeof (GumPeTlsEntry));

  gum_pe_mapper_get_tls_entry (self, &entry);
  gum_process_memory_write (self->target,
      self->tls_shared_entry + G_STRUCT_OFFSET (GumPeTlsEntry, template_start),
      &entry.template_start, 2 * sizeof (GumAddress));

  shared.live++;
  gum_process_memory_write (self->target, region, &shared, sizeof (shared));
}

static void
gum_pe_mapper_restore_thread_init_hook (GumPeMapper * self)
{
  gum_pe_mapper_remove_tls_entry (self);
}

static void
gum_pe_mapper_remove_tls_entry (GumPeMapper * self)
{
  GumPeTlsEntry vacant = { 0, };
  GumAddress region = self->tls_shared_region;
  GumPeTlsShared shared;

  gum_process_memory_write (self->target, self->tls_shared_entry, &vacant,
      sizeof (vacant));

  gum_process_memory_read (self->target, region, &shared, sizeof (shared));
  shared.live--;
  gum_process_memory_write (self->target, region, &shared, sizeof (shared));

  if (shared.live == 0)
  {
    gum_pe_mapper_patch_target_code (self, self->tls_thunk, shared.orig,
        GUM_PE_TLS_THUNK_PATCH_SIZE);
    gum_process_memory_free (self->target, region, GUM_PE_TLS_SHARED_SIZE);
  }
}

static void
gum_pe_mapper_patch_target_code (GumPeMapper * self,
                                 GumAddress address,
                                 gconstpointer data,
                                 gsize size)
{
  gum_process_memory_protect (self->target, address, size, GUM_PAGE_RW);
  gum_process_memory_write (self->target, address, data, size);
  gum_process_memory_mark_code (self->target, address, size);
}

#endif

static void
gum_pe_mapper_alloc_and_emit_runtime (GumPeMapper * self)
{
  gsize code_size;

  self->runtime = g_malloc0 (self->runtime_file_size);

  gum_emit_runtime (self, self->runtime, self->runtime_address, &code_size);

  g_assert (code_size <= self->runtime_file_size);
}

#if defined (HAVE_I386)

static void
gum_emit_runtime (GumPeMapper * self,
                  gpointer output_buffer,
                  GumAddress pc,
                  gsize * size)
{
  GumX86Writer cw;
  guint i;

  gum_x86_writer_init (&cw, output_buffer);
  cw.pc = pc;
  gum_x86_writer_set_target_cpu (&cw, self->cpu_type);

  self->constructor_offset = gum_x86_writer_offset (&cw);
  gum_x86_writer_put_push_reg (&cw, GUM_X86_XBP);

  if (self->add_function_table != 0)
  {
    gum_x86_writer_put_call_address_with_aligned_arguments (&cw,
        GUM_CALL_SYSAPI, self->add_function_table, 3,
        GUM_ARG_ADDRESS, self->function_table,
        GUM_ARG_ADDRESS, (GumAddress) self->function_table_count,
        GUM_ARG_ADDRESS, self->image_address);
  }

  if (self->has_static_tls && !self->tls_via_thread &&
      !self->tls_via_run_once)
  {
    if (self->pointer_size == 8)
    {
      gum_x86_writer_put_call_address_with_aligned_arguments (&cw,
          GUM_CALL_SYSAPI, self->tls_handle, 1,
          GUM_ARG_ADDRESS, self->tls_entry);
    }
    else
    {
      gum_x86_writer_put_mov_reg_address (&cw, GUM_X86_XCX, self->tls_entry);
      gum_x86_writer_put_call_address (&cw, self->tls_handle);
    }
  }
#if GLIB_SIZEOF_VOID_P == 8
  if (self->tls_via_thread)
    gum_emit_tls_thread_init (self, &cw);
#else
  if (self->tls_via_run_once)
    gum_emit_call_via_run_once (self, &cw, self->tls_handle);
#endif

  for (i = 0; i != self->tls_callbacks->len; i++)
  {
    GumAddress callback = g_array_index (self->tls_callbacks, GumAddress, i);

    gum_x86_writer_put_call_address_with_aligned_arguments (&cw,
        GUM_CALL_SYSAPI, callback, 3,
        GUM_ARG_ADDRESS, self->image_address,
        GUM_ARG_ADDRESS, (GumAddress) GUM_PE_DLL_PROCESS_ATTACH,
        GUM_ARG_ADDRESS, (GumAddress) 0);
  }

  if (self->entrypoint != 0)
  {
    gum_x86_writer_put_call_address_with_aligned_arguments (&cw,
        GUM_CALL_SYSAPI, self->entrypoint, 3,
        GUM_ARG_ADDRESS, self->image_address,
        GUM_ARG_ADDRESS, (GumAddress) GUM_PE_DLL_PROCESS_ATTACH,
        GUM_ARG_ADDRESS, (GumAddress) 0);
  }

  gum_x86_writer_put_pop_reg (&cw, GUM_X86_XBP);
  gum_x86_writer_put_ret (&cw);

  self->destructor_offset = gum_x86_writer_offset (&cw);
  gum_x86_writer_put_push_reg (&cw, GUM_X86_XBP);

  if (self->entrypoint != 0)
  {
    gum_x86_writer_put_call_address_with_aligned_arguments (&cw,
        GUM_CALL_SYSAPI, self->entrypoint, 3,
        GUM_ARG_ADDRESS, self->image_address,
        GUM_ARG_ADDRESS, (GumAddress) GUM_PE_DLL_PROCESS_DETACH,
        GUM_ARG_ADDRESS, (GumAddress) 0);
  }

  for (i = self->tls_callbacks->len; i != 0; i--)
  {
    GumAddress callback =
        g_array_index (self->tls_callbacks, GumAddress, i - 1);

    gum_x86_writer_put_call_address_with_aligned_arguments (&cw,
        GUM_CALL_SYSAPI, callback, 3,
        GUM_ARG_ADDRESS, self->image_address,
        GUM_ARG_ADDRESS, (GumAddress) GUM_PE_DLL_PROCESS_DETACH,
        GUM_ARG_ADDRESS, (GumAddress) 0);
  }

  if (self->has_static_tls && !self->tls_via_thread &&
      !self->tls_via_run_once)
  {
    if (self->pointer_size == 8)
    {
      gum_x86_writer_put_call_address_with_aligned_arguments (&cw,
          GUM_CALL_SYSAPI, self->tls_release, 2,
          GUM_ARG_ADDRESS, self->tls_entry,
          GUM_ARG_ADDRESS, (GumAddress) 0);
    }
    else
    {
      gum_x86_writer_put_mov_reg_address (&cw, GUM_X86_XCX, self->tls_entry);
      gum_x86_writer_put_mov_reg_address (&cw, GUM_X86_XDX, (GumAddress) 0);
      gum_x86_writer_put_call_address (&cw, self->tls_release);
    }
  }
#if GLIB_SIZEOF_VOID_P == 8
  if (self->tls_via_thread)
    gum_emit_tls_thread_release (self, &cw);
#else
  if (self->tls_via_run_once)
    gum_emit_call_via_run_once (self, &cw, self->tls_release);
#endif

  if (self->delete_function_table != 0)
  {
    gum_x86_writer_put_call_address_with_aligned_arguments (&cw,
        GUM_CALL_SYSAPI, self->delete_function_table, 1,
        GUM_ARG_ADDRESS, self->function_table);
  }

  gum_x86_writer_put_pop_reg (&cw, GUM_X86_XBP);
  gum_x86_writer_put_ret (&cw);

  gum_x86_writer_flush (&cw);
  *size = gum_x86_writer_offset (&cw);
  gum_x86_writer_clear (&cw);
}

#if GLIB_SIZEOF_VOID_P == 8

static void
gum_emit_tls_thread_init (GumPeMapper * self,
                          GumX86Writer * cw)
{
  GumPeTlsEntry entry;
  const guint8 rep_movsb[] = { 0xf3, 0xa4 };

  gum_pe_mapper_get_tls_entry (self, &entry);

  gum_x86_writer_put_push_reg (cw, GUM_X86_RBX);
  gum_x86_writer_put_push_reg (cw, GUM_X86_RSI);
  gum_x86_writer_put_push_reg (cw, GUM_X86_RDI);
  gum_x86_writer_put_sub_reg_imm (cw, GUM_X86_RSP, 8);

  gum_emit_call_on_new_thread (self, cw,
      self->tls_thunks + G_STRUCT_OFFSET (GumPeTlsThunks, handle),
      self->tls_entry);

  gum_x86_writer_put_mov_reg_address (cw, GUM_X86_RAX, entry.index_slot);
  gum_x86_writer_put_mov_reg_address (cw, GUM_X86_RCX, self->tls_shared_entry);
  gum_x86_writer_put_mov_reg_ptr_reg (cw, GUM_X86_RCX, GUM_X86_RAX);

  gum_x86_writer_put_mov_reg_reg_offset_ptr (cw, GUM_X86_EAX, GUM_X86_RAX, 0);
  gum_x86_writer_put_mov_reg_gs_u32_ptr (cw, GUM_X86_RDX, 0x58);
  gum_x86_writer_put_mov_reg_base_index_scale_offset_ptr (cw, GUM_X86_RDI,
      GUM_X86_RDX, GUM_X86_RAX, 8, 0);
  gum_x86_writer_put_mov_reg_address (cw, GUM_X86_RSI, entry.template_start);
  gum_x86_writer_put_mov_reg_address (cw, GUM_X86_RCX, entry.template_size);
  gum_x86_writer_put_cld (cw);
  gum_x86_writer_put_bytes (cw, rep_movsb, sizeof (rep_movsb));

  gum_x86_writer_put_add_reg_imm (cw, GUM_X86_RSP, 8);
  gum_x86_writer_put_pop_reg (cw, GUM_X86_RDI);
  gum_x86_writer_put_pop_reg (cw, GUM_X86_RSI);
  gum_x86_writer_put_pop_reg (cw, GUM_X86_RBX);
}

static void
gum_emit_tls_thread_release (GumPeMapper * self,
                             GumX86Writer * cw)
{
  gum_x86_writer_put_push_reg (cw, GUM_X86_RBX);
  gum_x86_writer_put_sub_reg_imm (cw, GUM_X86_RSP, 8);

  gum_x86_writer_put_mov_reg_address (cw, GUM_X86_RCX, self->tls_shared_entry);
  gum_x86_writer_put_xor_reg_reg (cw, GUM_X86_EAX, GUM_X86_EAX);
  gum_x86_writer_put_mov_reg_ptr_reg (cw, GUM_X86_RCX, GUM_X86_RAX);

  gum_emit_call_on_new_thread (self, cw,
      self->tls_thunks + G_STRUCT_OFFSET (GumPeTlsThunks, release),
      self->tls_entry);

  gum_x86_writer_put_add_reg_imm (cw, GUM_X86_RSP, 8);
  gum_x86_writer_put_pop_reg (cw, GUM_X86_RBX);
}

static void
gum_emit_call_on_new_thread (GumPeMapper * self,
                             GumX86Writer * cw,
                             GumAddress start,
                             GumAddress parameter)
{
  gum_x86_writer_put_call_address_with_aligned_arguments (cw,
      GUM_CALL_SYSAPI, self->create_thread, 6,
      GUM_ARG_ADDRESS, (GumAddress) 0,
      GUM_ARG_ADDRESS, (GumAddress) 0,
      GUM_ARG_ADDRESS, start,
      GUM_ARG_ADDRESS, parameter,
      GUM_ARG_ADDRESS, (GumAddress) 0,
      GUM_ARG_ADDRESS, (GumAddress) 0);
  gum_x86_writer_put_mov_reg_reg (cw, GUM_X86_RBX, GUM_X86_RAX);
  gum_x86_writer_put_call_address_with_aligned_arguments (cw,
      GUM_CALL_SYSAPI, self->wait_for_single_object, 2,
      GUM_ARG_REGISTER, GUM_X86_RBX,
      GUM_ARG_ADDRESS, (GumAddress) INFINITE);
  gum_x86_writer_put_call_address_with_aligned_arguments (cw,
      GUM_CALL_SYSAPI, self->close_handle, 1,
      GUM_ARG_REGISTER, GUM_X86_RBX);
}

#else

static void
gum_emit_call_via_run_once (GumPeMapper * self,
                            GumX86Writer * cw,
                            GumAddress routine)
{
  gum_x86_writer_put_push_reg (cw, GUM_X86_EBX);
  gum_x86_writer_put_push_reg (cw, GUM_X86_ESI);
  gum_x86_writer_put_sub_reg_imm (cw, GUM_X86_ESP, 4);
  gum_x86_writer_put_mov_reg_reg (cw, GUM_X86_EBX, GUM_X86_ESP);

  gum_x86_writer_put_call_address_with_aligned_arguments (cw,
      GUM_CALL_SYSAPI, self->virtual_protect, 4,
      GUM_ARG_ADDRESS, gum_dispatch_icall_cfg_slot,
      GUM_ARG_ADDRESS, (GumAddress) sizeof (guint32),
      GUM_ARG_ADDRESS, (GumAddress) PAGE_READWRITE,
      GUM_ARG_REGISTER, GUM_X86_EBX);

  gum_x86_writer_put_mov_reg_address (cw, GUM_X86_ECX,
      gum_dispatch_icall_cfg_slot);
  gum_x86_writer_put_mov_reg_reg_ptr (cw, GUM_X86_ESI, GUM_X86_ECX);
  gum_x86_writer_put_mov_reg_address (cw, GUM_X86_EAX, gum_dispatch_icall_slot);
  gum_x86_writer_put_mov_reg_reg_ptr (cw, GUM_X86_EAX, GUM_X86_EAX);
  gum_x86_writer_put_mov_reg_ptr_reg (cw, GUM_X86_ECX, GUM_X86_EAX);

  gum_x86_writer_put_call_address_with_aligned_arguments (cw,
      GUM_CALL_SYSAPI, self->run_once_execute_once, 4,
      GUM_ARG_ADDRESS, self->tls_entry,
      GUM_ARG_ADDRESS, routine,
      GUM_ARG_ADDRESS, (GumAddress) 0,
      GUM_ARG_ADDRESS, (GumAddress) 0);

  gum_x86_writer_put_mov_reg_address (cw, GUM_X86_ECX,
      gum_dispatch_icall_cfg_slot);
  gum_x86_writer_put_mov_reg_ptr_reg (cw, GUM_X86_ECX, GUM_X86_ESI);

  gum_x86_writer_put_mov_reg_reg_ptr (cw, GUM_X86_EAX, GUM_X86_EBX);
  gum_x86_writer_put_call_address_with_aligned_arguments (cw,
      GUM_CALL_SYSAPI, self->virtual_protect, 4,
      GUM_ARG_ADDRESS, gum_dispatch_icall_cfg_slot,
      GUM_ARG_ADDRESS, (GumAddress) sizeof (guint32),
      GUM_ARG_REGISTER, GUM_X86_EAX,
      GUM_ARG_REGISTER, GUM_X86_EBX);

  gum_x86_writer_put_add_reg_imm (cw, GUM_X86_ESP, 4);
  gum_x86_writer_put_pop_reg (cw, GUM_X86_ESI);
  gum_x86_writer_put_pop_reg (cw, GUM_X86_EBX);
}

#endif

#elif defined (HAVE_ARM64)

static void
gum_emit_runtime (GumPeMapper * self,
                  gpointer output_buffer,
                  GumAddress pc,
                  gsize * size)
{
  GumArm64Writer cw;
  guint i;

  gum_arm64_writer_init (&cw, output_buffer);
  cw.pc = pc;

  self->constructor_offset = gum_arm64_writer_offset (&cw);
  gum_arm64_writer_put_push_reg_reg (&cw, ARM64_REG_FP, ARM64_REG_LR);

  if (self->add_function_table != 0)
  {
    gum_arm64_writer_put_call_address_with_arguments (&cw,
        self->add_function_table, 3,
        GUM_ARG_ADDRESS, self->function_table,
        GUM_ARG_ADDRESS, (GumAddress) self->function_table_count,
        GUM_ARG_ADDRESS, self->image_address);
  }

  if (self->has_static_tls)
  {
    gum_arm64_writer_put_call_address_with_arguments (&cw, self->tls_handle, 1,
        GUM_ARG_ADDRESS, self->tls_entry);
  }

  for (i = 0; i != self->tls_callbacks->len; i++)
  {
    GumAddress callback = g_array_index (self->tls_callbacks, GumAddress, i);

    gum_arm64_writer_put_call_address_with_arguments (&cw, callback, 3,
        GUM_ARG_ADDRESS, self->image_address,
        GUM_ARG_ADDRESS, (GumAddress) GUM_PE_DLL_PROCESS_ATTACH,
        GUM_ARG_ADDRESS, (GumAddress) 0);
  }

  if (self->entrypoint != 0)
  {
    gum_arm64_writer_put_call_address_with_arguments (&cw, self->entrypoint, 3,
        GUM_ARG_ADDRESS, self->image_address,
        GUM_ARG_ADDRESS, (GumAddress) GUM_PE_DLL_PROCESS_ATTACH,
        GUM_ARG_ADDRESS, (GumAddress) 0);
  }

  gum_arm64_writer_put_pop_reg_reg (&cw, ARM64_REG_FP, ARM64_REG_LR);
  gum_arm64_writer_put_ret (&cw);

  self->destructor_offset = gum_arm64_writer_offset (&cw);
  gum_arm64_writer_put_push_reg_reg (&cw, ARM64_REG_FP, ARM64_REG_LR);

  if (self->entrypoint != 0)
  {
    gum_arm64_writer_put_call_address_with_arguments (&cw, self->entrypoint, 3,
        GUM_ARG_ADDRESS, self->image_address,
        GUM_ARG_ADDRESS, (GumAddress) GUM_PE_DLL_PROCESS_DETACH,
        GUM_ARG_ADDRESS, (GumAddress) 0);
  }

  for (i = self->tls_callbacks->len; i != 0; i--)
  {
    GumAddress callback =
        g_array_index (self->tls_callbacks, GumAddress, i - 1);

    gum_arm64_writer_put_call_address_with_arguments (&cw, callback, 3,
        GUM_ARG_ADDRESS, self->image_address,
        GUM_ARG_ADDRESS, (GumAddress) GUM_PE_DLL_PROCESS_DETACH,
        GUM_ARG_ADDRESS, (GumAddress) 0);
  }

  if (self->has_static_tls)
  {
    gum_arm64_writer_put_call_address_with_arguments (&cw, self->tls_release, 2,
        GUM_ARG_ADDRESS, self->tls_entry,
        GUM_ARG_ADDRESS, (GumAddress) 0);
  }

  if (self->delete_function_table != 0)
  {
    gum_arm64_writer_put_call_address_with_arguments (&cw,
        self->delete_function_table, 1,
        GUM_ARG_ADDRESS, self->function_table);
  }

  gum_arm64_writer_put_pop_reg_reg (&cw, ARM64_REG_FP, ARM64_REG_LR);
  gum_arm64_writer_put_ret (&cw);

  gum_arm64_writer_flush (&cw);
  *size = gum_arm64_writer_offset (&cw);
  gum_arm64_writer_clear (&cw);
}

#endif

static void
gum_pe_mapper_commit_image (GumPeMapper * self)
{
  const guint8 * staged_image = GUM_PE_STAGED (self, self->image_address);
  gsize image_size = self->vm_size - self->runtime_vm_size;
  gsize shared_size = self->shared_range.size;
  const guint8 * shared_image;
  gsize page_size, offset;

  if (shared_size != 0)
  {
    shared_image = g_bytes_get_data (
        gum_pe_module_get_source_blob (self->module), NULL);
    page_size = gum_query_page_size ();

    for (offset = 0; offset != shared_size; offset += page_size)
    {
      if (memcmp (shared_image + offset, staged_image + offset,
          page_size) != 0)
      {
        gum_process_memory_write (self->target, self->image_address + offset,
            staged_image + offset, page_size);
      }
    }
  }

  gum_process_memory_write (self->target, self->image_address + shared_size,
      staged_image + shared_size, image_size - shared_size);
}

static gboolean
gum_protect_section (const GumPeSectionDetails * details,
                     gpointer user_data)
{
  GumPeMapper * self = user_data;
  GumAddress start = self->image_address + details->virtual_address;
  GumAddress end = start + details->virtual_size;
  GumAddress shared_end = self->shared_range.base_address +
      self->shared_range.size;

  if (start < shared_end && end > shared_end)
  {
    gum_process_memory_protect (self->target, start, shared_end - start,
        details->protection);
    gum_process_memory_protect (self->target, shared_end, end - shared_end,
        details->protection);
  }
  else
  {
    gum_process_memory_protect (self->target, start, details->virtual_size,
        details->protection);
  }

  return TRUE;
}

#if GLIB_SIZEOF_VOID_P == 8 && !defined (HAVE_ARM64)

static void
gum_pe_mapper_get_tls_entry (GumPeMapper * self,
                             GumPeTlsEntry * entry)
{
  GumPeTlsDetails tls;

  gum_pe_module_get_tls_details (self->module, &tls);

  entry->index_slot = self->image_address + tls.index_rva;
  entry->template_start = self->image_address + tls.template_rva;
  entry->template_size = tls.template_size;
}

#endif

static gboolean
gum_emit_export (const GumPeExportDetails * details,
                 gpointer user_data)
{
  GumPeEnumerateExportsContext * ctx = user_data;
  GumPeMapper * self = ctx->mapper;
  GumExportDetails export;

  if (details->name == NULL)
    return TRUE;

  export.type = gum_pe_mapper_classify_export (self, details);
  export.name = details->name;
  export.address = gum_pe_mapper_resolve_export (self, details);
  export.size = -1;

  return ctx->func (&export, ctx->user_data);
}

static GumExportType
gum_pe_mapper_classify_export (GumPeMapper * self,
                               const GumPeExportDetails * details)
{
  GumPeFindSectionContext ctx;

  if (details->type == GUM_PE_EXPORT_FORWARDED)
    return GUM_EXPORT_FUNCTION;

  ctx.rva = details->rva;
  ctx.protection = GUM_PAGE_NO_ACCESS;
  gum_pe_module_enumerate_sections (self->module, gum_match_section, &ctx);

  return ((ctx.protection & GUM_PAGE_EXECUTE) != 0)
      ? GUM_EXPORT_FUNCTION
      : GUM_EXPORT_VARIABLE;
}

static gboolean
gum_match_section (const GumPeSectionDetails * details,
                   gpointer user_data)
{
  GumPeFindSectionContext * ctx = user_data;

  if (ctx->rva < details->virtual_address ||
      ctx->rva >= details->virtual_address + details->virtual_size)
  {
    return TRUE;
  }

  ctx->protection = details->protection;

  return FALSE;
}

static GumAddress
gum_pe_mapper_resolve_export (GumPeMapper * self,
                              const GumPeExportDetails * details)
{
  GumAddress result = 0;
  gchar ** parts;
  GumModule * module;

  if (details->type == GUM_PE_EXPORT_REGULAR)
    return self->image_address + details->rva;

  parts = g_strsplit (details->forwarder, ".", 2);

  module = gum_module_resolver_find_module_by_name (self->resolver, parts[0]);
  if (module != NULL)
  {
    result = gum_module_find_export_by_name (module, parts[1]);
    g_object_unref (module);
  }

  g_strfreev (parts);

  return result;
}

static HANDLE
gum_pe_mapper_get_process_handle (GumPeMapper * self)
{
  HANDLE handle;

  handle = gum_native_process_memory_get_handle (
      GUM_NATIVE_PROCESS_MEMORY (self->target));

  return (handle != NULL) ? handle : GetCurrentProcess ();
}

static void
gum_resolve_section_api (void)
{
  static gsize initialized = 0;

  if (g_once_init_enter (&initialized))
  {
    HMODULE ntdll = GetModuleHandleW (L"ntdll.dll");

    gum_nt_map_view_of_section = (GumNtMapViewOfSectionFunc)
        GetProcAddress (ntdll, "NtMapViewOfSection");
    gum_nt_unmap_view_of_section = (GumNtUnmapViewOfSectionFunc)
        GetProcAddress (ntdll, "NtUnmapViewOfSection");

    g_once_init_leave (&initialized, 1);
  }
}

static GumCpuType
gum_cpu_type_from_pe (GumPeMachine machine)
{
  switch (machine)
  {
    case GUM_PE_MACHINE_I386:
      return GUM_CPU_IA32;
    case GUM_PE_MACHINE_AMD64:
      return GUM_CPU_AMD64;
    case GUM_PE_MACHINE_ARMNT:
      return GUM_CPU_ARM;
    case GUM_PE_MACHINE_ARM64:
      return GUM_CPU_ARM64;
    default:
      return GUM_CPU_INVALID;
  }
}
