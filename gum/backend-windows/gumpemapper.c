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
#include <tlhelp32.h>
#include <gio/gio.h>

#define GUM_PE_MAPPER_CODE_BASE_SIZE 512
#define GUM_PE_MAPPER_TLS_CALL_SIZE 128
#define GUM_PE_MAPPER_UNWIND_SIZE 128
#define GUM_PE_MAPPER_ENTRY_CALL_SIZE 128
#define GUM_PE_MAPPER_LEGACY_TLS_SIZE 1536

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
# define GUM_PE_TEB_SELF_OFFSET 0x30
# define GUM_PE_TEB_PROCESS_ID_OFFSET 0x40
# define GUM_PE_TEB_PEB_OFFSET 0x60
# define GUM_PE_TEB_TLS_POINTER_OFFSET 0x58
# define GUM_PE_PEB_PROCESS_HEAP_OFFSET 0x30
#else
# define GUM_PE_LOADER_ENTRY_SIZE 0x100
# define GUM_PE_LOADER_ENTRY_DLL_BASE_OFFSET 0x18
# define GUM_PE_TEB_SELF_OFFSET 0x18
# define GUM_PE_TEB_PROCESS_ID_OFFSET 0x20
# define GUM_PE_TEB_PEB_OFFSET 0x30
# define GUM_PE_TEB_TLS_POINTER_OFFSET 0x2c
# define GUM_PE_PEB_PROCESS_HEAP_OFFSET 0x18
#endif

#define GUM_PE_THREAD_BASIC_INFORMATION 0
#define GUM_PE_LEGACY_TLS_FRAME_SIZE \
    (GUM_ALIGN_SIZE (sizeof (GumPeLegacyTlsFrame) + \
        (3 * GLIB_SIZEOF_VOID_P), 16) - (3 * GLIB_SIZEOF_VOID_P))

#define GUM_PE_TLS_HEAD_MAX_INSNS 64
#define GUM_PE_NT_HEADERS_TLS_DIRECTORY_OFFSET \
    G_STRUCT_OFFSET (IMAGE_NT_HEADERS, \
        OptionalHeader.DataDirectory[GUM_PE_DIRECTORY_TLS])

#define GUM_PE_ARM64_MAX_VALUES (5 * GUM_PE_TLS_HEAD_MAX_INSNS)
#define GUM_PE_ARM64_MAX_FUNCTION_INSNS 4096
#define GUM_PE_ARM64_IP0 16
#define GUM_PE_ARM64_PLATFORM_REG 18
#define GUM_PE_ARM64_SP 31
#define GUM_PE_ARM64_ZR 31
#define GUM_PE_ARM64_UNKNOWN 0
#define GUM_PE_ARM64_ENTRY 1
#define GUM_PE_ARM64_STACK 2

#if defined (HAVE_I386) && GLIB_SIZEOF_VOID_P == 4
# define GUM_PE_TLS_ENTRY_REG X86_REG_ECX
# define GUM_PE_TLS_ENTRY_SLOT 8
# define GUM_PE_TLS_RETURN_REG X86_REG_EAX
# define GUM_PE_TEB_SEGMENT_REG X86_REG_FS
#elif defined (HAVE_I386)
# define GUM_PE_TLS_ENTRY_REG X86_REG_RCX
# define GUM_PE_TLS_RETURN_REG X86_REG_RAX
# define GUM_PE_TEB_SEGMENT_REG X86_REG_GS
#endif

#define GUM_TYPE_PE_MAPPER (gum_pe_mapper_get_type ())
G_DECLARE_FINAL_TYPE (GumPeMapper, gum_pe_mapper, GUM, PE_MAPPER, GObject)

typedef struct _GumPeResolveContext GumPeResolveContext;
typedef struct _GumPeFindWritableContext GumPeFindWritableContext;
typedef struct _GumPeTlsCollectContext GumPeTlsCollectContext;
typedef struct _GumPeEnumerateExportsContext GumPeEnumerateExportsContext;
typedef struct _GumPeMatchOrdinalContext GumPeMatchOrdinalContext;
typedef struct _GumPeFindSectionContext GumPeFindSectionContext;
typedef enum _GumPeArm64InsnKind GumPeArm64InsnKind;
typedef struct _GumPeArm64Insn GumPeArm64Insn;
typedef enum _GumPeArm64ValueKind GumPeArm64ValueKind;
typedef struct _GumPeArm64Value GumPeArm64Value;
typedef enum _GumPeArm64EventKind GumPeArm64EventKind;
typedef struct _GumPeArm64Event GumPeArm64Event;
typedef struct _GumPeArm64Flow GumPeArm64Flow;
#if defined (HAVE_I386) && GLIB_SIZEOF_VOID_P == 4
typedef struct _GumPeChpeMetadataX86 GumPeChpeMetadataX86;
#endif
#if defined (HAVE_I386)
typedef struct _GumPeX86TlsScanner GumPeX86TlsScanner;
typedef struct _GumPeX86FunctionHead GumPeX86FunctionHead;
typedef struct _GumPeLegacyTlsEntry GumPeLegacyTlsEntry;
typedef struct _GumPeLegacyTlsFrame GumPeLegacyTlsFrame;
typedef struct _GumPeThreadBasicInformation GumPeThreadBasicInformation;
#endif
#if GLIB_SIZEOF_VOID_P == 8 && !defined (HAVE_ARM64)
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
#if defined (HAVE_I386)
typedef void (* GumEmitThreadFunc) (GumPeMapper * self, GumX86Writer * cw);
#endif
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
  gboolean tls_via_legacy_loader;
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
  GumAddress lock_loader_lock;
  GumAddress unlock_loader_lock;
  GumAddress allocate_heap;
  GumAddress free_heap;
  GumAddress create_toolhelp_snapshot;
  GumAddress thread32_first;
  GumAddress thread32_next;
  GumAddress open_thread;
  GumAddress query_information_thread;
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

enum _GumPeArm64InsnKind
{
  GUM_PE_ARM64_INSN_OTHER,
  GUM_PE_ARM64_INSN_MOV_REG,
  GUM_PE_ARM64_INSN_MOV_IMM,
  GUM_PE_ARM64_INSN_ADD_IMM,
  GUM_PE_ARM64_INSN_AND_IMM,
  GUM_PE_ARM64_INSN_LOAD,
  GUM_PE_ARM64_INSN_LOAD_PAIR,
  GUM_PE_ARM64_INSN_STORE,
  GUM_PE_ARM64_INSN_CALL,
  GUM_PE_ARM64_INSN_CALL_INDIRECT,
  GUM_PE_ARM64_INSN_JUMP,
  GUM_PE_ARM64_INSN_BRANCH_IF,
  GUM_PE_ARM64_INSN_EXIT,
  GUM_PE_ARM64_INSN_CLEAR_BITS,
  GUM_PE_ARM64_INSN_INVERT,
  GUM_PE_ARM64_INSN_AND_REG,
  GUM_PE_ARM64_INSN_WRITE
};

struct _GumPeArm64Insn
{
  GumPeArm64InsnKind kind;
  guint rt;
  guint rt2;
  guint rn;
  guint rm;
  gint64 imm;
  guint size;
};

enum _GumPeArm64ValueKind
{
  GUM_PE_ARM64_VALUE_UNKNOWN,
  GUM_PE_ARM64_VALUE_ENTRY,
  GUM_PE_ARM64_VALUE_STACK,
  GUM_PE_ARM64_VALUE_CONSTANT,
  GUM_PE_ARM64_VALUE_CALL_RESULT,
  GUM_PE_ARM64_VALUE_LOAD,
  GUM_PE_ARM64_VALUE_ADDRESS,
  GUM_PE_ARM64_VALUE_INVERTED
};

struct _GumPeArm64Value
{
  GumPeArm64ValueKind kind;
  guint parent;
  gint64 offset;
};

enum _GumPeArm64EventKind
{
  GUM_PE_ARM64_EVENT_CALL,
  GUM_PE_ARM64_EVENT_LOAD,
  GUM_PE_ARM64_EVENT_STORE,
  GUM_PE_ARM64_EVENT_CLEAR_BITS
};

struct _GumPeArm64Event
{
  GumPeArm64EventKind kind;
  guint value;
  guint address;
  guint size;
  guint args[4];
};

struct _GumPeArm64Flow
{
  GumPeArm64Value values[GUM_PE_ARM64_MAX_VALUES];
  guint num_values;
  GumPeArm64Event events[GUM_PE_TLS_HEAD_MAX_INSNS];
  guint num_events;
  guint regs[32];
  guint num_calls;
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

#if defined (HAVE_I386)
struct _GumPeX86FunctionHead
{
  cs_insn insns[GUM_PE_TLS_HEAD_MAX_INSNS];
  cs_detail details[GUM_PE_TLS_HEAD_MAX_INSNS];
  size_t count;
};

struct _GumPeX86TlsScanner
{
  csh cs;
  cs_insn * insn;
  GumAddress base;
  GumAddress limit;
  gboolean legacy;
  GumAddress handle;
  GumAddress release;
  GumAddress list;
  GumAddress count;
  GumPeX86FunctionHead head;
};

struct _GumPeLegacyTlsEntry
{
  LIST_ENTRY links;
  IMAGE_TLS_DIRECTORY tls;
};

struct _GumPeThreadBasicInformation
{
  LONG exit_status;
  gpointer teb_base_address;
  gpointer client_id[2];
  ULONG_PTR affinity_mask;
  LONG priority;
  LONG base_priority;
};

struct _GumPeLegacyTlsFrame
{
  THREADENTRY32 thread;
  GumPeThreadBasicInformation info;
  gpointer heap;
  ULONG_PTR cookie;
  guint32 index;
};
#endif

#if GLIB_SIZEOF_VOID_P == 8 && !defined (HAVE_ARM64)
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
static gboolean gum_loader_supports_dynamic_tls (void);
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
#if defined (HAVE_I386)
static void gum_pe_mapper_prepare_legacy_tls (GumPeMapper * self);
#endif
static void gum_resolve_loader_tls (void);
#if !defined (HAVE_ARM64)
static gboolean gum_is_emulated (void);
#endif
static void gum_resolve_arm64_tls (GumModule * ntdll, GumAddress base,
    GumAddress limit, GumAddress * handle, GumAddress * release);
static GumAddress gum_find_arm64_loader_function (GumModule * ntdll,
    const gchar * name);
#if !defined (HAVE_ARM64)
static gpointer gum_follow_x86_thunk (gpointer fn);
#endif
static void gum_pe_arm64_flow_trace (GumPeArm64Flow * self,
    GumAddress function, GumAddress base, GumAddress limit);
static void gum_pe_arm64_flow_reset (GumPeArm64Flow * self);
static guint gum_pe_arm64_flow_intern (GumPeArm64Flow * self,
    GumPeArm64ValueKind kind, guint parent, gint64 offset);
static gboolean gum_address_list_contains (const GumAddress * addresses,
    guint n, GumAddress address);
static void gum_pe_arm64_insn_decode (guint32 code, GumPeArm64Insn * insn);
static gint64 gum_sign_extend (guint32 value, guint bits);
static gboolean gum_arm64_code_writes_rt (guint32 code);
static void gum_pe_arm64_flow_step (GumPeArm64Flow * self,
    const GumPeArm64Insn * insn, GumAddress pc, GumAddress base,
    GumAddress limit);
static void gum_pe_arm64_flow_set (GumPeArm64Flow * self, guint reg,
    guint value);
static guint gum_pe_arm64_flow_resolve_address (GumPeArm64Flow * self,
    guint reg, gint64 offset);
static guint gum_pe_arm64_flow_get (GumPeArm64Flow * self, guint reg);
static guint gum_pe_arm64_flow_mask (GumPeArm64Flow * self, guint value);
static void gum_pe_arm64_flow_add_event (GumPeArm64Flow * self,
    GumPeArm64EventKind kind, guint value, guint address, guint size);
static guint gum_pe_arm64_flow_load (GumPeArm64Flow * self, guint address,
    gint64 offset);
static gboolean gum_pe_arm64_call_preserves_arguments (GumAddress target,
    GumAddress base, GumAddress limit);
static void gum_pe_arm64_flow_call (GumPeArm64Flow * self);
static void gum_pe_arm64_flow_clear_bits (GumPeArm64Flow * self, guint reg);
static gboolean gum_pe_arm64_flow_is_inverted (GumPeArm64Flow * self,
    guint reg);
static gboolean gum_pe_arm64_flow_is_handle_tls_data (GumPeArm64Flow * self);
static gboolean gum_uint_list_contains (const guint * values, guint n,
    guint value);
static gboolean gum_pe_arm64_flow_is_release_tls_entry (
    GumPeArm64Flow * self);
static gboolean gum_pe_arm64_flow_passes_field_of (GumPeArm64Flow * self,
    const GumPeArm64Event * event, guint record);
static void gum_enqueue_arm64_callees (GumAddress function, GumAddress base,
    GumAddress limit, GHashTable * visited, GQueue * queue);
#if !defined (HAVE_ARM64)
# if GLIB_SIZEOF_VOID_P == 8
static GumPeX86TlsScanner * gum_scan_x64_loader (GumPeModule * ntdll,
    GumAddress base, GumAddress limit, gboolean legacy);
static gboolean gum_scan_x64_function (GumAddress rva, gpointer user_data);
# else
static void gum_resolve_wowa64_dispatch_slots (GumPeModule * ntdll,
    GumAddress base);
static GumPeX86TlsScanner * gum_scan_x86_loader (GumPeModule * ntdll,
    GumAddress base, gboolean legacy);
static gboolean gum_find_text_section (const GumPeSectionDetails * details,
    gpointer user_data);
static GArray * gum_collect_x86_call_targets (GumAddress base,
    GumAddress limit);
static gint gum_compare_addresses (gconstpointer a, gconstpointer b);
# endif
#endif
#if defined (HAVE_I386)
static GumPeX86TlsScanner * gum_pe_x86_tls_scanner_new (cs_mode mode,
    GumAddress base, GumAddress limit, gboolean legacy);
static gboolean gum_pe_x86_tls_scanner_consider (GumPeX86TlsScanner * self,
    GumAddress function);
static void gum_pe_x86_tls_scanner_free (GumPeX86TlsScanner * scanner);
static void gum_pe_x86_tls_scanner_read_head (GumPeX86TlsScanner * self,
    GumAddress function);
static gboolean gum_pe_x86_function_head_contains (
    const GumPeX86FunctionHead * head, GumAddress address);
static GumAddress gum_pe_x86_tls_scanner_resolve_jump (
    GumPeX86TlsScanner * self, const cs_insn * insn);
static void gum_pe_x86_function_head_append (GumPeX86FunctionHead * head,
    const cs_insn * insn);
static gboolean gum_function_is_ldrp_allocate_tls (
    const GumPeX86FunctionHead * head, GumAddress * list, GumAddress * count);
static GumAddress gum_x86_insn_find_global_u32 (const cs_insn * insn);
static gboolean gum_x86_insn_references_address (const cs_insn * insn,
    GumAddress address);
static GumAddress gum_x86_op_resolve_global (const cs_insn * insn,
    const cs_x86_op * op);
static gboolean gum_x86_op_is_teb_self (const cs_x86_op * op);
static gboolean gum_function_is_ldr_handle_tls_data (
    const GumPeX86FunctionHead * head);
static gboolean gum_x86_insn_passes_tls_directory (const cs_insn * insn);
static gboolean gum_x86_insn_reads_dll_base (const cs_insn * insn,
    const x86_reg * entry_regs, guint num_entry_regs);
static gboolean gum_function_is_ldr_release_tls_entry (
    const GumPeX86FunctionHead * head);
static gboolean gum_x86_op_is_field_of (const cs_x86_op * op,
    const x86_reg * regs, guint n);
static void gum_entry_regs_track (x86_reg * regs, guint * n,
    const cs_insn * insn);
static gboolean gum_x86_op_is_entry_slot (const cs_x86_op * op);
static void gum_reg_set_track (x86_reg * regs, guint * n,
    const cs_insn * insn);
static void gum_reg_set_add (x86_reg * regs, guint * n, x86_reg reg);
static void gum_reg_set_remove (x86_reg * regs, guint * n, x86_reg reg);
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
#if defined (HAVE_I386)
static void gum_emit_legacy_tls_attach (GumPeMapper * self,
    GumX86Writer * cw);
static void gum_emit_legacy_tls_enter (GumPeMapper * self, GumX86Writer * cw);
static void gum_emit_mov_reg_teb_field (GumX86Writer * cw, GumX86Reg reg,
    guint32 offset);
static void gum_emit_for_each_thread (GumPeMapper * self, GumX86Writer * cw,
    GumEmitThreadFunc func);
static void gum_emit_attach_to_thread (GumPeMapper * self, GumX86Writer * cw);
static void gum_emit_legacy_tls_leave (GumPeMapper * self, GumX86Writer * cw);
static void gum_emit_legacy_tls_detach (GumPeMapper * self,
    GumX86Writer * cw);
static void gum_emit_detach_from_thread (GumPeMapper * self,
    GumX86Writer * cw);
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
static GumAddress gum_ldrp_tls_list;
static GumAddress gum_ldrp_number_of_tls_entries;
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
  self->tls_via_legacy_loader =
      self->has_static_tls && !gum_loader_supports_dynamic_tls ();

  runtime_size = GUM_PE_MAPPER_CODE_BASE_SIZE +
      (2 * self->tls_callback_count * GUM_PE_MAPPER_TLS_CALL_SIZE) +
      GUM_PE_MAPPER_ENTRY_CALL_SIZE;
  if (self->has_exception_table && self->pointer_size == 8)
    runtime_size += 2 * GUM_PE_MAPPER_UNWIND_SIZE;
  if (self->has_static_tls)
    runtime_size += 4 * GUM_PE_MAPPER_TLS_CALL_SIZE;
  if (self->tls_via_legacy_loader)
    runtime_size += GUM_PE_MAPPER_LEGACY_TLS_SIZE;

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
gum_loader_supports_dynamic_tls (void)
{
  NTSTATUS (WINAPI * rtl_get_version) (PRTL_OSVERSIONINFOW info);
  RTL_OSVERSIONINFOW info = { 0, };

  rtl_get_version = (NTSTATUS (WINAPI *) (PRTL_OSVERSIONINFOW))
      GetProcAddress (GetModuleHandleW (L"ntdll.dll"), "RtlGetVersion");

  info.dwOSVersionInfoSize = sizeof (info);
  rtl_get_version (&info);

  return info.dwMajorVersion >= 6;
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

  memcpy (image, gum_pe_module_get_data_at_rva (module, 0, NULL),
      gum_pe_module_get_size_of_headers (module));

  gum_pe_module_enumerate_sections (module, gum_copy_section, self);
}

static gboolean
gum_copy_section (const GumPeSectionDetails * details,
                  gpointer user_data)
{
  GumPeMapper * self = user_data;
  guint8 * image = GUM_PE_STAGED (self, self->image_address);
  gconstpointer source;
  gsize available;

  if (details->raw_data_size == 0)
    return TRUE;

  source = gum_pe_module_get_data_at_rva (self->module,
      details->virtual_address, &available);
  memcpy (image + details->virtual_address, source,
      MIN (details->raw_data_size, available));

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
  GumPeMatchOrdinalContext ctx;

  ctx.ordinal = ordinal;
  ctx.rva = 0;
  ctx.found = FALSE;
  gum_pe_module_enumerate_exports (
      _gum_native_module_get_pe_module (GUM_NATIVE_MODULE (module)),
      gum_match_ordinal, &ctx);

  if (!ctx.found)
    return 0;

  return gum_module_get_range (module)->base_address + ctx.rva;
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
  GumAddress dll_base;

  if (!self->has_static_tls)
    return;

  gum_resolve_loader_tls ();

#if defined (HAVE_I386)
  if (self->tls_via_legacy_loader)
  {
    gum_pe_mapper_prepare_legacy_tls (self);
    return;
  }
#endif

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

#if defined (HAVE_I386)

static void
gum_pe_mapper_prepare_legacy_tls (GumPeMapper * self)
{
  GumPeTlsDetails tls;
  GumPeLegacyTlsEntry entry = { 0, };

  self->lock_loader_lock = gum_module_resolver_find_dynamic_address (
      self->resolver, "LdrLockLoaderLock");
  self->unlock_loader_lock = gum_module_resolver_find_dynamic_address (
      self->resolver, "LdrUnlockLoaderLock");
  self->allocate_heap = gum_module_resolver_find_dynamic_address (
      self->resolver, "RtlAllocateHeap");
  self->free_heap = gum_module_resolver_find_dynamic_address (
      self->resolver, "RtlFreeHeap");
  self->create_toolhelp_snapshot = gum_module_resolver_find_dynamic_address (
      self->resolver, "CreateToolhelp32Snapshot");
  self->thread32_first = gum_module_resolver_find_dynamic_address (
      self->resolver, "Thread32First");
  self->thread32_next = gum_module_resolver_find_dynamic_address (
      self->resolver, "Thread32Next");
  self->open_thread = gum_module_resolver_find_dynamic_address (
      self->resolver, "OpenThread");
  self->query_information_thread = gum_module_resolver_find_dynamic_address (
      self->resolver, "NtQueryInformationThread");
  self->close_handle = gum_module_resolver_find_dynamic_address (
      self->resolver, "CloseHandle");

  gum_pe_module_get_tls_details (self->module, &tls);

  entry.tls.StartAddressOfRawData = self->image_address + tls.template_rva;
  entry.tls.EndAddressOfRawData =
      entry.tls.StartAddressOfRawData + tls.template_size;
  entry.tls.AddressOfIndex = self->image_address + tls.index_rva;
  entry.tls.SizeOfZeroFill = tls.zero_fill_size;

  self->tls_entry = gum_process_memory_alloc (self->target,
      GUM_PE_LOADER_ENTRY_SIZE, gum_query_page_size ());
  gum_process_memory_write (self->target, self->tls_entry, &entry,
      sizeof (entry));
}

#endif

static void
gum_resolve_loader_tls (void)
{
  static gsize initialized = 0;

  if (g_once_init_enter (&initialized))
  {
    GumNativeModule * ntdll;
    const GumMemoryRange * range;
    GumAddress base, limit, handle = 0, release = 0, list = 0, count = 0;
    gboolean legacy;

    ntdll = _gum_native_module_make (GetModuleHandleW (L"ntdll.dll"));
    range = gum_module_get_range (GUM_MODULE (ntdll));
    base = range->base_address;
    limit = base + range->size;
    legacy = !gum_loader_supports_dynamic_tls ();

#if defined (HAVE_ARM64)
    gum_resolve_arm64_tls (GUM_MODULE (ntdll), base, limit, &handle, &release);
#else
    if (gum_is_emulated ())
    {
      gum_resolve_arm64_tls (GUM_MODULE (ntdll), base, limit, &handle,
          &release);
# if GLIB_SIZEOF_VOID_P == 4
      gum_resolve_wowa64_dispatch_slots (
          _gum_native_module_get_pe_module (ntdll), base);
# endif
    }
    else
    {
      GumPeX86TlsScanner * scanner;

# if GLIB_SIZEOF_VOID_P == 8
      scanner = gum_scan_x64_loader (_gum_native_module_get_pe_module (ntdll),
          base, limit, legacy);
# else
      scanner = gum_scan_x86_loader (_gum_native_module_get_pe_module (ntdll),
          base, legacy);
# endif

      handle = scanner->handle;
      release = scanner->release;
      list = scanner->list;
      count = scanner->count;

      gum_pe_x86_tls_scanner_free (scanner);
    }
#endif

    g_object_unref (ntdll);

    if (legacy ? (list == 0 || count == 0) : (handle == 0 || release == 0))
      g_error ("Unable to locate the ntdll loader TLS routines");
    gum_ldr_handle_tls_data = GSIZE_TO_POINTER (handle);
    gum_ldr_release_tls_entry = GSIZE_TO_POINTER (release);
    gum_ldrp_tls_list = list;
    gum_ldrp_number_of_tls_entries = count;

    g_once_init_leave (&initialized, 1);
  }
}

#if !defined (HAVE_ARM64)

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

#endif

static void
gum_resolve_arm64_tls (GumModule * ntdll,
                       GumAddress base,
                       GumAddress limit,
                       GumAddress * handle,
                       GumAddress * release)
{
  GHashTable * visited;
  guint i;
  const gchar * anchors[] = { "LdrLoadDll", "LdrUnloadDll" };
  GQueue queue = G_QUEUE_INIT;
  GumPeArm64Flow * flow;
  guint budget = 0;

  visited = g_hash_table_new (NULL, NULL);
  for (i = 0; i != G_N_ELEMENTS (anchors); i++)
  {
    gpointer a = GSIZE_TO_POINTER (
        gum_find_arm64_loader_function (ntdll, anchors[i]));

    g_hash_table_add (visited, a);
    g_queue_push_tail (&queue, a);
  }

  flow = g_new (GumPeArm64Flow, 1);

  while (!g_queue_is_empty (&queue) && (*handle == 0 || *release == 0) &&
      budget++ != 100000)
  {
    GumAddress fn = GPOINTER_TO_SIZE (g_queue_pop_head (&queue));

    if (fn < base || fn >= limit)
      continue;

    gum_pe_arm64_flow_trace (flow, fn, base, limit);

    if (*handle == 0 && gum_pe_arm64_flow_is_handle_tls_data (flow))
      *handle = fn;
    if (*release == 0 && gum_pe_arm64_flow_is_release_tls_entry (flow))
      *release = fn;

    gum_enqueue_arm64_callees (fn, base, limit, visited, &queue);
  }

  g_free (flow);
  g_hash_table_unref (visited);
  g_queue_clear (&queue);
}

static GumAddress
gum_find_arm64_loader_function (GumModule * ntdll,
                                const gchar * name)
{
  GumAddress address = gum_module_find_export_by_name (ntdll, name);

#if defined (HAVE_ARM64)
  return address;
#else
  return GUM_ADDRESS (gum_follow_x86_thunk (GSIZE_TO_POINTER (address)));
#endif
}

#if !defined (HAVE_ARM64)

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

#endif

static void
gum_pe_arm64_flow_trace (GumPeArm64Flow * self,
                         GumAddress function,
                         GumAddress base,
                         GumAddress limit)
{
  guint num_visited = 0, num_pending = 0;
  GumAddress pc = function;
  GumAddress visited[GUM_PE_TLS_HEAD_MAX_INSNS];
  GumAddress pending[GUM_PE_TLS_HEAD_MAX_INSNS];

  gum_pe_arm64_flow_reset (self);

  while (num_visited != GUM_PE_TLS_HEAD_MAX_INSNS)
  {
    if (pc >= base && pc < limit &&
        !gum_address_list_contains (visited, num_visited, pc))
    {
      GumPeArm64Insn insn;

      gum_pe_arm64_insn_decode (*((const guint32 *) GSIZE_TO_POINTER (pc)),
          &insn);
      visited[num_visited++] = pc;

      if (insn.kind == GUM_PE_ARM64_INSN_JUMP)
      {
        pc += insn.imm;
        continue;
      }

      if (insn.kind != GUM_PE_ARM64_INSN_EXIT)
      {
        if (insn.kind == GUM_PE_ARM64_INSN_BRANCH_IF)
          pending[num_pending++] = pc + insn.imm;
        gum_pe_arm64_flow_step (self, &insn, pc, base, limit);
        pc += sizeof (guint32);
        continue;
      }
    }

    if (num_pending == 0)
      return;
    pc = pending[--num_pending];
  }
}

static void
gum_pe_arm64_flow_reset (GumPeArm64Flow * self)
{
  guint i;

  self->num_values = 0;
  self->num_events = 0;
  self->num_calls = 0;

  gum_pe_arm64_flow_intern (self, GUM_PE_ARM64_VALUE_UNKNOWN, 0, 0);
  gum_pe_arm64_flow_intern (self, GUM_PE_ARM64_VALUE_ENTRY, 0, 0);
  gum_pe_arm64_flow_intern (self, GUM_PE_ARM64_VALUE_STACK, 0, 0);

  for (i = 0; i != G_N_ELEMENTS (self->regs); i++)
    self->regs[i] = GUM_PE_ARM64_UNKNOWN;
  self->regs[0] = GUM_PE_ARM64_ENTRY;
}

static guint
gum_pe_arm64_flow_intern (GumPeArm64Flow * self,
                          GumPeArm64ValueKind kind,
                          guint parent,
                          gint64 offset)
{
  guint i;
  GumPeArm64Value * value;

  for (i = 0; i != self->num_values; i++)
  {
    value = &self->values[i];
    if (value->kind == kind && value->parent == parent &&
        value->offset == offset)
      return i;
  }

  value = &self->values[self->num_values];
  value->kind = kind;
  value->parent = parent;
  value->offset = offset;

  return self->num_values++;
}

static gboolean
gum_address_list_contains (const GumAddress * addresses,
                           guint n,
                           GumAddress address)
{
  guint i;

  for (i = 0; i != n; i++)
  {
    if (addresses[i] == address)
      return TRUE;
  }

  return FALSE;
}

static void
gum_pe_arm64_insn_decode (guint32 code,
                          GumPeArm64Insn * insn)
{
  insn->kind = GUM_PE_ARM64_INSN_OTHER;
  insn->rt = code & 0x1f;
  insn->rt2 = (code >> 10) & 0x1f;
  insn->rn = (code >> 5) & 0x1f;
  insn->rm = (code >> 16) & 0x1f;
  insn->imm = 0;
  insn->size = 0;

  if ((code & 0x7fe0ffe0) == 0x2a0003e0)
  {
    insn->kind = (insn->rm == GUM_PE_ARM64_ZR)
        ? GUM_PE_ARM64_INSN_MOV_IMM
        : GUM_PE_ARM64_INSN_MOV_REG;
  }
  else if ((code & 0x7f800000) == 0x52800000)
  {
    insn->kind = GUM_PE_ARM64_INSN_MOV_IMM;
    insn->imm = (gint64) ((code >> 5) & 0xffff) << (((code >> 21) & 3) * 16);
  }
  else if ((code & 0x7f800000) == 0x11000000)
  {
    insn->kind = GUM_PE_ARM64_INSN_ADD_IMM;
    insn->imm = ((code >> 10) & 0xfff) << (((code >> 22) & 1) * 12);
  }
  else if ((code & 0x7f800000) == 0x12000000)
  {
    insn->kind = GUM_PE_ARM64_INSN_AND_IMM;
  }
  else if ((code & 0x3fc00000) == 0x39400000)
  {
    insn->kind = GUM_PE_ARM64_INSN_LOAD;
    insn->size = 1 << (code >> 30);
    insn->imm = ((code >> 10) & 0xfff) * insn->size;
  }
  else if ((code & 0x3fc00000) == 0x39000000)
  {
    insn->kind = GUM_PE_ARM64_INSN_STORE;
    insn->size = 1 << (code >> 30);
    insn->imm = ((code >> 10) & 0xfff) * insn->size;
  }
  else if ((code & 0x3e400000) == 0x28400000)
  {
    insn->kind = GUM_PE_ARM64_INSN_LOAD_PAIR;
    insn->size = ((code >> 31) != 0) ? 8 : 4;
    if (((code >> 23) & 3) != 1)
      insn->imm = gum_sign_extend ((code >> 15) & 0x7f, 7) * insn->size;
  }
  else if ((code & 0x3e400000) == 0x28000000)
  {
    insn->kind = GUM_PE_ARM64_INSN_OTHER;
  }
  else if ((code & 0xfc000000) == 0x94000000)
  {
    insn->kind = GUM_PE_ARM64_INSN_CALL;
    insn->imm = gum_sign_extend (code & 0x3ffffff, 26) * 4;
  }
  else if ((code & 0xfffffc1f) == 0xd63f0000)
  {
    insn->kind = GUM_PE_ARM64_INSN_CALL_INDIRECT;
  }
  else if ((code & 0xfc000000) == 0x14000000)
  {
    insn->kind = GUM_PE_ARM64_INSN_JUMP;
    insn->imm = gum_sign_extend (code & 0x3ffffff, 26) * 4;
  }
  else if ((code & 0xff000010) == 0x54000000 ||
      (code & 0x7e000000) == 0x34000000)
  {
    insn->kind = GUM_PE_ARM64_INSN_BRANCH_IF;
    insn->imm = gum_sign_extend ((code >> 5) & 0x7ffff, 19) * 4;
  }
  else if ((code & 0x7e000000) == 0x36000000)
  {
    insn->kind = GUM_PE_ARM64_INSN_BRANCH_IF;
    insn->imm = gum_sign_extend ((code >> 5) & 0x3fff, 14) * 4;
  }
  else if (code == GUM_ARM64_RET || (code & 0xfffffc1f) == 0xd61f0000 ||
      (code & 0xffe0001f) == 0xd4200000)
  {
    insn->kind = GUM_PE_ARM64_INSN_EXIT;
  }
  else if ((code & 0x7f200000) == 0x0a200000)
  {
    insn->kind = GUM_PE_ARM64_INSN_CLEAR_BITS;
  }
  else if ((code & 0x7f2003e0) == 0x2a2003e0)
  {
    insn->kind = GUM_PE_ARM64_INSN_INVERT;
  }
  else if ((code & 0x7f200000) == 0x0a000000)
  {
    insn->kind = GUM_PE_ARM64_INSN_AND_REG;
  }
  else if (gum_arm64_code_writes_rt (code))
  {
    insn->kind = GUM_PE_ARM64_INSN_WRITE;
  }
}

static gint64
gum_sign_extend (guint32 value,
                 guint bits)
{
  guint shift = 64 - bits;

  return ((gint64) ((guint64) value << shift)) >> shift;
}

static gboolean
gum_arm64_code_writes_rt (guint32 code)
{
  if ((code & 0x1c000000) == 0x10000000 || (code & 0x0e000000) == 0x0a000000)
    return TRUE;

  if ((code & 0x0a000000) != 0x08000000 || (code & 0x04000000) != 0)
    return FALSE;

  switch ((code >> 27) & 7)
  {
    case 3:
      return TRUE;
    case 7:
      return (code & 0x00c00000) != 0 ||
          (code & 0x00200c00) == 0x00200000;
    default:
      return (code & 0x00400000) != 0;
  }
}

static void
gum_pe_arm64_flow_step (GumPeArm64Flow * self,
                        const GumPeArm64Insn * insn,
                        GumAddress pc,
                        GumAddress base,
                        GumAddress limit)
{
  guint address;

  switch (insn->kind)
  {
    case GUM_PE_ARM64_INSN_MOV_REG:
      gum_pe_arm64_flow_set (self, insn->rt, self->regs[insn->rm]);
      break;
    case GUM_PE_ARM64_INSN_MOV_IMM:
      gum_pe_arm64_flow_set (self, insn->rt, gum_pe_arm64_flow_intern (self,
          GUM_PE_ARM64_VALUE_CONSTANT, 0, insn->imm));
      break;
    case GUM_PE_ARM64_INSN_ADD_IMM:
      gum_pe_arm64_flow_set (self, insn->rt,
          gum_pe_arm64_flow_resolve_address (self, insn->rn, insn->imm));
      break;
    case GUM_PE_ARM64_INSN_AND_IMM:
      gum_pe_arm64_flow_set (self, insn->rt, gum_pe_arm64_flow_mask (self,
          gum_pe_arm64_flow_get (self, insn->rn)));
      break;
    case GUM_PE_ARM64_INSN_LOAD:
      address = gum_pe_arm64_flow_resolve_address (self, insn->rn, insn->imm);
      gum_pe_arm64_flow_add_event (self, GUM_PE_ARM64_EVENT_LOAD,
          GUM_PE_ARM64_UNKNOWN, address, insn->size);
      gum_pe_arm64_flow_set (self, insn->rt,
          gum_pe_arm64_flow_load (self, address, 0));
      break;
    case GUM_PE_ARM64_INSN_LOAD_PAIR:
      address = gum_pe_arm64_flow_resolve_address (self, insn->rn, insn->imm);
      gum_pe_arm64_flow_set (self, insn->rt,
          gum_pe_arm64_flow_load (self, address, 0));
      gum_pe_arm64_flow_set (self, insn->rt2,
          gum_pe_arm64_flow_load (self, address, insn->size));
      break;
    case GUM_PE_ARM64_INSN_STORE:
      gum_pe_arm64_flow_add_event (self, GUM_PE_ARM64_EVENT_STORE,
          self->regs[insn->rt],
          gum_pe_arm64_flow_resolve_address (self, insn->rn, insn->imm),
          insn->size);
      break;
    case GUM_PE_ARM64_INSN_CALL:
      if (!gum_pe_arm64_call_preserves_arguments (pc + insn->imm, base, limit))
        gum_pe_arm64_flow_call (self);
      break;
    case GUM_PE_ARM64_INSN_CALL_INDIRECT:
      gum_pe_arm64_flow_call (self);
      break;
    case GUM_PE_ARM64_INSN_CLEAR_BITS:
      gum_pe_arm64_flow_clear_bits (self, insn->rt);
      break;
    case GUM_PE_ARM64_INSN_INVERT:
      gum_pe_arm64_flow_set (self, insn->rt, gum_pe_arm64_flow_intern (self,
          GUM_PE_ARM64_VALUE_INVERTED, self->regs[insn->rm], 0));
      break;
    case GUM_PE_ARM64_INSN_AND_REG:
      if (gum_pe_arm64_flow_is_inverted (self, insn->rn) ||
          gum_pe_arm64_flow_is_inverted (self, insn->rm))
        gum_pe_arm64_flow_clear_bits (self, insn->rt);
      else
        gum_pe_arm64_flow_set (self, insn->rt, GUM_PE_ARM64_UNKNOWN);
      break;
    case GUM_PE_ARM64_INSN_WRITE:
      gum_pe_arm64_flow_set (self, insn->rt, GUM_PE_ARM64_UNKNOWN);
      break;
    default:
      break;
  }
}

static void
gum_pe_arm64_flow_set (GumPeArm64Flow * self,
                       guint reg,
                       guint value)
{
  if (reg != GUM_PE_ARM64_ZR)
    self->regs[reg] = value;
}

static guint
gum_pe_arm64_flow_resolve_address (GumPeArm64Flow * self,
                                   guint reg,
                                   gint64 offset)
{
  guint base = gum_pe_arm64_flow_get (self, reg);
  const GumPeArm64Value * value = &self->values[base];

  if (base == GUM_PE_ARM64_UNKNOWN)
    return GUM_PE_ARM64_UNKNOWN;

  if (value->kind == GUM_PE_ARM64_VALUE_ADDRESS)
  {
    return gum_pe_arm64_flow_intern (self, GUM_PE_ARM64_VALUE_ADDRESS,
        value->parent, value->offset + offset);
  }

  return gum_pe_arm64_flow_intern (self, GUM_PE_ARM64_VALUE_ADDRESS, base,
      offset);
}

static guint
gum_pe_arm64_flow_get (GumPeArm64Flow * self,
                       guint reg)
{
  return (reg == GUM_PE_ARM64_SP) ? GUM_PE_ARM64_STACK : self->regs[reg];
}

static guint
gum_pe_arm64_flow_mask (GumPeArm64Flow * self,
                        guint value)
{
  return (self->values[value].kind == GUM_PE_ARM64_VALUE_LOAD)
      ? value
      : GUM_PE_ARM64_UNKNOWN;
}

static void
gum_pe_arm64_flow_add_event (GumPeArm64Flow * self,
                             GumPeArm64EventKind kind,
                             guint value,
                             guint address,
                             guint size)
{
  GumPeArm64Event * event = &self->events[self->num_events++];

  event->kind = kind;
  event->value = value;
  event->address = address;
  event->size = size;
}

static guint
gum_pe_arm64_flow_load (GumPeArm64Flow * self,
                        guint address,
                        gint64 offset)
{
  const GumPeArm64Value * value = &self->values[address];

  if (address == GUM_PE_ARM64_UNKNOWN)
    return GUM_PE_ARM64_UNKNOWN;

  return gum_pe_arm64_flow_intern (self, GUM_PE_ARM64_VALUE_LOAD,
      value->parent, value->offset + offset);
}

static gboolean
gum_pe_arm64_call_preserves_arguments (GumAddress target,
                                       GumAddress base,
                                       GumAddress limit)
{
  const guint32 * code = GSIZE_TO_POINTER (target);
  guint i;

  if (target < base || target + (8 * sizeof (guint32)) > limit)
    return FALSE;

  for (i = 0; i != 8; i++)
  {
    GumPeArm64Insn insn;

    gum_pe_arm64_insn_decode (code[i], &insn);

    switch (insn.kind)
    {
      case GUM_PE_ARM64_INSN_EXIT:
        return code[i] == GUM_ARM64_RET;
      case GUM_PE_ARM64_INSN_CALL:
      case GUM_PE_ARM64_INSN_CALL_INDIRECT:
      case GUM_PE_ARM64_INSN_JUMP:
      case GUM_PE_ARM64_INSN_BRANCH_IF:
        return FALSE;
      case GUM_PE_ARM64_INSN_LOAD_PAIR:
        if (insn.rt < GUM_PE_ARM64_IP0 ||
            insn.rt2 < GUM_PE_ARM64_IP0)
          return FALSE;
        break;
      case GUM_PE_ARM64_INSN_STORE:
      case GUM_PE_ARM64_INSN_OTHER:
        break;
      default:
        if (insn.rt < GUM_PE_ARM64_IP0)
          return FALSE;
        break;
    }
  }

  return FALSE;
}

static void
gum_pe_arm64_flow_call (GumPeArm64Flow * self)
{
  GumPeArm64Event * event = &self->events[self->num_events++];
  guint i;

  event->kind = GUM_PE_ARM64_EVENT_CALL;
  memcpy (event->args, self->regs, sizeof (event->args));
  event->value = gum_pe_arm64_flow_intern (self,
      GUM_PE_ARM64_VALUE_CALL_RESULT, 0, self->num_calls++);

  for (i = 0; i != GUM_PE_ARM64_PLATFORM_REG; i++)
    self->regs[i] = GUM_PE_ARM64_UNKNOWN;
  self->regs[0] = event->value;
}

static void
gum_pe_arm64_flow_clear_bits (GumPeArm64Flow * self,
                              guint reg)
{
  gum_pe_arm64_flow_add_event (self, GUM_PE_ARM64_EVENT_CLEAR_BITS,
      GUM_PE_ARM64_UNKNOWN, GUM_PE_ARM64_UNKNOWN, 0);
  gum_pe_arm64_flow_set (self, reg, GUM_PE_ARM64_UNKNOWN);
}

static gboolean
gum_pe_arm64_flow_is_inverted (GumPeArm64Flow * self,
                               guint reg)
{
  return self->values[gum_pe_arm64_flow_get (self, reg)].kind ==
      GUM_PE_ARM64_VALUE_INVERTED;
}

static gboolean
gum_pe_arm64_flow_is_handle_tls_data (GumPeArm64Flow * self)
{
  guint dll_base, tls_directory;
  guint out_values[GUM_PE_TLS_HEAD_MAX_INSNS];
  guint num_out_values = 0;
  guint i;

  dll_base = gum_pe_arm64_flow_intern (self, GUM_PE_ARM64_VALUE_LOAD,
      GUM_PE_ARM64_ENTRY, GUM_PE_LOADER_ENTRY_DLL_BASE_OFFSET);
  tls_directory = gum_pe_arm64_flow_intern (self,
      GUM_PE_ARM64_VALUE_CONSTANT, 0, GUM_PE_DIRECTORY_TLS);

  for (i = 0; i != self->num_events; i++)
  {
    const GumPeArm64Event * event = &self->events[i];

    if (event->kind == GUM_PE_ARM64_EVENT_CALL &&
        (event->args[0] == dll_base || event->args[1] == dll_base))
    {
      const GumPeArm64Value * out = &self->values[event->args[3]];

      if (event->args[2] == tls_directory)
        return TRUE;

      if (out->kind == GUM_PE_ARM64_VALUE_ADDRESS)
      {
        out_values[num_out_values++] = gum_pe_arm64_flow_intern (self,
            GUM_PE_ARM64_VALUE_LOAD, out->parent, out->offset);
      }
    }
    else if (event->kind == GUM_PE_ARM64_EVENT_LOAD &&
        event->size == sizeof (guint32) &&
        event->address != GUM_PE_ARM64_UNKNOWN)
    {
      const GumPeArm64Value * address = &self->values[event->address];

      if (address->offset == GUM_PE_NT_HEADERS_TLS_DIRECTORY_OFFSET &&
          gum_uint_list_contains (out_values, num_out_values,
              address->parent))
        return TRUE;
    }
  }

  return FALSE;
}

static gboolean
gum_uint_list_contains (const guint * values,
                        guint n,
                        guint value)
{
  guint i;

  for (i = 0; i != n; i++)
  {
    if (values[i] == value)
      return TRUE;
  }

  return FALSE;
}

static gboolean
gum_pe_arm64_flow_is_release_tls_entry (GumPeArm64Flow * self)
{
  guint record = GUM_PE_ARM64_UNKNOWN, flink = 0, blink = 0;
  guint flink_back_link = 0, blink_forward_link = 0;
  gboolean unlinked_blink = FALSE, unlinked_flink = FALSE;
  guint i;

  for (i = 0; i != self->num_events; i++)
  {
    const GumPeArm64Event * event = &self->events[i];

    if (record == GUM_PE_ARM64_UNKNOWN)
    {
      if (event->kind == GUM_PE_ARM64_EVENT_CALL &&
          event->args[0] == GUM_PE_ARM64_ENTRY)
      {
        record = event->value;
        flink = gum_pe_arm64_flow_intern (self, GUM_PE_ARM64_VALUE_LOAD,
            record, 0);
        blink = gum_pe_arm64_flow_intern (self, GUM_PE_ARM64_VALUE_LOAD,
            record, GLIB_SIZEOF_VOID_P);
        flink_back_link = gum_pe_arm64_flow_intern (self,
            GUM_PE_ARM64_VALUE_ADDRESS, flink, GLIB_SIZEOF_VOID_P);
        blink_forward_link = gum_pe_arm64_flow_intern (self,
            GUM_PE_ARM64_VALUE_ADDRESS, blink, 0);
      }
      continue;
    }

    if (event->kind == GUM_PE_ARM64_EVENT_STORE)
    {
      if (event->value == flink && event->address == blink_forward_link)
        unlinked_blink = TRUE;
      if (event->value == blink && event->address == flink_back_link)
        unlinked_flink = TRUE;
    }
    else if (unlinked_blink && unlinked_flink &&
        (event->kind == GUM_PE_ARM64_EVENT_CLEAR_BITS ||
         (event->kind == GUM_PE_ARM64_EVENT_CALL &&
          gum_pe_arm64_flow_passes_field_of (self, event, record))))
    {
      return TRUE;
    }
  }

  return FALSE;
}

static gboolean
gum_pe_arm64_flow_passes_field_of (GumPeArm64Flow * self,
                                   const GumPeArm64Event * event,
                                   guint record)
{
  guint i;

  for (i = 0; i != G_N_ELEMENTS (event->args); i++)
  {
    const GumPeArm64Value * arg = &self->values[event->args[i]];

    if (arg->kind == GUM_PE_ARM64_VALUE_LOAD && arg->parent == record)
      return TRUE;
  }

  return FALSE;
}

static void
gum_enqueue_arm64_callees (GumAddress function,
                           GumAddress base,
                           GumAddress limit,
                           GHashTable * visited,
                           GQueue * queue)
{
  GHashTable * seen;
  GQueue pending = G_QUEUE_INIT;

  seen = g_hash_table_new (NULL, NULL);
  g_queue_push_tail (&pending, GSIZE_TO_POINTER (function));

  while (!g_queue_is_empty (&pending))
  {
    GumAddress pc = GPOINTER_TO_SIZE (g_queue_pop_tail (&pending));

    while (pc >= base && pc < limit &&
        g_hash_table_size (seen) != GUM_PE_ARM64_MAX_FUNCTION_INSNS &&
        g_hash_table_add (seen, GSIZE_TO_POINTER (pc)))
    {
      GumPeArm64Insn insn;
      GumAddress target;

      gum_pe_arm64_insn_decode (*((const guint32 *) GSIZE_TO_POINTER (pc)),
          &insn);

      if (insn.kind == GUM_PE_ARM64_INSN_JUMP)
      {
        pc += insn.imm;
        continue;
      }

      if (insn.kind == GUM_PE_ARM64_INSN_EXIT)
        break;

      target = pc + insn.imm;
      if (insn.kind == GUM_PE_ARM64_INSN_BRANCH_IF)
      {
        g_queue_push_tail (&pending, GSIZE_TO_POINTER (target));
      }
      else if (insn.kind == GUM_PE_ARM64_INSN_CALL && target >= base &&
          target < limit && g_hash_table_add (visited,
              GSIZE_TO_POINTER (target)))
      {
        g_queue_push_tail (queue, GSIZE_TO_POINTER (target));
      }

      pc += sizeof (guint32);
    }
  }

  g_queue_clear (&pending);
  g_hash_table_unref (seen);
}

#if !defined (HAVE_ARM64)

# if GLIB_SIZEOF_VOID_P == 8

static GumPeX86TlsScanner *
gum_scan_x64_loader (GumPeModule * ntdll,
                     GumAddress base,
                     GumAddress limit,
                     gboolean legacy)
{
  GumPeX86TlsScanner * scanner;

  scanner = gum_pe_x86_tls_scanner_new (CS_MODE_64, base, limit, legacy);

  gum_pe_module_enumerate_function_starts (ntdll, gum_scan_x64_function,
      scanner);

  return scanner;
}

static gboolean
gum_scan_x64_function (GumAddress rva,
                       gpointer user_data)
{
  GumPeX86TlsScanner * scanner = user_data;

  return gum_pe_x86_tls_scanner_consider (scanner, scanner->base + rva);
}

# else

static void
gum_resolve_wowa64_dispatch_slots (GumPeModule * ntdll,
                                   GumAddress base)
{
  const GumPeChpeMetadataX86 * metadata;

  metadata = gum_pe_module_get_data_at_rva (ntdll,
      gum_pe_module_get_chpe_metadata_rva (ntdll), NULL);

  gum_dispatch_icall_slot =
      base + metadata->dispatch_indirect_call_function_pointer;
  gum_dispatch_icall_cfg_slot =
      base + metadata->dispatch_indirect_call_cfg_function_pointer;
}

static GumPeX86TlsScanner *
gum_scan_x86_loader (GumPeModule * ntdll,
                     GumAddress base,
                     gboolean legacy)
{
  GumMemoryRange text;
  GumAddress text_start, text_end;
  GArray * functions;
  GumPeX86TlsScanner * scanner;
  guint i;

  gum_pe_module_enumerate_sections (ntdll, gum_find_text_section, &text);
  text_start = base + text.base_address;
  text_end = text_start + text.size;

  functions = gum_collect_x86_call_targets (text_start, text_end);
  scanner = gum_pe_x86_tls_scanner_new (CS_MODE_32, text_start, text_end,
      legacy);

  for (i = 0; i != functions->len; i++)
  {
    if (!gum_pe_x86_tls_scanner_consider (scanner,
        g_array_index (functions, GumAddress, i)))
      break;
  }

  g_array_unref (functions);

  return scanner;
}

static gboolean
gum_find_text_section (const GumPeSectionDetails * details,
                       gpointer user_data)
{
  GumMemoryRange * text = user_data;

  if (strcmp (details->name, ".text") != 0)
    return TRUE;

  text->base_address = details->virtual_address;
  text->size = details->virtual_size;

  return FALSE;
}

static GArray *
gum_collect_x86_call_targets (GumAddress base,
                              GumAddress limit)
{
  GArray * targets;
  GHashTable * seen;
  csh cs;
  cs_insn * insn;
  const uint8_t * code = GSIZE_TO_POINTER (base);
  size_t code_size = limit - base;
  uint64_t address = base;

  targets = g_array_new (FALSE, FALSE, sizeof (GumAddress));
  seen = g_hash_table_new (NULL, NULL);

  cs_arch_register_x86 ();
  cs_open (CS_ARCH_X86, CS_MODE_32, &cs);
  cs_option (cs, CS_OPT_DETAIL, CS_OPT_ON);
  cs_option (cs, CS_OPT_SKIPDATA, CS_OPT_ON);
  insn = cs_malloc (cs);

  while (cs_disasm_iter (cs, &code, &code_size, &address, insn))
  {
    const cs_x86 * d = &insn->detail->x86;
    GumAddress target;

    if (insn->id != X86_INS_CALL || d->op_count != 1 ||
        d->operands[0].type != X86_OP_IMM)
      continue;

    target = d->operands[0].imm;
    if (target < base || target >= limit ||
        !g_hash_table_add (seen, GSIZE_TO_POINTER (target)))
      continue;

    g_array_append_val (targets, target);
  }

  cs_free (insn, 1);
  cs_close (&cs);

  g_hash_table_unref (seen);

  g_array_sort (targets, gum_compare_addresses);

  return targets;
}

static gint
gum_compare_addresses (gconstpointer a,
                       gconstpointer b)
{
  GumAddress lhs = *((const GumAddress *) a);
  GumAddress rhs = *((const GumAddress *) b);

  if (lhs < rhs)
    return -1;
  if (lhs > rhs)
    return 1;
  return 0;
}

# endif

#endif

#if defined (HAVE_I386)

static GumPeX86TlsScanner *
gum_pe_x86_tls_scanner_new (cs_mode mode,
                            GumAddress base,
                            GumAddress limit,
                            gboolean legacy)
{
  GumPeX86TlsScanner * scanner;

  scanner = g_new0 (GumPeX86TlsScanner, 1);

  cs_arch_register_x86 ();
  cs_open (CS_ARCH_X86, mode, &scanner->cs);
  cs_option (scanner->cs, CS_OPT_DETAIL, CS_OPT_ON);
  scanner->insn = cs_malloc (scanner->cs);

  scanner->base = base;
  scanner->limit = limit;
  scanner->legacy = legacy;

  return scanner;
}

static gboolean
gum_pe_x86_tls_scanner_consider (GumPeX86TlsScanner * self,
                                 GumAddress function)
{
  GumPeX86FunctionHead * head = &self->head;

  gum_pe_x86_tls_scanner_read_head (self, function);

  if (self->legacy)
  {
    return !gum_function_is_ldrp_allocate_tls (head, &self->list,
        &self->count);
  }

  if (self->handle == 0 && gum_function_is_ldr_handle_tls_data (head))
    self->handle = function;
  if (self->release == 0 && gum_function_is_ldr_release_tls_entry (head))
    self->release = function;

  return self->handle == 0 || self->release == 0;
}

static void
gum_pe_x86_tls_scanner_free (GumPeX86TlsScanner * scanner)
{
  cs_free (scanner->insn, 1);
  cs_close (&scanner->cs);

  g_free (scanner);
}

static void
gum_pe_x86_tls_scanner_read_head (GumPeX86TlsScanner * self,
                                  GumAddress function)
{
  GumPeX86FunctionHead * head = &self->head;
  cs_insn * insn = self->insn;
  GumAddress pending[GUM_PE_TLS_HEAD_MAX_INSNS];
  guint num_pending = 0;
  GumAddress pc = function;

  head->count = 0;

  while (head->count != GUM_PE_TLS_HEAD_MAX_INSNS)
  {
    const uint8_t * code = GSIZE_TO_POINTER (pc);
    size_t code_size = MIN (16, self->limit - pc);
    uint64_t address = pc;

    if (!gum_pe_x86_function_head_contains (head, pc) &&
        cs_disasm_iter (self->cs, &code, &code_size, &address, insn))
    {
      GumAddress target = gum_pe_x86_tls_scanner_resolve_jump (self, insn);

      gum_pe_x86_function_head_append (head, insn);

      if (insn->id == X86_INS_JMP && target != 0)
      {
        pc = target;
        continue;
      }

      if (insn->id != X86_INS_JMP && insn->id != X86_INS_RET &&
          insn->id != X86_INS_INT3)
      {
        if (target != 0)
          pending[num_pending++] = target;
        pc = address;
        continue;
      }
    }

    if (num_pending == 0)
      return;
    pc = pending[--num_pending];
  }
}

static gboolean
gum_pe_x86_function_head_contains (const GumPeX86FunctionHead * head,
                                   GumAddress address)
{
  size_t i;

  for (i = 0; i != head->count; i++)
  {
    if (head->insns[i].address == address)
      return TRUE;
  }

  return FALSE;
}

static GumAddress
gum_pe_x86_tls_scanner_resolve_jump (GumPeX86TlsScanner * self,
                                     const cs_insn * insn)
{
  const cs_x86 * d = &insn->detail->x86;
  GumAddress target;

  if (!cs_insn_group (self->cs, insn, CS_GRP_JUMP) || d->op_count != 1 ||
      d->operands[0].type != X86_OP_IMM)
    return 0;

  target = d->operands[0].imm;
  if (target < self->base || target >= self->limit)
    return 0;

  return target;
}

static void
gum_pe_x86_function_head_append (GumPeX86FunctionHead * head,
                                 const cs_insn * insn)
{
  cs_insn * slot = &head->insns[head->count];
  cs_detail * detail = &head->details[head->count];

  *slot = *insn;
  *detail = *insn->detail;
  slot->detail = detail;

  head->count++;
}

static gboolean
gum_function_is_ldrp_allocate_tls (const GumPeX86FunctionHead * head,
                                   GumAddress * list,
                                   GumAddress * count)
{
  GumAddress first_counter = 0, list_head = 0;
  x86_reg teb_regs[8];
  guint num_teb_regs = 0;
  gboolean stored_tls_pointer = FALSE, compared_list_head = FALSE;
  size_t i;

  for (i = 0; i != head->count; i++)
  {
    const cs_insn * insn = &head->insns[i];
    const cs_x86 * d = &insn->detail->x86;
    const cs_x86_op * dst = &d->operands[0];
    const cs_x86_op * src = &d->operands[1];
    gboolean is_mov = insn->id == X86_INS_MOV && d->op_count == 2;

    if (first_counter == 0)
      first_counter = gum_x86_insn_find_global_u32 (insn);

    if (list_head != 0 && gum_x86_insn_references_address (insn, list_head))
      compared_list_head = TRUE;

    if (is_mov && gum_x86_op_is_field_of (dst, teb_regs, num_teb_regs) &&
        dst->mem.disp == GUM_PE_TEB_TLS_POINTER_OFFSET)
    {
      stored_tls_pointer = TRUE;
    }
    else if (stored_tls_pointer && list_head == 0 && is_mov &&
        dst->type == X86_OP_REG && src->size == GLIB_SIZEOF_VOID_P)
    {
      list_head = gum_x86_op_resolve_global (insn, src);
    }

    if (is_mov && dst->type == X86_OP_REG &&
        (gum_x86_op_is_teb_self (src) || (src->type == X86_OP_REG &&
            gum_reg_set_contains (teb_regs, num_teb_regs, src->reg))))
    {
      gum_reg_set_add (teb_regs, &num_teb_regs, dst->reg);
    }
  }

  if (first_counter == 0 || !compared_list_head)
    return FALSE;

  *list = list_head;
  *count = first_counter;

  return TRUE;
}

static GumAddress
gum_x86_insn_find_global_u32 (const cs_insn * insn)
{
  const cs_x86 * d = &insn->detail->x86;
  uint8_t i;

  for (i = 0; i != d->op_count; i++)
  {
    const cs_x86_op * op = &d->operands[i];

    if (op->size == sizeof (guint32))
    {
      GumAddress address = gum_x86_op_resolve_global (insn, op);
      if (address != 0)
        return address;
    }
  }

  return 0;
}

static gboolean
gum_x86_insn_references_address (const cs_insn * insn,
                                 GumAddress address)
{
  const cs_x86 * d = &insn->detail->x86;
  uint8_t i;

  for (i = 0; i != d->op_count; i++)
  {
    const cs_x86_op * op = &d->operands[i];

    if (op->type == X86_OP_IMM && (GumAddress) op->imm == address)
      return TRUE;

    if (insn->id == X86_INS_LEA &&
        gum_x86_op_resolve_global (insn, op) == address)
      return TRUE;
  }

  return FALSE;
}

static GumAddress
gum_x86_op_resolve_global (const cs_insn * insn,
                           const cs_x86_op * op)
{
  if (op->type != X86_OP_MEM || op->mem.segment != X86_REG_INVALID ||
      op->mem.index != X86_REG_INVALID)
    return 0;

#if GLIB_SIZEOF_VOID_P == 8
  if (op->mem.base != X86_REG_RIP)
    return 0;

  return insn->address + insn->size + op->mem.disp;
#else
  if (op->mem.base != X86_REG_INVALID)
    return 0;

  return (guint32) op->mem.disp;
#endif
}

static gboolean
gum_x86_op_is_teb_self (const cs_x86_op * op)
{
  return op->type == X86_OP_MEM &&
      op->mem.segment == GUM_PE_TEB_SEGMENT_REG &&
      op->mem.base == X86_REG_INVALID &&
      op->mem.index == X86_REG_INVALID &&
      op->mem.disp == GUM_PE_TEB_SELF_OFFSET;
}

static gboolean
gum_function_is_ldr_handle_tls_data (const GumPeX86FunctionHead * head)
{
  x86_reg entry_regs[8];
  guint num_entry_regs = 1;
  gboolean passed_tls_directory = FALSE, read_dll_base = FALSE;
  size_t i;

  entry_regs[0] = GUM_PE_TLS_ENTRY_REG;

  for (i = 0; i != head->count; i++)
  {
    const cs_insn * insn = &head->insns[i];

    if (insn->id == X86_INS_CALL)
    {
      if (passed_tls_directory && read_dll_base)
        return TRUE;
      passed_tls_directory = FALSE;
      read_dll_base = FALSE;
      continue;
    }

    if (gum_x86_insn_passes_tls_directory (insn))
      passed_tls_directory = TRUE;

    if (gum_x86_insn_reads_dll_base (insn, entry_regs, num_entry_regs))
      read_dll_base = TRUE;

    gum_entry_regs_track (entry_regs, &num_entry_regs, insn);
  }

  return FALSE;
}

static gboolean
gum_x86_insn_passes_tls_directory (const cs_insn * insn)
{
  const cs_x86 * d = &insn->detail->x86;
#if GLIB_SIZEOF_VOID_P == 8
  const cs_x86_op * dst = &d->operands[0];
  const cs_x86_op * src = &d->operands[1];

  if (d->op_count != 2 || dst->type != X86_OP_REG ||
      (dst->reg != X86_REG_R8D && dst->reg != X86_REG_R8W))
    return FALSE;

  switch (insn->id)
  {
    case X86_INS_MOV:
      return src->type == X86_OP_IMM && src->imm == GUM_PE_DIRECTORY_TLS;
    case X86_INS_LEA:
      return src->mem.index == X86_REG_INVALID &&
          src->mem.disp == GUM_PE_DIRECTORY_TLS;
    default:
      return FALSE;
  }
#else
  return insn->id == X86_INS_PUSH && d->op_count == 1 &&
      d->operands[0].type == X86_OP_IMM &&
      d->operands[0].imm == GUM_PE_DIRECTORY_TLS;
#endif
}

static gboolean
gum_x86_insn_reads_dll_base (const cs_insn * insn,
                             const x86_reg * entry_regs,
                             guint num_entry_regs)
{
  const cs_x86 * d = &insn->detail->x86;
  const cs_x86_op * src;

  if (insn->id == X86_INS_MOV && d->op_count == 2)
    src = &d->operands[1];
  else if (insn->id == X86_INS_PUSH && d->op_count == 1)
    src = &d->operands[0];
  else
    return FALSE;

  return gum_x86_op_is_field_of (src, entry_regs, num_entry_regs) &&
      src->mem.disp == GUM_PE_LOADER_ENTRY_DLL_BASE_OFFSET;
}

static gboolean
gum_function_is_ldr_release_tls_entry (const GumPeX86FunctionHead * head)
{
  x86_reg entry_regs[8], found_regs[8], flink_regs[8], blink_regs[8];
  guint num_entry_regs = 1, num_found_regs = 0, num_flink_regs = 0,
      num_blink_regs = 0;
  gboolean passing_entry = TRUE, looked_up_entry = FALSE;
  gboolean unlinked_blink = FALSE, unlinked_flink = FALSE;
  gboolean pushed_found_field = FALSE, cleared_bit = FALSE;
  x86_reg inverted_reg = X86_REG_INVALID;
  size_t i;

  entry_regs[0] = GUM_PE_TLS_ENTRY_REG;

  for (i = 0; i != head->count; i++)
  {
    const cs_insn * insn = &head->insns[i];
    const cs_x86 * d = &insn->detail->x86;
    const cs_x86_op * dst = &d->operands[0];
    const cs_x86_op * src = &d->operands[1];
    gboolean is_mov = insn->id == X86_INS_MOV && d->op_count == 2;
    gboolean loads_link = is_mov && dst->type == X86_OP_REG &&
        gum_x86_op_is_field_of (src, found_regs, num_found_regs);

    if (is_mov && dst->type == X86_OP_MEM && src->type == X86_OP_REG &&
        dst->mem.index == X86_REG_INVALID)
    {
      if (dst->mem.disp == 0 &&
          gum_reg_set_contains (blink_regs, num_blink_regs, dst->mem.base) &&
          gum_reg_set_contains (flink_regs, num_flink_regs, src->reg))
        unlinked_blink = TRUE;

      if (dst->mem.disp == GLIB_SIZEOF_VOID_P &&
          gum_reg_set_contains (flink_regs, num_flink_regs, dst->mem.base) &&
          gum_reg_set_contains (blink_regs, num_blink_regs, src->reg))
        unlinked_flink = TRUE;
    }

    if (is_mov && dst->type == X86_OP_REG && dst->reg == GUM_PE_TLS_ENTRY_REG)
    {
      passing_entry = (src->type == X86_OP_REG &&
          gum_reg_set_contains (entry_regs, num_entry_regs, src->reg)) ||
          gum_x86_op_is_entry_slot (src);
    }

    gum_entry_regs_track (entry_regs, &num_entry_regs, insn);
    gum_reg_set_track (found_regs, &num_found_regs, insn);
    gum_reg_set_track (flink_regs, &num_flink_regs, insn);
    gum_reg_set_track (blink_regs, &num_blink_regs, insn);

    if (loads_link && src->mem.disp == 0)
      gum_reg_set_add (flink_regs, &num_flink_regs, dst->reg);
    else if (loads_link && src->mem.disp == GLIB_SIZEOF_VOID_P)
      gum_reg_set_add (blink_regs, &num_blink_regs, dst->reg);

    if (unlinked_blink && unlinked_flink)
    {
      switch (insn->id)
      {
        case X86_INS_BTR:
          if (d->op_count == 2 && src->type == X86_OP_REG)
            cleared_bit = TRUE;
          break;
        case X86_INS_AND:
          if (d->op_count == 2 && dst->type == X86_OP_MEM &&
              src->type == X86_OP_REG && src->reg == inverted_reg)
            cleared_bit = TRUE;
          break;
        case X86_INS_NOT:
          if (d->op_count == 1 && dst->type == X86_OP_REG)
            inverted_reg = dst->reg;
          break;
        case X86_INS_PUSH:
          if (d->op_count == 1 &&
              gum_x86_op_is_field_of (dst, found_regs, num_found_regs))
            pushed_found_field = TRUE;
          break;
        case X86_INS_CALL:
          if (pushed_found_field)
            cleared_bit = TRUE;
          break;
        default:
          break;
      }
    }

    if (insn->id == X86_INS_CALL)
    {
      if (passing_entry && !looked_up_entry &&
          gum_reg_set_contains (entry_regs, num_entry_regs,
              GUM_PE_TLS_ENTRY_REG))
      {
        looked_up_entry = TRUE;
        found_regs[0] = GUM_PE_TLS_RETURN_REG;
        num_found_regs = 1;
      }
      passing_entry = FALSE;
    }
  }

  return looked_up_entry && unlinked_blink && unlinked_flink && cleared_bit;
}

static gboolean
gum_x86_op_is_field_of (const cs_x86_op * op,
                        const x86_reg * regs,
                        guint n)
{
  return op->type == X86_OP_MEM &&
      gum_reg_set_contains (regs, n, op->mem.base) &&
      op->mem.index == X86_REG_INVALID;
}

static void
gum_entry_regs_track (x86_reg * regs,
                      guint * n,
                      const cs_insn * insn)
{
  const cs_x86 * d = &insn->detail->x86;

  if (insn->id == X86_INS_MOV && d->op_count == 2 &&
      d->operands[0].type == X86_OP_REG &&
      gum_x86_op_is_entry_slot (&d->operands[1]))
  {
    gum_reg_set_add (regs, n, d->operands[0].reg);
    return;
  }

  gum_reg_set_track (regs, n, insn);
}

static gboolean
gum_x86_op_is_entry_slot (const cs_x86_op * op)
{
#if GLIB_SIZEOF_VOID_P == 4
  return op->type == X86_OP_MEM && op->mem.base == X86_REG_EBP &&
      op->mem.index == X86_REG_INVALID &&
      op->mem.disp == GUM_PE_TLS_ENTRY_SLOT;
#else
  return FALSE;
#endif
}

static void
gum_reg_set_track (x86_reg * regs,
                   guint * n,
                   const cs_insn * insn)
{
  const cs_x86 * d = &insn->detail->x86;
  const cs_x86_op * dst = &d->operands[0];
  x86_reg src = X86_REG_INVALID;

  if (d->op_count == 0 || dst->type != X86_OP_REG ||
      (dst->access & CS_AC_WRITE) == 0)
    return;

  if (insn->id == X86_INS_MOV && d->operands[1].type == X86_OP_REG)
    src = d->operands[1].reg;

  if (gum_reg_set_contains (regs, *n, src))
    gum_reg_set_add (regs, n, dst->reg);
  else
    gum_reg_set_remove (regs, n, dst->reg);
}

static void
gum_reg_set_add (x86_reg * regs,
                 guint * n,
                 x86_reg reg)
{
  if (!gum_reg_set_contains (regs, *n, reg) && *n != 8)
    regs[(*n)++] = reg;
}

static void
gum_reg_set_remove (x86_reg * regs,
                    guint * n,
                    x86_reg reg)
{
  guint i;

  for (i = 0; i != *n; i++)
  {
    if (regs[i] == reg)
    {
      regs[i] = regs[*n - 1];
      (*n)--;
      return;
    }
  }
}

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
      !self->tls_via_run_once && !self->tls_via_legacy_loader)
  {
    if (self->pointer_size == 8)
    {
      gum_x86_writer_put_call_address_with_aligned_arguments (&cw,
          GUM_CALL_SYSAPI, self->tls_handle, 1,
          GUM_ARG_ADDRESS, self->tls_entry);
    }
    else
    {
      gum_x86_writer_put_mov_reg_reg (&cw, GUM_X86_XBP, GUM_X86_XSP);
      gum_x86_writer_put_mov_reg_address (&cw, GUM_X86_XCX, self->tls_entry);
      gum_x86_writer_put_call_address_with_arguments (&cw, GUM_CALL_SYSAPI,
          self->tls_handle, 1,
          GUM_ARG_ADDRESS, self->tls_entry);
      gum_x86_writer_put_mov_reg_reg (&cw, GUM_X86_XSP, GUM_X86_XBP);
    }
  }
#if GLIB_SIZEOF_VOID_P == 8
  if (self->tls_via_thread)
    gum_emit_tls_thread_init (self, &cw);
#else
  if (self->tls_via_run_once)
    gum_emit_call_via_run_once (self, &cw, self->tls_handle);
#endif
  if (self->tls_via_legacy_loader)
    gum_emit_legacy_tls_attach (self, &cw);

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
      !self->tls_via_run_once && !self->tls_via_legacy_loader)
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
      gum_x86_writer_put_mov_reg_reg (&cw, GUM_X86_XBP, GUM_X86_XSP);
      gum_x86_writer_put_mov_reg_address (&cw, GUM_X86_XCX, self->tls_entry);
      gum_x86_writer_put_mov_reg_address (&cw, GUM_X86_XDX, (GumAddress) 0);
      gum_x86_writer_put_call_address_with_arguments (&cw, GUM_CALL_SYSAPI,
          self->tls_release, 2,
          GUM_ARG_ADDRESS, self->tls_entry,
          GUM_ARG_ADDRESS, (GumAddress) 0);
      gum_x86_writer_put_mov_reg_reg (&cw, GUM_X86_XSP, GUM_X86_XBP);
    }
  }
#if GLIB_SIZEOF_VOID_P == 8
  if (self->tls_via_thread)
    gum_emit_tls_thread_release (self, &cw);
#else
  if (self->tls_via_run_once)
    gum_emit_call_via_run_once (self, &cw, self->tls_release);
#endif
  if (self->tls_via_legacy_loader)
    gum_emit_legacy_tls_detach (self, &cw);

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

static void
gum_emit_legacy_tls_attach (GumPeMapper * self,
                            GumX86Writer * cw)
{
  gssize characteristics_offset =
      G_STRUCT_OFFSET (GumPeLegacyTlsEntry, tls.Characteristics);
  GumPeTlsDetails tls;

  gum_pe_module_get_tls_details (self->module, &tls);

  gum_emit_legacy_tls_enter (self, cw);

  gum_x86_writer_put_mov_reg_address (cw, GUM_X86_XCX,
      gum_ldrp_number_of_tls_entries);
  gum_x86_writer_put_mov_reg_reg_ptr (cw, GUM_X86_EAX, GUM_X86_XCX);
  gum_x86_writer_put_mov_reg_offset_ptr_reg (cw, GUM_X86_XBP,
      G_STRUCT_OFFSET (GumPeLegacyTlsFrame, index), GUM_X86_EAX);
  gum_x86_writer_put_mov_reg_address (cw, GUM_X86_XDX,
      self->image_address + tls.index_rva);
  gum_x86_writer_put_mov_reg_ptr_reg (cw, GUM_X86_XDX, GUM_X86_EAX);
  gum_x86_writer_put_mov_reg_address (cw, GUM_X86_XDX, self->tls_entry);
  gum_x86_writer_put_mov_reg_offset_ptr_reg (cw, GUM_X86_XDX,
      characteristics_offset, GUM_X86_EAX);
  gum_x86_writer_put_inc_reg (cw, GUM_X86_EAX);
  gum_x86_writer_put_mov_reg_ptr_reg (cw, GUM_X86_XCX, GUM_X86_EAX);

  gum_x86_writer_put_mov_reg_address (cw, GUM_X86_XAX, gum_ldrp_tls_list);
  gum_x86_writer_put_mov_reg_reg_offset_ptr (cw, GUM_X86_XCX, GUM_X86_XAX,
      GLIB_SIZEOF_VOID_P);
  gum_x86_writer_put_mov_reg_ptr_reg (cw, GUM_X86_XDX, GUM_X86_XAX);
  gum_x86_writer_put_mov_reg_offset_ptr_reg (cw, GUM_X86_XDX,
      GLIB_SIZEOF_VOID_P, GUM_X86_XCX);
  gum_x86_writer_put_mov_reg_ptr_reg (cw, GUM_X86_XCX, GUM_X86_XDX);
  gum_x86_writer_put_mov_reg_offset_ptr_reg (cw, GUM_X86_XAX,
      GLIB_SIZEOF_VOID_P, GUM_X86_XDX);

  gum_emit_for_each_thread (self, cw, gum_emit_attach_to_thread);

  gum_emit_legacy_tls_leave (self, cw);
}

static void
gum_emit_legacy_tls_enter (GumPeMapper * self,
                           GumX86Writer * cw)
{
  gum_x86_writer_put_push_reg (cw, GUM_X86_XBX);
  gum_x86_writer_put_push_reg (cw, GUM_X86_XSI);
  gum_x86_writer_put_push_reg (cw, GUM_X86_XDI);
  gum_x86_writer_put_sub_reg_imm (cw, GUM_X86_XSP,
      GUM_PE_LEGACY_TLS_FRAME_SIZE);
  gum_x86_writer_put_mov_reg_reg (cw, GUM_X86_XBP, GUM_X86_XSP);

  gum_emit_mov_reg_teb_field (cw, GUM_X86_XAX, GUM_PE_TEB_PEB_OFFSET);
  gum_x86_writer_put_mov_reg_reg_offset_ptr (cw, GUM_X86_XAX, GUM_X86_XAX,
      GUM_PE_PEB_PROCESS_HEAP_OFFSET);
  gum_x86_writer_put_mov_reg_offset_ptr_reg (cw, GUM_X86_XBP,
      G_STRUCT_OFFSET (GumPeLegacyTlsFrame, heap), GUM_X86_XAX);

  gum_x86_writer_put_lea_reg_reg_offset (cw, GUM_X86_XAX, GUM_X86_XBP,
      G_STRUCT_OFFSET (GumPeLegacyTlsFrame, cookie));
  gum_x86_writer_put_call_address_with_aligned_arguments (cw,
      GUM_CALL_SYSAPI, self->lock_loader_lock, 3,
      GUM_ARG_ADDRESS, (GumAddress) 0,
      GUM_ARG_ADDRESS, (GumAddress) 0,
      GUM_ARG_REGISTER, GUM_X86_XAX);
}

static void
gum_emit_mov_reg_teb_field (GumX86Writer * cw,
                            GumX86Reg reg,
                            guint32 offset)
{
#if GLIB_SIZEOF_VOID_P == 8
  gum_x86_writer_put_mov_reg_gs_u32_ptr (cw, reg, offset);
#else
  gum_x86_writer_put_mov_reg_fs_u32_ptr (cw, reg, offset);
#endif
}

static void
gum_emit_for_each_thread (GumPeMapper * self,
                          GumX86Writer * cw,
                          GumEmitThreadFunc func)
{
  gconstpointer loop = cw->code + 1;
  gconstpointer next = cw->code + 2;
  gconstpointer done = cw->code + 3;

  gum_x86_writer_put_call_address_with_aligned_arguments (cw,
      GUM_CALL_SYSAPI, self->create_toolhelp_snapshot, 2,
      GUM_ARG_ADDRESS, (GumAddress) TH32CS_SNAPTHREAD,
      GUM_ARG_ADDRESS, (GumAddress) 0);
  gum_x86_writer_put_mov_reg_reg (cw, GUM_X86_XBX, GUM_X86_XAX);

  gum_x86_writer_put_mov_reg_offset_ptr_u32 (cw, GUM_X86_XBP,
      G_STRUCT_OFFSET (GumPeLegacyTlsFrame, thread.dwSize),
      sizeof (THREADENTRY32));
  gum_x86_writer_put_lea_reg_reg_offset (cw, GUM_X86_XSI, GUM_X86_XBP,
      G_STRUCT_OFFSET (GumPeLegacyTlsFrame, thread));
  gum_x86_writer_put_call_address_with_aligned_arguments (cw,
      GUM_CALL_SYSAPI, self->thread32_first, 2,
      GUM_ARG_REGISTER, GUM_X86_XBX,
      GUM_ARG_REGISTER, GUM_X86_XSI);

  gum_x86_writer_put_label (cw, loop);
  gum_x86_writer_put_test_reg_reg (cw, GUM_X86_EAX, GUM_X86_EAX);
  gum_x86_writer_put_jcc_near_label (cw, X86_INS_JE, done, GUM_NO_HINT);

  gum_x86_writer_put_mov_reg_reg_offset_ptr (cw, GUM_X86_EAX, GUM_X86_XBP,
      G_STRUCT_OFFSET (GumPeLegacyTlsFrame, thread.th32OwnerProcessID));
  gum_emit_mov_reg_teb_field (cw, GUM_X86_EDX, GUM_PE_TEB_PROCESS_ID_OFFSET);
  gum_x86_writer_put_cmp_reg_reg (cw, GUM_X86_EAX, GUM_X86_EDX);
  gum_x86_writer_put_jcc_near_label (cw, X86_INS_JNE, next, GUM_NO_HINT);

  gum_x86_writer_put_mov_reg_reg_offset_ptr (cw, GUM_X86_EDI, GUM_X86_XBP,
      G_STRUCT_OFFSET (GumPeLegacyTlsFrame, thread.th32ThreadID));
  gum_x86_writer_put_call_address_with_aligned_arguments (cw,
      GUM_CALL_SYSAPI, self->open_thread, 3,
      GUM_ARG_ADDRESS, (GumAddress) THREAD_QUERY_INFORMATION,
      GUM_ARG_ADDRESS, (GumAddress) FALSE,
      GUM_ARG_REGISTER, GUM_X86_XDI);
  gum_x86_writer_put_test_reg_reg (cw, GUM_X86_XAX, GUM_X86_XAX);
  gum_x86_writer_put_jcc_near_label (cw, X86_INS_JE, next, GUM_NO_HINT);
  gum_x86_writer_put_mov_reg_reg (cw, GUM_X86_XDI, GUM_X86_XAX);

  gum_x86_writer_put_lea_reg_reg_offset (cw, GUM_X86_XSI, GUM_X86_XBP,
      G_STRUCT_OFFSET (GumPeLegacyTlsFrame, info));
  gum_x86_writer_put_call_address_with_aligned_arguments (cw,
      GUM_CALL_SYSAPI, self->query_information_thread, 5,
      GUM_ARG_REGISTER, GUM_X86_XDI,
      GUM_ARG_ADDRESS, (GumAddress) GUM_PE_THREAD_BASIC_INFORMATION,
      GUM_ARG_REGISTER, GUM_X86_XSI,
      GUM_ARG_ADDRESS, (GumAddress) sizeof (GumPeThreadBasicInformation),
      GUM_ARG_ADDRESS, (GumAddress) 0);
  gum_x86_writer_put_mov_reg_reg (cw, GUM_X86_XSI, GUM_X86_XAX);
  gum_x86_writer_put_call_address_with_aligned_arguments (cw,
      GUM_CALL_SYSAPI, self->close_handle, 1,
      GUM_ARG_REGISTER, GUM_X86_XDI);
  gum_x86_writer_put_test_reg_reg (cw, GUM_X86_ESI, GUM_X86_ESI);
  gum_x86_writer_put_jcc_near_label (cw, X86_INS_JNE, next, GUM_NO_HINT);

  gum_x86_writer_put_mov_reg_reg_offset_ptr (cw, GUM_X86_XSI, GUM_X86_XBP,
      G_STRUCT_OFFSET (GumPeLegacyTlsFrame, info.teb_base_address));
  func (self, cw);

  gum_x86_writer_put_label (cw, next);
  gum_x86_writer_put_lea_reg_reg_offset (cw, GUM_X86_XSI, GUM_X86_XBP,
      G_STRUCT_OFFSET (GumPeLegacyTlsFrame, thread));
  gum_x86_writer_put_call_address_with_aligned_arguments (cw,
      GUM_CALL_SYSAPI, self->thread32_next, 2,
      GUM_ARG_REGISTER, GUM_X86_XBX,
      GUM_ARG_REGISTER, GUM_X86_XSI);
  gum_x86_writer_put_jmp_near_label (cw, loop);

  gum_x86_writer_put_label (cw, done);
  gum_x86_writer_put_call_address_with_aligned_arguments (cw,
      GUM_CALL_SYSAPI, self->close_handle, 1,
      GUM_ARG_REGISTER, GUM_X86_XBX);
}

static void
gum_emit_attach_to_thread (GumPeMapper * self,
                           GumX86Writer * cw)
{
  gconstpointer copied = cw->code + 1;
  gconstpointer freed = cw->code + 2;
  const guint8 rep_movsb[] = { 0xf3, 0xa4 };
  GumPeTlsDetails tls;

  gum_pe_module_get_tls_details (self->module, &tls);

  gum_x86_writer_put_mov_reg_reg_offset_ptr (cw, GUM_X86_EAX, GUM_X86_XBP,
      G_STRUCT_OFFSET (GumPeLegacyTlsFrame, index));
  gum_x86_writer_put_inc_reg (cw, GUM_X86_EAX);
  gum_x86_writer_put_shl_reg_u8 (cw, GUM_X86_EAX,
      g_bit_nth_lsf (GLIB_SIZEOF_VOID_P, -1));
  gum_x86_writer_put_mov_reg_reg_offset_ptr (cw, GUM_X86_XCX, GUM_X86_XBP,
      G_STRUCT_OFFSET (GumPeLegacyTlsFrame, heap));
  gum_x86_writer_put_call_address_with_aligned_arguments (cw,
      GUM_CALL_SYSAPI, self->allocate_heap, 3,
      GUM_ARG_REGISTER, GUM_X86_XCX,
      GUM_ARG_ADDRESS, (GumAddress) HEAP_ZERO_MEMORY,
      GUM_ARG_REGISTER, GUM_X86_XAX);
  gum_x86_writer_put_mov_reg_reg (cw, GUM_X86_XDI, GUM_X86_XAX);

  gum_x86_writer_put_mov_reg_reg_offset_ptr (cw, GUM_X86_XAX, GUM_X86_XSI,
      GUM_PE_TEB_TLS_POINTER_OFFSET);
  gum_x86_writer_put_test_reg_reg (cw, GUM_X86_XAX, GUM_X86_XAX);
  gum_x86_writer_put_jcc_near_label (cw, X86_INS_JE, copied, GUM_NO_HINT);
  gum_x86_writer_put_push_reg (cw, GUM_X86_XSI);
  gum_x86_writer_put_push_reg (cw, GUM_X86_XDI);
  gum_x86_writer_put_mov_reg_reg (cw, GUM_X86_XSI, GUM_X86_XAX);
  gum_x86_writer_put_mov_reg_reg_offset_ptr (cw, GUM_X86_ECX, GUM_X86_XBP,
      G_STRUCT_OFFSET (GumPeLegacyTlsFrame, index));
  gum_x86_writer_put_shl_reg_u8 (cw, GUM_X86_ECX,
      g_bit_nth_lsf (GLIB_SIZEOF_VOID_P, -1));
  gum_x86_writer_put_cld (cw);
  gum_x86_writer_put_bytes (cw, rep_movsb, sizeof (rep_movsb));
  gum_x86_writer_put_pop_reg (cw, GUM_X86_XDI);
  gum_x86_writer_put_pop_reg (cw, GUM_X86_XSI);
  gum_x86_writer_put_label (cw, copied);

  gum_x86_writer_put_mov_reg_reg_offset_ptr (cw, GUM_X86_XCX, GUM_X86_XBP,
      G_STRUCT_OFFSET (GumPeLegacyTlsFrame, heap));
  gum_x86_writer_put_call_address_with_aligned_arguments (cw,
      GUM_CALL_SYSAPI, self->allocate_heap, 3,
      GUM_ARG_REGISTER, GUM_X86_XCX,
      GUM_ARG_ADDRESS, (GumAddress) HEAP_ZERO_MEMORY,
      GUM_ARG_ADDRESS, (GumAddress) (tls.template_size + tls.zero_fill_size));
  gum_x86_writer_put_push_reg (cw, GUM_X86_XSI);
  gum_x86_writer_put_push_reg (cw, GUM_X86_XDI);
  gum_x86_writer_put_mov_reg_reg (cw, GUM_X86_XDI, GUM_X86_XAX);
  gum_x86_writer_put_mov_reg_address (cw, GUM_X86_XSI,
      self->image_address + tls.template_rva);
  gum_x86_writer_put_mov_reg_address (cw, GUM_X86_XCX, tls.template_size);
  gum_x86_writer_put_bytes (cw, rep_movsb, sizeof (rep_movsb));
  gum_x86_writer_put_pop_reg (cw, GUM_X86_XDI);
  gum_x86_writer_put_pop_reg (cw, GUM_X86_XSI);

  gum_x86_writer_put_mov_reg_reg_offset_ptr (cw, GUM_X86_EDX, GUM_X86_XBP,
      G_STRUCT_OFFSET (GumPeLegacyTlsFrame, index));
  gum_x86_writer_put_shl_reg_u8 (cw, GUM_X86_EDX,
      g_bit_nth_lsf (GLIB_SIZEOF_VOID_P, -1));
  gum_x86_writer_put_add_reg_reg (cw, GUM_X86_XDX, GUM_X86_XDI);
  gum_x86_writer_put_mov_reg_ptr_reg (cw, GUM_X86_XDX, GUM_X86_XAX);

  gum_x86_writer_put_mov_reg_reg_offset_ptr (cw, GUM_X86_XAX, GUM_X86_XSI,
      GUM_PE_TEB_TLS_POINTER_OFFSET);
  gum_x86_writer_put_mov_reg_offset_ptr_reg (cw, GUM_X86_XSI,
      GUM_PE_TEB_TLS_POINTER_OFFSET, GUM_X86_XDI);
  gum_x86_writer_put_test_reg_reg (cw, GUM_X86_XAX, GUM_X86_XAX);
  gum_x86_writer_put_jcc_near_label (cw, X86_INS_JE, freed, GUM_NO_HINT);
  gum_x86_writer_put_mov_reg_reg_offset_ptr (cw, GUM_X86_XCX, GUM_X86_XBP,
      G_STRUCT_OFFSET (GumPeLegacyTlsFrame, heap));
  gum_x86_writer_put_call_address_with_aligned_arguments (cw,
      GUM_CALL_SYSAPI, self->free_heap, 3,
      GUM_ARG_REGISTER, GUM_X86_XCX,
      GUM_ARG_ADDRESS, (GumAddress) 0,
      GUM_ARG_REGISTER, GUM_X86_XAX);
  gum_x86_writer_put_label (cw, freed);
}

static void
gum_emit_legacy_tls_leave (GumPeMapper * self,
                           GumX86Writer * cw)
{
  gum_x86_writer_put_mov_reg_reg_offset_ptr (cw, GUM_X86_XAX, GUM_X86_XBP,
      G_STRUCT_OFFSET (GumPeLegacyTlsFrame, cookie));
  gum_x86_writer_put_call_address_with_aligned_arguments (cw,
      GUM_CALL_SYSAPI, self->unlock_loader_lock, 2,
      GUM_ARG_ADDRESS, (GumAddress) 0,
      GUM_ARG_REGISTER, GUM_X86_XAX);

  gum_x86_writer_put_add_reg_imm (cw, GUM_X86_XSP,
      GUM_PE_LEGACY_TLS_FRAME_SIZE);
  gum_x86_writer_put_pop_reg (cw, GUM_X86_XDI);
  gum_x86_writer_put_pop_reg (cw, GUM_X86_XSI);
  gum_x86_writer_put_pop_reg (cw, GUM_X86_XBX);
}

static void
gum_emit_legacy_tls_detach (GumPeMapper * self,
                            GumX86Writer * cw)
{
  gum_emit_legacy_tls_enter (self, cw);

  gum_x86_writer_put_mov_reg_address (cw, GUM_X86_XDX, self->tls_entry);
  gum_x86_writer_put_mov_reg_reg_offset_ptr (cw, GUM_X86_EAX, GUM_X86_XDX,
      G_STRUCT_OFFSET (GumPeLegacyTlsEntry, tls.Characteristics));
  gum_x86_writer_put_mov_reg_offset_ptr_reg (cw, GUM_X86_XBP,
      G_STRUCT_OFFSET (GumPeLegacyTlsFrame, index), GUM_X86_EAX);

  gum_x86_writer_put_mov_reg_reg_ptr (cw, GUM_X86_XAX, GUM_X86_XDX);
  gum_x86_writer_put_mov_reg_reg_offset_ptr (cw, GUM_X86_XCX, GUM_X86_XDX,
      GLIB_SIZEOF_VOID_P);
  gum_x86_writer_put_mov_reg_ptr_reg (cw, GUM_X86_XCX, GUM_X86_XAX);
  gum_x86_writer_put_mov_reg_offset_ptr_reg (cw, GUM_X86_XAX,
      GLIB_SIZEOF_VOID_P, GUM_X86_XCX);

  gum_emit_for_each_thread (self, cw, gum_emit_detach_from_thread);

  gum_emit_legacy_tls_leave (self, cw);
}

static void
gum_emit_detach_from_thread (GumPeMapper * self,
                             GumX86Writer * cw)
{
  gconstpointer freed = cw->code + 1;

  gum_x86_writer_put_mov_reg_reg_offset_ptr (cw, GUM_X86_XDI, GUM_X86_XSI,
      GUM_PE_TEB_TLS_POINTER_OFFSET);
  gum_x86_writer_put_test_reg_reg (cw, GUM_X86_XDI, GUM_X86_XDI);
  gum_x86_writer_put_jcc_near_label (cw, X86_INS_JE, freed, GUM_NO_HINT);
  gum_x86_writer_put_mov_reg_reg_offset_ptr (cw, GUM_X86_EDX, GUM_X86_XBP,
      G_STRUCT_OFFSET (GumPeLegacyTlsFrame, index));
  gum_x86_writer_put_shl_reg_u8 (cw, GUM_X86_EDX,
      g_bit_nth_lsf (GLIB_SIZEOF_VOID_P, -1));
  gum_x86_writer_put_add_reg_reg (cw, GUM_X86_XDI, GUM_X86_XDX);
  gum_x86_writer_put_mov_reg_reg_ptr (cw, GUM_X86_XAX, GUM_X86_XDI);
  gum_x86_writer_put_test_reg_reg (cw, GUM_X86_XAX, GUM_X86_XAX);
  gum_x86_writer_put_jcc_near_label (cw, X86_INS_JE, freed, GUM_NO_HINT);
  gum_x86_writer_put_xor_reg_reg (cw, GUM_X86_ECX, GUM_X86_ECX);
  gum_x86_writer_put_mov_reg_ptr_reg (cw, GUM_X86_XDI, GUM_X86_XCX);
  gum_x86_writer_put_mov_reg_reg_offset_ptr (cw, GUM_X86_XCX, GUM_X86_XBP,
      G_STRUCT_OFFSET (GumPeLegacyTlsFrame, heap));
  gum_x86_writer_put_call_address_with_aligned_arguments (cw,
      GUM_CALL_SYSAPI, self->free_heap, 3,
      GUM_ARG_REGISTER, GUM_X86_XCX,
      GUM_ARG_ADDRESS, (GumAddress) 0,
      GUM_ARG_REGISTER, GUM_X86_XAX);
  gum_x86_writer_put_label (cw, freed);
}

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
