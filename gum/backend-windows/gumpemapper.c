/*
 * Copyright (C) 2026 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gum/gumpemapper.h"

#include "gummodule-windows.h"
#include "gumnativeprocessmemory.h"
#include "gumpemodule.h"
#if defined (HAVE_I386)
# include "gumx86writer.h"
#elif defined (HAVE_ARM64)
# include "gumarm64writer.h"
#endif
#include "gum/gumwindows.h"

#include <capstone.h>

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

#define GUM_PE_DLL_PROCESS_DETACH 0
#define GUM_PE_DLL_PROCESS_ATTACH 1

#define GUM_PE_STAGED(self, address) \
    ((self)->staging + ((address) - (self)->runtime_address))

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

typedef struct _GumPeResolveContext GumPeResolveContext;
typedef struct _GumPeTlsCollectContext GumPeTlsCollectContext;
typedef struct _GumPeMatchOrdinalContext GumPeMatchOrdinalContext;
#if GLIB_SIZEOF_VOID_P == 8 && !defined (HAVE_ARM64)
typedef struct _GumPeX64TlsScanContext GumPeX64TlsScanContext;
typedef struct _GumPeTlsShared GumPeTlsShared;
typedef struct _GumPeTlsEntry GumPeTlsEntry;
#endif

#if defined (HAVE_I386) && GLIB_SIZEOF_VOID_P == 4
typedef void (__fastcall * GumLdrHandleTlsDataFunc) (gpointer entry);
typedef void (__fastcall * GumLdrReleaseTlsEntryFunc) (gpointer entry,
    gsize flags);
#else
typedef void (* GumLdrHandleTlsDataFunc) (gpointer entry);
typedef void (* GumLdrReleaseTlsEntryFunc) (gpointer entry, gsize flags);
#endif
#if GLIB_SIZEOF_VOID_P == 8 && !defined (HAVE_ARM64)
typedef BOOL (WINAPI * GumIsWow64Process2Func) (HANDLE process,
    USHORT * process_machine, USHORT * native_machine);
#endif

struct _GumPeMapper
{
  GObject parent;

  gchar * name;
  GBytes * blob;
  GumPeModule * module;
  GumModuleResolver * resolver;
  GumProcessMemory * target;

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

  gboolean has_static_tls;
  gboolean tls_via_thread;
  GumAddress tls_entry;
  GumAddress tls_handle;
  GumAddress tls_release;
  GumAddress tls_thunk;
  GumAddress tls_shared_region;
  GumAddress tls_shared_entry;
  GumAddress create_thread;
  GumAddress wait_for_single_object;
  GumAddress close_handle;
};

struct _GumPeResolveContext
{
  GumPeMapper * mapper;
  GHashTable * modules;
  gboolean success;
  GError ** error;
};

struct _GumPeTlsCollectContext
{
  GumPeMapper * mapper;
  GArray * callbacks;
};

struct _GumPeMatchOrdinalContext
{
  guint16 ordinal;
  guint32 rva;
  gboolean found;
};

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
#endif

static void gum_pe_mapper_dispose (GObject * object);
static void gum_pe_mapper_finalize (GObject * object);

static GumPeMapper * gum_pe_mapper_new (const gchar * name,
    GumPeModule * module, GumModuleResolver * resolver);
static GumCpuType gum_pe_cpu_type_from_machine (GumPeMachine machine);
static void gum_pe_mapper_init_footprint_budget (GumPeMapper * self);
static gboolean gum_pe_mapper_count_tls_callback (GumAddress rva,
    gpointer user_data);
static void gum_pe_mapper_copy_image (GumPeMapper * self);
static gboolean gum_pe_mapper_emit_section (const GumPeSectionDetails * details,
    gpointer user_data);
static gboolean gum_pe_mapper_apply_relocation (
    const GumPeRelocationDetails * details, gpointer user_data);
static gboolean gum_pe_mapper_resolve_import (
    const GumPeImportDetails * details, gpointer user_data);
static GumAddress gum_pe_mapper_resolve_ordinal (GumPeMapper * self,
    GumModule * module, guint16 ordinal);
static gboolean gum_pe_mapper_match_ordinal (const GumPeExportDetails * details,
    gpointer user_data);
static gboolean gum_pe_mapper_collect_tls_callback (GumAddress rva,
    gpointer user_data);
static void gum_pe_mapper_prepare_tls (GumPeMapper * self);
static void gum_pe_resolve_loader_tls (void);
#if defined (HAVE_ARM64)
static void gum_pe_resolve_arm64_tls (GumModule * ntdll, GumAddress base,
    GumAddress limit, GumAddress * handle, GumAddress * release);
static gboolean gum_pe_arm64_is_handle_tls_data (cs_insn * insns,
    size_t count);
static gboolean gum_pe_arm64_is_release_tls_entry (cs_insn * insns,
    size_t count);
#elif GLIB_SIZEOF_VOID_P == 8
static gboolean gum_pe_is_emulated (void);
static void gum_pe_resolve_arm64_tls_emulated (GumModule * ntdll,
    GumAddress base, GumAddress limit, GumAddress * handle,
    GumAddress * release);
static gpointer gum_pe_follow_x64_thunk (gpointer fn);
static gboolean gum_pe_arm64_raw_is_handle_tls_data (const guint32 * code,
    guint n);
static gboolean gum_pe_arm64_raw_is_release_tls_entry (const guint32 * code,
    guint n);
static void gum_pe_resolve_x64_tls (GumPeModule * ntdll, GumAddress base,
    GumAddress limit, GumAddress * handle, GumAddress * release);
static gboolean gum_pe_scan_x64_function (GumAddress rva, gpointer user_data);
#else
static void gum_pe_resolve_x86_tls (GumAddress base, GumAddress limit,
    GumAddress * handle, GumAddress * release);
#endif
#if defined (HAVE_I386)
static gboolean gum_pe_function_is_ldr_handle_tls_data (cs_insn * insns,
    size_t count);
static gboolean gum_pe_function_is_ldr_release_tls_entry (cs_insn * insns,
    size_t count);
# if GLIB_SIZEOF_VOID_P == 4
static void gum_pe_reg_set_update (x86_reg * regs, guint * n, x86_reg dst,
    x86_reg src);
# endif
static gboolean gum_pe_reg_set_contains (const x86_reg * regs, guint n,
    x86_reg reg);
#endif
#if GLIB_SIZEOF_VOID_P == 8 && !defined (HAVE_ARM64)
static void gum_pe_mapper_install_thread_init_hook (GumPeMapper * self);
static GumAddress gum_pe_mapper_resolve_shared_region (GumPeMapper * self);
static gsize gum_pe_mapper_emit_shared_hook (GumPeMapper * self,
    GumAddress code_address, gpointer output);
static void gum_pe_mapper_add_tls_entry (GumPeMapper * self);
static void gum_pe_mapper_restore_thread_init_hook (GumPeMapper * self);
static void gum_pe_mapper_remove_tls_entry (GumPeMapper * self);
static void gum_pe_patch_target_code (GumPeMapper * self, GumAddress address,
    gconstpointer data, gsize size);
#endif
static void gum_pe_mapper_alloc_and_emit_runtime (GumPeMapper * self);
static void gum_pe_mapper_emit_runtime (GumPeMapper * self,
    gpointer output_buffer, GumAddress pc, gsize * size);
#if defined (HAVE_I386) && GLIB_SIZEOF_VOID_P == 8
static void gum_pe_mapper_emit_tls_thread_init (GumPeMapper * self,
    GumX86Writer * cw);
#endif
static gboolean gum_pe_mapper_protect_section (
    const GumPeSectionDetails * details, gpointer user_data);
#if GLIB_SIZEOF_VOID_P == 8 && !defined (HAVE_ARM64)
static void gum_pe_mapper_get_tls_entry (GumPeMapper * self,
    GumPeTlsEntry * entry);
#endif

G_DEFINE_TYPE (GumPeMapper, gum_pe_mapper, G_TYPE_OBJECT)

static GumLdrHandleTlsDataFunc gum_ldr_handle_tls_data;
static GumLdrReleaseTlsEntryFunc gum_ldr_release_tls_entry;

static void
gum_pe_mapper_class_init (GumPeMapperClass * klass)
{
  GObjectClass * object_class = G_OBJECT_CLASS (klass);

  object_class->dispose = gum_pe_mapper_dispose;
  object_class->finalize = gum_pe_mapper_finalize;
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

  if (self->target != NULL)
  {
#if GLIB_SIZEOF_VOID_P == 8 && !defined (HAVE_ARM64)
    if (self->tls_via_thread)
      gum_pe_mapper_restore_thread_init_hook (self);
#endif

    gum_process_memory_free (self->target, self->tls_entry,
        GUM_PE_LOADER_ENTRY_SIZE);

    g_clear_object (&self->target);
  }

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
  g_free (self->name);

  G_OBJECT_CLASS (gum_pe_mapper_parent_class)->finalize (object);
}

GumPeMapper *
gum_pe_mapper_new_from_file (const gchar * path,
                             GumModuleResolver * resolver,
                             GError ** error)
{
  GumPeMapper * mapper;
  GumPeModule * module;

  module = gum_pe_module_new_from_file (path, error);
  if (module == NULL)
    return NULL;

  mapper = gum_pe_mapper_new (path, module, resolver);

  if (!gum_pe_mapper_load (mapper, error))
  {
    g_object_unref (mapper);
    return NULL;
  }

  return mapper;
}

GumPeMapper *
gum_pe_mapper_new_take_blob (const gchar * name,
                             GBytes * blob,
                             GumModuleResolver * resolver,
                             GError ** error)
{
  GumPeMapper * mapper;
  GumPeModule * module;

  module = gum_pe_module_new_from_blob (blob, error);
  if (module == NULL)
  {
    g_bytes_unref (blob);
    return NULL;
  }

  mapper = gum_pe_mapper_new (name, module, resolver);
  mapper->blob = blob;

  if (!gum_pe_mapper_load (mapper, error))
  {
    g_object_unref (mapper);
    return NULL;
  }

  return mapper;
}

gboolean
gum_pe_mapper_load (GumPeMapper * self,
                    GError ** error)
{
  return TRUE;
}

void
gum_pe_mapper_set_target (GumPeMapper * self,
                          GumProcessMemory * target)
{
  g_set_object (&self->target, target);
}

gsize
gum_pe_mapper_size (GumPeMapper * self)
{
  if (self->vm_size == 0)
    gum_pe_mapper_init_footprint_budget (self);

  return self->vm_size;
}

gboolean
gum_pe_mapper_map (GumPeMapper * self,
                   GumAddress base_address,
                   GError ** error)
{
  GumPeModule * module = self->module;
  GumPeResolveContext ctx;
  guint32 entrypoint_rva;
  GumPeTlsCollectContext tls_ctx;
  const GumPeDataDirectory * exception;

  gum_pe_mapper_size (self);

  self->runtime_address = base_address;
  self->image_address = base_address + self->runtime_vm_size;
  self->staging = g_malloc0 (self->vm_size);

  gum_pe_mapper_copy_image (self);

  gum_pe_module_enumerate_relocations (module,
      gum_pe_mapper_apply_relocation, self);

  ctx.mapper = self;
  ctx.modules = g_hash_table_new_full (g_str_hash, g_str_equal, g_free,
      g_object_unref);
  ctx.success = TRUE;
  ctx.error = error;
  gum_pe_module_enumerate_imports (module, gum_pe_mapper_resolve_import, &ctx);
  g_hash_table_unref (ctx.modules);
  if (!ctx.success)
    return FALSE;

  entrypoint_rva = gum_pe_module_get_entrypoint (module);
  self->entrypoint = (entrypoint_rva != 0)
      ? self->image_address + entrypoint_rva
      : 0;

  tls_ctx.mapper = self;
  tls_ctx.callbacks = self->tls_callbacks;
  gum_pe_module_enumerate_tls_callbacks (module,
      gum_pe_mapper_collect_tls_callback, &tls_ctx);

  exception = gum_pe_module_get_directory (module, GUM_PE_DIRECTORY_EXCEPTION);
  if (exception->size != 0 && self->pointer_size == 8)
  {
    self->function_table = self->image_address + exception->rva;
    self->function_table_count = gum_pe_module_get_function_count (module);
    self->add_function_table = gum_module_resolver_find_dynamic_address (
        self->resolver, "RtlAddFunctionTable");
  }

  gum_pe_mapper_prepare_tls (self);
#if GLIB_SIZEOF_VOID_P == 8 && !defined (HAVE_ARM64)
  if (self->tls_via_thread)
    gum_pe_mapper_install_thread_init_hook (self);
#endif

  gum_pe_mapper_alloc_and_emit_runtime (self);

  memcpy (self->staging, self->runtime, self->runtime_file_size);

  gum_process_memory_write (self->target, self->runtime_address, self->staging,
      self->vm_size);

  gum_pe_module_enumerate_sections (module, gum_pe_mapper_protect_section,
      self);

  gum_process_memory_mark_code (self->target, self->runtime_address,
      self->runtime_vm_size);

  g_clear_pointer (&self->staging, g_free);

  return TRUE;
}

GumAddress
gum_pe_mapper_constructor (GumPeMapper * self)
{
  return self->runtime_address + self->constructor_offset;
}

GumAddress
gum_pe_mapper_destructor (GumPeMapper * self)
{
  return self->runtime_address + self->destructor_offset;
}

GumAddress
gum_pe_mapper_resolve (GumPeMapper * self,
                       const gchar * symbol)
{
  GumPeExportDetails details;

  if (!gum_pe_module_find_export_by_name (self->module, symbol, &details))
    return 0;

  if (details.type == GUM_PE_EXPORT_FORWARDED)
  {
    GumAddress result = 0;
    gchar ** parts = g_strsplit (details.forwarder, ".", 2);
    GumModule * module;

    module = gum_module_resolver_find_module_by_name (self->resolver,
        parts[0]);
    if (module != NULL)
    {
      result = gum_module_find_export_by_name (module, parts[1]);
      g_object_unref (module);
    }

    g_strfreev (parts);

    return result;
  }

  return self->image_address + details.rva;
}

static GumPeMapper *
gum_pe_mapper_new (const gchar * name,
                   GumPeModule * module,
                   GumModuleResolver * resolver)
{
  GumPeMapper * mapper;

  mapper = g_object_new (GUM_TYPE_PE_MAPPER, NULL);
  mapper->name = g_strdup (name);
  mapper->module = module;
  mapper->resolver = g_object_ref (resolver);
  mapper->cpu_type =
      gum_pe_cpu_type_from_machine (gum_pe_module_get_machine (module));
  mapper->pointer_size = gum_pe_module_get_pointer_size (module);

  return mapper;
}

static GumCpuType
gum_pe_cpu_type_from_machine (GumPeMachine machine)
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
  gum_pe_module_enumerate_tls_callbacks (module,
      gum_pe_mapper_count_tls_callback, self);

  self->has_exception_table =
      gum_pe_module_get_directory (module, GUM_PE_DIRECTORY_EXCEPTION)->size
      != 0;

  self->has_static_tls =
      gum_pe_module_get_directory (module, GUM_PE_DIRECTORY_TLS)->size != 0;

  runtime_size = GUM_PE_MAPPER_CODE_BASE_SIZE +
      (2 * self->tls_callback_count * GUM_PE_MAPPER_TLS_CALL_SIZE) +
      GUM_PE_MAPPER_ENTRY_CALL_SIZE;
  if (self->has_exception_table && self->pointer_size == 8)
    runtime_size += GUM_PE_MAPPER_UNWIND_SIZE;
  if (self->has_static_tls)
    runtime_size += 4 * GUM_PE_MAPPER_TLS_CALL_SIZE;

  self->runtime_file_size = runtime_size;
  self->runtime_vm_size = GUM_ALIGN_SIZE (runtime_size, page_size);

  self->vm_size = image_vm_size + self->runtime_vm_size;
}

static gboolean
gum_pe_mapper_count_tls_callback (GumAddress rva,
                                  gpointer user_data)
{
  GumPeMapper * self = user_data;

  self->tls_callback_count++;

  return TRUE;
}

static void
gum_pe_mapper_copy_image (GumPeMapper * self)
{
  GumPeModule * module = self->module;
  guint8 * image = GUM_PE_STAGED (self, self->image_address);

  memcpy (image, gum_pe_module_get_data_at_rva (module, 0),
      gum_pe_module_get_size_of_headers (module));

  gum_pe_module_enumerate_sections (module, gum_pe_mapper_emit_section, self);
}

static gboolean
gum_pe_mapper_emit_section (const GumPeSectionDetails * details,
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
gum_pe_mapper_apply_relocation (const GumPeRelocationDetails * details,
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
gum_pe_mapper_resolve_import (const GumPeImportDetails * details,
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
    g_set_error (ctx->error, GUM_ERROR, GUM_ERROR_NOT_FOUND,
        "Unable to resolve import from '%s'", details->module_name);
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
  gum_pe_module_enumerate_exports (dependency, gum_pe_mapper_match_ordinal,
      &ctx);

  if (ctx.found)
    result = range->base_address + ctx.rva;

  g_object_unref (dependency);

  return result;
}

static gboolean
gum_pe_mapper_match_ordinal (const GumPeExportDetails * details,
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

static gboolean
gum_pe_mapper_collect_tls_callback (GumAddress rva,
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

  gum_pe_resolve_loader_tls ();

  self->has_static_tls = TRUE;
#if GLIB_SIZEOF_VOID_P == 8 && !defined (HAVE_ARM64)
  self->tls_via_thread = gum_pe_is_emulated ();
  if (self->tls_via_thread)
  {
    self->create_thread = gum_module_resolver_find_dynamic_address (
        self->resolver, "CreateThread");
    self->wait_for_single_object = gum_module_resolver_find_dynamic_address (
        self->resolver, "WaitForSingleObject");
    self->close_handle = gum_module_resolver_find_dynamic_address (
        self->resolver, "CloseHandle");
  }
#else
  self->tls_via_thread = FALSE;
#endif
  self->tls_handle = GUM_ADDRESS (gum_ldr_handle_tls_data);
  self->tls_release = GUM_ADDRESS (gum_ldr_release_tls_entry);
  self->tls_entry = gum_process_memory_alloc (self->target,
      GUM_PE_LOADER_ENTRY_SIZE);

  dll_base = self->image_address;
  gum_process_memory_write (self->target,
      self->tls_entry + GUM_PE_LOADER_ENTRY_DLL_BASE_OFFSET, &dll_base,
      self->pointer_size);
}

static void
gum_pe_resolve_loader_tls (void)
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
    gum_pe_resolve_arm64_tls (GUM_MODULE (ntdll), base, limit, &handle,
        &release);
#elif GLIB_SIZEOF_VOID_P == 8
    if (gum_pe_is_emulated ())
    {
      gum_pe_resolve_arm64_tls_emulated (GUM_MODULE (ntdll), base, limit,
          &handle, &release);
    }
    else
    {
      gum_pe_resolve_x64_tls (_gum_native_module_get_pe_module (ntdll), base,
          limit, &handle, &release);
    }
#else
    gum_pe_resolve_x86_tls (base, limit, &handle, &release);
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
gum_pe_resolve_arm64_tls (GumModule * ntdll,
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
    if (*handle == 0 && gum_pe_arm64_is_handle_tls_data (insns, scan))
      *handle = fn;
    if (*release == 0 && gum_pe_arm64_is_release_tls_entry (insns, scan))
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
gum_pe_arm64_is_handle_tls_data (cs_insn * insns,
                                 size_t count)
{
  size_t i;

  for (i = 0; i != count; i++)
  {
    cs_arm64 * d = &insns[i].detail->arm64;
    size_t k;

    if (!(insns[i].id == ARM64_INS_LDR && d->op_count >= 2 &&
        d->operands[1].type == ARM64_OP_MEM &&
        d->operands[1].mem.base == ARM64_REG_X0 &&
        d->operands[1].mem.disp == GUM_PE_LDR_TLS_FLAGS_FIELD))
    {
      continue;
    }

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
        return TRUE;
    }
  }

  return FALSE;
}

static gboolean
gum_pe_arm64_is_release_tls_entry (cs_insn * insns,
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

#elif GLIB_SIZEOF_VOID_P == 8

static gboolean
gum_pe_is_emulated (void)
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
gum_pe_resolve_arm64_tls_emulated (GumModule * ntdll,
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
    gpointer a = gum_pe_follow_x64_thunk (GSIZE_TO_POINTER (
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

    n = MIN (256, (guint) ((limit - fn) / sizeof (guint32)));
    scan = MIN (n, 48);

    if (*handle == 0 && gum_pe_arm64_raw_is_handle_tls_data (code, scan))
      *handle = fn;
    if (*release == 0 && gum_pe_arm64_raw_is_release_tls_entry (code, scan))
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
gum_pe_follow_x64_thunk (gpointer fn)
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

static gboolean
gum_pe_arm64_raw_is_handle_tls_data (const guint32 * code,
                                     guint n)
{
  guint i;

  for (i = 0; i != n; i++)
  {
    guint k;

    if ((code[i] & 0xffffffe0) != 0xb9410c00)
      continue;

    for (k = i + 1; k != n && k != i + 6; k++)
    {
      if ((code[k] & 0x7f000000) == 0x71000000 &&
          ((code[k] >> 10) & 0xfff) == 9)
        return TRUE;
    }
  }

  return FALSE;
}

static gboolean
gum_pe_arm64_raw_is_release_tls_entry (const guint32 * code,
                                       guint n)
{
  guint i;
  gboolean saved_entry = FALSE, saved_flags = FALSE, branches_on_flags = FALSE;

  for (i = 0; i != n; i++)
  {
    guint32 insn = code[i];

    if ((insn & 0xffe0ffe0) == 0xaa0003e0)
    {
      guint rm = (insn >> 16) & 0x1f;
      guint rd = insn & 0x1f;

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

static void
gum_pe_resolve_x64_tls (GumPeModule * ntdll,
                        GumAddress base,
                        GumAddress limit,
                        GumAddress * handle,
                        GumAddress * release)
{
  GumPeX64TlsScanContext ctx;

  cs_open (CS_ARCH_X86, CS_MODE_64, &ctx.cs);
  cs_option (ctx.cs, CS_OPT_DETAIL, CS_OPT_ON);
  cs_option (ctx.cs, CS_OPT_SKIPDATA, CS_OPT_ON);
  ctx.base = base;
  ctx.limit = limit;
  ctx.handle = handle;
  ctx.release = release;

  gum_pe_module_enumerate_function_starts (ntdll, gum_pe_scan_x64_function,
      &ctx);

  cs_close (&ctx.cs);
}

static gboolean
gum_pe_scan_x64_function (GumAddress rva,
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
      gum_pe_function_is_ldr_handle_tls_data (insns, scan))
    *ctx->handle = fn;
  if (*ctx->release == 0 &&
      gum_pe_function_is_ldr_release_tls_entry (insns, scan))
    *ctx->release = fn;

  cs_free (insns, n);

  return *ctx->handle == 0 || *ctx->release == 0;
}

#else

static void
gum_pe_resolve_x86_tls (GumAddress base,
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
            gum_pe_function_is_ldr_handle_tls_data (insns, count))
          *handle = fn;
        if (*release == 0 &&
            gum_pe_function_is_ldr_release_tls_entry (insns, count))
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

#endif
#if defined (HAVE_I386)

static gboolean
gum_pe_function_is_ldr_handle_tls_data (cs_insn * insns,
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
      gum_pe_reg_set_update (entry_regs, &num_entry_regs, d->operands[0].reg,
          d->operands[1].reg);
#endif

    if (insns[i].id == X86_INS_CMP && d->op_count == 2 &&
        d->operands[0].type == X86_OP_MEM &&
        gum_pe_reg_set_contains (entry_regs, num_entry_regs,
            d->operands[0].mem.base) &&
        d->operands[0].mem.disp == GUM_PE_LDR_TLS_FLAGS_FIELD &&
        d->operands[1].type == X86_OP_IMM &&
        d->operands[1].imm == 9)
      checked_flag = TRUE;

    if (insns[i].id == X86_INS_MOV && d->op_count == 2 &&
        d->operands[1].type == X86_OP_MEM &&
        gum_pe_reg_set_contains (entry_regs, num_entry_regs,
            d->operands[1].mem.base) &&
        d->operands[1].mem.disp == GUM_PE_LOADER_ENTRY_DLL_BASE_OFFSET)
      read_dll_base = TRUE;
  }

  return checked_flag && read_dll_base;
}

static gboolean
gum_pe_function_is_ldr_release_tls_entry (cs_insn * insns,
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
      gum_pe_reg_set_update (flags_regs, &num_flags_regs, d->operands[0].reg,
          d->operands[1].reg);
#endif
    }

    if (insns[i].id == X86_INS_TEST && d->op_count == 2 &&
        d->operands[0].type == X86_OP_REG &&
        d->operands[1].type == X86_OP_REG &&
        d->operands[0].reg == d->operands[1].reg &&
        gum_pe_reg_set_contains (flags_regs, num_flags_regs,
            d->operands[0].reg))
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
gum_pe_reg_set_update (x86_reg * regs,
                       guint * n,
                       x86_reg dst,
                       x86_reg src)
{
  guint i;

  if (gum_pe_reg_set_contains (regs, *n, src))
  {
    if (!gum_pe_reg_set_contains (regs, *n, dst) && *n != 8)
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
gum_pe_reg_set_contains (const x86_reg * regs,
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
      GUM_PE_TLS_HOOK_MAX_DISTANCE, GUM_PE_TLS_SHARED_SIZE);
  if (region == 0)
    g_error ("Unable to allocate thread-init hook near kernel32");

  shared.magic = GUM_PE_TLS_SHARED_MAGIC;
  memcpy (shared.orig, head, sizeof (head));
  gum_process_memory_write (self->target, region, &shared, sizeof (shared));

  code_size = gum_pe_mapper_emit_shared_hook (self,
      region + GUM_PE_TLS_HANDLER_OFFSET, code);
  gum_pe_patch_target_code (self, region + GUM_PE_TLS_HANDLER_OFFSET, code,
      code_size);

  patch[0] = 0xe9;
  *((gint32 *) (patch + 1)) =
      (gint32) (region + GUM_PE_TLS_HANDLER_OFFSET - (self->tls_thunk + 5));
  gum_pe_patch_target_code (self, self->tls_thunk, patch, sizeof (patch));

  return region;
}

static gsize
gum_pe_mapper_emit_shared_hook (GumPeMapper * self,
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
    gum_pe_patch_target_code (self, self->tls_thunk, shared.orig,
        GUM_PE_TLS_THUNK_PATCH_SIZE);
    gum_process_memory_free (self->target, region, GUM_PE_TLS_SHARED_SIZE);
  }
}

static void
gum_pe_patch_target_code (GumPeMapper * self,
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

  gum_pe_mapper_emit_runtime (self, self->runtime, self->runtime_address,
      &code_size);

  g_assert (code_size <= self->runtime_file_size);
}

#if defined (HAVE_I386)

static void
gum_pe_mapper_emit_runtime (GumPeMapper * self,
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

  if (self->has_static_tls && !self->tls_via_thread)
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
    gum_pe_mapper_emit_tls_thread_init (self, &cw);
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

  if (self->has_static_tls && !self->tls_via_thread)
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

  gum_x86_writer_put_pop_reg (&cw, GUM_X86_XBP);
  gum_x86_writer_put_ret (&cw);

  gum_x86_writer_flush (&cw);
  *size = gum_x86_writer_offset (&cw);
  gum_x86_writer_clear (&cw);
}

#if GLIB_SIZEOF_VOID_P == 8

static void
gum_pe_mapper_emit_tls_thread_init (GumPeMapper * self,
                                    GumX86Writer * cw)
{
  GumPeTlsEntry entry;
  const guint8 rep_movsb[] = { 0xf3, 0xa4 };

  gum_pe_mapper_get_tls_entry (self, &entry);

  gum_x86_writer_put_push_reg (cw, GUM_X86_RBX);
  gum_x86_writer_put_push_reg (cw, GUM_X86_RSI);
  gum_x86_writer_put_push_reg (cw, GUM_X86_RDI);
  gum_x86_writer_put_sub_reg_imm (cw, GUM_X86_RSP, 8);

  gum_x86_writer_put_call_address_with_aligned_arguments (cw,
      GUM_CALL_SYSAPI, self->create_thread, 6,
      GUM_ARG_ADDRESS, (GumAddress) 0,
      GUM_ARG_ADDRESS, (GumAddress) 0,
      GUM_ARG_ADDRESS, self->tls_handle,
      GUM_ARG_ADDRESS, self->tls_entry,
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

#endif
#elif defined (HAVE_ARM64)

static void
gum_pe_mapper_emit_runtime (GumPeMapper * self,
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

  gum_arm64_writer_put_pop_reg_reg (&cw, ARM64_REG_FP, ARM64_REG_LR);
  gum_arm64_writer_put_ret (&cw);

  gum_arm64_writer_flush (&cw);
  *size = gum_arm64_writer_offset (&cw);
  gum_arm64_writer_clear (&cw);
}

#endif

static gboolean
gum_pe_mapper_protect_section (const GumPeSectionDetails * details,
                               gpointer user_data)
{
  GumPeMapper * self = user_data;

  gum_process_memory_protect (self->target,
      self->image_address + details->virtual_address, details->virtual_size,
      details->protection);

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
