/*
 * Copyright (C) 2014-2022 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 * Copyright (C) 2022 Francesco Tamagni <mrmacete@protonmail.ch>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "guminterceptor-priv.h"

#include "gumarm64reader.h"
#include "gumarm64relocator.h"
#include "gumarm64writer.h"
#include "gumlibc.h"
#include "gummemory.h"
#ifdef HAVE_DARWIN
# include "gumdarwin.h"
# include "gumdarwingrafter-priv.h"
#endif

#include <string.h>
#include <unistd.h>
#ifdef HAVE_DARWIN
# include <dlfcn.h>
# include <mach-o/dyld.h>
# include <mach-o/loader.h>
# include <stdlib.h>
#endif

#define GUM_ARM64_LOGICAL_PAGE_SIZE 4096

#define GUM_FRAME_OFFSET_CPU_CONTEXT 0
#define GUM_FRAME_OFFSET_NEXT_HOP \
    (GUM_FRAME_OFFSET_CPU_CONTEXT + sizeof (GumCpuContext))

#define GUM_FCDATA(context) \
    ((GumArm64FunctionContextData *) (context)->backend_data.storage)

typedef struct _GumArm64FunctionContextData GumArm64FunctionContextData;

struct _GumInterceptorBackend
{
  GRecMutex * mutex;
  GumCodeAllocator * allocator;

  GumArm64Writer writer;
  GumArm64Relocator relocator;

  gpointer thunks;
  gpointer enter_thunk;
  gpointer leave_thunk;
};

struct _GumArm64FunctionContextData
{
  guint redirect_code_size;
  arm64_reg scratch_reg;
};

G_STATIC_ASSERT (sizeof (GumArm64FunctionContextData)
    <= sizeof (GumFunctionContextBackendData));

extern void _gum_interceptor_begin_invocation (void);
extern void _gum_interceptor_end_invocation (void);

static void gum_interceptor_backend_create_thunks (
    GumInterceptorBackend * self);
static void gum_interceptor_backend_destroy_thunks (
    GumInterceptorBackend * self);

static void gum_emit_thunks (gpointer mem, GumInterceptorBackend * self);
static void gum_emit_enter_thunk (GumArm64Writer * aw);
static void gum_emit_leave_thunk (GumArm64Writer * aw);

static void gum_emit_prolog (GumArm64Writer * aw);
static void gum_emit_epilog (GumArm64Writer * aw);

GumInterceptorBackend *
_gum_interceptor_backend_create (GRecMutex * mutex,
                                 GumCodeAllocator * allocator)
{
  GumInterceptorBackend * backend;

  backend = g_slice_new0 (GumInterceptorBackend);
  backend->mutex = mutex;
  backend->allocator = allocator;

  if (gum_process_get_code_signing_policy () == GUM_CODE_SIGNING_OPTIONAL)
  {
    gum_arm64_writer_init (&backend->writer, NULL);
    gum_arm64_relocator_init (&backend->relocator, NULL, &backend->writer);

    gum_interceptor_backend_create_thunks (backend);
  }

  return backend;
}

void
_gum_interceptor_backend_destroy (GumInterceptorBackend * backend)
{
  if (backend->thunks != NULL)
  {
    gum_interceptor_backend_destroy_thunks (backend);

    gum_arm64_relocator_clear (&backend->relocator);
    gum_arm64_writer_clear (&backend->writer);
  }

  g_slice_free (GumInterceptorBackend, backend);
}

#ifdef HAVE_DARWIN

typedef struct _GumImportTarget GumImportTarget;
typedef struct _GumImportEntry GumImportEntry;
typedef struct _GumClaimHookOperation GumClaimHookOperation;
typedef struct _GumGraftedSegmentPairDetails GumGraftedSegmentPairDetails;

typedef gboolean (* GumFoundGraftedSegmentPairFunc) (
    const GumGraftedSegmentPairDetails * details, gpointer user_data);

struct _GumImportTarget
{
  gpointer implementation;
  GumFunctionContext * ctx;
  GArray * entries;
};

struct _GumImportEntry
{
  const struct mach_header_64 * mach_header;
  GumGraftedImport * import;
};

struct _GumClaimHookOperation
{
  GumFunctionContext * ctx;
  guint32 code_offset;

  gboolean success;
};

struct _GumGraftedSegmentPairDetails
{
  const struct mach_header_64 * mach_header;

  GumGraftedHeader * header;

  GumGraftedHook * hooks;
  guint32 num_hooks;

  GumGraftedImport * imports;
  guint32 num_imports;
};

static void gum_on_module_added (const struct mach_header * mh,
    intptr_t vmaddr_slide);
static void gum_on_module_removed (const struct mach_header * mh,
    intptr_t vmaddr_slide);
static gboolean gum_attach_segment_pair (
    const GumGraftedSegmentPairDetails * details, gpointer user_data);
static gboolean gum_detach_segment_pair (
    const GumGraftedSegmentPairDetails * details, gpointer user_data);
static gboolean gum_claim_hook_if_found_in_pair (
    const GumGraftedSegmentPairDetails * details, gpointer user_data);

static GumImportTarget * gum_import_target_register (gpointer implementation);
static void gum_import_target_link (GumImportTarget * self,
    GumFunctionContext * ctx);
static void gum_import_target_free (GumImportTarget * target);
static void gum_import_target_maybe_activate (GumImportTarget * self,
    const GumImportEntry * entry);
static void gum_import_target_activate (GumImportTarget * self,
    const GumImportEntry * entry);
static void gum_import_target_deactivate (GumImportTarget * self,
    const GumImportEntry * entry);

static void gum_enumerate_grafted_segment_pairs (gconstpointer mach_header,
    GumFoundGraftedSegmentPairFunc func, gpointer user_data);

static int gum_compare_grafted_hook (const void * element_a,
    const void * element_b);

static gboolean gum_is_system_module (const gchar * path);

static GumInterceptorBackend * gum_interceptor_backend = NULL;
static GHashTable * gum_import_targets = NULL;

gboolean
_gum_interceptor_backend_claim_grafted_trampoline (GumInterceptorBackend * self,
                                                   GumFunctionContext * ctx)
{
  GumImportTarget * target;
  Dl_info info;
  GumClaimHookOperation op;

  if (gum_interceptor_backend == NULL)
  {
    gum_interceptor_backend = self;
    gum_import_targets = g_hash_table_new_full (NULL, NULL, NULL,
        (GDestroyNotify) gum_import_target_free);

    _dyld_register_func_for_add_image (gum_on_module_added);
    _dyld_register_func_for_remove_image (gum_on_module_removed);
  }

  target = g_hash_table_lookup (gum_import_targets, ctx->function_address);
  if (target != NULL)
  {
    gum_import_target_link (target, ctx);
    return TRUE;
  }

  if (dladdr (ctx->function_address, &info) == 0)
    return FALSE;

  op.ctx = ctx;
  op.code_offset = (guint8 *) ctx->function_address - (guint8 *) info.dli_fbase;

  op.success = FALSE;

  gum_enumerate_grafted_segment_pairs (info.dli_fbase,
      gum_claim_hook_if_found_in_pair, &op);

  if (!op.success && gum_is_system_module (info.dli_fname))
  {
    target = gum_import_target_register (ctx->function_address);
    gum_import_target_link (target, ctx);
    return TRUE;
  }

  return op.success;
}

static void
gum_on_module_added (const struct mach_header * mh,
                     intptr_t vmaddr_slide)
{
  g_rec_mutex_lock (gum_interceptor_backend->mutex);
  gum_enumerate_grafted_segment_pairs (mh, gum_attach_segment_pair, NULL);
  g_rec_mutex_unlock (gum_interceptor_backend->mutex);
}

static void
gum_on_module_removed (const struct mach_header * mh,
                       intptr_t vmaddr_slide)
{
  g_rec_mutex_lock (gum_interceptor_backend->mutex);
  gum_enumerate_grafted_segment_pairs (mh, gum_detach_segment_pair, NULL);
  g_rec_mutex_unlock (gum_interceptor_backend->mutex);
}

static gboolean
gum_attach_segment_pair (const GumGraftedSegmentPairDetails * details,
                         gpointer user_data)
{
  const struct mach_header_64 * mach_header = details->mach_header;
  GumGraftedHeader * header = details->header;
  GumGraftedImport * imports = details->imports;
  guint32 i;

  header->begin_invocation =
      GPOINTER_TO_SIZE (_gum_interceptor_begin_invocation);
  header->end_invocation =
      GPOINTER_TO_SIZE (_gum_interceptor_end_invocation);

  for (i = 0; i != header->num_imports; i++)
  {
    GumGraftedImport * import = &imports[i];
    gpointer * slot, implementation;
    GumImportTarget * target;
    GumImportEntry entry;

    slot = (gpointer *) ((const guint8 *) mach_header + import->slot_offset);
    implementation = *slot;

    target = g_hash_table_lookup (gum_import_targets, implementation);
    if (target == NULL)
      target = gum_import_target_register (implementation);

    entry.mach_header = mach_header;
    entry.import = import;
    g_array_append_val (target->entries, entry);

    gum_import_target_maybe_activate (target, &entry);
  }

  return TRUE;
}

static gboolean
gum_detach_segment_pair (const GumGraftedSegmentPairDetails * details,
                         gpointer user_data)
{
  const struct mach_header_64 * mach_header = details->mach_header;
  GHashTableIter iter;
  gpointer implementation;
  GumImportTarget * target;
  GQueue empty_targets = G_QUEUE_INIT;
  GList * cur;

  g_hash_table_iter_init (&iter, gum_import_targets);
  while (g_hash_table_iter_next (&iter, &implementation, (gpointer *) &target))
  {
    GArray * entries = target->entries;
    gint i;

    for (i = 0; i < entries->len; i++)
    {
      GumImportEntry * entry = &g_array_index (entries, GumImportEntry, i);
      if (entry->mach_header == mach_header)
      {
        g_array_remove_index_fast (entries, i);
        i--;
      }
    }

    if (target->ctx == NULL && entries->len == 0)
    {
      g_queue_push_tail (&empty_targets, implementation);
    }
    else if (entries->len != 0)
    {
      gum_import_target_maybe_activate (target,
          &g_array_index (entries, GumImportEntry, 0));
    }
  }

  for (cur = empty_targets.head; cur != NULL; cur = cur->next)
  {
    g_hash_table_remove (gum_import_targets, cur->data);
  }

  g_queue_clear (&empty_targets);

  return TRUE;
}

static gboolean
gum_claim_hook_if_found_in_pair (const GumGraftedSegmentPairDetails * details,
                                 gpointer user_data)
{
  GumClaimHookOperation * op = user_data;
  GumFunctionContext * ctx = op->ctx;
  GumGraftedHook key = { 0, };
  GumGraftedHook * hook;
  guint8 * trampoline;

  key.code_offset = op->code_offset;
  hook = bsearch (&key, details->hooks, details->header->num_hooks,
      sizeof (GumGraftedHook), gum_compare_grafted_hook);
  if (hook == NULL)
    return TRUE;

  hook->user_data = GPOINTER_TO_SIZE (ctx);

  ctx->grafted_hook = hook;

  trampoline = (guint8 *) details->mach_header + hook->trampoline_offset;
  ctx->on_enter_trampoline =
      trampoline + GUM_GRAFTED_HOOK_ON_ENTER_OFFSET (hook);
  ctx->on_leave_trampoline =
      trampoline + GUM_GRAFTED_HOOK_ON_LEAVE_OFFSET (hook);
  ctx->on_invoke_trampoline =
      trampoline + GUM_GRAFTED_HOOK_ON_INVOKE_OFFSET (hook);

  op->success = TRUE;

  return FALSE;
}

static GumImportTarget *
gum_import_target_register (gpointer implementation)
{
  GumImportTarget * target;

  target = g_slice_new (GumImportTarget);
  target->implementation = implementation;
  target->ctx = NULL;
  target->entries = g_array_new (FALSE, FALSE, sizeof (GumImportEntry));

  g_hash_table_insert (gum_import_targets, implementation, target);

  return target;
}

static void
gum_import_target_link (GumImportTarget * self,
                        GumFunctionContext * ctx)
{
  self->ctx = ctx;
  ctx->import_target = self;
}

static void
gum_import_target_free (GumImportTarget * target)
{
  g_array_free (target->entries, TRUE);

  g_slice_free (GumImportTarget, target);
}

static void
gum_import_target_activate_all (GumImportTarget * self)
{
  GArray * entries = self->entries;
  guint i;

  for (i = 0; i != entries->len; i++)
  {
    const GumImportEntry * entry = &g_array_index (entries, GumImportEntry, i);
    gum_import_target_activate (self, entry);
  }
}

static void
gum_import_target_deactivate_all (GumImportTarget * self)
{
  GArray * entries = self->entries;
  guint i;

  for (i = 0; i != entries->len; i++)
  {
    const GumImportEntry * entry = &g_array_index (entries, GumImportEntry, i);
    gum_import_target_deactivate (self, entry);
  }
}

static void
gum_import_target_maybe_activate (GumImportTarget * self,
                                  const GumImportEntry * entry)
{
  GumFunctionContext * ctx = self->ctx;

  if (ctx == NULL || !ctx->activated)
    return;

  gum_import_target_activate (self, entry);
}

static void
gum_import_target_activate (GumImportTarget * self,
                            const GumImportEntry * entry)
{
  GumFunctionContext * ctx = self->ctx;
  GumGraftedImport * import = entry->import;
  gpointer * slot;
  guint8 * trampoline;
  mach_port_t self_task;
  GumPageProtection prot;
  gboolean flip_needed;

  import->user_data = GPOINTER_TO_SIZE (ctx);

  slot = (gpointer *) ((guint8 *) entry->mach_header + import->slot_offset);

  trampoline = (guint8 *) entry->mach_header + import->trampoline_offset;
  ctx->on_enter_trampoline =
      trampoline + GUM_GRAFTED_IMPORT_ON_ENTER_OFFSET (import);
  ctx->on_leave_trampoline =
      trampoline + GUM_GRAFTED_IMPORT_ON_LEAVE_OFFSET (import);
  ctx->on_invoke_trampoline = self->implementation;

  self_task = mach_task_self ();

  if (!gum_darwin_query_protection (self_task, GUM_ADDRESS (slot), &prot))
    return;

  flip_needed = (prot & GUM_PAGE_WRITE) == 0;
  if (flip_needed)
  {
    if (!gum_try_mprotect (slot, 4, prot | GUM_PAGE_WRITE))
      return;
  }

  *slot = ctx->on_enter_trampoline;

  if (flip_needed)
    gum_try_mprotect (slot, 4, prot);
}

static void
gum_import_target_deactivate (GumImportTarget * self,
                              const GumImportEntry * entry)
{
  mach_port_t self_task;
  GumPageProtection prot;
  gboolean flip_needed;
  gpointer * slot =
      (gpointer *) ((guint8 *) entry->mach_header + entry->import->slot_offset);

  self_task = mach_task_self ();

  if (!gum_darwin_query_protection (self_task, GUM_ADDRESS (slot), &prot))
    return;

  flip_needed = (prot & GUM_PAGE_WRITE) == 0;
  if (flip_needed)
  {
    if (!gum_try_mprotect (slot, 4, prot | GUM_PAGE_WRITE))
      return;
  }

  *slot = self->implementation;

  if (flip_needed)
    gum_try_mprotect (slot, 4, prot);
}

static void
gum_import_target_clear_user_data (GumImportTarget * self)
{
  GArray * entries = self->entries;
  guint i;

  for (i = 0; i != entries->len; i++)
  {
    const GumImportEntry * entry = &g_array_index (entries, GumImportEntry, i);
    entry->import->user_data = 0;
  }
}

static void
gum_enumerate_grafted_segment_pairs (gconstpointer mach_header,
                                     GumFoundGraftedSegmentPairFunc func,
                                     gpointer user_data)
{
  const struct mach_header_64 * mh;
  gconstpointer command;
  intptr_t slide;
  guint i;

  mh = mach_header;
  command = mh + 1;
  slide = 0;
  for (i = 0; i != mh->ncmds; i++)
  {
    const struct load_command * lc = command;

    if (lc->cmd == LC_SEGMENT_64)
    {
      const struct segment_command_64 * sc = command;

      if (strcmp (sc->segname, "__TEXT") == 0)
      {
        slide = (guint8 *) mach_header - (guint8 *) sc->vmaddr;
      }
      else if (g_str_has_prefix (sc->segname, "__FRIDA_DATA"))
      {
        GumGraftedHeader * header = GSIZE_TO_POINTER (sc->vmaddr + slide);

        if (header->abi_version == GUM_DARWIN_GRAFTER_ABI_VERSION)
        {
          GumGraftedSegmentPairDetails d;

          d.mach_header = mh;

          d.header = header;

          d.hooks = (GumGraftedHook *) (header + 1);
          d.num_hooks = header->num_hooks;

          d.imports = (GumGraftedImport *) (d.hooks + header->num_hooks);
          d.num_imports = header->num_imports;

          if (!func (&d, user_data))
            return;
        }
      }
    }

    command = (const guint8 *) command + lc->cmdsize;
  }
}

static int
gum_compare_grafted_hook (const void * element_a,
                          const void * element_b)
{
  const GumGraftedHook * a = element_a;
  const GumGraftedHook * b = element_b;

  return (gssize) a->code_offset - (gssize) b->code_offset;
}

static gboolean
gum_is_system_module (const gchar * path)
{
  gboolean has_system_prefix;
  static gboolean api_initialized = FALSE;
  static bool (* dsc_contains_path) (const char * path) = NULL;

  has_system_prefix = g_str_has_prefix (path, "/System/") ||
      g_str_has_prefix (path, "/usr/lib/") ||
      g_str_has_prefix (path, "/Developer/") ||
      g_str_has_prefix (path, "/private/preboot/");
  if (has_system_prefix)
    return TRUE;

  if (!api_initialized)
  {
    dsc_contains_path =
        dlsym (RTLD_DEFAULT, "_dyld_shared_cache_contains_path");
    api_initialized = TRUE;
  }

  if (dsc_contains_path != NULL)
    return dsc_contains_path (path);

  return FALSE;
}

#else

gboolean
_gum_interceptor_backend_claim_grafted_trampoline (GumInterceptorBackend * self,
                                                   GumFunctionContext * ctx)
{
  return FALSE;
}

#endif

static gboolean
gum_interceptor_backend_prepare_trampoline (GumInterceptorBackend * self,
                                            GumFunctionContext * ctx,
                                            gboolean * need_deflector)
{
  GumArm64FunctionContextData * data = GUM_FCDATA (ctx);
  gpointer function_address = ctx->function_address;
  guint redirect_limit;

  *need_deflector = FALSE;

  if (gum_arm64_relocator_can_relocate (function_address, 16,
      GUM_SCENARIO_ONLINE, &redirect_limit, &data->scratch_reg))
  {
    data->redirect_code_size = 16;

    ctx->trampoline_slice = gum_code_allocator_alloc_slice (self->allocator);
  }
  else
  {
    GumAddressSpec spec;
    gsize alignment;

    if (redirect_limit >= 8)
    {
      data->redirect_code_size = 8;

      spec.near_address = GSIZE_TO_POINTER (
          GPOINTER_TO_SIZE (function_address) &
          ~((gsize) (GUM_ARM64_LOGICAL_PAGE_SIZE - 1)));
      spec.max_distance = GUM_ARM64_ADRP_MAX_DISTANCE;
      alignment = GUM_ARM64_LOGICAL_PAGE_SIZE;
    }
    else if (redirect_limit >= 4)
    {
      data->redirect_code_size = 4;

      spec.near_address = function_address;
      spec.max_distance = GUM_ARM64_B_MAX_DISTANCE;
      alignment = 0;
    }
    else
    {
      return FALSE;
    }

    ctx->trampoline_slice = gum_code_allocator_try_alloc_slice_near (
        self->allocator, &spec, alignment);
    if (ctx->trampoline_slice == NULL)
    {
      ctx->trampoline_slice = gum_code_allocator_alloc_slice (self->allocator);
      *need_deflector = TRUE;
    }
  }

  if (data->scratch_reg == ARM64_REG_INVALID)
    goto no_scratch_reg;

  return TRUE;

no_scratch_reg:
  {
    gum_code_slice_unref (ctx->trampoline_slice);
    ctx->trampoline_slice = NULL;
    return FALSE;
  }
}

gboolean
_gum_interceptor_backend_create_trampoline (GumInterceptorBackend * self,
                                            GumFunctionContext * ctx)
{
  GumArm64Writer * aw = &self->writer;
  GumArm64Relocator * ar = &self->relocator;
  gpointer function_address = ctx->function_address;
  GumArm64FunctionContextData * data = GUM_FCDATA (ctx);
  gboolean need_deflector;
  gpointer deflector_target;
  GString * signature;
  gboolean is_eligible_for_lr_rewriting;
  guint reloc_bytes;

  if (!gum_interceptor_backend_prepare_trampoline (self, ctx, &need_deflector))
    return FALSE;

  gum_arm64_writer_reset (aw, ctx->trampoline_slice->data);

  if (ctx->type == GUM_INTERCEPTOR_TYPE_FAST)
  {
    deflector_target = ctx->replacement_function;
  }
  else
  {
    ctx->on_enter_trampoline = gum_sign_code_pointer (gum_arm64_writer_cur (aw));
    deflector_target = ctx->on_enter_trampoline;
  }

  if (need_deflector)
  {
    GumAddressSpec caller;
    gpointer return_address;
    gboolean dedicated;

    caller.near_address = function_address + data->redirect_code_size - 4;
    caller.max_distance = GUM_ARM64_B_MAX_DISTANCE;

    return_address = function_address + data->redirect_code_size;

    dedicated = data->redirect_code_size == 4;

    ctx->trampoline_deflector = gum_code_allocator_alloc_deflector (
        self->allocator, &caller, return_address, deflector_target, dedicated);
    if (ctx->trampoline_deflector == NULL)
    {
      gum_code_slice_unref (ctx->trampoline_slice);
      ctx->trampoline_slice = NULL;
      return FALSE;
    }

    gum_arm64_writer_put_pop_reg_reg (aw, ARM64_REG_X0, ARM64_REG_LR);
  }

  if (ctx->type != GUM_INTERCEPTOR_TYPE_FAST)
  {
    gum_arm64_writer_put_ldr_reg_address (aw, ARM64_REG_X17, GUM_ADDRESS (ctx));
    gum_arm64_writer_put_ldr_reg_address (aw, ARM64_REG_X16,
        GUM_ADDRESS (gum_sign_code_pointer (self->enter_thunk)));
    gum_arm64_writer_put_br_reg (aw, ARM64_REG_X16);

    ctx->on_leave_trampoline = gum_arm64_writer_cur (aw);

    gum_arm64_writer_put_ldr_reg_address (aw, ARM64_REG_X17, GUM_ADDRESS (ctx));
    gum_arm64_writer_put_ldr_reg_address (aw, ARM64_REG_X16,
        GUM_ADDRESS (gum_sign_code_pointer (self->leave_thunk)));
    gum_arm64_writer_put_br_reg (aw, ARM64_REG_X16);

    gum_arm64_writer_flush (aw);
    g_assert (gum_arm64_writer_offset (aw) <= ctx->trampoline_slice->size);
  }

  ctx->on_invoke_trampoline = gum_sign_code_pointer (gum_arm64_writer_cur (aw));

  gum_arm64_relocator_reset (ar, function_address, aw);

  signature = g_string_sized_new (16);

  do
  {
    const cs_insn * insn;

    reloc_bytes = gum_arm64_relocator_read_one (ar, &insn);
    g_assert (reloc_bytes != 0);

    if (signature->len != 0)
      g_string_append_c (signature, ';');
    g_string_append (signature, insn->mnemonic);
  }
  while (reloc_bytes < data->redirect_code_size);

  /*
   * Try to deal with minimal thunks that determine their caller and pass
   * it along to some inner function. This is important to support hooking
   * dlopen() on Android, where the dynamic linker uses the caller address
   * to decide on namespace and whether to allow the particular library to
   * be used by a particular caller.
   *
   * Because we potentially replace LR in order to trap the return, we end
   * up breaking dlopen() in such cases. We work around this by detecting
   * LR being read, and replace that instruction with a load of the actual
   * caller.
   *
   * This is however a bit risky done blindly, so we try to limit the
   * scope to the bare minimum. A potentially better longer term solution
   * is to analyze the function and patch each point of return, so we don't
   * have to replace LR on entry. That is however a bit complex, so we
   * opt for this simpler solution for now.
   */
  is_eligible_for_lr_rewriting = strcmp (signature->str, "mov;b") == 0 ||
      g_str_has_prefix (signature->str, "stp;mov;mov;bl");

  g_string_free (signature, TRUE);

  if (is_eligible_for_lr_rewriting)
  {
    const cs_insn * insn;

    while ((insn = gum_arm64_relocator_peek_next_write_insn (ar)) != NULL)
    {
      if (insn->id == ARM64_INS_MOV &&
          insn->detail->arm64.operands[1].reg == ARM64_REG_LR)
      {
        arm64_reg dst_reg = insn->detail->arm64.operands[0].reg;
        const guint reg_size = sizeof (gpointer);
        const guint reg_pair_size = 2 * reg_size;
        guint dst_reg_index, dst_reg_slot_index, dst_reg_offset_in_frame;

        gum_arm64_writer_put_push_all_x_registers (aw);

        gum_arm64_writer_put_call_address_with_arguments (aw,
            GUM_ADDRESS (_gum_interceptor_translate_top_return_address), 1,
            GUM_ARG_REGISTER, ARM64_REG_LR);

        if (dst_reg >= ARM64_REG_X0 && dst_reg <= ARM64_REG_X28)
        {
          dst_reg_index = dst_reg - ARM64_REG_X0;
        }
        else
        {
          g_assert (dst_reg >= ARM64_REG_X29 && dst_reg <= ARM64_REG_X30);

          dst_reg_index = dst_reg - ARM64_REG_X29;
        }

        dst_reg_slot_index = (dst_reg_index * reg_size) / reg_pair_size;

        dst_reg_offset_in_frame = (15 - dst_reg_slot_index) * reg_pair_size;
        if (dst_reg_index % 2 != 0)
          dst_reg_offset_in_frame += reg_size;

        gum_arm64_writer_put_str_reg_reg_offset (aw, ARM64_REG_X0, ARM64_REG_SP,
            dst_reg_offset_in_frame);

        gum_arm64_writer_put_pop_all_x_registers (aw);

        gum_arm64_relocator_skip_one (ar);
      }
      else
      {
        gum_arm64_relocator_write_one (ar);
      }
    }
  }
  else
  {
    gum_arm64_relocator_write_all (ar);
  }

  if (!ar->eoi)
  {
    GumAddress resume_at;

    resume_at = gum_sign_code_address (
        GUM_ADDRESS (function_address) + reloc_bytes);
    gum_arm64_writer_put_ldr_reg_address (aw, data->scratch_reg, resume_at);
    gum_arm64_writer_put_br_reg (aw, data->scratch_reg);
  }

  gum_arm64_writer_flush (aw);
  g_assert (gum_arm64_writer_offset (aw) <= ctx->trampoline_slice->size);

  ctx->overwritten_prologue_len = reloc_bytes;
  gum_memcpy (ctx->overwritten_prologue, function_address, reloc_bytes);

  return TRUE;
}

void
_gum_interceptor_backend_destroy_trampoline (GumInterceptorBackend * self,
                                             GumFunctionContext * ctx)
{
#ifdef HAVE_DARWIN
  if (ctx->grafted_hook != NULL)
  {
    GumGraftedHook * func = ctx->grafted_hook;
    func->user_data = 0;
    return;
  }

  if (ctx->import_target != NULL)
  {
    gum_import_target_clear_user_data (ctx->import_target);
    return;
  }
#endif

  gum_code_slice_unref (ctx->trampoline_slice);
  gum_code_deflector_unref (ctx->trampoline_deflector);
  ctx->trampoline_slice = NULL;
  ctx->trampoline_deflector = NULL;
}

void
_gum_interceptor_backend_activate_trampoline (GumInterceptorBackend * self,
                                              GumFunctionContext * ctx,
                                              gpointer prologue)
{
  GumArm64Writer * aw = &self->writer;
  GumArm64FunctionContextData * data = GUM_FCDATA (ctx);
  GumAddress on_enter;

  if (ctx->type == GUM_INTERCEPTOR_TYPE_FAST)
    on_enter = GUM_ADDRESS (ctx->replacement_function);
  else
    on_enter = GUM_ADDRESS (ctx->on_enter_trampoline);

#ifdef HAVE_DARWIN
  if (ctx->grafted_hook != NULL)
  {
    _gum_grafted_hook_activate (ctx->grafted_hook);
    return;
  }

  if (ctx->import_target != NULL)
  {
    gum_import_target_activate_all (ctx->import_target);
    return;
  }
#endif

  gum_arm64_writer_reset (aw, prologue);
  aw->pc = GUM_ADDRESS (ctx->function_address);

  if (ctx->trampoline_deflector != NULL)
  {
    if (data->redirect_code_size == 8)
    {
      gum_arm64_writer_put_push_reg_reg (aw, ARM64_REG_X0, ARM64_REG_LR);
      gum_arm64_writer_put_bl_imm (aw,
          GUM_ADDRESS (ctx->trampoline_deflector->trampoline));
    }
    else
    {
      g_assert (data->redirect_code_size == 4);
      gum_arm64_writer_put_b_imm (aw,
          GUM_ADDRESS (ctx->trampoline_deflector->trampoline));
    }
  }
  else
  {
    switch (data->redirect_code_size)
    {
      case 4:
        gum_arm64_writer_put_b_imm (aw, on_enter);
        break;
      case 8:
        gum_arm64_writer_put_adrp_reg_address (aw, data->scratch_reg, on_enter);
        gum_arm64_writer_put_br_reg_no_auth (aw, data->scratch_reg);
        break;
      case 16:
        gum_arm64_writer_put_ldr_reg_address (aw, data->scratch_reg, on_enter);
        gum_arm64_writer_put_br_reg (aw, data->scratch_reg);
        break;
      default:
        g_assert_not_reached ();
    }
  }

  gum_arm64_writer_flush (aw);
  g_assert (gum_arm64_writer_offset (aw) <= data->redirect_code_size);
}

void
_gum_interceptor_backend_deactivate_trampoline (GumInterceptorBackend * self,
                                                GumFunctionContext * ctx,
                                                gpointer prologue)
{
#ifdef HAVE_DARWIN
  if (ctx->grafted_hook != NULL)
  {
    _gum_grafted_hook_deactivate (ctx->grafted_hook);
    return;
  }

  if (ctx->import_target != NULL)
  {
    gum_import_target_deactivate_all (ctx->import_target);
    return;
  }
#endif

  gum_memcpy (prologue, ctx->overwritten_prologue,
      ctx->overwritten_prologue_len);
}

gpointer
_gum_interceptor_backend_get_function_address (GumFunctionContext * ctx)
{
  return ctx->function_address;
}

gpointer
_gum_interceptor_backend_resolve_redirect (GumInterceptorBackend * self,
                                           gpointer address)
{
  return gum_arm64_reader_try_get_relative_jump_target (address);
}

static void
gum_interceptor_backend_create_thunks (GumInterceptorBackend * self)
{
  gsize page_size, code_size;

  page_size = gum_query_page_size ();
  code_size = page_size;

  self->thunks = gum_memory_allocate (NULL, code_size, page_size, GUM_PAGE_RW);
  gum_memory_patch_code (self->thunks, 1024,
      (GumMemoryPatchApplyFunc) gum_emit_thunks, self);
}

static void
gum_interceptor_backend_destroy_thunks (GumInterceptorBackend * self)
{
  gum_memory_free (self->thunks, gum_query_page_size ());
}

static void
gum_emit_thunks (gpointer mem,
                 GumInterceptorBackend * self)
{
  GumArm64Writer * aw = &self->writer;

  self->enter_thunk = self->thunks;
  gum_arm64_writer_reset (aw, mem);
  aw->pc = GUM_ADDRESS (self->enter_thunk);
  gum_emit_enter_thunk (aw);
  gum_arm64_writer_flush (aw);

  self->leave_thunk =
      (guint8 *) self->enter_thunk + gum_arm64_writer_offset (aw);
  gum_emit_leave_thunk (aw);
  gum_arm64_writer_flush (aw);
}

static void
gum_emit_enter_thunk (GumArm64Writer * aw)
{
  gum_emit_prolog (aw);

  gum_arm64_writer_put_add_reg_reg_imm (aw, ARM64_REG_X1, ARM64_REG_SP,
      GUM_FRAME_OFFSET_CPU_CONTEXT);
  gum_arm64_writer_put_add_reg_reg_imm (aw, ARM64_REG_X2, ARM64_REG_SP,
      GUM_FRAME_OFFSET_CPU_CONTEXT + G_STRUCT_OFFSET (GumCpuContext, lr));
  gum_arm64_writer_put_add_reg_reg_imm (aw, ARM64_REG_X3, ARM64_REG_SP,
      GUM_FRAME_OFFSET_NEXT_HOP);

  gum_arm64_writer_put_call_address_with_arguments (aw,
      GUM_ADDRESS (_gum_function_context_begin_invocation), 4,
      GUM_ARG_REGISTER, ARM64_REG_X17,
      GUM_ARG_REGISTER, ARM64_REG_X1,
      GUM_ARG_REGISTER, ARM64_REG_X2,
      GUM_ARG_REGISTER, ARM64_REG_X3);

  gum_emit_epilog (aw);
}

static void
gum_emit_leave_thunk (GumArm64Writer * aw)
{
  gum_emit_prolog (aw);

  gum_arm64_writer_put_add_reg_reg_imm (aw, ARM64_REG_X1, ARM64_REG_SP,
      GUM_FRAME_OFFSET_CPU_CONTEXT);
  gum_arm64_writer_put_add_reg_reg_imm (aw, ARM64_REG_X2, ARM64_REG_SP,
      GUM_FRAME_OFFSET_NEXT_HOP);

  gum_arm64_writer_put_call_address_with_arguments (aw,
      GUM_ADDRESS (_gum_function_context_end_invocation), 3,
      GUM_ARG_REGISTER, ARM64_REG_X17,
      GUM_ARG_REGISTER, ARM64_REG_X1,
      GUM_ARG_REGISTER, ARM64_REG_X2);

  gum_emit_epilog (aw);
}

static void
gum_emit_prolog (GumArm64Writer * aw)
{
  gint i;

  /*
   * Set up our stack frame:
   *
   * [in: frame pointer chain entry, out: next_hop]
   * [in/out: cpu_context]
   */

  /* Reserve space for next_hop */
  gum_arm64_writer_put_sub_reg_reg_imm (aw, ARM64_REG_SP, ARM64_REG_SP, 16);

  /* Store vector registers */
  for (i = 30; i != -2; i -= 2)
    gum_arm64_writer_put_push_reg_reg (aw, ARM64_REG_Q0 + i, ARM64_REG_Q1 + i);

  /* Store X1-X28, FP, and LR */
  gum_arm64_writer_put_push_reg_reg (aw, ARM64_REG_FP, ARM64_REG_LR);
  for (i = 27; i != -1; i -= 2)
    gum_arm64_writer_put_push_reg_reg (aw, ARM64_REG_X0 + i, ARM64_REG_X1 + i);

  /* Store NZCV and X0 */
  gum_arm64_writer_put_mov_reg_nzcv (aw, ARM64_REG_X1);
  gum_arm64_writer_put_push_reg_reg (aw, ARM64_REG_X1, ARM64_REG_X0);

  /* PC placeholder and SP */
  gum_arm64_writer_put_add_reg_reg_imm (aw, ARM64_REG_X0,
      ARM64_REG_SP, sizeof (GumCpuContext) -
      G_STRUCT_OFFSET (GumCpuContext, nzcv) + 16);
  gum_arm64_writer_put_push_reg_reg (aw, ARM64_REG_XZR, ARM64_REG_X0);

  /* Frame pointer chain entry */
  gum_arm64_writer_put_str_reg_reg_offset (aw, ARM64_REG_LR, ARM64_REG_SP,
      sizeof (GumCpuContext) + 8);
  gum_arm64_writer_put_str_reg_reg_offset (aw, ARM64_REG_FP, ARM64_REG_SP,
      sizeof (GumCpuContext) + 0);
  gum_arm64_writer_put_add_reg_reg_imm (aw, ARM64_REG_FP, ARM64_REG_SP,
      sizeof (GumCpuContext));
}

static void
gum_emit_epilog (GumArm64Writer * aw)
{
  guint i;

  /* Skip PC and SP */
  gum_arm64_writer_put_add_reg_reg_imm (aw, ARM64_REG_SP, ARM64_REG_SP, 16);

  /* Restore NZCV and X0 */
  gum_arm64_writer_put_pop_reg_reg (aw, ARM64_REG_X1, ARM64_REG_X0);
  gum_arm64_writer_put_mov_nzcv_reg (aw, ARM64_REG_X1);

  /* Restore X1-X28, FP, and LR */
  for (i = 1; i != 29; i += 2)
    gum_arm64_writer_put_pop_reg_reg (aw, ARM64_REG_X0 + i, ARM64_REG_X1 + i);
  gum_arm64_writer_put_pop_reg_reg (aw, ARM64_REG_FP, ARM64_REG_LR);

  /* Restore vector registers */
  for (i = 0; i != 32; i += 2)
    gum_arm64_writer_put_pop_reg_reg (aw, ARM64_REG_Q0 + i, ARM64_REG_Q1 + i);

  gum_arm64_writer_put_pop_reg_reg (aw, ARM64_REG_X16, ARM64_REG_X17);
#ifndef HAVE_PTRAUTH
  gum_arm64_writer_put_ret_reg (aw, ARM64_REG_X16);
#else
  gum_arm64_writer_put_br_reg (aw, ARM64_REG_X16);
#endif
}
