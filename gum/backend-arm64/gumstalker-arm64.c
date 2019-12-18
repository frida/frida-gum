/*
 * Copyright (C) 2014-2019 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 * Copyright (C) 2017 Antonio Ken Iannillo <ak.iannillo@gmail.com>
 * Copyright (C) 2019 John Coates <john@johncoates.dev>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumstalker.h"

#include "gumarm64reader.h"
#include "gumarm64relocator.h"
#include "gumarm64writer.h"
#include "gummemory.h"
#include "gummetalhash.h"
#include "gumspinlock.h"
#include "gumtls.h"

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/syscall.h>

#define GUM_CODE_SLAB_MAX_SIZE  (4 * 1024 * 1024)
#define GUM_EXEC_BLOCK_MIN_SIZE 1024

#define GUM_RESTORATION_PROLOG_SIZE 4

#define GUM_INSTRUCTION_OFFSET_NONE (-1)

#define GUM_STALKER_LOCK(o) g_mutex_lock (&(o)->mutex)
#define GUM_STALKER_UNLOCK(o) g_mutex_unlock (&(o)->mutex)

typedef struct _GumInfectContext GumInfectContext;
typedef struct _GumDisinfectContext GumDisinfectContext;

typedef struct _GumCallProbe GumCallProbe;
typedef struct _GumSlab GumSlab;

typedef struct _GumExecFrame GumExecFrame;
typedef struct _GumExecCtx GumExecCtx;
typedef void (* GumExecHelperWriteFunc) (GumExecCtx * ctx, GumArm64Writer * cw);
typedef struct _GumExecBlock GumExecBlock;
typedef gpointer (GUM_THUNK * GumExecCtxReplaceCurrentBlockFunc) (
    GumExecCtx * ctx, gpointer start_address);

typedef guint GumPrologType;
typedef guint GumCodeContext;
typedef struct _GumGeneratorContext GumGeneratorContext;
typedef struct _GumCalloutEntry GumCalloutEntry;
typedef struct _GumInstruction GumInstruction;
typedef struct _GumBranchTarget GumBranchTarget;

typedef guint GumVirtualizationRequirements;

struct _GumStalker
{
  GObject parent;

  guint page_size;
  guint slab_size;
  guint slab_header_size;
  guint slab_max_blocks;
  gboolean is_rwx_supported;

  GMutex mutex;
  GSList * contexts;
  GumTlsKey exec_ctx;

  GArray * exclusions;
  gint trust_threshold;
  volatile gboolean any_probes_attached;
  volatile gint last_probe_id;
  GumSpinlock probe_lock;
  GHashTable * probe_target_by_id;
  GHashTable * probe_array_by_address;
};

struct _GumInfectContext
{
  GumStalker * stalker;
  GumStalkerTransformer * transformer;
  GumEventSink * sink;
};

struct _GumDisinfectContext
{
  GumExecCtx * exec_ctx;
  gboolean success;
};

struct _GumCallProbe
{
  GumProbeId id;
  GumCallProbeCallback callback;
  gpointer user_data;
  GDestroyNotify user_notify;
};

struct _GumExecFrame
{
  gpointer real_address;
  gpointer code_address;
};

enum _GumExecCtxState
{
  GUM_EXEC_CTX_ACTIVE,
  GUM_EXEC_CTX_UNFOLLOW_PENDING,
  GUM_EXEC_CTX_DESTROY_PENDING
};

struct _GumExecCtx
{
  volatile gint state;
  volatile gboolean invalidate_pending;
  gint64 destroy_pending_since;

  GumStalker * stalker;
  GumThreadId thread_id;

  GumArm64Writer code_writer;
  GumArm64Relocator relocator;

  GumStalkerTransformer * transformer;
  void (* transform_block_impl) (GumStalkerTransformer * self,
      GumStalkerIterator * iterator, GumStalkerWriter * output);
  GQueue callout_entries;
  GumSpinlock callout_lock;
  GumEventSink * sink;
  gboolean sink_started;
  GumEventType sink_mask;
  void (* sink_process_impl) (GumEventSink * self, const GumEvent * ev);
  GumEvent tmp_event;

  gboolean unfollow_called_while_still_following;
  GumExecBlock * current_block;
  gpointer pending_return_location;
  guint pending_calls;
  GumExecFrame * current_frame;
  GumExecFrame * first_frame;
  GumExecFrame * frames;

  gpointer resume_at;
  gpointer return_at;
  gconstpointer activation_target;

  gpointer thunks;
  gpointer infect_thunk;

  GumSlab * code_slab;
  gpointer last_prolog_minimal;
  gpointer last_epilog_minimal;
  gpointer last_prolog_full;
  gpointer last_epilog_full;
  gpointer last_stack_push;
  gpointer last_stack_pop_and_go;
  GumMetalHashTable * mappings;
};

struct _GumExecBlock
{
  GumExecCtx * ctx;
  GumSlab * slab;

  guint8 * real_begin;
  guint8 * real_end;
  guint8 * real_snapshot;
  guint8 * code_begin;
  guint8 * code_end;

  gint recycle_count;
};

struct _GumSlab
{
  guint8 * data;
  guint offset;
  guint size;
  GumSlab * next;

  guint num_blocks;
  GumExecBlock blocks[];
};

enum _GumPrologType
{
  GUM_PROLOG_NONE,
  GUM_PROLOG_MINIMAL,
  GUM_PROLOG_FULL
};

enum _GumCodeContext
{
  GUM_CODE_INTERRUPTIBLE,
  GUM_CODE_UNINTERRUPTIBLE
};

struct _GumGeneratorContext
{
  GumInstruction * instruction;
  GumArm64Relocator * relocator;
  GumArm64Writer * code_writer;
  gpointer continuation_real_address;
  GumPrologType opened_prolog;
  gint exclusive_load_offset;
};

struct _GumInstruction
{
  const cs_insn * ci;
  guint8 * begin;
  guint8 * end;
};

struct _GumStalkerIterator
{
  GumExecCtx * exec_context;
  GumExecBlock * exec_block;
  GumGeneratorContext * generator_context;

  GumInstruction instruction;
  GumVirtualizationRequirements requirements;
};

struct _GumCalloutEntry
{
  GumStalkerCallout callout;
  gpointer data;
  GDestroyNotify data_destroy;

  gpointer pc;

  GumExecCtx * exec_context;
};

struct _GumBranchTarget
{
  gpointer origin_ip;

  gpointer absolute_address;
  gssize relative_offset;

  arm64_reg reg;
};

enum _GumVirtualizationRequirements
{
  GUM_REQUIRE_NOTHING          = 0,
  GUM_REQUIRE_RELOCATION       = 1 << 0,
  GUM_REQUIRE_EXCLUSIVE_STORE  = 1 << 1,
};

static void gum_stalker_finalize (GObject * object);

G_GNUC_INTERNAL gpointer _gum_stalker_do_follow_me (GumStalker * self,
    GumStalkerTransformer * transformer, GumEventSink * sink,
    gpointer ret_addr);
static void gum_stalker_infect (GumThreadId thread_id,
    GumCpuContext * cpu_context, gpointer user_data);
static void gum_stalker_disinfect (GumThreadId thread_id,
    GumCpuContext * cpu_context, gpointer user_data);
G_GNUC_INTERNAL gpointer _gum_stalker_do_activate (GumStalker * self,
    gconstpointer target, gpointer ret_addr);
G_GNUC_INTERNAL gpointer _gum_stalker_do_deactivate (GumStalker * self,
    gpointer ret_addr);

static void gum_stalker_free_probe_array (gpointer data);

static GumExecCtx * gum_stalker_create_exec_ctx (GumStalker * self,
    GumThreadId thread_id, GumStalkerTransformer * transformer,
    GumEventSink * sink);
static void gum_stalker_destroy_exec_ctx (GumStalker * self, GumExecCtx * ctx);
static GumExecCtx * gum_stalker_get_exec_ctx (GumStalker * self);
static void gum_stalker_invalidate_caches (GumStalker * self);

static void gum_stalker_thaw (GumStalker * self, gpointer code, gsize size);
static void gum_stalker_freeze (GumStalker * self, gpointer code, gsize size);

static void gum_exec_ctx_dispose_callouts (GumExecCtx * ctx);
static void gum_exec_ctx_free (GumExecCtx * ctx);
static GumSlab * gum_exec_ctx_add_slab (GumExecCtx * ctx);
static gboolean gum_exec_ctx_maybe_unfollow (GumExecCtx * ctx,
    gpointer resume_at);
static void gum_exec_ctx_unfollow (GumExecCtx * ctx, gpointer resume_at);
static gboolean gum_exec_ctx_has_executed (GumExecCtx * ctx);
static gboolean gum_exec_ctx_contains (GumExecCtx * ctx, gconstpointer address);
static gpointer gum_exec_ctx_replace_current_block_with (GumExecCtx * ctx,
    gpointer start_address);
static void gum_exec_ctx_begin_call (GumExecCtx * ctx, gpointer ret_addr);
static void gum_exec_ctx_end_call (GumExecCtx * ctx);
static void gum_exec_ctx_create_thunks (GumExecCtx * ctx);
static void gum_exec_ctx_destroy_thunks (GumExecCtx * ctx);

static GumExecBlock * gum_exec_ctx_obtain_block_for (GumExecCtx * ctx,
    gpointer real_address, gpointer * code_address);

static void gum_stalker_invoke_callout (GumCpuContext * cpu_context,
    GumCalloutEntry * entry);

static void gum_exec_ctx_write_prolog (GumExecCtx * ctx, GumPrologType type,
    GumArm64Writer * cw);
static void gum_exec_ctx_write_epilog (GumExecCtx * ctx, GumPrologType type,
    GumArm64Writer * cw);

static void gum_exec_ctx_ensure_inline_helpers_reachable (GumExecCtx * ctx);
static void gum_exec_ctx_write_minimal_prolog_helper (GumExecCtx * ctx,
    GumArm64Writer * cw);
static void gum_exec_ctx_write_minimal_epilog_helper (GumExecCtx * ctx,
    GumArm64Writer * cw);
static void gum_exec_ctx_write_full_prolog_helper (GumExecCtx * ctx,
    GumArm64Writer * cw);
static void gum_exec_ctx_write_full_epilog_helper (GumExecCtx * ctx,
    GumArm64Writer * cw);
static void gum_exec_ctx_write_prolog_helper (GumExecCtx * ctx,
    GumPrologType type, GumArm64Writer * cw);
static void gum_exec_ctx_write_epilog_helper (GumExecCtx * ctx,
    GumPrologType type, GumArm64Writer * cw);
static void gum_exec_ctx_write_stack_push_helper (GumExecCtx * ctx,
    GumArm64Writer * cw);
static void gum_exec_ctx_write_stack_pop_and_go_helper (GumExecCtx * ctx,
    GumArm64Writer * cw);
static void gum_exec_ctx_ensure_helper_reachable (GumExecCtx * ctx,
    gpointer * helper_ptr, GumExecHelperWriteFunc write);
static gboolean gum_exec_ctx_is_helper_reachable (GumExecCtx * ctx,
    gpointer * helper_ptr);

static void gum_exec_ctx_write_push_branch_target_address (GumExecCtx * ctx,
    const GumBranchTarget * target, GumGeneratorContext * gc);
static void gum_exec_ctx_load_real_register_into (GumExecCtx * ctx,
    arm64_reg target_register, arm64_reg source_register,
    GumGeneratorContext * gc);
static void gum_exec_ctx_load_real_register_from_minimal_frame_into (
    GumExecCtx * ctx, arm64_reg target_register, arm64_reg source_register,
    GumGeneratorContext * gc);
static void gum_exec_ctx_load_real_register_from_full_frame_into (
    GumExecCtx * ctx, arm64_reg target_register, arm64_reg source_register,
    GumGeneratorContext * gc);

static GumExecBlock * gum_exec_block_new (GumExecCtx * ctx);
static GumExecBlock * gum_exec_block_obtain (GumExecCtx * ctx,
    gpointer real_address, gpointer * code_address);
static gboolean gum_exec_block_is_full (GumExecBlock * block);
static gconstpointer gum_exec_block_check_address_for_exclusion (
    GumExecBlock * block, gconstpointer address);
static void gum_exec_block_commit (GumExecBlock * block);

static GumVirtualizationRequirements gum_exec_block_virtualize_branch_insn (
    GumExecBlock * block, GumGeneratorContext * gc);
static GumVirtualizationRequirements gum_exec_block_virtualize_ret_insn (
    GumExecBlock * block, GumGeneratorContext * gc);
static GumVirtualizationRequirements gum_exec_block_virtualize_sysenter_insn (
    GumExecBlock * block, GumGeneratorContext * gc);
#ifdef HAVE_LINUX
static GumVirtualizationRequirements gum_exec_block_virtualize_linux_sysenter (
    GumExecBlock * block, GumGeneratorContext * gc);
#endif

static void gum_exec_block_write_call_invoke_code (GumExecBlock * block,
    const GumBranchTarget * target, GumGeneratorContext * gc);
static void gum_exec_block_write_jmp_transfer_code (GumExecBlock * block,
    const GumBranchTarget * target, GumExecCtxReplaceCurrentBlockFunc func,
    GumGeneratorContext * gc);
static void gum_exec_block_write_jmp_to_block_start (GumExecBlock * block,
    gpointer block_start);
static void gum_exec_block_write_ret_transfer_code (GumExecBlock * block,
    GumGeneratorContext * gc, arm64_reg ret_reg);

static void gum_exec_block_write_call_event_code (GumExecBlock * block,
    const GumBranchTarget * target, GumGeneratorContext * gc,
    GumCodeContext cc);
static void gum_exec_block_write_ret_event_code (GumExecBlock * block,
    GumGeneratorContext * gc, GumCodeContext cc);
static void gum_exec_block_write_exec_event_code (GumExecBlock * block,
    GumGeneratorContext * gc, GumCodeContext cc);
static void gum_exec_block_write_block_event_code (GumExecBlock * block,
    GumGeneratorContext * gc, GumCodeContext cc);
static void gum_exec_block_write_unfollow_check_code (GumExecBlock * block,
    GumGeneratorContext * gc, GumCodeContext cc);

static void gum_exec_block_write_call_probe_code (GumExecBlock * block,
    const GumBranchTarget * target, GumGeneratorContext * gc);

static void gum_exec_block_write_exec_generated_code (GumArm64Writer * cw,
    GumExecCtx * ctx);

static void gum_exec_block_open_prolog (GumExecBlock * block,
    GumPrologType type, GumGeneratorContext * gc);
static void gum_exec_block_close_prolog (GumExecBlock * block,
    GumGeneratorContext * gc);

static gpointer gum_find_thread_exit_implementation (void);

G_DEFINE_TYPE (GumStalker, gum_stalker, G_TYPE_OBJECT)

static gpointer _gum_thread_exit_impl;

gboolean
gum_stalker_is_supported (void)
{
  return TRUE;
}

static void
gum_stalker_class_init (GumStalkerClass * klass)
{
  GObjectClass * object_class = G_OBJECT_CLASS (klass);

  object_class->finalize = gum_stalker_finalize;

  _gum_thread_exit_impl = gum_find_thread_exit_implementation ();
}

static void
gum_stalker_init (GumStalker * self)
{
  self->exclusions = g_array_new (FALSE, FALSE, sizeof (GumMemoryRange));
  self->trust_threshold = 1;

  gum_spinlock_init (&self->probe_lock);
  self->probe_target_by_id =
      g_hash_table_new_full (NULL, NULL, NULL, NULL);
  self->probe_array_by_address =
      g_hash_table_new_full (NULL, NULL, NULL, gum_stalker_free_probe_array);

  self->page_size = gum_query_page_size ();
  self->slab_size =
      GUM_ALIGN_SIZE (GUM_CODE_SLAB_MAX_SIZE, self->page_size);
  self->slab_header_size =
      GUM_ALIGN_SIZE (GUM_CODE_SLAB_MAX_SIZE / 12, self->page_size);
  self->slab_max_blocks = (self->slab_header_size -
      G_STRUCT_OFFSET (GumSlab, blocks)) / sizeof (GumExecBlock);
  self->is_rwx_supported = gum_query_rwx_support () != GUM_RWX_NONE;

  g_mutex_init (&self->mutex);
  self->contexts = NULL;
  self->exec_ctx = gum_tls_key_new ();
}

static void
gum_stalker_finalize (GObject * object)
{
  GumStalker * self = GUM_STALKER (object);

  g_hash_table_unref (self->probe_array_by_address);
  g_hash_table_unref (self->probe_target_by_id);

  g_array_free (self->exclusions, TRUE);

  g_assert (self->contexts == NULL);
  gum_tls_key_free (self->exec_ctx);
  g_mutex_clear (&self->mutex);

  G_OBJECT_CLASS (gum_stalker_parent_class)->finalize (object);
}

GumStalker *
gum_stalker_new (void)
{
  return g_object_new (GUM_TYPE_STALKER, NULL);
}

void
gum_stalker_exclude (GumStalker * self,
                     const GumMemoryRange * range)
{
  g_array_append_val (self->exclusions, *range);
}

static gboolean
gum_stalker_is_excluding (GumStalker * self,
                          gconstpointer address)
{
  GArray * exclusions = self->exclusions;
  guint i;

  for (i = 0; i != exclusions->len; i++)
  {
    GumMemoryRange * r = &g_array_index (exclusions, GumMemoryRange, i);

    if (GUM_MEMORY_RANGE_INCLUDES (r, GUM_ADDRESS (address)))
      return TRUE;
  }

  return FALSE;
}

gint
gum_stalker_get_trust_threshold (GumStalker * self)
{
  return self->trust_threshold;
}

void
gum_stalker_set_trust_threshold (GumStalker * self,
                                 gint trust_threshold)
{
  self->trust_threshold = trust_threshold;
}

void
gum_stalker_flush (GumStalker * self)
{
  GSList * sinks, * cur;

  GUM_STALKER_LOCK (self);

  sinks = NULL;
  for (cur = self->contexts; cur != NULL; cur = cur->next)
  {
    GumExecCtx * ctx = cur->data;

    sinks = g_slist_prepend (sinks, g_object_ref (ctx->sink));
  }

  GUM_STALKER_UNLOCK (self);

  for (cur = sinks; cur != NULL; cur = cur->next)
  {
    GumEventSink * sink = cur->data;

    gum_event_sink_flush (sink);
  }

  g_slist_free_full (sinks, g_object_unref);
}

void
gum_stalker_stop (GumStalker * self)
{
  GSList * cur;

  gum_spinlock_acquire (&self->probe_lock);
  g_hash_table_remove_all (self->probe_target_by_id);
  g_hash_table_remove_all (self->probe_array_by_address);
  self->any_probes_attached = FALSE;
  gum_spinlock_release (&self->probe_lock);

rescan:
  GUM_STALKER_LOCK (self);

  for (cur = self->contexts; cur != NULL; cur = cur->next)
  {
    GumExecCtx * ctx = cur->data;

    if (g_atomic_int_get (&ctx->state) == GUM_EXEC_CTX_ACTIVE)
    {
      GumThreadId thread_id = ctx->thread_id;

      GUM_STALKER_UNLOCK (self);

      gum_stalker_unfollow (self, thread_id);

      goto rescan;
    }
  }

  GUM_STALKER_UNLOCK (self);

  gum_stalker_garbage_collect (self);
}

gboolean
gum_stalker_garbage_collect (GumStalker * self)
{
  gboolean have_pending_garbage;
  GumThreadId current_thread_id;
  gint64 now;
  GSList * cur;

  current_thread_id = gum_process_get_current_thread_id ();
  now = g_get_monotonic_time ();

rescan:
  GUM_STALKER_LOCK (self);

  for (cur = self->contexts; cur != NULL; cur = cur->next)
  {
    GumExecCtx * ctx = cur->data;
    gboolean destroy_pending_and_thread_likely_back_in_original_code;

    destroy_pending_and_thread_likely_back_in_original_code =
        g_atomic_int_get (&ctx->state) == GUM_EXEC_CTX_DESTROY_PENDING &&
        (ctx->thread_id == current_thread_id ||
        now - ctx->destroy_pending_since > 20000);

    if (destroy_pending_and_thread_likely_back_in_original_code ||
        !gum_process_has_thread (ctx->thread_id))
    {
      GUM_STALKER_UNLOCK (self);

      gum_stalker_destroy_exec_ctx (self, ctx);

      goto rescan;
    }
  }

  have_pending_garbage = self->contexts != NULL;

  GUM_STALKER_UNLOCK (self);

  return have_pending_garbage;
}

gpointer
_gum_stalker_do_follow_me (GumStalker * self,
                           GumStalkerTransformer * transformer,
                           GumEventSink * sink,
                           gpointer ret_addr)
{
  GumExecCtx * ctx;
  gpointer code_address;

  ctx = gum_stalker_create_exec_ctx (self, gum_process_get_current_thread_id (),
      transformer, sink);
  gum_tls_key_set_value (self->exec_ctx, ctx);

  ctx->current_block = gum_exec_ctx_obtain_block_for (ctx, ret_addr,
      &code_address);

  if (gum_exec_ctx_maybe_unfollow (ctx, ret_addr))
  {
    gum_stalker_destroy_exec_ctx (self, ctx);
    return ret_addr;
  }

  gum_event_sink_start (sink);
  ctx->sink_started = TRUE;

  return code_address + GUM_RESTORATION_PROLOG_SIZE;
}

void
gum_stalker_unfollow_me (GumStalker * self)
{
  GumExecCtx * ctx;

  ctx = gum_stalker_get_exec_ctx (self);
  if (ctx == NULL)
    return;

  g_atomic_int_set (&ctx->state, GUM_EXEC_CTX_UNFOLLOW_PENDING);

  if (!gum_exec_ctx_maybe_unfollow (ctx, NULL))
    return;

  g_assert (ctx->unfollow_called_while_still_following);

  gum_stalker_destroy_exec_ctx (self, ctx);
}

gboolean
gum_stalker_is_following_me (GumStalker * self)
{
  return gum_stalker_get_exec_ctx (self) != NULL;
}

void
gum_stalker_follow (GumStalker * self,
                    GumThreadId thread_id,
                    GumStalkerTransformer * transformer,
                    GumEventSink * sink)
{
  if (thread_id == gum_process_get_current_thread_id ())
  {
    gum_stalker_follow_me (self, transformer, sink);
  }
  else
  {
    GumInfectContext ctx;

    ctx.stalker = self;
    ctx.transformer = transformer;
    ctx.sink = sink;

    gum_process_modify_thread (thread_id, gum_stalker_infect, &ctx);
  }
}

void
gum_stalker_unfollow (GumStalker * self,
                      GumThreadId thread_id)
{
  if (thread_id == gum_process_get_current_thread_id ())
  {
    gum_stalker_unfollow_me (self);
  }
  else
  {
    GSList * cur;

    GUM_STALKER_LOCK (self);

    for (cur = self->contexts; cur != NULL; cur = cur->next)
    {
      GumExecCtx * ctx = (GumExecCtx *) cur->data;

      if (ctx->thread_id == thread_id &&
          g_atomic_int_compare_and_exchange (&ctx->state, GUM_EXEC_CTX_ACTIVE,
              GUM_EXEC_CTX_UNFOLLOW_PENDING))
      {
        GUM_STALKER_UNLOCK (self);

        if (!gum_exec_ctx_has_executed (ctx))
        {
          GumDisinfectContext dc;

          dc.exec_ctx = ctx;
          dc.success = FALSE;

          gum_process_modify_thread (thread_id, gum_stalker_disinfect, &dc);

          if (dc.success)
            gum_stalker_destroy_exec_ctx (self, ctx);
        }

        return;
      }
    }

    GUM_STALKER_UNLOCK (self);
  }
}

static void
gum_stalker_infect (GumThreadId thread_id,
                    GumCpuContext * cpu_context,
                    gpointer user_data)
{
  GumInfectContext * infect_context;
  GumStalker * self;
  GumExecCtx * ctx;
  const guint potential_svc_size = 4;
  gpointer code_address;
  GumArm64Writer cw;

  infect_context = user_data;
  self = infect_context->stalker;
  ctx = gum_stalker_create_exec_ctx (self, thread_id,
      infect_context->transformer, infect_context->sink);

  ctx->current_block = gum_exec_ctx_obtain_block_for (ctx,
      GSIZE_TO_POINTER (cpu_context->pc), &code_address);

  if (gum_exec_ctx_maybe_unfollow (ctx, NULL))
  {
    gum_stalker_destroy_exec_ctx (self, ctx);
    return;
  }

  cpu_context->pc = GPOINTER_TO_SIZE (ctx->infect_thunk) + potential_svc_size;

  gum_stalker_thaw (self, ctx->thunks, self->page_size);
  gum_arm64_writer_init (&cw, ctx->infect_thunk);

  /*
   * In case the thread is in a Linux system call we should allow it to be
   * restarted by bringing along the SVC instruction.
   */
  gum_arm64_writer_put_bytes (&cw,
      ctx->current_block->real_begin - potential_svc_size, potential_svc_size);

  gum_exec_ctx_write_prolog (ctx, GUM_PROLOG_MINIMAL, &cw);
  gum_arm64_writer_put_call_address_with_arguments (&cw,
      GUM_ADDRESS (gum_tls_key_set_value), 2,
      GUM_ARG_ADDRESS, self->exec_ctx,
      GUM_ARG_ADDRESS, ctx);
  gum_exec_ctx_write_epilog (ctx, GUM_PROLOG_MINIMAL, &cw);

  gum_arm64_writer_put_branch_address (&cw, GUM_ADDRESS (
      code_address + GUM_RESTORATION_PROLOG_SIZE));

  gum_arm64_writer_flush (&cw);
  gum_stalker_freeze (self, cw.base, gum_arm64_writer_offset (&cw));
  gum_arm64_writer_clear (&cw);

  gum_event_sink_start (infect_context->sink);
}

static void
gum_stalker_disinfect (GumThreadId thread_id,
                       GumCpuContext * cpu_context,
                       gpointer user_data)
{
  GumDisinfectContext * disinfect_context = user_data;
  GumExecCtx * ctx = disinfect_context->exec_ctx;
  gboolean infection_not_active_yet;

  infection_not_active_yet =
      cpu_context->pc == GPOINTER_TO_SIZE (ctx->infect_thunk);
  if (infection_not_active_yet)
  {
    cpu_context->pc = GPOINTER_TO_SIZE (ctx->current_block->real_begin);

    disinfect_context->success = TRUE;
  }
}

gpointer
_gum_stalker_do_activate (GumStalker * self,
                          gconstpointer target,
                          gpointer ret_addr)
{
  GumExecCtx * ctx;

  ctx = gum_stalker_get_exec_ctx (self);
  if (ctx == NULL)
    return ret_addr;

  ctx->activation_target = target;

  if (!gum_exec_ctx_contains (ctx, ret_addr))
  {
    gpointer code_address;

    ctx->current_block =
        gum_exec_ctx_obtain_block_for (ctx, ret_addr, &code_address);

    if (gum_exec_ctx_maybe_unfollow (ctx, ret_addr))
      return ret_addr;

    return code_address + GUM_RESTORATION_PROLOG_SIZE;
  }

  return ret_addr;
}

gpointer
_gum_stalker_do_deactivate (GumStalker * self,
                            gpointer ret_addr)
{
  GumExecCtx * ctx;

  ctx = gum_stalker_get_exec_ctx (self);
  if (ctx == NULL)
    return ret_addr;

  ctx->activation_target = NULL;

  if (gum_exec_ctx_contains (ctx, ret_addr))
  {
    ctx->pending_calls--;

    return ctx->pending_return_location;
  }

  return ret_addr;
}

GumProbeId
gum_stalker_add_call_probe (GumStalker * self,
                            gpointer target_address,
                            GumCallProbeCallback callback,
                            gpointer data,
                            GDestroyNotify notify)
{
  GumCallProbe probe;
  GArray * probes;

  probe.id = g_atomic_int_add (&self->last_probe_id, 1) + 1;
  probe.callback = callback;
  probe.user_data = data;
  probe.user_notify = notify;

  gum_spinlock_acquire (&self->probe_lock);

  g_hash_table_insert (self->probe_target_by_id, GSIZE_TO_POINTER (probe.id),
      target_address);

  probes = (GArray *)
      g_hash_table_lookup (self->probe_array_by_address, target_address);
  if (probes == NULL)
  {
    probes = g_array_sized_new (FALSE, FALSE, sizeof (GumCallProbe), 4);
    g_hash_table_insert (self->probe_array_by_address, target_address, probes);
  }

  g_array_append_val (probes, probe);

  self->any_probes_attached = TRUE;

  gum_spinlock_release (&self->probe_lock);

  gum_stalker_invalidate_caches (self);

  return probe.id;
}

void
gum_stalker_remove_call_probe (GumStalker * self,
                               GumProbeId id)
{
  gpointer target_address;

  gum_spinlock_acquire (&self->probe_lock);

  target_address =
      g_hash_table_lookup (self->probe_target_by_id, GSIZE_TO_POINTER (id));
  if (target_address != NULL)
  {
    GArray * probes;
    gint match_index = -1;
    guint i;
    GumCallProbe * probe;

    g_hash_table_remove (self->probe_target_by_id, GSIZE_TO_POINTER (id));

    probes = (GArray *)
        g_hash_table_lookup (self->probe_array_by_address, target_address);
    g_assert (probes != NULL);

    for (i = 0; i != probes->len; i++)
    {
      if (g_array_index (probes, GumCallProbe, i).id == id)
      {
        match_index = i;
        break;
      }
    }
    g_assert (match_index != -1);

    probe = &g_array_index (probes, GumCallProbe, match_index);
    if (probe->user_notify != NULL)
      probe->user_notify (probe->user_data);
    g_array_remove_index (probes, match_index);

    if (probes->len == 0)
      g_hash_table_remove (self->probe_array_by_address, target_address);

    self->any_probes_attached =
        g_hash_table_size (self->probe_array_by_address) != 0;
  }

  gum_spinlock_release (&self->probe_lock);

  gum_stalker_invalidate_caches (self);
}

static void
gum_stalker_free_probe_array (gpointer data)
{
  GArray * probes = (GArray *) data;
  guint i;

  for (i = 0; i != probes->len; i++)
  {
    GumCallProbe * probe = &g_array_index (probes, GumCallProbe, i);
    if (probe->user_notify != NULL)
      probe->user_notify (probe->user_data);
  }

  g_array_free (probes, TRUE);
}

static GumExecCtx *
gum_stalker_create_exec_ctx (GumStalker * self,
                             GumThreadId thread_id,
                             GumStalkerTransformer * transformer,
                             GumEventSink * sink)
{
  GumExecCtx * ctx;

  ctx = g_slice_new0 (GumExecCtx);

  ctx->state = GUM_EXEC_CTX_ACTIVE;

  ctx->stalker = g_object_ref (self);
  ctx->thread_id = thread_id;

  gum_arm64_writer_init (&ctx->code_writer, NULL);
  gum_arm64_relocator_init (&ctx->relocator, NULL, &ctx->code_writer);

  if (transformer != NULL)
    ctx->transformer = g_object_ref (transformer);
  else
    ctx->transformer = gum_stalker_transformer_make_default ();
  ctx->transform_block_impl =
      GUM_STALKER_TRANSFORMER_GET_IFACE (ctx->transformer)->transform_block;
  g_queue_init (&ctx->callout_entries);
  gum_spinlock_init (&ctx->callout_lock);
  ctx->sink = g_object_ref (sink);
  ctx->sink_mask = gum_event_sink_query_mask (sink);
  ctx->sink_process_impl = GUM_EVENT_SINK_GET_IFACE (sink)->process;

  ctx->frames =
      gum_memory_allocate (NULL, self->page_size, self->page_size, GUM_PAGE_RW);
  ctx->first_frame = (GumExecFrame *) ((guint8 *) ctx->frames +
      self->page_size - sizeof (GumExecFrame));
  ctx->current_frame = ctx->first_frame;

  ctx->mappings = gum_metal_hash_table_new (NULL, NULL);

  gum_exec_ctx_create_thunks (ctx);

  GUM_STALKER_LOCK (self);
  self->contexts = g_slist_prepend (self->contexts, ctx);
  GUM_STALKER_UNLOCK (self);

  gum_exec_ctx_add_slab (ctx);

  gum_exec_ctx_ensure_inline_helpers_reachable (ctx);

  return ctx;
}

static void
gum_stalker_destroy_exec_ctx (GumStalker * self,
                              GumExecCtx * ctx)
{
  GSList * entry;

  GUM_STALKER_LOCK (self);
  entry = g_slist_find (self->contexts, ctx);
  if (entry != NULL)
    self->contexts = g_slist_delete_link (self->contexts, entry);
  GUM_STALKER_UNLOCK (self);

  /* Racy due to garbage-collection. */
  if (entry == NULL)
    return;

  gum_exec_ctx_dispose_callouts (ctx);

  if (ctx->sink_started)
  {
    gum_event_sink_stop (ctx->sink);

    ctx->sink_started = FALSE;
  }

  gum_exec_ctx_free (ctx);
}

static GumExecCtx *
gum_stalker_get_exec_ctx (GumStalker * self)
{
  return (GumExecCtx *) gum_tls_key_get_value (self->exec_ctx);
}

static void
gum_stalker_invalidate_caches (GumStalker * self)
{
  GSList * cur;

  GUM_STALKER_LOCK (self);

  for (cur = self->contexts; cur != NULL; cur = cur->next)
  {
    GumExecCtx * ctx = (GumExecCtx *) cur->data;

    ctx->invalidate_pending = TRUE;
  }

  GUM_STALKER_UNLOCK (self);
}

static void
gum_stalker_thaw (GumStalker * self,
                  gpointer code,
                  gsize size)
{
  if (!self->is_rwx_supported)
    gum_mprotect (code, size, GUM_PAGE_RW);
}

static void
gum_stalker_freeze (GumStalker * self,
                    gpointer code,
                    gsize size)
{
  if (!self->is_rwx_supported)
    gum_memory_mark_code (code, size);

  gum_clear_cache (code, size);
}

static void
gum_exec_ctx_dispose_callouts (GumExecCtx * ctx)
{
  GList * cur;

  gum_spinlock_acquire (&ctx->callout_lock);

  for (cur = ctx->callout_entries.head; cur != NULL; cur = cur->next)
  {
    GumCalloutEntry * entry = cur->data;

    if (entry->data_destroy != NULL)
      entry->data_destroy (entry->data);

    entry->callout = NULL;
    entry->data = NULL;
    entry->data_destroy = NULL;
  }

  gum_spinlock_release (&ctx->callout_lock);
}

static void
gum_exec_ctx_finalize_callouts (GumExecCtx * ctx)
{
  GList * cur;

  for (cur = ctx->callout_entries.head; cur != NULL; cur = cur->next)
  {
    GumCalloutEntry * entry = cur->data;

    g_slice_free (GumCalloutEntry, entry);
  }

  g_queue_clear (&ctx->callout_entries);
}

static void
gum_exec_ctx_free (GumExecCtx * ctx)
{
  GumStalker * stalker = ctx->stalker;
  GumSlab * slab;

  gum_metal_hash_table_unref (ctx->mappings);

  slab = ctx->code_slab;
  while (slab != NULL)
  {
    GumSlab * next = slab->next;
    gum_memory_free (slab, stalker->slab_size);
    slab = next;
  }

  gum_exec_ctx_destroy_thunks (ctx);

  gum_memory_free (ctx->frames, stalker->page_size);

  g_object_unref (ctx->sink);
  gum_exec_ctx_finalize_callouts (ctx);
  g_object_unref (ctx->transformer);

  gum_arm64_relocator_clear (&ctx->relocator);
  gum_arm64_writer_clear (&ctx->code_writer);

  g_object_unref (stalker);

  g_slice_free (GumExecCtx, ctx);
}

static GumSlab *
gum_exec_ctx_add_slab (GumExecCtx * ctx)
{
  GumSlab * slab;
  GumStalker * stalker = ctx->stalker;

  slab = gum_memory_allocate (NULL, stalker->slab_size, stalker->page_size,
      stalker->is_rwx_supported ? GUM_PAGE_RWX : GUM_PAGE_RW);

  slab->data = (guint8 *) slab + stalker->slab_header_size;
  slab->offset = 0;
  slab->size = stalker->slab_size - stalker->slab_header_size;
  slab->next = ctx->code_slab;

  slab->num_blocks = 0;

  ctx->code_slab = slab;

  return slab;
}

static gboolean
gum_exec_ctx_maybe_unfollow (GumExecCtx * ctx,
                             gpointer resume_at)
{
  if (g_atomic_int_get (&ctx->state) != GUM_EXEC_CTX_UNFOLLOW_PENDING)
    return FALSE;

  if (ctx->pending_calls > 0)
    return FALSE;

  gum_exec_ctx_unfollow (ctx, resume_at);

  return TRUE;
}

static void
gum_exec_ctx_unfollow (GumExecCtx * ctx,
                       gpointer resume_at)
{
  ctx->current_block = NULL;

  ctx->resume_at = resume_at;

  gum_tls_key_set_value (ctx->stalker->exec_ctx, NULL);

  ctx->destroy_pending_since = g_get_monotonic_time ();
  g_atomic_int_set (&ctx->state, GUM_EXEC_CTX_DESTROY_PENDING);
}

static gboolean
gum_exec_ctx_has_executed (GumExecCtx * ctx)
{
  return ctx->resume_at != NULL;
}

static gboolean
gum_exec_ctx_contains (GumExecCtx * ctx,
                       gconstpointer address)
{
  GumSlab * cur = ctx->code_slab;

  do {
    if ((const guint8 *) address >= cur->data &&
        (const guint8 *) address < cur->data + cur->size)
    {
      return TRUE;
    }

    cur = cur->next;
  } while (cur != NULL);

  return FALSE;
}

static gboolean counters_enabled = FALSE;
static guint total_transitions = 0;

#define GUM_ENTRYGATE(name) \
  gum_exec_ctx_replace_current_block_from_##name
#define GUM_DEFINE_ENTRYGATE(name) \
  static guint total_##name##s = 0; \
  \
  static gpointer GUM_THUNK \
  GUM_ENTRYGATE (name) ( \
      GumExecCtx * ctx, \
      gpointer start_address) \
  { \
    if (counters_enabled) \
      total_##name##s++; \
    \
    return gum_exec_ctx_replace_current_block_with (ctx, start_address); \
  }
#define GUM_PRINT_ENTRYGATE_COUNTER(name) \
  g_printerr ("\t" G_STRINGIFY (name) "s: %u\n", total_##name##s)

GUM_DEFINE_ENTRYGATE (call_imm)
GUM_DEFINE_ENTRYGATE (call_reg)
GUM_DEFINE_ENTRYGATE (post_call_invoke)
GUM_DEFINE_ENTRYGATE (excluded_call_imm)
GUM_DEFINE_ENTRYGATE (excluded_call_reg)
GUM_DEFINE_ENTRYGATE (ret)

GUM_DEFINE_ENTRYGATE (jmp_imm)
GUM_DEFINE_ENTRYGATE (jmp_reg)

GUM_DEFINE_ENTRYGATE (jmp_cond_cbz)
GUM_DEFINE_ENTRYGATE (jmp_cond_cbnz)
GUM_DEFINE_ENTRYGATE (jmp_cond_tbz)
GUM_DEFINE_ENTRYGATE (jmp_cond_tbnz)
GUM_DEFINE_ENTRYGATE (jmp_cond_cc)

GUM_DEFINE_ENTRYGATE (jmp_continuation)

static gpointer
gum_exec_ctx_replace_current_block_with (GumExecCtx * ctx,
                                         gpointer start_address)
{
  if (counters_enabled)
    total_transitions++;

  if (ctx->invalidate_pending)
  {
    gum_metal_hash_table_remove_all (ctx->mappings);

    ctx->invalidate_pending = FALSE;
  }

  if (start_address == gum_stalker_unfollow_me)
  {
    ctx->unfollow_called_while_still_following = TRUE;
    ctx->current_block = NULL;
    ctx->resume_at = start_address;
  }
  else if (start_address == gum_stalker_deactivate)
  {
    ctx->current_block = NULL;
    ctx->resume_at = start_address;
  }
  else if (start_address == _gum_thread_exit_impl)
  {
    gum_exec_ctx_unfollow (ctx, start_address);
  }
  else if (gum_exec_ctx_maybe_unfollow (ctx, start_address))
  {
  }
  else if (gum_exec_ctx_contains (ctx, start_address))
  {
    ctx->current_block = NULL;
    ctx->resume_at = start_address;
  }
  else
  {
    ctx->current_block = gum_exec_ctx_obtain_block_for (ctx, start_address,
        &ctx->resume_at);

    if (start_address == ctx->activation_target)
      ctx->activation_target = NULL;

    gum_exec_ctx_maybe_unfollow (ctx, start_address);
  }

  return ctx->resume_at;
}

static void
gum_exec_ctx_begin_call (GumExecCtx * ctx,
                         gpointer ret_addr)
{
  ctx->pending_return_location = ret_addr;
  ctx->pending_calls++;
}

static void
gum_exec_ctx_end_call (GumExecCtx * ctx)
{
  ctx->pending_calls--;
}

static void
gum_exec_ctx_create_thunks (GumExecCtx * ctx)
{
  gsize page_size;

  page_size = ctx->stalker->page_size;

  ctx->thunks = gum_memory_allocate (NULL, page_size, page_size,
      ctx->stalker->is_rwx_supported ? GUM_PAGE_RWX : GUM_PAGE_RW);

  ctx->infect_thunk = ctx->thunks;
}

static void
gum_exec_ctx_destroy_thunks (GumExecCtx * ctx)
{
  gum_memory_free (ctx->thunks, ctx->stalker->page_size);
}

static GumExecBlock *
gum_exec_ctx_obtain_block_for (GumExecCtx * ctx,
                               gpointer real_address,
                               gpointer * code_address_ptr)
{
  GumExecBlock * block;
  GumArm64Writer * cw;
  GumArm64Relocator * rl;
  GumGeneratorContext gc;
  GumStalkerIterator iterator;
  gboolean all_labels_resolved;

  if (ctx->stalker->trust_threshold >= 0)
  {
    block = gum_exec_block_obtain (ctx, real_address, code_address_ptr);
    if (block != NULL)
    {
      if (block->recycle_count >= ctx->stalker->trust_threshold ||
          memcmp (real_address, block->real_snapshot,
              block->real_end - block->real_begin) == 0)
      {
        block->recycle_count++;
        return block;
      }
      else
      {
        gum_metal_hash_table_remove (ctx->mappings, real_address);
      }
    }
  }

  block = gum_exec_block_new (ctx);
  block->real_begin = real_address;
  *code_address_ptr = block->code_begin;

  if (ctx->stalker->trust_threshold >= 0)
    gum_metal_hash_table_insert (ctx->mappings, real_address, block);

  cw = &ctx->code_writer;
  rl = &ctx->relocator;

  gum_arm64_writer_reset (cw, block->code_begin);
  gum_arm64_relocator_reset (rl, real_address, cw);

  gum_ensure_code_readable (real_address, ctx->stalker->page_size);

  gc.instruction = NULL;
  gc.relocator = rl;
  gc.code_writer = cw;
  gc.continuation_real_address = NULL;
  gc.opened_prolog = GUM_PROLOG_NONE;
  gc.exclusive_load_offset = GUM_INSTRUCTION_OFFSET_NONE;

  iterator.exec_context = ctx;
  iterator.exec_block = block;
  iterator.generator_context = &gc;

  iterator.instruction.ci = NULL;
  iterator.instruction.begin = NULL;
  iterator.instruction.end = NULL;
  iterator.requirements = GUM_REQUIRE_NOTHING;

  gum_arm64_writer_put_ldp_reg_reg_reg_offset (cw, ARM64_REG_X16, ARM64_REG_X17,
      ARM64_REG_SP, 16 + GUM_RED_ZONE_SIZE, GUM_INDEX_POST_ADJUST);

  ctx->pending_calls++;

  ctx->transform_block_impl (ctx->transformer, &iterator,
      (GumStalkerWriter *) cw);

  ctx->pending_calls--;

  if (gc.continuation_real_address != NULL)
  {
    GumBranchTarget continue_target = { 0, };

    continue_target.absolute_address = gc.continuation_real_address;
    continue_target.reg = ARM64_REG_INVALID;
    gum_exec_block_write_jmp_transfer_code (block, &continue_target,
        GUM_ENTRYGATE (jmp_continuation), &gc);
  }

  gum_arm64_writer_put_brk_imm (cw, 14);

  all_labels_resolved = gum_arm64_writer_flush (cw);
  if (!all_labels_resolved)
    g_error ("Failed to resolve labels");

  block->code_end = (guint8 *) gum_arm64_writer_cur (cw);
  block->real_end = (guint8 *) rl->input_cur;

  gum_exec_block_commit (block);

  if ((ctx->sink_mask & GUM_COMPILE) != 0)
  {
    ctx->tmp_event.type = GUM_COMPILE;
    ctx->tmp_event.compile.begin = block->real_begin;
    ctx->tmp_event.compile.end = block->real_end;

    gum_event_sink_process (ctx->sink, &ctx->tmp_event);
  }

  return block;
}

gboolean
gum_stalker_iterator_next (GumStalkerIterator * self,
                           const cs_insn ** insn)
{
  GumGeneratorContext * gc = self->generator_context;
  GumArm64Relocator * rl = gc->relocator;
  GumInstruction * instruction;
  guint n_read;

  instruction = self->generator_context->instruction;
  if (instruction != NULL)
  {
    GumExecBlock * block = self->exec_block;
    gboolean skip_implicitly_requested;

    skip_implicitly_requested = rl->outpos != rl->inpos;
    if (skip_implicitly_requested)
    {
      gum_arm64_relocator_skip_one (rl);
    }

    block->code_end = gum_arm64_writer_cur (gc->code_writer);

    if (gum_exec_block_is_full (block))
    {
      gc->continuation_real_address = instruction->end;
      return FALSE;
    }
    else if ((self->requirements & GUM_REQUIRE_EXCLUSIVE_STORE) == 0 &&
        gum_arm64_relocator_eob (rl))
    {
      return FALSE;
    }

    switch (instruction->ci->id)
    {
      case ARM64_INS_STXR:
      case ARM64_INS_STXP:
      case ARM64_INS_STXRB:
      case ARM64_INS_STXRH:
      case ARM64_INS_STLXR:
      case ARM64_INS_STLXP:
      case ARM64_INS_STLXRB:
      case ARM64_INS_STLXRH:
        gc->exclusive_load_offset = GUM_INSTRUCTION_OFFSET_NONE;
        break;
      default:
        break;
    }

    if (gc->exclusive_load_offset != GUM_INSTRUCTION_OFFSET_NONE)
    {
      gc->exclusive_load_offset++;
      if (gc->exclusive_load_offset == 4)
        gc->exclusive_load_offset = GUM_INSTRUCTION_OFFSET_NONE;
    }
  }

  instruction = &self->instruction;

  n_read = gum_arm64_relocator_read_one (rl, &instruction->ci);
  if (n_read == 0)
    return FALSE;

  instruction->begin = GSIZE_TO_POINTER (instruction->ci->address);
  instruction->end = instruction->begin + instruction->ci->size;

  self->generator_context->instruction = instruction;

  if (insn != NULL)
    *insn = instruction->ci;

  return TRUE;
}

void
gum_stalker_iterator_keep (GumStalkerIterator * self)
{
  GumExecCtx * ec = self->exec_context;
  GumExecBlock * block = self->exec_block;
  GumGeneratorContext * gc = self->generator_context;
  GumArm64Relocator * rl = gc->relocator;
  const cs_insn * insn = gc->instruction->ci;
  GumVirtualizationRequirements requirements;

  requirements = GUM_REQUIRE_NOTHING;

  switch (insn->id)
  {
    case ARM64_INS_LDAXR:
    case ARM64_INS_LDAXP:
    case ARM64_INS_LDAXRB:
    case ARM64_INS_LDAXRH:
    case ARM64_INS_LDXR:
    case ARM64_INS_LDXP:
    case ARM64_INS_LDXRB:
    case ARM64_INS_LDXRH:
      gc->exclusive_load_offset = 0;
      break;
    default:
      break;
  }

  if ((ec->sink_mask & GUM_EXEC) != 0 &&
      gc->exclusive_load_offset == GUM_INSTRUCTION_OFFSET_NONE)
  {
    gum_exec_block_write_exec_event_code (block, gc, GUM_CODE_INTERRUPTIBLE);
  }

  if ((ec->sink_mask & GUM_BLOCK) != 0 &&
      gc->exclusive_load_offset == GUM_INSTRUCTION_OFFSET_NONE &&
      gum_arm64_relocator_eob (rl) &&
      insn->id != ARM64_INS_BL && insn->id != ARM64_INS_BLR)
  {
    gum_exec_block_write_block_event_code (block, gc, GUM_CODE_UNINTERRUPTIBLE);
  }

  switch (insn->id)
  {
    case ARM64_INS_BL:
    case ARM64_INS_B:
    case ARM64_INS_BLR:
    case ARM64_INS_BR:
    case ARM64_INS_CBZ:
    case ARM64_INS_CBNZ:
    case ARM64_INS_TBZ:
    case ARM64_INS_TBNZ:
      requirements = gum_exec_block_virtualize_branch_insn (block, gc);
      break;
    case ARM64_INS_RET:
      requirements = gum_exec_block_virtualize_ret_insn (block, gc);
      break;
    case ARM64_INS_SVC:
      requirements = gum_exec_block_virtualize_sysenter_insn (block, gc);
      break;
    case ARM64_INS_SMC:
    case ARM64_INS_HVC:
      g_assert ("" == "not implemented");
      break;
    default:
      requirements = GUM_REQUIRE_RELOCATION;
  }

  gum_exec_block_close_prolog (block, gc);

  if ((requirements & GUM_REQUIRE_RELOCATION) != 0)
    gum_arm64_relocator_write_one (rl);

  self->requirements = requirements;
}

static void
gum_exec_ctx_emit_call_event (GumExecCtx * ctx,
                              gpointer location,
                              gpointer target)
{
  GumEvent ev;
  GumCallEvent * call = &ev.call;

  ev.type = GUM_CALL;

  call->location = location;
  call->target = target;
  call->depth = ctx->first_frame - ctx->current_frame;

  ctx->sink_process_impl (ctx->sink, &ev);
}

static void
gum_exec_ctx_emit_ret_event (GumExecCtx * ctx,
                             gpointer location,
                             gpointer target)
{
  GumEvent ev;
  GumRetEvent * ret = &ev.ret;

  ev.type = GUM_RET;

  ret->location = location;
  ret->target = target;
  ret->depth = ctx->first_frame - ctx->current_frame;

  ctx->sink_process_impl (ctx->sink, &ev);
}

static void
gum_exec_ctx_emit_exec_event (GumExecCtx * ctx,
                              gpointer location)
{
  GumEvent ev;
  GumExecEvent * exec = &ev.exec;

  ev.type = GUM_EXEC;

  exec->location = location;

  ctx->sink_process_impl (ctx->sink, &ev);
}

static void
gum_exec_ctx_emit_block_event (GumExecCtx * ctx,
                               gpointer begin,
                               gpointer end)
{
  GumEvent ev;
  GumBlockEvent * block = &ev.block;

  ev.type = GUM_BLOCK;

  block->begin = begin;
  block->end = end;

  ctx->sink_process_impl (ctx->sink, &ev);
}

void
gum_stalker_iterator_put_callout (GumStalkerIterator * self,
                                  GumStalkerCallout callout,
                                  gpointer data,
                                  GDestroyNotify data_destroy)
{
  GumCalloutEntry * entry;
  GumExecCtx * ec = self->exec_context;
  GumExecBlock * block = self->exec_block;
  GumGeneratorContext * gc = self->generator_context;

  entry = g_slice_new (GumCalloutEntry);
  entry->callout = callout;
  entry->data = data;
  entry->data_destroy = data_destroy;
  entry->pc = gc->instruction->begin;
  entry->exec_context = ec;

  gum_exec_block_open_prolog (block, GUM_PROLOG_FULL, gc);

  gum_arm64_writer_put_call_address_with_arguments (gc->code_writer,
      GUM_ADDRESS (gum_stalker_invoke_callout), 2,
      GUM_ARG_REGISTER, ARM64_REG_X20,
      GUM_ARG_ADDRESS, GUM_ADDRESS (entry));

  gum_exec_block_close_prolog (block, gc);

  gum_spinlock_acquire (&ec->callout_lock);
  g_queue_push_head (&ec->callout_entries, entry);
  gum_spinlock_release (&ec->callout_lock);
}

static void
gum_stalker_invoke_callout (GumCpuContext * cpu_context,
                            GumCalloutEntry * entry)
{
  GumExecCtx * ec = entry->exec_context;

  cpu_context->pc = GPOINTER_TO_SIZE (entry->pc);

  gum_spinlock_acquire (&ec->callout_lock);

  if (entry->callout != NULL)
  {
    entry->callout (cpu_context, entry->data);
  }

  gum_spinlock_release (&ec->callout_lock);
}

static void
gum_exec_ctx_write_prolog (GumExecCtx * ctx,
                           GumPrologType type,
                           GumArm64Writer * cw)
{
  gpointer helper;

  helper = (type == GUM_PROLOG_MINIMAL)
      ? ctx->last_prolog_minimal
      : ctx->last_prolog_full;

  gum_arm64_writer_put_stp_reg_reg_reg_offset (cw, ARM64_REG_X19,
      ARM64_REG_LR, ARM64_REG_SP, -(16 + GUM_RED_ZONE_SIZE),
      GUM_INDEX_PRE_ADJUST);
  gum_arm64_writer_put_bl_imm (cw, GUM_ADDRESS (helper));
}

static void
gum_exec_ctx_write_epilog (GumExecCtx * ctx,
                           GumPrologType type,
                           GumArm64Writer * cw)
{
  gpointer helper;

  helper = (type == GUM_PROLOG_MINIMAL)
      ? ctx->last_epilog_minimal
      : ctx->last_epilog_full;

  gum_arm64_writer_put_bl_imm (cw, GUM_ADDRESS (helper));
  gum_arm64_writer_put_ldp_reg_reg_reg_offset (cw, ARM64_REG_X19,
      ARM64_REG_X20, ARM64_REG_SP, 16 + GUM_RED_ZONE_SIZE,
      GUM_INDEX_POST_ADJUST);
}

static void
gum_exec_ctx_ensure_inline_helpers_reachable (GumExecCtx * ctx)
{
  gum_exec_ctx_ensure_helper_reachable (ctx, &ctx->last_prolog_minimal,
      gum_exec_ctx_write_minimal_prolog_helper);
  gum_exec_ctx_ensure_helper_reachable (ctx, &ctx->last_epilog_minimal,
      gum_exec_ctx_write_minimal_epilog_helper);

  gum_exec_ctx_ensure_helper_reachable (ctx, &ctx->last_prolog_full,
      gum_exec_ctx_write_full_prolog_helper);
  gum_exec_ctx_ensure_helper_reachable (ctx, &ctx->last_epilog_full,
      gum_exec_ctx_write_full_epilog_helper);

  gum_exec_ctx_ensure_helper_reachable (ctx, &ctx->last_stack_push,
      gum_exec_ctx_write_stack_push_helper);
  gum_exec_ctx_ensure_helper_reachable (ctx, &ctx->last_stack_pop_and_go,
      gum_exec_ctx_write_stack_pop_and_go_helper);
}

static void
gum_exec_ctx_write_minimal_prolog_helper (GumExecCtx * ctx,
                                          GumArm64Writer * cw)
{
  gum_exec_ctx_write_prolog_helper (ctx, GUM_PROLOG_MINIMAL, cw);
}

static void
gum_exec_ctx_write_minimal_epilog_helper (GumExecCtx * ctx,
                                          GumArm64Writer * cw)
{
  gum_exec_ctx_write_epilog_helper (ctx, GUM_PROLOG_MINIMAL, cw);
}

static void
gum_exec_ctx_write_full_prolog_helper (GumExecCtx * ctx,
                                       GumArm64Writer * cw)
{
  gum_exec_ctx_write_prolog_helper (ctx, GUM_PROLOG_FULL, cw);
}

static void
gum_exec_ctx_write_full_epilog_helper (GumExecCtx * ctx,
                                       GumArm64Writer * cw)
{
  gum_exec_ctx_write_epilog_helper (ctx, GUM_PROLOG_FULL, cw);
}

static void
gum_exec_ctx_write_prolog_helper (GumExecCtx * ctx,
                                  GumPrologType type,
                                  GumArm64Writer * cw)
{
  gint immediate_for_sp = 16 + GUM_RED_ZONE_SIZE;
  const guint32 mrs_x15_nzcv = 0xd53b420f;

  gum_arm64_writer_put_mov_reg_reg (cw, ARM64_REG_X19, ARM64_REG_LR);
  gum_arm64_writer_put_ldr_reg_reg_offset (cw, ARM64_REG_LR, ARM64_REG_SP, 8);
  gum_arm64_writer_put_str_reg_reg_offset (cw, ARM64_REG_X20, ARM64_REG_SP,
      8);

  if (type == GUM_PROLOG_MINIMAL)
  {
    gum_arm64_writer_put_push_reg_reg (cw, ARM64_REG_Q6, ARM64_REG_Q7);
    gum_arm64_writer_put_push_reg_reg (cw, ARM64_REG_Q4, ARM64_REG_Q5);
    gum_arm64_writer_put_push_reg_reg (cw, ARM64_REG_Q2, ARM64_REG_Q3);
    gum_arm64_writer_put_push_reg_reg (cw, ARM64_REG_Q0, ARM64_REG_Q1);
    immediate_for_sp += 4 * 32;

    gum_arm64_writer_put_push_reg_reg (cw, ARM64_REG_X29, ARM64_REG_X30);
    /* X19 - X28 are callee-saved registers */
    gum_arm64_writer_put_push_reg_reg (cw, ARM64_REG_X18, ARM64_REG_X30);
    gum_arm64_writer_put_push_reg_reg (cw, ARM64_REG_X16, ARM64_REG_X17);
    gum_arm64_writer_put_push_reg_reg (cw, ARM64_REG_X14, ARM64_REG_X15);
    gum_arm64_writer_put_push_reg_reg (cw, ARM64_REG_X12, ARM64_REG_X13);
    gum_arm64_writer_put_push_reg_reg (cw, ARM64_REG_X10, ARM64_REG_X11);
    gum_arm64_writer_put_push_reg_reg (cw, ARM64_REG_X8, ARM64_REG_X9);
    gum_arm64_writer_put_push_reg_reg (cw, ARM64_REG_X6, ARM64_REG_X7);
    gum_arm64_writer_put_push_reg_reg (cw, ARM64_REG_X4, ARM64_REG_X5);
    gum_arm64_writer_put_push_reg_reg (cw, ARM64_REG_X2, ARM64_REG_X3);
    gum_arm64_writer_put_push_reg_reg (cw, ARM64_REG_X0, ARM64_REG_X1);
    immediate_for_sp += 11 * 16;
  }
  else if (type == GUM_PROLOG_FULL)
  {
    /* GumCpuContext.q[128] */
    gum_arm64_writer_put_push_reg_reg (cw, ARM64_REG_Q6, ARM64_REG_Q7);
    gum_arm64_writer_put_push_reg_reg (cw, ARM64_REG_Q4, ARM64_REG_Q5);
    gum_arm64_writer_put_push_reg_reg (cw, ARM64_REG_Q2, ARM64_REG_Q3);
    gum_arm64_writer_put_push_reg_reg (cw, ARM64_REG_Q0, ARM64_REG_Q1);

    /* GumCpuContext.x[29] + fp + lr + padding */
    gum_arm64_writer_put_push_reg_reg (cw, ARM64_REG_X30, ARM64_REG_X15);
    gum_arm64_writer_put_push_reg_reg (cw, ARM64_REG_X28, ARM64_REG_X29);
    gum_arm64_writer_put_push_reg_reg (cw, ARM64_REG_X26, ARM64_REG_X27);
    gum_arm64_writer_put_push_reg_reg (cw, ARM64_REG_X24, ARM64_REG_X25);
    gum_arm64_writer_put_push_reg_reg (cw, ARM64_REG_X22, ARM64_REG_X23);
    gum_arm64_writer_put_push_reg_reg (cw, ARM64_REG_X20, ARM64_REG_X21);

    gum_arm64_writer_put_mov_reg_reg (cw, ARM64_REG_X20, ARM64_REG_X19);
    gum_arm64_writer_put_ldr_reg_reg_offset (cw, ARM64_REG_X19, ARM64_REG_SP,
        (6 * 16) + (4 * 32));

    gum_arm64_writer_put_push_reg_reg (cw, ARM64_REG_X18, ARM64_REG_X19);

    gum_arm64_writer_put_mov_reg_reg (cw, ARM64_REG_X19, ARM64_REG_X20);

    gum_arm64_writer_put_push_reg_reg (cw, ARM64_REG_X16, ARM64_REG_X17);
    gum_arm64_writer_put_push_reg_reg (cw, ARM64_REG_X14, ARM64_REG_X15);
    gum_arm64_writer_put_push_reg_reg (cw, ARM64_REG_X12, ARM64_REG_X13);
    gum_arm64_writer_put_push_reg_reg (cw, ARM64_REG_X10, ARM64_REG_X11);
    gum_arm64_writer_put_push_reg_reg (cw, ARM64_REG_X8, ARM64_REG_X9);
    gum_arm64_writer_put_push_reg_reg (cw, ARM64_REG_X6, ARM64_REG_X7);
    gum_arm64_writer_put_push_reg_reg (cw, ARM64_REG_X4, ARM64_REG_X5);
    gum_arm64_writer_put_push_reg_reg (cw, ARM64_REG_X2, ARM64_REG_X3);
    gum_arm64_writer_put_push_reg_reg (cw, ARM64_REG_X0, ARM64_REG_X1);

    /* GumCpuContext.pc + sp */
    gum_arm64_writer_put_mov_reg_reg (cw, ARM64_REG_X0, ARM64_REG_XZR);
    gum_arm64_writer_put_add_reg_reg_imm (cw, ARM64_REG_X1, ARM64_REG_SP,
        (16 * 16) + (4 * 32) + 16 + GUM_RED_ZONE_SIZE);
    gum_arm64_writer_put_push_reg_reg (cw, ARM64_REG_X0, ARM64_REG_X1);

    immediate_for_sp += sizeof (GumCpuContext) + 8;
  }

  gum_arm64_writer_put_instruction (cw, mrs_x15_nzcv);

  /* conveniently point X20 at the beginning of the saved registers */
  gum_arm64_writer_put_mov_reg_reg (cw, ARM64_REG_X20, ARM64_REG_SP);

  /* padding + status */
  gum_arm64_writer_put_push_reg_reg (cw, ARM64_REG_X14, ARM64_REG_X15);
  immediate_for_sp += 1 * 16;

  gum_arm64_writer_put_br_reg (cw, ARM64_REG_X19);
}

static void
gum_exec_ctx_write_epilog_helper (GumExecCtx * ctx,
                                  GumPrologType type,
                                  GumArm64Writer * cw)
{
  const guint32 msr_nzcv_x15 = 0xd51b420f;

  /* padding + status */
  gum_arm64_writer_put_pop_reg_reg (cw, ARM64_REG_X14, ARM64_REG_X15);

  if (type == GUM_PROLOG_MINIMAL)
  {
    gum_arm64_writer_put_mov_reg_reg (cw, ARM64_REG_X19, ARM64_REG_LR);

    /* restore status */
    gum_arm64_writer_put_instruction (cw, msr_nzcv_x15);

    gum_arm64_writer_put_pop_reg_reg (cw, ARM64_REG_X0, ARM64_REG_X1);
    gum_arm64_writer_put_pop_reg_reg (cw, ARM64_REG_X2, ARM64_REG_X3);
    gum_arm64_writer_put_pop_reg_reg (cw, ARM64_REG_X4, ARM64_REG_X5);
    gum_arm64_writer_put_pop_reg_reg (cw, ARM64_REG_X6, ARM64_REG_X7);
    gum_arm64_writer_put_pop_reg_reg (cw, ARM64_REG_X8, ARM64_REG_X9);
    gum_arm64_writer_put_pop_reg_reg (cw, ARM64_REG_X10, ARM64_REG_X11);
    gum_arm64_writer_put_pop_reg_reg (cw, ARM64_REG_X12, ARM64_REG_X13);
    gum_arm64_writer_put_pop_reg_reg (cw, ARM64_REG_X14, ARM64_REG_X15);
    gum_arm64_writer_put_pop_reg_reg (cw, ARM64_REG_X16, ARM64_REG_X17);
    gum_arm64_writer_put_pop_reg_reg (cw, ARM64_REG_X18, ARM64_REG_X30);
    gum_arm64_writer_put_pop_reg_reg (cw, ARM64_REG_X29, ARM64_REG_X30);

    gum_arm64_writer_put_pop_reg_reg (cw, ARM64_REG_Q0, ARM64_REG_Q1);
    gum_arm64_writer_put_pop_reg_reg (cw, ARM64_REG_Q2, ARM64_REG_Q3);
    gum_arm64_writer_put_pop_reg_reg (cw, ARM64_REG_Q4, ARM64_REG_Q5);
    gum_arm64_writer_put_pop_reg_reg (cw, ARM64_REG_Q6, ARM64_REG_Q7);
  }
  else if (type == GUM_PROLOG_FULL)
  {
    /* GumCpuContext.pc + sp */
    gum_arm64_writer_put_add_reg_reg_imm (cw, ARM64_REG_SP, ARM64_REG_SP, 16);

    /* restore status */
    gum_arm64_writer_put_instruction (cw, msr_nzcv_x15);

    /* GumCpuContext.x[29] + fp + lr + padding */
    gum_arm64_writer_put_pop_reg_reg (cw, ARM64_REG_X0, ARM64_REG_X1);
    gum_arm64_writer_put_pop_reg_reg (cw, ARM64_REG_X2, ARM64_REG_X3);
    gum_arm64_writer_put_pop_reg_reg (cw, ARM64_REG_X4, ARM64_REG_X5);
    gum_arm64_writer_put_pop_reg_reg (cw, ARM64_REG_X6, ARM64_REG_X7);
    gum_arm64_writer_put_pop_reg_reg (cw, ARM64_REG_X8, ARM64_REG_X9);
    gum_arm64_writer_put_pop_reg_reg (cw, ARM64_REG_X10, ARM64_REG_X11);
    gum_arm64_writer_put_pop_reg_reg (cw, ARM64_REG_X12, ARM64_REG_X13);
    gum_arm64_writer_put_pop_reg_reg (cw, ARM64_REG_X14, ARM64_REG_X15);
    gum_arm64_writer_put_pop_reg_reg (cw, ARM64_REG_X16, ARM64_REG_X17);
    gum_arm64_writer_put_pop_reg_reg (cw, ARM64_REG_X18, ARM64_REG_X19);
    gum_arm64_writer_put_pop_reg_reg (cw, ARM64_REG_X20, ARM64_REG_X21);

    gum_arm64_writer_put_stp_reg_reg_reg_offset (cw, ARM64_REG_X19,
        ARM64_REG_X20, ARM64_REG_SP, (5 * 16) + (4 * 32),
        GUM_INDEX_SIGNED_OFFSET);
    gum_arm64_writer_put_mov_reg_reg (cw, ARM64_REG_X19, ARM64_REG_LR);

    gum_arm64_writer_put_pop_reg_reg (cw, ARM64_REG_X22, ARM64_REG_X23);
    gum_arm64_writer_put_pop_reg_reg (cw, ARM64_REG_X24, ARM64_REG_X25);
    gum_arm64_writer_put_pop_reg_reg (cw, ARM64_REG_X26, ARM64_REG_X27);
    gum_arm64_writer_put_pop_reg_reg (cw, ARM64_REG_X28, ARM64_REG_X29);

    gum_arm64_writer_put_str_reg_reg_offset (cw, ARM64_REG_X15, ARM64_REG_SP,
        8);
    gum_arm64_writer_put_pop_reg_reg (cw, ARM64_REG_X30, ARM64_REG_X15);

    /* GumCpuContext.q[128] */
    gum_arm64_writer_put_pop_reg_reg (cw, ARM64_REG_Q0, ARM64_REG_Q1);
    gum_arm64_writer_put_pop_reg_reg (cw, ARM64_REG_Q2, ARM64_REG_Q3);
    gum_arm64_writer_put_pop_reg_reg (cw, ARM64_REG_Q4, ARM64_REG_Q5);
    gum_arm64_writer_put_pop_reg_reg (cw, ARM64_REG_Q6, ARM64_REG_Q7);
  }

  gum_arm64_writer_put_br_reg (cw, ARM64_REG_X19);
}

static void
gum_exec_ctx_write_stack_push_helper (GumExecCtx * ctx,
                                      GumArm64Writer * cw)
{
  gconstpointer skip_stack_push = cw->code + 1;

  gum_arm64_writer_put_ldr_reg_address (cw, ARM64_REG_X16,
      GUM_ADDRESS (&ctx->current_frame));

  gum_arm64_writer_put_ldr_reg_reg_offset (cw, ARM64_REG_X17, ARM64_REG_X16, 0);

  gum_arm64_writer_put_and_reg_reg_imm (cw, ARM64_REG_X2, ARM64_REG_X17,
      ctx->stalker->page_size - 1);
  gum_arm64_writer_put_cbz_reg_label (cw, ARM64_REG_X2, skip_stack_push);

  gum_arm64_writer_put_stp_reg_reg_reg_offset (cw, ARM64_REG_X0, ARM64_REG_X1,
      ARM64_REG_X17, -((gint) sizeof (GumExecFrame)), GUM_INDEX_PRE_ADJUST);

  gum_arm64_writer_put_str_reg_reg_offset (cw, ARM64_REG_X17, ARM64_REG_X16, 0);

  gum_arm64_writer_put_label (cw, skip_stack_push);
  gum_arm64_writer_put_ret (cw);
}

static void
gum_exec_ctx_write_stack_pop_and_go_helper (GumExecCtx * ctx,
                                            GumArm64Writer * cw)
{
  gconstpointer resolve_dynamically = cw->code + 1;

  /*
   * Fast path (try the stack)
   */
  gum_arm64_writer_put_push_reg_reg (cw, ARM64_REG_X0, ARM64_REG_X1);

  gum_arm64_writer_put_ldr_reg_address (cw, ARM64_REG_X0,
      GUM_ADDRESS (&ctx->current_frame));
  gum_arm64_writer_put_ldr_reg_reg_offset (cw, ARM64_REG_X1, ARM64_REG_X0, 0);

  gum_arm64_writer_put_ldr_reg_reg_offset (cw, ARM64_REG_X17, ARM64_REG_X1,
      G_STRUCT_OFFSET (GumExecFrame, real_address));
  gum_arm64_writer_put_sub_reg_reg_reg (cw, ARM64_REG_X17, ARM64_REG_X17,
      ARM64_REG_X16);
  gum_arm64_writer_put_cbnz_reg_label (cw, ARM64_REG_X17,
      resolve_dynamically);

  gum_arm64_writer_put_ldr_reg_reg_offset (cw, ARM64_REG_X17, ARM64_REG_X1,
      G_STRUCT_OFFSET (GumExecFrame, code_address));
  gum_arm64_writer_put_add_reg_reg_imm (cw, ARM64_REG_X1, ARM64_REG_X1,
      sizeof (GumExecFrame));
  gum_arm64_writer_put_str_reg_reg_offset (cw, ARM64_REG_X1, ARM64_REG_X0, 0);

  gum_arm64_writer_put_pop_reg_reg (cw, ARM64_REG_X0, ARM64_REG_X1);
  gum_arm64_writer_put_br_reg (cw, ARM64_REG_X17);

  /*
   * Slow path (resolve dynamically)
   */
  gum_arm64_writer_put_label (cw, resolve_dynamically);

  /* Clear our stack so we might resync later */
  gum_arm64_writer_put_ldr_reg_address (cw, ARM64_REG_X1,
      GUM_ADDRESS (ctx->first_frame));
  gum_arm64_writer_put_str_reg_reg_offset (cw, ARM64_REG_X1, ARM64_REG_X0, 0);

  gum_arm64_writer_put_ldr_reg_address (cw, ARM64_REG_X0,
      GUM_ADDRESS (&ctx->return_at));
  gum_arm64_writer_put_str_reg_reg_offset (cw, ARM64_REG_X16, ARM64_REG_X0, 0);

  gum_arm64_writer_put_pop_reg_reg (cw, ARM64_REG_X0, ARM64_REG_X1);
  gum_arm64_writer_put_ldp_reg_reg_reg_offset (cw, ARM64_REG_X16, ARM64_REG_X17,
      ARM64_REG_SP, 0, GUM_INDEX_SIGNED_OFFSET);
  gum_arm64_writer_put_stp_reg_reg_reg_offset (cw, ARM64_REG_X19, ARM64_REG_LR,
      ARM64_REG_SP, 0, GUM_INDEX_SIGNED_OFFSET);
  gum_arm64_writer_put_bl_imm (cw, GUM_ADDRESS (ctx->last_prolog_minimal));

  gum_arm64_writer_put_ldr_reg_address (cw, ARM64_REG_X0,
      GUM_ADDRESS (&ctx->return_at));
  gum_arm64_writer_put_ldr_reg_reg_offset (cw, ARM64_REG_X1, ARM64_REG_X0, 0);

  gum_arm64_writer_put_call_address_with_arguments (cw,
      GUM_ADDRESS (GUM_ENTRYGATE (ret)), 2,
      GUM_ARG_ADDRESS, GUM_ADDRESS (ctx),
      GUM_ARG_REGISTER, ARM64_REG_X1);

  gum_exec_ctx_write_epilog (ctx, GUM_PROLOG_MINIMAL, cw);

  gum_exec_block_write_exec_generated_code (cw, ctx);
}

static void
gum_exec_ctx_ensure_helper_reachable (GumExecCtx * ctx,
                                      gpointer * helper_ptr,
                                      GumExecHelperWriteFunc write)
{
  GumSlab * slab;
  GumArm64Writer * cw;

  if (gum_exec_ctx_is_helper_reachable (ctx, helper_ptr))
    return;

  slab = ctx->code_slab;
  cw = &ctx->code_writer;

  gum_stalker_thaw (ctx->stalker, slab->data + slab->offset,
      slab->size - slab->offset);
  gum_arm64_writer_reset (cw, slab->data + slab->offset);
  *helper_ptr = gum_arm64_writer_cur (cw);

  write (ctx, cw);

  gum_arm64_writer_flush (cw);
  gum_stalker_freeze (ctx->stalker, cw->base, gum_arm64_writer_offset (cw));

  slab->offset += gum_arm64_writer_offset (cw);
}

static gboolean
gum_exec_ctx_is_helper_reachable (GumExecCtx * ctx,
                                  gpointer * helper_ptr)
{
  GumAddress helper;
  GumSlab * slab;
  GumAddress start, end;

  helper = GUM_ADDRESS (*helper_ptr);
  if (helper == 0)
    return FALSE;

  slab = ctx->code_slab;

  start = GUM_ADDRESS (slab->data);
  end = start + slab->size;

  if (!gum_arm64_writer_can_branch_directly_between (start, helper))
    return FALSE;

  return gum_arm64_writer_can_branch_directly_between (end, helper);
}

static void
gum_exec_ctx_write_push_branch_target_address (GumExecCtx * ctx,
                                               const GumBranchTarget * target,
                                               GumGeneratorContext * gc)
{
  GumArm64Writer * cw = gc->code_writer;

  if (target->reg == ARM64_REG_INVALID)
  {
    gum_arm64_writer_put_ldr_reg_address (cw, ARM64_REG_X15,
        GUM_ADDRESS (target->absolute_address));
    gum_arm64_writer_put_push_reg_reg (cw, ARM64_REG_X15, ARM64_REG_X15);
  }
  else
  {
    gum_exec_ctx_load_real_register_into (ctx, ARM64_REG_X15, target->reg, gc);
    gum_arm64_writer_put_push_reg_reg (cw, ARM64_REG_X15, ARM64_REG_X15);
  }
}

static void
gum_exec_ctx_load_real_register_into (GumExecCtx * ctx,
                                      arm64_reg target_register,
                                      arm64_reg source_register,
                                      GumGeneratorContext * gc)
{
  if (gc->opened_prolog == GUM_PROLOG_MINIMAL)
  {
    gum_exec_ctx_load_real_register_from_minimal_frame_into (ctx,
        target_register, source_register, gc);
    return;
  }
  else if (gc->opened_prolog == GUM_PROLOG_FULL)
  {
    gum_exec_ctx_load_real_register_from_full_frame_into (ctx, target_register,
        source_register, gc);
    return;
  }

  g_assert_not_reached ();
}

static void
gum_exec_ctx_load_real_register_from_minimal_frame_into (
    GumExecCtx * ctx,
    arm64_reg target_register,
    arm64_reg source_register,
    GumGeneratorContext * gc)
{
  GumArm64Writer * cw;

  cw = gc->code_writer;

  if (source_register >= ARM64_REG_X0 && source_register <= ARM64_REG_X18)
  {
    gum_arm64_writer_put_ldr_reg_reg_offset (cw, target_register, ARM64_REG_X20,
        (source_register - ARM64_REG_X0) * 8);
  }
  else if (source_register == ARM64_REG_X19 || source_register == ARM64_REG_X20)
  {
    gum_arm64_writer_put_ldr_reg_reg_offset (cw, target_register, ARM64_REG_X20,
        (11 * 16) + (4 * 32) + ((source_register - ARM64_REG_X19) * 8));
  }
  else if (source_register == ARM64_REG_X29 || source_register == ARM64_REG_X30)
  {
    gum_arm64_writer_put_ldr_reg_reg_offset (cw, target_register, ARM64_REG_X20,
        (10 * 16) + ((source_register - ARM64_REG_X29) * 8));
  }
  else
  {
    gum_arm64_writer_put_mov_reg_reg (cw, target_register, source_register);
  }
}

static void
gum_exec_ctx_load_real_register_from_full_frame_into (GumExecCtx * ctx,
                                                      arm64_reg target_register,
                                                      arm64_reg source_register,
                                                      GumGeneratorContext * gc)
{
  GumArm64Writer * cw;

  cw = gc->code_writer;

  if (source_register >= ARM64_REG_X0 && source_register <= ARM64_REG_X28)
  {
    gum_arm64_writer_put_ldr_reg_reg_offset (cw, target_register, ARM64_REG_X20,
        G_STRUCT_OFFSET (GumCpuContext, x) +
        ((source_register - ARM64_REG_X0) * 8));
  }
  else if (source_register == ARM64_REG_X29)
  {
    gum_arm64_writer_put_ldr_reg_reg_offset (cw, target_register, ARM64_REG_X20,
        G_STRUCT_OFFSET (GumCpuContext, fp));
  }
  else if (source_register == ARM64_REG_X30)
  {
    gum_arm64_writer_put_ldr_reg_reg_offset (cw, target_register, ARM64_REG_X20,
        G_STRUCT_OFFSET (GumCpuContext, lr));
  }
  else
  {
    gum_arm64_writer_put_mov_reg_reg (cw, target_register, source_register);
  }
}

static GumExecBlock *
gum_exec_block_new (GumExecCtx * ctx)
{
  GumStalker * stalker = ctx->stalker;
  GumSlab * slab = ctx->code_slab;
  gsize available;

  available = (slab != NULL) ? slab->size - slab->offset : 0;
  if (available >= GUM_EXEC_BLOCK_MIN_SIZE &&
      slab->num_blocks != stalker->slab_max_blocks)
  {
    GumExecBlock * block = slab->blocks + slab->num_blocks;

    block->ctx = ctx;
    block->slab = slab;

    block->code_begin = slab->data + slab->offset;
    block->code_end = block->code_begin;

    block->recycle_count = 0;

    gum_stalker_thaw (stalker, block->code_begin, available);
    slab->num_blocks++;

    return block;
  }

  if (stalker->trust_threshold < 0 && slab != NULL)
  {
    slab->offset = 0;

    return gum_exec_block_new (ctx);
  }

  gum_exec_ctx_add_slab (ctx);

  gum_exec_ctx_ensure_inline_helpers_reachable (ctx);

  return gum_exec_block_new (ctx);
}

static GumExecBlock *
gum_exec_block_obtain (GumExecCtx * ctx,
                       gpointer real_address,
                       gpointer * code_address_ptr)
{
  GumExecBlock * block;

  block = gum_metal_hash_table_lookup (ctx->mappings, real_address);
  if (block != NULL)
    *code_address_ptr = block->code_begin;

  return block;
}

static gboolean
gum_exec_block_is_full (GumExecBlock * block)
{
  guint8 * slab_end = block->slab->data + block->slab->size;

  return slab_end - block->code_end < GUM_EXEC_BLOCK_MIN_SIZE;
}

static gconstpointer
gum_exec_block_check_address_for_exclusion (GumExecBlock * block,
                                            gconstpointer address)
{
  GumExecCtx * ctx = block->ctx;

  if (ctx->activation_target != NULL)
    return address;

  if (gum_stalker_is_excluding (ctx->stalker, address))
    return NULL;

  return address;
}

static void
gum_exec_block_commit (GumExecBlock * block)
{
  gsize code_size, real_size;

  code_size = block->code_end - block->code_begin;
  block->slab->offset += code_size;

  real_size = block->real_end - block->real_begin;
  block->real_snapshot = block->code_end;
  memcpy (block->real_snapshot, block->real_begin, real_size);
  block->slab->offset += real_size;

  gum_stalker_freeze (block->ctx->stalker, block->code_begin, code_size);
}

static void
gum_exec_block_backpatch_call (GumExecBlock * block,
                               gpointer code_start,
                               GumPrologType opened_prolog,
                               gpointer target_address,
                               gpointer ret_real_address,
                               gpointer ret_code_address)
{
  gboolean just_unfollowed;
  GumExecCtx * ctx;
  GumStalker * stalker;

  just_unfollowed = block == NULL;
  if (just_unfollowed)
    return;

  ctx = block->ctx;
  stalker = ctx->stalker;

  if (g_atomic_int_get (&ctx->state) == GUM_EXEC_CTX_ACTIVE &&
      block->recycle_count >= stalker->trust_threshold)
  {
    GumArm64Writer * cw = &ctx->code_writer;
    const gsize code_max_size = ret_code_address - code_start;

    gum_stalker_thaw (stalker, code_start, code_max_size);
    gum_arm64_writer_reset (cw, code_start);

    if (opened_prolog == GUM_PROLOG_NONE)
    {
      gum_arm64_writer_put_stp_reg_reg_reg_offset (cw, ARM64_REG_X16,
          ARM64_REG_X17, ARM64_REG_SP, -(16 + GUM_RED_ZONE_SIZE),
          GUM_INDEX_PRE_ADJUST);
      gum_arm64_writer_put_push_reg_reg (cw, ARM64_REG_X0, ARM64_REG_X1);
      gum_arm64_writer_put_push_reg_reg (cw, ARM64_REG_X2, ARM64_REG_LR);
    }

    gum_arm64_writer_put_ldr_reg_address (cw, ARM64_REG_X0,
        GUM_ADDRESS (ret_real_address));
    gum_arm64_writer_put_ldr_reg_address (cw, ARM64_REG_X1,
        GUM_ADDRESS (ret_code_address));
    gum_arm64_writer_put_bl_imm (cw, GUM_ADDRESS (block->ctx->last_stack_push));

    if (opened_prolog == GUM_PROLOG_NONE)
    {
      gum_arm64_writer_put_pop_reg_reg (cw, ARM64_REG_X2, ARM64_REG_LR);
      gum_arm64_writer_put_pop_reg_reg (cw, ARM64_REG_X0, ARM64_REG_X1);
      gum_arm64_writer_put_ldp_reg_reg_reg_offset (cw, ARM64_REG_X16,
          ARM64_REG_X17, ARM64_REG_SP, 16 + GUM_RED_ZONE_SIZE,
          GUM_INDEX_POST_ADJUST);
    }
    else
    {
      gum_exec_ctx_write_epilog (block->ctx, opened_prolog, cw);
    }

    gum_arm64_writer_put_ldr_reg_address (cw, ARM64_REG_LR,
        GUM_ADDRESS (ret_real_address));

    gum_exec_block_write_jmp_to_block_start (block, target_address);

    gum_arm64_writer_flush (cw);
    g_assert (gum_arm64_writer_offset (cw) <= code_max_size);
    gum_stalker_freeze (stalker, code_start, code_max_size);
  }
}

static void
gum_exec_block_backpatch_jmp (GumExecBlock * block,
                              gpointer code_start,
                              GumPrologType opened_prolog,
                              gpointer target_address)
{
  gboolean just_unfollowed;
  GumExecCtx * ctx;
  GumArm64Writer * cw;
  GumStalker * stalker;

  just_unfollowed = block == NULL;
  if (just_unfollowed)
    return;

  ctx = block->ctx;
  cw = &ctx->code_writer;
  stalker = ctx->stalker;

  if (g_atomic_int_get (&ctx->state) == GUM_EXEC_CTX_ACTIVE &&
      block->recycle_count >= stalker->trust_threshold)
  {
    const gsize code_max_size = 128;

    gum_stalker_thaw (stalker, code_start, code_max_size);
    gum_arm64_writer_reset (cw, code_start);

    if (opened_prolog != GUM_PROLOG_NONE)
    {
      gum_exec_ctx_write_epilog (block->ctx, opened_prolog, cw);
    }

    gum_exec_block_write_jmp_to_block_start (block, target_address);

    gum_arm64_writer_flush (cw);
    g_assert (gum_arm64_writer_offset (cw) <= code_max_size);
    gum_stalker_freeze (stalker, code_start, code_max_size);
  }
}

static void
gum_exec_block_backpatch_ret (GumExecBlock * block,
                              gpointer code_start,
                              gpointer target_address)
{
  gboolean just_unfollowed;
  GumExecCtx * ctx;
  GumArm64Writer * cw;
  GumStalker * stalker;

  just_unfollowed = block == NULL;
  if (just_unfollowed)
    return;

  ctx = block->ctx;
  cw = &ctx->code_writer;
  stalker = ctx->stalker;

  if (g_atomic_int_get (&ctx->state) == GUM_EXEC_CTX_ACTIVE &&
      block->recycle_count >= stalker->trust_threshold)
  {
    const gsize code_max_size = 128;

    gum_stalker_thaw (stalker, code_start, code_max_size);
    gum_arm64_writer_reset (cw, code_start);

    gum_arm64_writer_put_ldp_reg_reg_reg_offset (cw, ARM64_REG_X16,
        ARM64_REG_X17, ARM64_REG_SP, 16 + GUM_RED_ZONE_SIZE,
        GUM_INDEX_POST_ADJUST);

    gum_exec_block_write_jmp_to_block_start (block, target_address);

    gum_arm64_writer_flush (cw);
    g_assert (gum_arm64_writer_offset (cw) <= code_max_size);
    gum_stalker_freeze (stalker, code_start, code_max_size);
  }
}

static void
gum_exec_block_backpatch_inline_cache (GumExecBlock * block,
                                       gpointer * ic_entries)
{
  gboolean just_unfollowed;
  GumExecCtx * ctx;
  GumStalker * stalker;

  just_unfollowed = block == NULL;
  if (just_unfollowed)
    return;

  ctx = block->ctx;
  stalker = ctx->stalker;

  if (g_atomic_int_get (&ctx->state) == GUM_EXEC_CTX_ACTIVE &&
      block->recycle_count >= stalker->trust_threshold)
  {
    guint offset;

    offset = (ic_entries[0] == NULL) ? 0 : 2;

    if (ic_entries[offset + 0] == NULL)
    {
      const gsize ic_slot_size = 2 * sizeof (gpointer);

      gum_stalker_thaw (stalker, ic_entries + offset, ic_slot_size);

      ic_entries[offset + 0] = block->real_begin;
      ic_entries[offset + 1] = block->code_begin;

      gum_stalker_freeze (stalker, ic_entries + offset, ic_slot_size);
    }
  }
}

static GumVirtualizationRequirements
gum_exec_block_virtualize_branch_insn (GumExecBlock * block,
                                       GumGeneratorContext * gc)
{
  GumExecCtx * ctx = block->ctx;
  GumInstruction * insn = gc->instruction;
  GumArm64Writer * cw = gc->code_writer;
  cs_arm64 * arm64 = &insn->ci->detail->arm64;
  cs_arm64_op * op = &arm64->operands[0];
  cs_arm64_op * op2 = NULL;
  cs_arm64_op * op3 = NULL;
  arm64_cc cc = arm64->cc;
  gboolean is_conditional;
  GumBranchTarget target = { 0, };

  g_assert (arm64->op_count != 0);

  is_conditional = (insn->ci->id == ARM64_INS_CBZ) ||
      (insn->ci->id == ARM64_INS_CBNZ) ||
      (insn->ci->id == ARM64_INS_TBZ) ||
      (insn->ci->id == ARM64_INS_TBNZ) ||
      (insn->ci->id == ARM64_INS_B && cc != ARM64_CC_INVALID);

  target.origin_ip = insn->end;

  if (insn->ci->id == ARM64_INS_BL || insn->ci->id == ARM64_INS_B)
  {
    g_assert (op->type == ARM64_OP_IMM);

    target.absolute_address = GSIZE_TO_POINTER (op->imm);
    target.reg = ARM64_REG_INVALID;
  }
  else if (insn->ci->id == ARM64_INS_BLR || insn->ci->id == ARM64_INS_BR)
  {
    g_assert (op->type == ARM64_OP_REG);

    target.reg = op->reg;
  }
  else if (insn->ci->id == ARM64_INS_CBZ || insn->ci->id == ARM64_INS_CBNZ)
  {
    op2 = &arm64->operands[1];

    g_assert (op->type == ARM64_OP_REG);
    g_assert (op2->type == ARM64_OP_IMM);

    target.absolute_address = GSIZE_TO_POINTER (op2->imm);
    target.reg = ARM64_REG_INVALID;
  }
  else if (insn->ci->id == ARM64_INS_TBZ || insn->ci->id == ARM64_INS_TBNZ)
  {
    op2 = &arm64->operands[1];
    op3 = &arm64->operands[2];

    g_assert (op->type == ARM64_OP_REG);
    g_assert (op2->type == ARM64_OP_IMM);
    g_assert (op3->type == ARM64_OP_IMM);

    target.absolute_address = GSIZE_TO_POINTER (op3->imm);
    target.reg = ARM64_REG_INVALID;
  }
  else
  {
    g_assert_not_reached ();
  }

  if (insn->ci->id == ARM64_INS_BL || insn->ci->id == ARM64_INS_BLR)
  {
    gboolean target_is_excluded = FALSE;

    if ((ctx->sink_mask & GUM_CALL) != 0)
    {
      gum_exec_block_write_call_event_code (block, &target, gc,
          GUM_CODE_INTERRUPTIBLE);
    }

    if (ctx->stalker->any_probes_attached)
    {
      gum_exec_block_write_call_probe_code (block, &target, gc);
    }

    if (target.reg == ARM64_REG_INVALID &&
        ctx->activation_target == NULL)
    {
      target_is_excluded =
          gum_stalker_is_excluding (ctx->stalker, target.absolute_address);
    }

    if (target_is_excluded)
    {
      GumBranchTarget next_instruction = { 0, };

      gum_exec_block_open_prolog (block, GUM_PROLOG_MINIMAL, gc);
      gum_arm64_writer_put_call_address_with_arguments (cw,
          GUM_ADDRESS (gum_exec_ctx_begin_call), 2,
          GUM_ARG_ADDRESS, GUM_ADDRESS (ctx),
          GUM_ARG_ADDRESS, GUM_ADDRESS (insn->end));
      gum_exec_block_close_prolog (block, gc);

      gum_arm64_relocator_write_one (gc->relocator);

      gum_exec_block_open_prolog (block, GUM_PROLOG_MINIMAL, gc);
      gum_arm64_writer_put_call_address_with_arguments (cw,
          GUM_ADDRESS (gum_exec_ctx_end_call), 1,
          GUM_ARG_ADDRESS, GUM_ADDRESS (ctx));
      gum_exec_block_close_prolog (block, gc);

      next_instruction.absolute_address = insn->end;
      next_instruction.reg = ARM64_REG_INVALID;
      gum_exec_block_write_jmp_transfer_code (block, &next_instruction,
          GUM_ENTRYGATE (excluded_call_imm), gc);

      return GUM_REQUIRE_NOTHING;
    }

    gum_arm64_relocator_skip_one (gc->relocator);
    gum_exec_block_write_call_invoke_code (block, &target, gc);
  }
  else if (insn->ci->id == ARM64_INS_CBZ || insn->ci->id == ARM64_INS_CBNZ
      || insn->ci->id == ARM64_INS_TBZ || insn->ci->id == ARM64_INS_TBNZ
      || insn->ci->id == ARM64_INS_B || insn->ci->id == ARM64_INS_BR)
  {
    gpointer is_false;
    GumExecCtxReplaceCurrentBlockFunc regular_entry_func, cond_entry_func;

    gum_arm64_relocator_skip_one (gc->relocator);

    is_false =
        GUINT_TO_POINTER ((GPOINTER_TO_UINT (insn->begin) << 16) | 0xbeef);

    if (is_conditional)
    {
      gum_exec_block_close_prolog (block, gc);

      regular_entry_func = NULL;

      /* jump to is_false if is_false */
      if (insn->ci->id == ARM64_INS_CBZ)
      {
        gum_arm64_writer_put_cbnz_reg_label (cw, op->reg, is_false);

        cond_entry_func = GUM_ENTRYGATE (jmp_cond_cbz);
      }
      else if (insn->ci->id == ARM64_INS_CBNZ)
      {
        gum_arm64_writer_put_cbz_reg_label (cw, op->reg, is_false);

        cond_entry_func = GUM_ENTRYGATE (jmp_cond_cbnz);
      }
      else if (insn->ci->id == ARM64_INS_TBZ)
      {
        gum_arm64_writer_put_tbnz_reg_imm_label (cw, op->reg, op2->imm,
            is_false);

        cond_entry_func = GUM_ENTRYGATE (jmp_cond_tbz);
      }
      else if (insn->ci->id == ARM64_INS_TBNZ)
      {
        gum_arm64_writer_put_tbz_reg_imm_label (cw, op->reg, op2->imm,
            is_false);

        cond_entry_func = GUM_ENTRYGATE (jmp_cond_tbnz);
      }
      else if (insn->ci->id == ARM64_INS_B)
      {
        arm64_cc not_cc;

        g_assert (cc != ARM64_CC_INVALID);
        g_assert (cc > ARM64_CC_INVALID);
        g_assert (cc <= ARM64_CC_NV);

        not_cc = cc + 2 * (cc % 2) - 1;
        gum_arm64_writer_put_b_cond_label (cw, not_cc, is_false);

        cond_entry_func = GUM_ENTRYGATE (jmp_cond_cc);
      }
      else
      {
        cond_entry_func = NULL;

        g_assert_not_reached ();
      }
    }
    else
    {
      if (target.reg != ARM64_REG_INVALID)
        regular_entry_func = GUM_ENTRYGATE (jmp_reg);
      else
        regular_entry_func = GUM_ENTRYGATE (jmp_imm);
      cond_entry_func = NULL;
    }

    gum_exec_block_write_jmp_transfer_code (block, &target,
        is_conditional ? cond_entry_func : regular_entry_func, gc);

    if (is_conditional)
    {
      GumBranchTarget cond_target = { 0, };

      cond_target.absolute_address = insn->end;
      cond_target.reg = ARM64_REG_INVALID;

      gum_arm64_writer_put_label (cw, is_false);

      if (gc->exclusive_load_offset == GUM_INSTRUCTION_OFFSET_NONE)
      {
        gum_exec_block_write_jmp_transfer_code (block, &cond_target,
            cond_entry_func, gc);
      }
      else
      {
        return GUM_REQUIRE_EXCLUSIVE_STORE;
      }
    }
  }
  else
  {
    g_assert ("" == "not implemented");
  }

  return GUM_REQUIRE_NOTHING;
}

static GumVirtualizationRequirements
gum_exec_block_virtualize_ret_insn (GumExecBlock * block,
                                    GumGeneratorContext * gc)
{
  GumInstruction * insn;
  cs_arm64 * arm64;
  cs_arm64_op * op;
  arm64_reg ret_reg;

  if ((block->ctx->sink_mask & GUM_RET) != 0)
    gum_exec_block_write_ret_event_code (block, gc, GUM_CODE_INTERRUPTIBLE);

  insn = gc->instruction;
  arm64 = &insn->ci->detail->arm64;

  if (arm64->op_count == 0)
  {
    ret_reg = ARM64_REG_X30;
  }
  else
  {
    g_assert (arm64->op_count == 1);

    op = &arm64->operands[0];
    g_assert (op->type == ARM64_OP_REG);

    ret_reg = op->reg;
  }
  gum_arm64_relocator_skip_one (gc->relocator);
  gum_exec_block_write_ret_transfer_code (block, gc, ret_reg);

  return GUM_REQUIRE_NOTHING;
}

static GumVirtualizationRequirements
gum_exec_block_virtualize_sysenter_insn (GumExecBlock * block,
                                         GumGeneratorContext * gc)
{
#ifdef HAVE_LINUX
  return gum_exec_block_virtualize_linux_sysenter (block, gc);
#else
  return GUM_REQUIRE_RELOCATION;
#endif
}

#ifdef HAVE_LINUX

static GumVirtualizationRequirements
gum_exec_block_virtualize_linux_sysenter (GumExecBlock * block,
                                          GumGeneratorContext * gc)
{
  GumArm64Writer * cw = gc->code_writer;
  const cs_insn * insn = gc->instruction->ci;
  gconstpointer perform_regular_syscall = cw->code + 1;
  gconstpointer perform_next_instruction = cw->code + 2;
  const guint32 mrs_x15_nzcv = 0xd53b420f;
  const guint32 msr_nzcv_x15 = 0xd51b420f;

  gum_arm64_relocator_skip_one (gc->relocator);

  if (gc->opened_prolog != GUM_PROLOG_NONE)
    gum_exec_block_close_prolog (block, gc);

  gum_arm64_writer_put_stp_reg_reg_reg_offset (cw, ARM64_REG_X15, ARM64_REG_X17,
      ARM64_REG_SP, -(16 + GUM_RED_ZONE_SIZE), GUM_INDEX_PRE_ADJUST);
  gum_arm64_writer_put_instruction (cw, mrs_x15_nzcv);

  gum_arm64_writer_put_sub_reg_reg_imm (cw, ARM64_REG_X17,
      ARM64_REG_X8, __NR_clone);
  gum_arm64_writer_put_cbnz_reg_label (cw, ARM64_REG_X17,
      perform_regular_syscall);

  gum_arm64_writer_put_instruction (cw, msr_nzcv_x15);
  gum_arm64_writer_put_ldp_reg_reg_reg_offset (cw, ARM64_REG_X15,
      ARM64_REG_X17, ARM64_REG_SP, 16 + GUM_RED_ZONE_SIZE,
      GUM_INDEX_POST_ADJUST);
  gum_arm64_writer_put_bytes (cw, insn->bytes, 4);
  gum_arm64_writer_put_cbnz_reg_label (cw, ARM64_REG_X0,
      perform_next_instruction);

  /*
   * We are on the child return to the original next instruction
   *
   * TODO: Is there any way we can avoid clobbering X17 here?
   */
  gum_arm64_writer_put_ldr_reg_address (cw, ARM64_REG_X17,
      GUM_ADDRESS (gc->instruction->begin + GUM_RESTORATION_PROLOG_SIZE));
  gum_arm64_writer_put_br_reg (cw, ARM64_REG_X17);

  gum_arm64_writer_put_label (cw, perform_regular_syscall);
  gum_arm64_writer_put_instruction (cw, msr_nzcv_x15);
  gum_arm64_writer_put_ldp_reg_reg_reg_offset (cw, ARM64_REG_X15,
      ARM64_REG_X17, ARM64_REG_SP, 16 + GUM_RED_ZONE_SIZE,
      GUM_INDEX_POST_ADJUST);
  gum_arm64_writer_put_bytes (cw, insn->bytes, 4);

  gum_arm64_writer_put_label (cw, perform_next_instruction);

  return GUM_REQUIRE_NOTHING;
}

#endif

static void
gum_exec_block_write_call_invoke_code (GumExecBlock * block,
                                       const GumBranchTarget * target,
                                       GumGeneratorContext * gc)
{
  GumExecCtx * ctx = block->ctx;
  GumArm64Writer * cw = gc->code_writer;
  gpointer call_code_start;
  GumPrologType opened_prolog;
  gboolean can_backpatch_statically;
  guint ic_push_real_address_ref = 0;
  guint ic_push_code_address_ref = 0;
  guint ic_load_real_address_ref = 0;
  gpointer * ic_entries = NULL;
  GumPrologType second_prolog;
  GumExecCtxReplaceCurrentBlockFunc entry_func;
  gconstpointer perform_stack_push = cw->code + 1;
  gconstpointer try_second = cw->code + 2;
  gconstpointer jump_to_cached = cw->code + 3;
  gconstpointer resolve_dynamically = cw->code + 4;
  gconstpointer keep_this_blr = cw->code + 5;
  gpointer ret_real_address, ret_code_address;

  call_code_start = cw->code;
  opened_prolog = gc->opened_prolog;

  can_backpatch_statically = (ctx->stalker->trust_threshold >= 0 &&
      target->reg == ARM64_REG_INVALID);

  if (ctx->stalker->trust_threshold >= 0 && target->reg != ARM64_REG_INVALID)
  {
    arm64_reg scratch_reg;
    guint ic1_real_ref, ic1_code_ref;
    guint ic2_real_ref, ic2_code_ref;

    if (opened_prolog == GUM_PROLOG_NONE)
    {
      gum_arm64_writer_put_stp_reg_reg_reg_offset (cw, ARM64_REG_X16,
          ARM64_REG_X17, ARM64_REG_SP, -(16 + GUM_RED_ZONE_SIZE),
          GUM_INDEX_PRE_ADJUST);
      gum_arm64_writer_put_push_reg_reg (cw, ARM64_REG_X0, ARM64_REG_X1);
      gum_arm64_writer_put_push_reg_reg (cw, ARM64_REG_X2, ARM64_REG_LR);
    }

    ic_push_real_address_ref =
        gum_arm64_writer_put_ldr_reg_ref (cw, ARM64_REG_X0);
    ic_push_code_address_ref =
        gum_arm64_writer_put_ldr_reg_ref (cw, ARM64_REG_X1);
    gum_arm64_writer_put_bl_imm (cw, GUM_ADDRESS (ctx->last_stack_push));

    if (opened_prolog == GUM_PROLOG_NONE)
    {
      gum_arm64_writer_put_pop_reg_reg (cw, ARM64_REG_X2, ARM64_REG_LR);
      gum_arm64_writer_put_pop_reg_reg (cw, ARM64_REG_X0, ARM64_REG_X1);
      gum_arm64_writer_put_ldp_reg_reg_reg_offset (cw, ARM64_REG_X16,
          ARM64_REG_X17, ARM64_REG_SP, 16 + GUM_RED_ZONE_SIZE,
          GUM_INDEX_POST_ADJUST);
    }
    else
    {
      gum_exec_block_close_prolog (block, gc);
    }

    gum_arm64_writer_put_stp_reg_reg_reg_offset (cw, ARM64_REG_X16,
        ARM64_REG_X17, ARM64_REG_SP, -(16 + GUM_RED_ZONE_SIZE),
        GUM_INDEX_PRE_ADJUST);

    scratch_reg = (target->reg != ARM64_REG_X16)
        ? ARM64_REG_X16
        : ARM64_REG_X17;

    ic1_real_ref = gum_arm64_writer_put_ldr_reg_ref (cw, scratch_reg);
    gum_arm64_writer_put_sub_reg_reg_reg (cw, scratch_reg, scratch_reg,
        target->reg);
    gum_arm64_writer_put_cbnz_reg_label (cw, scratch_reg, try_second);
    ic1_code_ref = gum_arm64_writer_put_ldr_reg_ref (cw, scratch_reg);
    gum_arm64_writer_put_b_label (cw, jump_to_cached);

    gum_arm64_writer_put_label (cw, try_second);
    ic2_real_ref = gum_arm64_writer_put_ldr_reg_ref (cw, scratch_reg);
    gum_arm64_writer_put_sub_reg_reg_reg (cw, scratch_reg, scratch_reg,
        target->reg);
    gum_arm64_writer_put_cbnz_reg_label (cw, scratch_reg, resolve_dynamically);
    ic2_code_ref = gum_arm64_writer_put_ldr_reg_ref (cw, scratch_reg);
    gum_arm64_writer_put_b_label (cw, jump_to_cached);

    ic_entries = gum_arm64_writer_cur (cw);
    gum_arm64_writer_put_ldr_reg_value (cw, ic1_real_ref, 0);
    gum_arm64_writer_put_ldr_reg_value (cw, ic1_code_ref, 0);
    gum_arm64_writer_put_ldr_reg_value (cw, ic2_real_ref, 0);
    gum_arm64_writer_put_ldr_reg_value (cw, ic2_code_ref, 0);

    gum_arm64_writer_put_label (cw, jump_to_cached);
    ic_load_real_address_ref =
        gum_arm64_writer_put_ldr_reg_ref (cw, ARM64_REG_LR);
    gum_arm64_writer_put_br_reg (cw, scratch_reg);

    gum_arm64_writer_put_label (cw, resolve_dynamically);
    gum_arm64_writer_put_ldp_reg_reg_reg_offset (cw, ARM64_REG_X16,
        ARM64_REG_X17, ARM64_REG_SP, 16 + GUM_RED_ZONE_SIZE,
        GUM_INDEX_POST_ADJUST);
  }

  gum_exec_block_open_prolog (block, GUM_PROLOG_MINIMAL, gc);
  second_prolog = gc->opened_prolog;

  gum_exec_ctx_write_push_branch_target_address (ctx, target, gc);
  gum_arm64_writer_put_pop_reg_reg (cw, ARM64_REG_X14, ARM64_REG_X15);

  if (target->reg != ARM64_REG_INVALID)
  {
    entry_func = GUM_ENTRYGATE (call_reg);

    gum_arm64_writer_put_call_address_with_arguments (cw,
        GUM_ADDRESS (gum_exec_block_check_address_for_exclusion), 2,
        GUM_ARG_ADDRESS, GUM_ADDRESS (block),
        GUM_ARG_REGISTER, ARM64_REG_X15);

    gum_arm64_writer_put_mov_reg_reg (cw, ARM64_REG_X15, ARM64_REG_X0);
    gum_arm64_writer_put_cbz_reg_label (cw, ARM64_REG_X15, keep_this_blr);
  }
  else
  {
    entry_func = GUM_ENTRYGATE (call_imm);
  }

  gum_arm64_writer_put_call_address_with_arguments (cw,
      GUM_ADDRESS (entry_func), 2,
      GUM_ARG_ADDRESS, GUM_ADDRESS (ctx),
      GUM_ARG_REGISTER, ARM64_REG_X15);
  gum_arm64_writer_put_mov_reg_reg (cw, ARM64_REG_X3, ARM64_REG_X0);
  gum_arm64_writer_put_b_label (cw, perform_stack_push);

  if (can_backpatch_statically)
  {
    guint i;

    /*
     * We need some padding so the backpatching doesn't overwrite the return
     * handling logic below
     */
    for (i = 0; i != 10; i++)
      gum_arm64_writer_put_brk_imm (cw, 15);
  }

  ret_real_address = gc->instruction->end;
  ret_code_address = cw->code;

  gum_arm64_writer_put_ldp_reg_reg_reg_offset (cw, ARM64_REG_X16, ARM64_REG_X17,
      ARM64_REG_SP, 16 + GUM_RED_ZONE_SIZE, GUM_INDEX_POST_ADJUST);

  gum_exec_ctx_write_prolog (ctx, GUM_PROLOG_MINIMAL, cw);

  gum_arm64_writer_put_call_address_with_arguments (cw,
      GUM_ADDRESS (GUM_ENTRYGATE (post_call_invoke)), 2,
      GUM_ARG_ADDRESS, GUM_ADDRESS (ctx),
      GUM_ARG_ADDRESS, GUM_ADDRESS (ret_real_address));

  if (ctx->stalker->trust_threshold >= 0)
  {
    gum_arm64_writer_put_ldr_reg_address (cw, ARM64_REG_X3,
        GUM_ADDRESS (&ctx->current_block));
    gum_arm64_writer_put_ldr_reg_reg_offset (cw, ARM64_REG_X3, ARM64_REG_X3, 0);
    gum_arm64_writer_put_call_address_with_arguments (cw,
        GUM_ADDRESS (gum_exec_block_backpatch_ret), 3,
        GUM_ARG_REGISTER, ARM64_REG_X3,
        GUM_ARG_ADDRESS, GUM_ADDRESS (ret_code_address),
        GUM_ARG_REGISTER, ARM64_REG_X0);
  }

  gum_exec_ctx_write_epilog (ctx, GUM_PROLOG_MINIMAL, cw);
  gum_exec_block_write_exec_generated_code (cw, ctx);

  gum_arm64_writer_put_label (cw, perform_stack_push);
  if (ic_entries == NULL)
  {
    gum_arm64_writer_put_ldr_reg_address (cw, ARM64_REG_X0,
        GUM_ADDRESS (ret_real_address));
    gum_arm64_writer_put_ldr_reg_address (cw, ARM64_REG_X1,
        GUM_ADDRESS (ret_code_address));
    gum_arm64_writer_put_bl_imm (cw, GUM_ADDRESS (ctx->last_stack_push));
  }

  if (ctx->stalker->trust_threshold >= 0)
  {
    gum_arm64_writer_put_ldr_reg_address (cw, ARM64_REG_X6,
        GUM_ADDRESS (&ctx->current_block));
    gum_arm64_writer_put_ldr_reg_reg_offset (cw, ARM64_REG_X6, ARM64_REG_X6, 0);
  }

  if (can_backpatch_statically)
  {
    gum_arm64_writer_put_call_address_with_arguments (cw,
        GUM_ADDRESS (gum_exec_block_backpatch_call), 6,
        GUM_ARG_REGISTER, ARM64_REG_X6,
        GUM_ARG_ADDRESS, GUM_ADDRESS (call_code_start),
        GUM_ARG_ADDRESS, GUM_ADDRESS (opened_prolog),
        GUM_ARG_REGISTER, ARM64_REG_X3,
        GUM_ARG_ADDRESS, GUM_ADDRESS (ret_real_address),
        GUM_ARG_ADDRESS, GUM_ADDRESS (ret_code_address));
  }

  if (ic_entries != NULL)
  {
    gum_arm64_writer_put_call_address_with_arguments (cw,
        GUM_ADDRESS (gum_exec_block_backpatch_inline_cache), 2,
        GUM_ARG_REGISTER, ARM64_REG_X6,
        GUM_ARG_ADDRESS, GUM_ADDRESS (ic_entries));
  }

  gum_exec_block_close_prolog (block, gc);

  gum_arm64_writer_put_ldr_reg_address (cw, ARM64_REG_LR,
      GUM_ADDRESS (ret_real_address));

  gum_exec_block_write_exec_generated_code (cw, ctx);

  if (ic_entries != NULL)
  {
    gum_arm64_writer_put_ldr_reg_value (cw, ic_push_real_address_ref,
        GUM_ADDRESS (ret_real_address));
    gum_arm64_writer_put_ldr_reg_value (cw, ic_push_code_address_ref,
        GUM_ADDRESS (ret_code_address));
    gum_arm64_writer_put_ldr_reg_value (cw, ic_load_real_address_ref,
        GUM_ADDRESS (ret_real_address));
  }

  if (target->reg != ARM64_REG_INVALID)
  {
    GumInstruction * insn = gc->instruction;
    GumBranchTarget next_insn_as_target = { 0, };
    next_insn_as_target.absolute_address = insn->end;
    next_insn_as_target.reg = ARM64_REG_INVALID;

    gum_arm64_writer_put_label (cw, keep_this_blr);

    gc->opened_prolog = second_prolog;

    gum_arm64_writer_put_call_address_with_arguments (cw,
        GUM_ADDRESS (gum_exec_ctx_begin_call), 2,
        GUM_ARG_ADDRESS, GUM_ADDRESS (ctx),
        GUM_ARG_ADDRESS, GUM_ADDRESS (insn->end));
    gum_exec_block_close_prolog (block, gc);

    gum_arm64_writer_put_blr_reg (cw, target->reg);

    gum_exec_block_open_prolog (block, GUM_PROLOG_MINIMAL, gc);
    gum_arm64_writer_put_call_address_with_arguments (cw,
        GUM_ADDRESS (gum_exec_ctx_end_call), 1,
        GUM_ARG_ADDRESS, GUM_ADDRESS (ctx));
    gum_exec_block_write_jmp_transfer_code (block, &next_insn_as_target,
        GUM_ENTRYGATE (excluded_call_reg), gc);
  }
}

static void
gum_exec_block_write_jmp_transfer_code (GumExecBlock * block,
                                        const GumBranchTarget * target,
                                        GumExecCtxReplaceCurrentBlockFunc func,
                                        GumGeneratorContext * gc)
{
  GumArm64Writer * cw;
  guint32 * code_start;
  GumPrologType opened_prolog;
  gpointer * ic_entries = NULL;

  cw = gc->code_writer;
  code_start = cw->code;
  opened_prolog = gc->opened_prolog;

  if (block->ctx->stalker->trust_threshold >= 0 &&
      target->reg != ARM64_REG_INVALID)
  {
    gconstpointer try_second = cw->code + 1;
    gconstpointer resolve_dynamically = cw->code + 2;
    arm64_reg scratch_reg;
    guint ic1_real_ref, ic1_code_ref;
    guint ic2_real_ref, ic2_code_ref;

    if (opened_prolog != GUM_PROLOG_NONE)
      gum_exec_block_close_prolog (block, gc);

    gum_arm64_writer_put_stp_reg_reg_reg_offset (cw, ARM64_REG_X16,
        ARM64_REG_X17, ARM64_REG_SP, -(16 + GUM_RED_ZONE_SIZE),
        GUM_INDEX_PRE_ADJUST);

    scratch_reg = (target->reg != ARM64_REG_X16)
        ? ARM64_REG_X16
        : ARM64_REG_X17;

    ic1_real_ref = gum_arm64_writer_put_ldr_reg_ref (cw, scratch_reg);
    gum_arm64_writer_put_sub_reg_reg_reg (cw, scratch_reg, scratch_reg,
        target->reg);
    gum_arm64_writer_put_cbnz_reg_label (cw, scratch_reg, try_second);
    ic1_code_ref = gum_arm64_writer_put_ldr_reg_ref (cw, scratch_reg);
    gum_arm64_writer_put_br_reg (cw, scratch_reg);

    gum_arm64_writer_put_label (cw, try_second);
    ic2_real_ref = gum_arm64_writer_put_ldr_reg_ref (cw, scratch_reg);
    gum_arm64_writer_put_sub_reg_reg_reg (cw, scratch_reg, scratch_reg,
        target->reg);
    gum_arm64_writer_put_cbnz_reg_label (cw, scratch_reg, resolve_dynamically);
    ic2_code_ref = gum_arm64_writer_put_ldr_reg_ref (cw, scratch_reg);
    gum_arm64_writer_put_br_reg (cw, scratch_reg);

    ic_entries = gum_arm64_writer_cur (cw);
    gum_arm64_writer_put_ldr_reg_value (cw, ic1_real_ref, 0);
    gum_arm64_writer_put_ldr_reg_value (cw, ic1_code_ref, 0);
    gum_arm64_writer_put_ldr_reg_value (cw, ic2_real_ref, 0);
    gum_arm64_writer_put_ldr_reg_value (cw, ic2_code_ref, 0);

    gum_arm64_writer_put_label (cw, resolve_dynamically);
    gum_arm64_writer_put_ldp_reg_reg_reg_offset (cw, ARM64_REG_X16,
        ARM64_REG_X17, ARM64_REG_SP, 16 + GUM_RED_ZONE_SIZE,
        GUM_INDEX_POST_ADJUST);
  }

  gum_exec_block_open_prolog (block, GUM_PROLOG_MINIMAL, gc);

  gum_exec_ctx_write_push_branch_target_address (block->ctx, target, gc);
  gum_arm64_writer_put_pop_reg_reg (cw, ARM64_REG_X14, ARM64_REG_X15);

  gum_arm64_writer_put_call_address_with_arguments (cw,
      GUM_ADDRESS (func), 2,
      GUM_ARG_ADDRESS, GUM_ADDRESS (block->ctx),
      GUM_ARG_REGISTER, ARM64_REG_X15);

  if (block->ctx->stalker->trust_threshold >= 0)
  {
    gum_arm64_writer_put_ldr_reg_address (cw, ARM64_REG_X4,
        GUM_ADDRESS (&block->ctx->current_block));
    gum_arm64_writer_put_ldr_reg_reg_offset (cw, ARM64_REG_X4, ARM64_REG_X4, 0);
  }

  if (block->ctx->stalker->trust_threshold >= 0 &&
      target->reg == ARM64_REG_INVALID)
  {
    gum_arm64_writer_put_call_address_with_arguments (cw,
        GUM_ADDRESS (gum_exec_block_backpatch_jmp), 4,
        GUM_ARG_REGISTER, ARM64_REG_X4,
        GUM_ARG_ADDRESS, GUM_ADDRESS (code_start),
        GUM_ARG_ADDRESS, GUM_ADDRESS (opened_prolog),
        GUM_ARG_REGISTER, ARM64_REG_X0);
  }

  if (ic_entries != NULL)
  {
    gum_arm64_writer_put_call_address_with_arguments (cw,
        GUM_ADDRESS (gum_exec_block_backpatch_inline_cache), 2,
        GUM_ARG_REGISTER, ARM64_REG_X4,
        GUM_ARG_ADDRESS, GUM_ADDRESS (ic_entries));
  }

  gum_exec_block_close_prolog (block, gc);
  gum_exec_block_write_exec_generated_code (cw, block->ctx);
}

static void
gum_exec_block_write_jmp_to_block_start (GumExecBlock * block,
                                         gpointer block_start)
{
  GumArm64Writer * cw = &block->ctx->code_writer;
  const GumAddress address = GUM_ADDRESS (block_start);
  const GumAddress body_address = address + GUM_RESTORATION_PROLOG_SIZE;

  if (gum_arm64_writer_can_branch_directly_between (cw->pc, body_address))
  {
    gum_arm64_writer_put_b_imm (cw, body_address);
  }
  else
  {
    gum_arm64_writer_put_stp_reg_reg_reg_offset (cw, ARM64_REG_X16,
        ARM64_REG_X17, ARM64_REG_SP, -(16 + GUM_RED_ZONE_SIZE),
        GUM_INDEX_PRE_ADJUST);
    gum_arm64_writer_put_ldr_reg_address (cw, ARM64_REG_X16, address);
    gum_arm64_writer_put_br_reg (cw, ARM64_REG_X16);
  }
}

static void
gum_exec_block_write_ret_transfer_code (GumExecBlock * block,
                                        GumGeneratorContext * gc,
                                        arm64_reg ret_reg)
{
  GumArm64Writer * cw = gc->code_writer;

  gum_exec_block_close_prolog (block, gc);

  gum_arm64_writer_put_stp_reg_reg_reg_offset (cw, ARM64_REG_X16,
      ARM64_REG_X17, ARM64_REG_SP, -(16 + GUM_RED_ZONE_SIZE),
      GUM_INDEX_PRE_ADJUST);
  if (ret_reg != ARM64_REG_X16)
    gum_arm64_writer_put_mov_reg_reg (cw, ARM64_REG_X16, ret_reg);
  gum_arm64_writer_put_b_imm (cw,
      GUM_ADDRESS (block->ctx->last_stack_pop_and_go));
}

static void
gum_exec_block_write_exec_generated_code (GumArm64Writer * cw,
                                          GumExecCtx * ctx)
{
  gconstpointer dont_pop_now = cw->code + 1;

  gum_arm64_writer_put_stp_reg_reg_reg_offset (cw, ARM64_REG_X16, ARM64_REG_X17,
      ARM64_REG_SP, -(16 + GUM_RED_ZONE_SIZE), GUM_INDEX_PRE_ADJUST);

  gum_arm64_writer_put_ldr_reg_address (cw, ARM64_REG_X16,
      GUM_ADDRESS (&ctx->current_block));
  gum_arm64_writer_put_ldr_reg_reg_offset (cw, ARM64_REG_X17, ARM64_REG_X16, 0);
  gum_arm64_writer_put_cbnz_reg_label (cw, ARM64_REG_X17, dont_pop_now);
  gum_arm64_writer_put_ldp_reg_reg_reg_offset (cw, ARM64_REG_X16, ARM64_REG_X17,
      ARM64_REG_SP, 16 + GUM_RED_ZONE_SIZE, GUM_INDEX_POST_ADJUST);

  gum_arm64_writer_put_label (cw, dont_pop_now);
  gum_arm64_writer_put_ldr_reg_address (cw, ARM64_REG_X16,
      GUM_ADDRESS (&ctx->resume_at));
  gum_arm64_writer_put_ldr_reg_reg_offset (cw, ARM64_REG_X17, ARM64_REG_X16, 0);
  gum_arm64_writer_put_br_reg (cw, ARM64_REG_X17);
}

static void
gum_exec_block_write_call_event_code (GumExecBlock * block,
                                      const GumBranchTarget * target,
                                      GumGeneratorContext * gc,
                                      GumCodeContext cc)
{
  GumArm64Writer * cw = gc->code_writer;

  gum_exec_block_open_prolog (block, GUM_PROLOG_MINIMAL, gc);

  gum_exec_ctx_write_push_branch_target_address (block->ctx, target, gc);
  gum_arm64_writer_put_pop_reg_reg (cw, ARM64_REG_X14, ARM64_REG_X15);

  gum_arm64_writer_put_call_address_with_arguments (cw,
      GUM_ADDRESS (gum_exec_ctx_emit_call_event), 3,
      GUM_ARG_ADDRESS, GUM_ADDRESS (block->ctx),
      GUM_ARG_ADDRESS, GUM_ADDRESS (gc->instruction->begin),
      GUM_ARG_REGISTER, ARM64_REG_X14);

  gum_exec_block_write_unfollow_check_code (block, gc, cc);
}

static void
gum_exec_block_write_ret_event_code (GumExecBlock * block,
                                     GumGeneratorContext * gc,
                                     GumCodeContext cc)
{
  gum_exec_block_open_prolog (block, GUM_PROLOG_MINIMAL, gc);

  gum_exec_ctx_load_real_register_into (block->ctx, ARM64_REG_X14, ARM64_REG_LR,
      gc);

  gum_arm64_writer_put_call_address_with_arguments (gc->code_writer,
      GUM_ADDRESS (gum_exec_ctx_emit_ret_event), 3,
      GUM_ARG_ADDRESS, GUM_ADDRESS (block->ctx),
      GUM_ARG_ADDRESS, GUM_ADDRESS (gc->instruction->begin),
      GUM_ARG_REGISTER, ARM64_REG_X14);

  gum_exec_block_write_unfollow_check_code (block, gc, cc);
}

static void
gum_exec_block_write_exec_event_code (GumExecBlock * block,
                                      GumGeneratorContext * gc,
                                      GumCodeContext cc)
{
  gum_exec_block_open_prolog (block, GUM_PROLOG_MINIMAL, gc);

  gum_arm64_writer_put_call_address_with_arguments (gc->code_writer,
      GUM_ADDRESS (gum_exec_ctx_emit_exec_event), 2,
      GUM_ARG_ADDRESS, GUM_ADDRESS (block->ctx),
      GUM_ARG_ADDRESS, GUM_ADDRESS (gc->instruction->begin));

  gum_exec_block_write_unfollow_check_code (block, gc, cc);
}

static void
gum_exec_block_write_block_event_code (GumExecBlock * block,
                                       GumGeneratorContext * gc,
                                       GumCodeContext cc)
{
  gum_exec_block_open_prolog (block, GUM_PROLOG_MINIMAL, gc);

  gum_arm64_writer_put_call_address_with_arguments (gc->code_writer,
      GUM_ADDRESS (gum_exec_ctx_emit_block_event), 3,
      GUM_ARG_ADDRESS, GUM_ADDRESS (block->ctx),
      GUM_ARG_ADDRESS, GUM_ADDRESS (gc->relocator->input_start),
      GUM_ARG_ADDRESS, GUM_ADDRESS (gc->relocator->input_cur));

  gum_exec_block_write_unfollow_check_code (block, gc, cc);
}

static void
gum_exec_block_write_unfollow_check_code (GumExecBlock * block,
                                          GumGeneratorContext * gc,
                                          GumCodeContext cc)
{
  GumExecCtx * ctx = block->ctx;
  GumArm64Writer * cw = gc->code_writer;
  gconstpointer beach = cw->code + 1;
  GumPrologType opened_prolog;

  if (cc != GUM_CODE_INTERRUPTIBLE)
    return;

  gum_arm64_writer_put_call_address_with_arguments (cw,
      GUM_ADDRESS (gum_exec_ctx_maybe_unfollow), 2,
      GUM_ARG_ADDRESS, GUM_ADDRESS (ctx),
      GUM_ARG_ADDRESS, GUM_ADDRESS (gc->instruction->begin));
  gum_arm64_writer_put_cbz_reg_label (cw, ARM64_REG_X0, beach);

  opened_prolog = gc->opened_prolog;
  gum_exec_block_close_prolog (block, gc);
  gc->opened_prolog = opened_prolog;

  gum_arm64_writer_put_ldr_reg_address (cw, ARM64_REG_X16,
      GUM_ADDRESS (&ctx->resume_at));
  gum_arm64_writer_put_ldr_reg_reg_offset (cw, ARM64_REG_X17, ARM64_REG_X16,
      0);
  gum_arm64_writer_put_br_reg (cw, ARM64_REG_X17);

  gum_arm64_writer_put_label (cw, beach);
}

static void
gum_exec_block_invoke_call_probes_for_target (GumExecBlock * block,
                                              gpointer location,
                                              gpointer target_address,
                                              GumCpuContext * cpu_context)
{
  GumStalker * stalker = block->ctx->stalker;
  GArray * probes;

  gum_spinlock_acquire (&stalker->probe_lock);

  probes = (GArray *)
      g_hash_table_lookup (stalker->probe_array_by_address, target_address);
  if (probes != NULL)
  {
    GumCallSite call_site;
    guint probe_index;

    call_site.block_address = block->real_begin;
    call_site.stack_data = GSIZE_TO_POINTER (cpu_context->sp);
    call_site.cpu_context = cpu_context;

    cpu_context->pc = GPOINTER_TO_SIZE (location);
    cpu_context->lr = cpu_context->pc + 4;

    for (probe_index = 0; probe_index != probes->len; probe_index++)
    {
      GumCallProbe * probe = &g_array_index (probes, GumCallProbe, probe_index);

      probe->callback (&call_site, probe->user_data);
    }
  }

  gum_spinlock_release (&stalker->probe_lock);
}

static void
gum_exec_block_write_call_probe_code (GumExecBlock * block,
                                      const GumBranchTarget * target,
                                      GumGeneratorContext * gc)
{
  GumArm64Writer * cw;
  gboolean skip_probing = FALSE;

  cw = gc->code_writer;

  if (target->reg == ARM64_REG_INVALID)
  {
    GumStalker * stalker = block->ctx->stalker;

    gum_spinlock_acquire (&stalker->probe_lock);
    skip_probing = g_hash_table_lookup (stalker->probe_array_by_address,
        target->absolute_address) == NULL;
    gum_spinlock_release (&stalker->probe_lock);
  }

  if (!skip_probing)
  {
    if (gc->opened_prolog != GUM_PROLOG_NONE)
      gum_exec_block_close_prolog (block, gc);
    gum_exec_block_open_prolog (block, GUM_PROLOG_FULL, gc);

    gum_exec_ctx_write_push_branch_target_address (block->ctx, target, gc);
    gum_arm64_writer_put_pop_reg_reg (cw, ARM64_REG_X14, ARM64_REG_X15);

    gum_arm64_writer_put_call_address_with_arguments (cw,
        GUM_ADDRESS (gum_exec_block_invoke_call_probes_for_target), 4,
        GUM_ARG_ADDRESS, GUM_ADDRESS (block),
        GUM_ARG_ADDRESS, GUM_ADDRESS (gc->instruction->begin),
        GUM_ARG_REGISTER, ARM64_REG_X14,
        GUM_ARG_REGISTER, ARM64_REG_X20);
  }
}

static void
gum_exec_block_open_prolog (GumExecBlock * block,
                            GumPrologType type,
                            GumGeneratorContext * gc)
{
  if (gc->opened_prolog >= type)
    return;

  /* We don't want to handle this case for performance reasons */
  g_assert (gc->opened_prolog == GUM_PROLOG_NONE);

  gc->opened_prolog = type;

  gum_exec_ctx_write_prolog (block->ctx, type, gc->code_writer);
}

static void
gum_exec_block_close_prolog (GumExecBlock * block,
                             GumGeneratorContext * gc)
{
  if (gc->opened_prolog == GUM_PROLOG_NONE)
    return;

  gum_exec_ctx_write_epilog (block->ctx, gc->opened_prolog, gc->code_writer);
  gc->opened_prolog = GUM_PROLOG_NONE;
}

void
gum_stalker_set_counters_enabled (gboolean enabled)
{
  counters_enabled = enabled;
}

void
gum_stalker_dump_counters (void)
{
  g_printerr ("\n\ntotal_transitions: %u\n", total_transitions);

  GUM_PRINT_ENTRYGATE_COUNTER (call_imm);
  GUM_PRINT_ENTRYGATE_COUNTER (call_reg);
  GUM_PRINT_ENTRYGATE_COUNTER (post_call_invoke);
  GUM_PRINT_ENTRYGATE_COUNTER (excluded_call_imm);
  GUM_PRINT_ENTRYGATE_COUNTER (excluded_call_reg);
  GUM_PRINT_ENTRYGATE_COUNTER (ret);

  GUM_PRINT_ENTRYGATE_COUNTER (jmp_imm);
  GUM_PRINT_ENTRYGATE_COUNTER (jmp_reg);

  GUM_PRINT_ENTRYGATE_COUNTER (jmp_cond_cbz);
  GUM_PRINT_ENTRYGATE_COUNTER (jmp_cond_cbnz);
  GUM_PRINT_ENTRYGATE_COUNTER (jmp_cond_tbz);
  GUM_PRINT_ENTRYGATE_COUNTER (jmp_cond_tbnz);
  GUM_PRINT_ENTRYGATE_COUNTER (jmp_cond_cc);

  GUM_PRINT_ENTRYGATE_COUNTER (jmp_continuation);
}

static gpointer
gum_find_thread_exit_implementation (void)
{
#ifdef HAVE_DARWIN
  guint32 * cursor;

  cursor = GSIZE_TO_POINTER (gum_module_find_export_by_name (
      "/usr/lib/system/libsystem_pthread.dylib", "pthread_exit"));

  do
  {
    guint32 insn = *cursor;
    gboolean is_bl_imm;

    is_bl_imm = (insn & ~GUM_INT26_MASK) == 0x94000000;
    if (is_bl_imm)
    {
      union
      {
        gint32 i;
        guint32 u;
      } distance;

      distance.u = insn & GUM_INT26_MASK;
      if ((distance.u & (1 << (26 - 1))) != 0)
        distance.u |= 0xfc000000;

      return cursor + distance.i;
    }

    cursor++;
  }
  while (TRUE);
#else
  return NULL;
#endif
}
