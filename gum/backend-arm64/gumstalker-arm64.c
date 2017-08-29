/*
 * Copyright (C) 2014-2017 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 * Copyright (C) 2017 Antonio Ken Iannillo <ak.iannillo@gmail.com>
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

#define GUM_CODE_SLAB_SIZE_IN_PAGES         1024
#define GUM_EXEC_BLOCK_MIN_SIZE             1024

#define STALKER_REG_CTX ARM64_REG_X12

#define STALKER_LOAD_REG_FROM_CTX(reg, field) \
  gum_arm64_writer_put_ldr_reg_reg_offset (cw, reg, STALKER_REG_CTX, \
      G_STRUCT_OFFSET (GumExecCtx, field));
#define STALKER_LOAD_REG_FROM_CTX_WITH_AO(reg, field, additional_offset) \
  gum_arm64_writer_put_ldr_reg_reg_offset (cw, reg, STALKER_REG_CTX, \
      G_STRUCT_OFFSET (GumExecCtx, field) + additional_offset);
#define STALKER_STORE_REG_INTO_CTX(reg, field) \
  gum_arm64_writer_put_str_reg_reg_offset (cw, reg, STALKER_REG_CTX, \
      G_STRUCT_OFFSET (GumExecCtx, field));
#define STALKER_STORE_REG_INTO_CTX_WITH_AO(reg, field, additional_offset) \
  gum_arm64_writer_put_str_reg_reg_offset (cw, reg, STALKER_REG_CTX, \
      G_STRUCT_OFFSET (GumExecCtx, field) + additional_offset);

#define GUM_INSTRUCTION_OFFSET_NONE (-1)

#define GUM_STALKER_LOCK(o) g_mutex_lock (&(o)->priv->mutex)
#define GUM_STALKER_UNLOCK(o) g_mutex_unlock (&(o)->priv->mutex)

#define GUM_STALKER_GET_PRIVATE(o) ((o)->priv)

typedef struct _GumInfectContext GumInfectContext;
typedef struct _GumDisinfectContext GumDisinfectContext;

typedef struct _GumCallProbe GumCallProbe;
typedef struct _GumSlab GumSlab;

typedef struct _GumExecCtx GumExecCtx;
typedef void (* GumExecHelperWriteFunc) (GumExecCtx * ctx, GumArm64Writer * cw);
typedef struct _GumExecBlock GumExecBlock;

typedef guint GumPrologType;
typedef guint GumCodeContext;
typedef struct _GumGeneratorContext GumGeneratorContext;
typedef struct _GumCalloutEntry GumCalloutEntry;
typedef struct _GumInstruction GumInstruction;
typedef struct _GumBranchTarget GumBranchTarget;

typedef guint GumVirtualizationRequirements;

struct _GumStalkerPrivate
{
  guint page_size;

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
  GumStalker * stalker;
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

struct _GumSlab
{
  guint8 * data;
  guint offset;
  guint size;
  GumSlab * next;
};

enum _GumExecCtxState
{
  GUM_EXEC_CTX_ACTIVE,
  GUM_EXEC_CTX_UNFOLLOW_PENDING,
  GUM_EXEC_CTX_DESTROY_PENDING
};

struct _GumExecCtx
{
  volatile guint state;
  volatile gboolean invalidate_pending;

  GumStalker * stalker;
  GumThreadId thread_id;

  GumArm64Writer code_writer;
  GumArm64Relocator relocator;

  GumStalkerTransformer * transformer;
  GQueue callout_entries;
  GumSpinlock callout_lock;
  GumEventSink * sink;
  GumEventType sink_mask;
  gpointer sink_process_impl; /* cached */
  GumEvent tmp_event;

  gboolean unfollow_called_while_still_following;
  GumExecBlock * current_block;

  gpointer resume_at;
  gpointer return_at;
  gpointer app_stack;

  gpointer thunks;
  gpointer infect_thunk;

  GumSlab * code_slab;
  GumSlab first_code_slab;
  gpointer last_prolog_minimal;
  gpointer last_epilog_minimal;
  gpointer last_prolog_full;
  gpointer last_epilog_full;
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
  gboolean has_call_to_excluded_range;
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

  gboolean is_indirect;
  arm64_reg base;
  arm64_reg index;
  int32_t disp;
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
    volatile gpointer ret_addr);

static void gum_stalker_infect (GumThreadId thread_id,
    GumCpuContext * cpu_context, gpointer user_data);
static void gum_stalker_disinfect (GumThreadId thread_id,
    GumCpuContext * cpu_context, gpointer user_data);

static void gum_stalker_free_probe_array (gpointer data);

static GumExecCtx * gum_stalker_create_exec_ctx (GumStalker * self,
    GumThreadId thread_id, GumStalkerTransformer * transformer,
    GumEventSink * sink);
static GumExecCtx * gum_stalker_get_exec_ctx (GumStalker * self);
static void gum_stalker_invalidate_caches (GumStalker * self);

static void gum_exec_ctx_dispose_callouts (GumExecCtx * ctx);
static void gum_exec_ctx_free (GumExecCtx * ctx);
static void gum_exec_ctx_unfollow (GumExecCtx * ctx, gpointer resume_at);
static gboolean gum_exec_ctx_has_executed (GumExecCtx * ctx);
static gpointer gum_exec_ctx_replace_current_block_with (GumExecCtx * ctx,
    gpointer start_address);
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
static void gum_exec_ctx_ensure_helper_reachable (GumExecCtx * ctx,
    gpointer * helper_ptr, GumExecHelperWriteFunc write);
static gboolean gum_exec_ctx_is_helper_reachable (GumExecCtx * ctx,
    gpointer * helper_ptr);

static void gum_exec_ctx_write_push_branch_target_address (GumExecCtx * ctx,
    const GumBranchTarget * target, GumGeneratorContext * gc);
static void gum_exec_ctx_load_real_register_into (GumExecCtx * ctx,
    arm64_reg target_register, arm64_reg source_register, gpointer ip,
    GumGeneratorContext * gc);
static void gum_exec_ctx_load_real_register_from_minimal_frame_into (
    GumExecCtx * ctx, arm64_reg target_register, arm64_reg source_register,
    gpointer ip, GumGeneratorContext * gc);
static void gum_exec_ctx_load_real_register_from_full_frame_into (
    GumExecCtx * ctx, arm64_reg target_register, arm64_reg source_register,
    gpointer ip, GumGeneratorContext * gc);

static GumExecBlock * gum_exec_block_new (GumExecCtx * ctx);
static GumExecBlock * gum_exec_block_obtain (GumExecCtx * ctx,
    gpointer real_address, gpointer * code_address);
static gboolean gum_exec_block_is_full (GumExecBlock * block);
static void gum_exec_block_commit (GumExecBlock * block);

static GumVirtualizationRequirements gum_exec_block_virtualize_branch_insn (
    GumExecBlock * block, GumGeneratorContext * gc);
static GumVirtualizationRequirements gum_exec_block_virtualize_ret_insn (
    GumExecBlock * block, GumGeneratorContext * gc);
static GumVirtualizationRequirements gum_exec_block_virtualize_sysenter_insn (
    GumExecBlock * block, GumGeneratorContext * gc);

static void gum_exec_block_write_call_invoke_code (GumExecBlock * block,
    const GumBranchTarget * target, GumGeneratorContext * gc);
static void gum_exec_block_write_jmp_transfer_code (GumExecBlock * block,
    const GumBranchTarget * target, GumGeneratorContext * gc);
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
static void gum_exec_block_write_event_init_code (GumExecBlock * block,
    GumEventType type, GumGeneratorContext * gc);
static void gum_exec_block_write_event_submit_code (GumExecBlock * block,
    GumGeneratorContext * gc, GumCodeContext cc);

static void gum_exec_block_write_call_probe_code (GumExecBlock * block,
    const GumBranchTarget * target, GumGeneratorContext * gc);

static void gum_exec_block_write_exec_generated_code (GumArm64Writer * cw,
    GumExecCtx * ctx);

static void gum_exec_block_open_prolog (GumExecBlock * block,
    GumPrologType type, GumGeneratorContext * gc);
static void gum_exec_block_close_prolog (GumExecBlock * block,
    GumGeneratorContext * gc);

G_DEFINE_TYPE (GumStalker, gum_stalker, G_TYPE_OBJECT);

static void
gum_stalker_class_init (GumStalkerClass * klass)
{
  GObjectClass * object_class = G_OBJECT_CLASS (klass);

  g_type_class_add_private (klass, sizeof (GumStalkerPrivate));

  object_class->finalize = gum_stalker_finalize;
}

static void
gum_stalker_init (GumStalker * self)
{
  GumStalkerPrivate * priv;

  self->priv = G_TYPE_INSTANCE_GET_PRIVATE (self, GUM_TYPE_STALKER,
      GumStalkerPrivate);
  priv = GUM_STALKER_GET_PRIVATE (self);

  priv->exclusions = g_array_new (FALSE, FALSE, sizeof (GumMemoryRange));
  priv->trust_threshold = 1;

  gum_spinlock_init (&priv->probe_lock);
  priv->probe_target_by_id =
      g_hash_table_new_full (NULL, NULL, NULL, NULL);
  priv->probe_array_by_address =
      g_hash_table_new_full (NULL, NULL, NULL, gum_stalker_free_probe_array);

  priv->page_size = gum_query_page_size ();
  g_mutex_init (&priv->mutex);
  priv->contexts = NULL;
  priv->exec_ctx = gum_tls_key_new ();
}

static void
gum_stalker_finalize (GObject * object)
{
  GumStalker * self = GUM_STALKER (object);
  GumStalkerPrivate * priv = self->priv;

  g_hash_table_unref (priv->probe_array_by_address);
  g_hash_table_unref (priv->probe_target_by_id);

  gum_spinlock_free (&priv->probe_lock);

  g_array_free (priv->exclusions, TRUE);

  g_assert (priv->contexts == NULL);
  gum_tls_key_free (priv->exec_ctx);
  g_mutex_clear (&priv->mutex);

  G_OBJECT_CLASS (gum_stalker_parent_class)->finalize (object);
}

GumStalker *
gum_stalker_new (void)
{
  return GUM_STALKER (g_object_new (GUM_TYPE_STALKER, NULL));
}

void
gum_stalker_exclude (GumStalker * self,
                     const GumMemoryRange * range)
{
  g_array_append_val (self->priv->exclusions, *range);
}

gint
gum_stalker_get_trust_threshold (GumStalker * self)
{
  return self->priv->trust_threshold;
}

void
gum_stalker_set_trust_threshold (GumStalker * self,
                                 gint trust_threshold)
{
  self->priv->trust_threshold = trust_threshold;
}

void
gum_stalker_stop (GumStalker * self)
{
  GumStalkerPrivate * priv = self->priv;
  gboolean rescan_needed;
  GSList * cur;

  gum_spinlock_acquire (&priv->probe_lock);
  g_hash_table_remove_all (priv->probe_target_by_id);
  g_hash_table_remove_all (priv->probe_array_by_address);
  priv->any_probes_attached = FALSE;
  gum_spinlock_release (&priv->probe_lock);

  GUM_STALKER_LOCK (self);

  do
  {
    rescan_needed = FALSE;

    for (cur = priv->contexts; cur != NULL; cur = cur->next)
    {
      GumExecCtx * ctx = (GumExecCtx *) cur->data;
      if (ctx->state == GUM_EXEC_CTX_ACTIVE)
      {
        GumThreadId thread_id = ctx->thread_id;

        GUM_STALKER_UNLOCK (self);
        gum_stalker_unfollow (self, thread_id);
        GUM_STALKER_LOCK (self);

        rescan_needed = TRUE;
        break;
      }
    }
  }
  while (rescan_needed);

  GUM_STALKER_UNLOCK (self);

  gum_stalker_garbage_collect (self);
}

gboolean
gum_stalker_garbage_collect (GumStalker * self)
{
  GSList * keep = NULL, * cur;
  gboolean pending_garbage;

  GUM_STALKER_LOCK (self);

  for (cur = self->priv->contexts; cur != NULL; cur = cur->next)
  {
    GumExecCtx * ctx = (GumExecCtx *) cur->data;
    if (ctx->state == GUM_EXEC_CTX_DESTROY_PENDING)
      gum_exec_ctx_free (ctx);
    else
      keep = g_slist_prepend (keep, ctx);
  }

  g_slist_free (self->priv->contexts);
  self->priv->contexts = keep;

  pending_garbage = keep != NULL;

  GUM_STALKER_UNLOCK (self);

  return pending_garbage;
}

gpointer
_gum_stalker_do_follow_me (GumStalker * self,
                           GumStalkerTransformer * transformer,
                           GumEventSink * sink,
                           volatile gpointer ret_addr)
{
  GumExecCtx * ctx;
  gpointer code_address;

  ctx = gum_stalker_create_exec_ctx (self, gum_process_get_current_thread_id (),
      transformer, sink);
  gum_tls_key_set_value (self->priv->exec_ctx, ctx);

  ctx->current_block = gum_exec_ctx_obtain_block_for (ctx, ret_addr,
      &code_address);

  gum_event_sink_start (sink);

  g_assert (ctx != NULL);
  g_assert (gum_stalker_get_exec_ctx (self) != NULL);

  return code_address;
}

void
gum_stalker_unfollow_me (GumStalker * self)
{
  GumExecCtx * ctx;

  ctx = gum_stalker_get_exec_ctx (self);
  g_assert (ctx != NULL);

  gum_exec_ctx_dispose_callouts (ctx);

  gum_event_sink_stop (ctx->sink);

  if (ctx->current_block != NULL &&
      ctx->current_block->has_call_to_excluded_range)
  {
    ctx->state = GUM_EXEC_CTX_UNFOLLOW_PENDING;
  }
  else
  {
    g_assert (ctx->unfollow_called_while_still_following);

    gum_tls_key_set_value (self->priv->exec_ctx, NULL);

    GUM_STALKER_LOCK (self);
    self->priv->contexts = g_slist_remove (self->priv->contexts, ctx);
    GUM_STALKER_UNLOCK (self);

    gum_exec_ctx_free (ctx);
  }
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

    for (cur = self->priv->contexts; cur != NULL; cur = cur->next)
    {
      GumExecCtx * ctx = (GumExecCtx *) cur->data;
      if (ctx->thread_id == thread_id && ctx->state == GUM_EXEC_CTX_ACTIVE)
      {
        gum_exec_ctx_dispose_callouts (ctx);

        gum_event_sink_stop (ctx->sink);

        if (gum_exec_ctx_has_executed (ctx))
        {
          ctx->state = GUM_EXEC_CTX_UNFOLLOW_PENDING;
        }
        else
        {
          GumDisinfectContext dc;
          dc.stalker = self;
          dc.exec_ctx = ctx;
          dc.success = FALSE;

          gum_process_modify_thread (thread_id, gum_stalker_disinfect, &dc);

          if (!dc.success)
            ctx->state = GUM_EXEC_CTX_UNFOLLOW_PENDING;
        }
        break;
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
  gpointer code_address;
  GumArm64Writer cw;

  infect_context = user_data;
  self = infect_context->stalker;
  ctx = gum_stalker_create_exec_ctx (self, thread_id,
      infect_context->transformer, infect_context->sink);

  ctx->current_block = gum_exec_ctx_obtain_block_for (ctx,
      GSIZE_TO_POINTER (cpu_context->pc), &code_address);
  cpu_context->pc = GPOINTER_TO_SIZE (ctx->infect_thunk);

  gum_arm64_writer_init (&cw, ctx->infect_thunk);

  gum_exec_ctx_write_prolog (ctx, GUM_PROLOG_MINIMAL, &cw);
  gum_arm64_writer_put_call_address_with_arguments (&cw,
      GUM_ADDRESS (gum_tls_key_set_value), 2,
      GUM_ARG_ADDRESS, self->priv->exec_ctx,
      GUM_ARG_ADDRESS, ctx);
  gum_exec_ctx_write_epilog (ctx, GUM_PROLOG_MINIMAL, &cw);

  gum_arm64_writer_put_branch_address (&cw, GUM_ADDRESS (code_address + 4));

  gum_arm64_writer_clear (&cw);

  gum_event_sink_start (infect_context->sink);
}

static void
gum_stalker_disinfect (GumThreadId thread_id,
                       GumCpuContext * cpu_context,
                       gpointer user_data)
{
  GumDisinfectContext * disinfect_context;
  GumStalker * self;
  GumExecCtx * ctx;
  gboolean infection_not_active_yet;

  (void) thread_id;

  disinfect_context = (GumDisinfectContext *) user_data;
  self = disinfect_context->stalker;
  ctx = disinfect_context->exec_ctx;

  infection_not_active_yet =
      cpu_context->pc == GPOINTER_TO_SIZE (ctx->infect_thunk);
  if (infection_not_active_yet)
  {
    cpu_context->pc = GPOINTER_TO_SIZE (ctx->current_block->real_begin);

    self->priv->contexts = g_slist_remove (self->priv->contexts, ctx);
    gum_exec_ctx_free (ctx);

    disinfect_context->success = TRUE;
  }
}

GumProbeId
gum_stalker_add_call_probe (GumStalker * self,
                            gpointer target_address,
                            GumCallProbeCallback callback,
                            gpointer data,
                            GDestroyNotify notify)
{
  GumStalkerPrivate * priv = self->priv;
  GumCallProbe probe;
  GArray * probes;

  probe.id = g_atomic_int_add (&priv->last_probe_id, 1) + 1;
  probe.callback = callback;
  probe.user_data = data;
  probe.user_notify = notify;

  gum_spinlock_acquire (&priv->probe_lock);

  g_hash_table_insert (priv->probe_target_by_id, GSIZE_TO_POINTER (probe.id),
      target_address);

  probes = (GArray *)
      g_hash_table_lookup (priv->probe_array_by_address, target_address);
  if (probes == NULL)
  {
    probes = g_array_sized_new (FALSE, FALSE, sizeof (GumCallProbe), 4);
    g_hash_table_insert (priv->probe_array_by_address, target_address, probes);
  }

  g_array_append_val (probes, probe);

  priv->any_probes_attached = TRUE;

  gum_spinlock_release (&priv->probe_lock);

  gum_stalker_invalidate_caches (self);

  return probe.id;
}

void
gum_stalker_remove_call_probe (GumStalker * self,
                               GumProbeId id)
{
  GumStalkerPrivate * priv = self->priv;
  gpointer target_address;

  gum_spinlock_acquire (&priv->probe_lock);

  target_address =
      g_hash_table_lookup (priv->probe_target_by_id, GSIZE_TO_POINTER (id));
  if (target_address != NULL)
  {
    GArray * probes;
    gint match_index = -1;
    guint i;
    GumCallProbe * probe;

    g_hash_table_remove (priv->probe_target_by_id, GSIZE_TO_POINTER (id));

    probes = (GArray *)
        g_hash_table_lookup (priv->probe_array_by_address, target_address);
    g_assert (probes != NULL);

    for (i = 0; i != probes->len; i++)
    {
      if (g_array_index (probes, GumCallProbe, i).id == id)
      {
        match_index = i;
        break;
      }
    }
    g_assert_cmpint (match_index, !=, -1);

    probe = &g_array_index (probes, GumCallProbe, match_index);
    if (probe->user_notify != NULL)
      probe->user_notify (probe->user_data);
    g_array_remove_index (probes, match_index);

    if (probes->len == 0)
      g_hash_table_remove (priv->probe_array_by_address, target_address);

    priv->any_probes_attached =
        g_hash_table_size (priv->probe_array_by_address) != 0;
  }

  gum_spinlock_release (&priv->probe_lock);

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
  GumStalkerPrivate * priv = self->priv;
  guint base_size;
  GumExecCtx * ctx;

  base_size = sizeof (GumExecCtx) / priv->page_size;
  if (sizeof (GumExecCtx) % priv->page_size != 0)
    base_size++;

  ctx = gum_alloc_n_pages (base_size + GUM_CODE_SLAB_SIZE_IN_PAGES + 1,
      GUM_PAGE_RWX);
  ctx->state = GUM_EXEC_CTX_ACTIVE;
  ctx->invalidate_pending = FALSE;

  ctx->code_slab = &ctx->first_code_slab;
  ctx->first_code_slab.data = ((guint8 *) ctx) + (base_size * priv->page_size);
  ctx->first_code_slab.offset = 0;
  ctx->first_code_slab.size = GUM_CODE_SLAB_SIZE_IN_PAGES * priv->page_size;
  ctx->first_code_slab.next = NULL;

  ctx->mappings = gum_metal_hash_table_new (NULL, NULL);

  ctx->resume_at = NULL;
  ctx->return_at = NULL;
  ctx->app_stack = NULL;

  ctx->stalker = g_object_ref (self);
  ctx->thread_id = thread_id;

  gum_arm64_writer_init (&ctx->code_writer, NULL);
  gum_arm64_relocator_init (&ctx->relocator, NULL, &ctx->code_writer);

  if (transformer != NULL)
    ctx->transformer = g_object_ref (transformer);
  else
    ctx->transformer = gum_stalker_transformer_make_default ();
  g_queue_init (&ctx->callout_entries);
  gum_spinlock_init (&ctx->callout_lock);
  ctx->sink = (GumEventSink *) g_object_ref (sink);
  ctx->sink_mask = gum_event_sink_query_mask (sink);
  ctx->sink_process_impl = GUM_FUNCPTR_TO_POINTER (
      GUM_EVENT_SINK_GET_INTERFACE (sink)->process);

  gum_exec_ctx_create_thunks (ctx);

  GUM_STALKER_LOCK (self);
  self->priv->contexts = g_slist_prepend (self->priv->contexts, ctx);
  GUM_STALKER_UNLOCK (self);

  gum_exec_ctx_ensure_inline_helpers_reachable (ctx);

  return ctx;
}

static GumExecCtx *
gum_stalker_get_exec_ctx (GumStalker * self)
{
  return (GumExecCtx *) gum_tls_key_get_value (self->priv->exec_ctx);
}

static void
gum_stalker_invalidate_caches (GumStalker * self)
{
  GSList * cur;

  GUM_STALKER_LOCK (self);

  for (cur = self->priv->contexts; cur != NULL; cur = cur->next)
  {
    GumExecCtx * ctx = (GumExecCtx *) cur->data;

    ctx->invalidate_pending = TRUE;
  }

  GUM_STALKER_UNLOCK (self);
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
  GumSlab * slab;

  gum_metal_hash_table_unref (ctx->mappings);

  slab = ctx->code_slab;
  while (slab != &ctx->first_code_slab)
  {
    GumSlab * next = slab->next;
    gum_free_pages (slab);
    slab = next;
  }

  gum_exec_ctx_destroy_thunks (ctx);

  g_object_unref (ctx->sink);
  gum_exec_ctx_finalize_callouts (ctx);
  gum_spinlock_free (&ctx->callout_lock);
  g_object_unref (ctx->transformer);

  gum_arm64_relocator_clear (&ctx->relocator);
  gum_arm64_writer_clear (&ctx->code_writer);

  g_object_unref (ctx->stalker);

  gum_free_pages (ctx);
}

static void
gum_exec_ctx_unfollow (GumExecCtx * ctx,
                       gpointer resume_at)
{
  ctx->resume_at = resume_at;

  gum_tls_key_set_value (ctx->stalker->priv->exec_ctx, NULL);
  ctx->current_block = NULL;
  ctx->state = GUM_EXEC_CTX_DESTROY_PENDING;
}

static gboolean
gum_exec_ctx_has_executed (GumExecCtx * ctx)
{
  return ctx->resume_at != NULL;
}

static gpointer
gum_exec_ctx_replace_current_block_with (GumExecCtx * ctx,
                                         gpointer start_address)
{
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
  else if (ctx->state == GUM_EXEC_CTX_UNFOLLOW_PENDING)
  {
    gum_exec_ctx_unfollow (ctx, start_address);
  }
  else
  {
    ctx->current_block = gum_exec_ctx_obtain_block_for (ctx, start_address,
        &ctx->resume_at);
  }

  return ctx->resume_at;
}

static void
gum_exec_ctx_create_thunks (GumExecCtx * ctx)
{
  GumArm64Writer cw;

  g_assert (ctx->thunks == NULL);

  ctx->thunks = gum_alloc_n_pages (1, GUM_PAGE_RWX);
  gum_arm64_writer_init (&cw, ctx->thunks);

  ctx->infect_thunk = gum_arm64_writer_cur (&cw);

  gum_arm64_writer_clear (&cw);
}

static void
gum_exec_ctx_destroy_thunks (GumExecCtx * ctx)
{
  gum_free_pages (ctx->thunks);
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

  if (ctx->stalker->priv->trust_threshold >= 0)
  {
    block = gum_exec_block_obtain (ctx, real_address, code_address_ptr);
    if (block != NULL)
    {
      if (block->recycle_count >= ctx->stalker->priv->trust_threshold ||
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
  *code_address_ptr = block->code_begin;

  if (ctx->stalker->priv->trust_threshold >= 0)
    gum_metal_hash_table_insert (ctx->mappings, real_address, block);

  cw = &ctx->code_writer;
  rl = &ctx->relocator;

  gum_arm64_writer_reset (cw, block->code_begin);
  gum_arm64_relocator_reset (rl, real_address, cw);

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

  gum_stalker_transformer_transform_block (ctx->transformer, &iterator,
      (GumStalkerWriter *) cw);

  if (gc.continuation_real_address != NULL)
  {
    GumBranchTarget continue_target = { 0, };

    continue_target.is_indirect = FALSE;
    continue_target.absolute_address = gc.continuation_real_address;
    gum_exec_block_write_jmp_transfer_code (block, &continue_target, &gc);
  }

  gum_arm64_writer_put_brk_imm (cw, 14);

  all_labels_resolved = gum_arm64_writer_flush (cw);
  g_assert (all_labels_resolved);

  block->code_end = (guint8 *) gum_arm64_writer_cur (cw);

  block->real_begin = (guint8 *) rl->input_start;
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
    else if (instruction->ci->id == ARM64_INS_BL)
    {
      gboolean call_is_to_excluded_range;

      call_is_to_excluded_range =
          (self->requirements & GUM_REQUIRE_RELOCATION) != 0;
      if (!call_is_to_excluded_range)
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
    gum_arm64_writer_put_push_reg_reg (cw, ARM64_REG_X18, STALKER_REG_CTX);
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

  /* save the stack pointer in context */
  gum_arm64_writer_put_ldr_reg_address (cw, STALKER_REG_CTX, GUM_ADDRESS (ctx));
  gum_arm64_writer_put_add_reg_reg_imm (cw, ARM64_REG_X14, ARM64_REG_SP,
      immediate_for_sp);
  STALKER_STORE_REG_INTO_CTX (ARM64_REG_X14, app_stack);

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
    gum_arm64_writer_put_pop_reg_reg (cw, ARM64_REG_X18, STALKER_REG_CTX);
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

  gum_arm64_writer_reset (cw, slab->data + slab->offset);
  *helper_ptr = gum_arm64_writer_cur (cw);

  write (ctx, cw);

  gum_arm64_writer_flush (cw);
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

  if (!target->is_indirect)
  {
    if (target->base == ARM64_REG_INVALID)
    {
      gum_arm64_writer_put_ldr_reg_address (cw, ARM64_REG_X15,
          GUM_ADDRESS (target->absolute_address));
      gum_arm64_writer_put_push_reg_reg (cw, ARM64_REG_X15, ARM64_REG_X15);
    }
    else
    {
      gum_exec_ctx_load_real_register_into (ctx, ARM64_REG_X15, target->base,
          target->origin_ip, gc);
      gum_arm64_writer_put_push_reg_reg (cw, ARM64_REG_X15, ARM64_REG_X15);
    }
  }
  else
  {
    g_assert ("" == "not implemented");
  }
}

static void
gum_exec_ctx_load_real_register_into (GumExecCtx * ctx,
                                      arm64_reg target_register,
                                      arm64_reg source_register,
                                      gpointer ip,
                                      GumGeneratorContext * gc)
{
  if (gc->opened_prolog == GUM_PROLOG_MINIMAL)
  {
    return gum_exec_ctx_load_real_register_from_minimal_frame_into (ctx,
        target_register, source_register, ip, gc);
  }
  else if (gc->opened_prolog == GUM_PROLOG_FULL)
  {
    return gum_exec_ctx_load_real_register_from_full_frame_into (ctx,
        target_register, source_register, ip, gc);
  }

  g_assert_not_reached ();
}

static void
gum_exec_ctx_load_real_register_from_minimal_frame_into (
    GumExecCtx * ctx,
    arm64_reg target_register,
    arm64_reg source_register,
    gpointer ip,
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
                                                      gpointer ip,
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
  GumSlab * slab = ctx->code_slab;

  if (slab->size - slab->offset >= GUM_EXEC_BLOCK_MIN_SIZE)
  {
    GumExecBlock * block = (GumExecBlock *) (slab->data + slab->offset);

    block->ctx = ctx;
    block->slab = slab;

    block->code_begin = GSIZE_TO_POINTER (GPOINTER_TO_SIZE (slab->data +
        slab->offset + sizeof (GumExecBlock)));
    block->code_end = block->code_begin;

    block->recycle_count = 0;
    block->has_call_to_excluded_range = FALSE;

    slab->offset += block->code_begin - (slab->data + slab->offset);

    return block;
  }

  if (ctx->stalker->priv->trust_threshold < 0)
  {
    ctx->code_slab->offset = 0;

    return gum_exec_block_new (ctx);
  }

  slab = gum_alloc_n_pages (GUM_CODE_SLAB_SIZE_IN_PAGES, GUM_PAGE_RWX);
  slab->data = (guint8 *) (slab + 1);
  slab->offset = 0;
  slab->size = (GUM_CODE_SLAB_SIZE_IN_PAGES * ctx->stalker->priv->page_size)
      - sizeof (GumSlab);
  slab->next = ctx->code_slab;
  ctx->code_slab = slab;

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

static void
gum_exec_block_commit (GumExecBlock * block)
{
  guint real_size;
  guint8 * aligned_end;

  real_size = block->real_end - block->real_begin;
  block->real_snapshot = block->code_end;
  memcpy (block->real_snapshot, block->real_begin, real_size);
  block->slab->offset += real_size;

  aligned_end = GSIZE_TO_POINTER (GPOINTER_TO_SIZE (block->real_snapshot +
      real_size));
  block->slab->offset += aligned_end - block->code_begin;

  gum_clear_cache (block->code_begin, block->code_end - block->code_begin);
}

static void
gum_exec_block_backpatch_jmp (GumExecBlock * block,
                              gpointer code_start,
                              GumPrologType opened_prolog,
                              gpointer target_address)
{
  GumExecCtx * ctx = block->ctx;
  GumArm64Writer * cw = &ctx->code_writer;

  if (ctx->state == GUM_EXEC_CTX_ACTIVE &&
      block->recycle_count >= ctx->stalker->priv->trust_threshold &&
      gum_arm64_writer_can_branch_directly_between (cw->pc,
          GUM_ADDRESS (target_address)))
  {
    gum_arm64_writer_reset (cw, code_start);

    if (opened_prolog != GUM_PROLOG_NONE)
    {
      gum_exec_ctx_write_epilog (block->ctx, opened_prolog, cw);
    }

    gum_arm64_writer_put_b_imm (cw, GUM_ADDRESS (target_address) + 4);
    gum_arm64_writer_flush (cw);
    gum_clear_cache (code_start, gum_arm64_writer_offset (cw));
  }
}

static GumVirtualizationRequirements
gum_exec_block_virtualize_branch_insn (GumExecBlock * block,
                                       GumGeneratorContext * gc)
{
  GumInstruction * insn;
  GumArm64Writer * cw;
  gboolean is_conditional;
  cs_arm64 * arm64;

  cs_arm64_op * op;
  cs_arm64_op * op2;
  cs_arm64_op * op3;

  arm64_cc cc;
  arm64_cc not_cc;
  GumBranchTarget target = { 0, };

  insn = gc->instruction;
  cw = gc->code_writer;
  arm64 = &insn->ci->detail->arm64;

  g_assert (arm64->op_count != 0);
  op = &arm64->operands[0];

  cc = arm64->cc;

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
    target.is_indirect = FALSE;
    target.base = ARM64_REG_INVALID;
    target.index = ARM64_REG_INVALID;
    target.disp = 0;
  }
  else if (insn->ci->id == ARM64_INS_BLR || insn->ci->id == ARM64_INS_BR)
  {
    g_assert (op->type == ARM64_OP_REG);

    target.is_indirect = FALSE;
    target.base = op->reg;
    target.index = ARM64_REG_INVALID;
    target.disp = 0;
  }
  else if (insn->ci->id == ARM64_INS_CBZ || insn->ci->id == ARM64_INS_CBNZ)
  {
    op2 = &arm64->operands[1];

    g_assert (op->type == ARM64_OP_REG);
    g_assert (op2->type == ARM64_OP_IMM);

    target.is_indirect = FALSE;
    target.absolute_address = GSIZE_TO_POINTER (op2->imm);
    target.base = ARM64_REG_INVALID;
    target.index = ARM64_REG_INVALID;
    target.disp = 0;
  }
  else if (insn->ci->id == ARM64_INS_TBZ || insn->ci->id == ARM64_INS_TBNZ)
  {
    op2 = &arm64->operands[1];
    op3 = &arm64->operands[2];

    g_assert (op->type == ARM64_OP_REG);
    g_assert (op2->type == ARM64_OP_IMM);
    g_assert (op3->type == ARM64_OP_IMM);

    target.is_indirect = FALSE;
    target.absolute_address = GSIZE_TO_POINTER (op3->imm);
    target.base = ARM64_REG_INVALID;
    target.index = ARM64_REG_INVALID;
    target.disp = 0;
  }
  else
  {
    g_assert_not_reached ();
  }

  if (insn->ci->id == ARM64_INS_BL || insn->ci->id == ARM64_INS_BLR)
  {
    gboolean target_is_excluded = FALSE;

    if ((block->ctx->sink_mask & GUM_CALL) != 0)
    {
      gum_exec_block_write_call_event_code (block, &target, gc,
          GUM_CODE_INTERRUPTIBLE);
    }

    if (block->ctx->stalker->priv->any_probes_attached)
    {
      gum_exec_block_write_call_probe_code (block, &target, gc);
    }

    if (!target.is_indirect && target.base == ARM64_REG_INVALID)
    {
      GArray * exclusions = block->ctx->stalker->priv->exclusions;
      guint i;

      for (i = 0; i != exclusions->len; i++)
      {
        GumMemoryRange * r = &g_array_index (exclusions, GumMemoryRange, i);
        if (GUM_MEMORY_RANGE_INCLUDES (r,
            GUM_ADDRESS (target.absolute_address)))
        {
          target_is_excluded = TRUE;
          break;
        }
      }
    }

    if (target_is_excluded)
    {
      block->has_call_to_excluded_range = TRUE;
      return GUM_REQUIRE_RELOCATION;
    }

    gum_arm64_relocator_skip_one (gc->relocator);

    gum_exec_block_write_call_invoke_code (block, &target, gc);
  }
  else if (insn->ci->id == ARM64_INS_CBZ || insn->ci->id == ARM64_INS_CBNZ
      || insn->ci->id == ARM64_INS_TBZ || insn->ci->id == ARM64_INS_TBNZ
      || insn->ci->id == ARM64_INS_B || insn->ci->id == ARM64_INS_BR)
  {
    gpointer is_false;

    gum_arm64_relocator_skip_one (gc->relocator);

    is_false =
        GUINT_TO_POINTER ((GPOINTER_TO_UINT (insn->begin) << 16) | 0xbeef);

    if (is_conditional)
    {
      g_assert (!target.is_indirect);

      gum_exec_block_close_prolog (block, gc);

      /* jump to is_false if is_false */
      if (insn->ci->id == ARM64_INS_CBZ)
      {
        gum_arm64_writer_put_cbnz_reg_label (cw, op->reg, is_false);
      }
      else if (insn->ci->id == ARM64_INS_CBNZ)
      {
        gum_arm64_writer_put_cbz_reg_label (cw, op->reg, is_false);
      }
      else if (insn->ci->id == ARM64_INS_TBZ)
      {
        gum_arm64_writer_put_tbnz_reg_imm_label (cw, op->reg, op2->imm,
            is_false);
      }
      else if (insn->ci->id == ARM64_INS_TBNZ)
      {
        gum_arm64_writer_put_tbz_reg_imm_label (cw, op->reg, op2->imm,
            is_false);
      }
      else if (insn->ci->id == ARM64_INS_B)
      {
        g_assert (cc != ARM64_CC_INVALID);
        g_assert (cc > ARM64_CC_INVALID);
        g_assert (cc <= ARM64_CC_NV);
        not_cc = cc + 2 * (cc % 2) - 1;
        gum_arm64_writer_put_b_cond_label (cw, not_cc, is_false);
      }
      else
      {
        g_assert_not_reached ();
      }
    }

    gum_exec_block_write_jmp_transfer_code (block, &target, gc);

    if (is_conditional)
    {
      GumBranchTarget cond_target = { 0, };

      cond_target.is_indirect = FALSE;
      cond_target.absolute_address = insn->end;

      gum_arm64_writer_put_label (cw, is_false);

      if (gc->exclusive_load_offset == GUM_INSTRUCTION_OFFSET_NONE)
      {
        gum_exec_block_write_jmp_transfer_code (block, &cond_target, gc);
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
  else if (arm64->op_count == 1)
  {
    op = &arm64->operands[0];
    g_assert (op->type == ARM64_OP_REG);
    ret_reg = op->reg;
  }
  else
  {
    g_assert_not_reached ();
  }
  gum_arm64_relocator_skip_one (gc->relocator);
  gum_exec_block_write_ret_transfer_code (block, gc, ret_reg);

  return GUM_REQUIRE_NOTHING;
}

static GumVirtualizationRequirements
gum_exec_block_virtualize_sysenter_insn (GumExecBlock * block,
                                         GumGeneratorContext * gc)
{
  (void) block;
  (void) gc;

  return GUM_REQUIRE_RELOCATION;
}

static void
gum_exec_block_write_call_invoke_code (GumExecBlock * block,
                                       const GumBranchTarget * target,
                                       GumGeneratorContext * gc)
{
  GumArm64Writer * cw;
  gpointer call_code_start;

  cw = gc->code_writer;
  call_code_start = cw->code;

  gum_exec_block_open_prolog (block, GUM_PROLOG_MINIMAL, gc);

  /*
   * generate code for the target
   * get the target
   */
  gum_exec_ctx_write_push_branch_target_address (block->ctx, target, gc);
  gum_arm64_writer_put_pop_reg_reg (cw, ARM64_REG_X14, ARM64_REG_X15);

  /* create new block for the target */
  gum_arm64_writer_put_call_address_with_arguments (cw,
      GUM_ADDRESS (gum_exec_ctx_replace_current_block_with), 2,
      GUM_ARG_ADDRESS, GUM_ADDRESS (block->ctx),
      GUM_ARG_REGISTER, ARM64_REG_X15);

  gum_exec_block_close_prolog (block, gc);

  /* we need to save the return address outside the prolog-epilog */
  gum_arm64_writer_put_ldr_reg_address (cw, ARM64_REG_X30,
      GUM_ADDRESS (gc->instruction->end));

  /* execute the generated code */
  gum_exec_block_write_exec_generated_code (cw, block->ctx);
}

static void
gum_exec_block_write_jmp_transfer_code (GumExecBlock * block,
                                        const GumBranchTarget * target,
                                        GumGeneratorContext * gc)
{
  GumArm64Writer * cw;
  guint32 * code_start;
  GumPrologType opened_prolog;

  cw = gc->code_writer;
  code_start = cw->code;
  opened_prolog = gc->opened_prolog;

  gum_exec_block_open_prolog (block, GUM_PROLOG_MINIMAL, gc);

  gum_exec_ctx_write_push_branch_target_address (block->ctx, target, gc);
  gum_arm64_writer_put_pop_reg_reg (cw, ARM64_REG_X14, ARM64_REG_X15);
  gum_arm64_writer_put_call_address_with_arguments (cw,
      GUM_ADDRESS (gum_exec_ctx_replace_current_block_with), 2,
      GUM_ARG_ADDRESS, GUM_ADDRESS (block->ctx),
      GUM_ARG_REGISTER, ARM64_REG_X15);

  if (block->ctx->stalker->priv->trust_threshold >= 0 &&
      !target->is_indirect &&
      target->base == ARM64_REG_INVALID)
  {
    gum_arm64_writer_put_call_address_with_arguments (cw,
        GUM_ADDRESS (gum_exec_block_backpatch_jmp), 4,
        GUM_ARG_ADDRESS, GUM_ADDRESS (block),
        GUM_ARG_ADDRESS, GUM_ADDRESS (code_start),
        GUM_ARG_ADDRESS, GUM_ADDRESS (opened_prolog),
        GUM_ARG_REGISTER, ARM64_REG_X0);
  }

  gum_exec_block_close_prolog (block, gc);
  gum_exec_block_write_exec_generated_code (cw, block->ctx);
}

static void
gum_exec_block_write_ret_transfer_code (GumExecBlock * block,
                                        GumGeneratorContext * gc,
                                        arm64_reg ret_reg)
{
  GumArm64Writer * cw;
  gconstpointer resolve_dynamically_label;

  cw = gc->code_writer;
  resolve_dynamically_label = cw->code;

  gum_exec_block_close_prolog (block, gc);
  gum_exec_block_open_prolog (block, GUM_PROLOG_MINIMAL, gc);

  gum_exec_ctx_load_real_register_into (block->ctx, ARM64_REG_X16, ret_reg, 0,
      gc);

  gum_arm64_writer_put_call_address_with_arguments (cw,
      GUM_ADDRESS (gum_exec_ctx_replace_current_block_with), 2,
      GUM_ARG_ADDRESS, GUM_ADDRESS (block->ctx),
      GUM_ARG_REGISTER, ARM64_REG_X16);

  gum_exec_block_close_prolog (block, gc);

  gum_exec_block_write_exec_generated_code (cw, block->ctx);
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
  GumArm64Writer * cw;

  cw = gc->code_writer;

  gum_exec_block_open_prolog (block, GUM_PROLOG_MINIMAL, gc);

  gum_exec_block_write_event_init_code (block, GUM_CALL, gc);

  /* save the location of the call event */
  gum_arm64_writer_put_ldr_reg_address (cw, ARM64_REG_X14,
      GUM_ADDRESS (gc->instruction->begin));
  STALKER_STORE_REG_INTO_CTX_WITH_AO (ARM64_REG_X14, tmp_event,
      G_STRUCT_OFFSET (GumCallEvent, location));

  /* save the target of the call event */
  gum_exec_ctx_write_push_branch_target_address (block->ctx, target, gc);
  /* previous function changes X15 */
  gum_arm64_writer_put_pop_reg_reg (cw, ARM64_REG_X14, ARM64_REG_X15);

  STALKER_STORE_REG_INTO_CTX_WITH_AO (ARM64_REG_X14, tmp_event,
      G_STRUCT_OFFSET (GumCallEvent, target));

  /* save the call depth TODO better understand... */
  gum_arm64_writer_put_ldr_reg_u64 (cw, ARM64_REG_X14, 4);
  STALKER_STORE_REG_INTO_CTX_WITH_AO (ARM64_REG_X14, tmp_event,
      G_STRUCT_OFFSET (GumCallEvent, depth));

  gum_exec_block_write_event_submit_code (block, gc, cc);
}

static void
gum_exec_block_write_ret_event_code (GumExecBlock * block,
                                     GumGeneratorContext * gc,
                                     GumCodeContext cc)
{
  GumArm64Writer * cw;

  cw = gc->code_writer;

  gum_exec_block_open_prolog (block, GUM_PROLOG_MINIMAL, gc);

  gum_exec_block_write_event_init_code (block, GUM_RET, gc);

  /* save the location of the call event */
  gum_arm64_writer_put_ldr_reg_address (cw, ARM64_REG_X14,
      GUM_ADDRESS (gc->instruction->begin));
  STALKER_STORE_REG_INTO_CTX_WITH_AO (ARM64_REG_X14, tmp_event,
      G_STRUCT_OFFSET (GumRetEvent, location));

  /* save return address of the ret (its target) */
  STALKER_STORE_REG_INTO_CTX_WITH_AO (ARM64_REG_X30, tmp_event,
      G_STRUCT_OFFSET (GumRetEvent, target));

  /* save the call depth TODO better understand... */
  gum_arm64_writer_put_ldr_reg_u64 (cw, ARM64_REG_X14, 4);
  STALKER_STORE_REG_INTO_CTX_WITH_AO (ARM64_REG_X14, tmp_event,
      G_STRUCT_OFFSET (GumRetEvent, depth));

  gum_exec_block_write_event_submit_code (block, gc, cc);
}

static void
gum_exec_block_write_exec_event_code (GumExecBlock * block,
                                      GumGeneratorContext * gc,
                                      GumCodeContext cc)
{
  GumArm64Writer * cw;

  cw = gc->code_writer;

  gum_exec_block_open_prolog (block, GUM_PROLOG_MINIMAL, gc);

  gum_exec_block_write_event_init_code (block, GUM_EXEC, gc);

  /* save location */
  gum_arm64_writer_put_ldr_reg_address (cw, ARM64_REG_X14,
      GUM_ADDRESS (gc->instruction->begin));
  STALKER_STORE_REG_INTO_CTX_WITH_AO (ARM64_REG_X14, tmp_event,
      G_STRUCT_OFFSET (GumExecEvent, location));

  gum_exec_block_write_event_submit_code (block, gc, cc);
}

static void
gum_exec_block_write_block_event_code (GumExecBlock * block,
                                       GumGeneratorContext * gc,
                                       GumCodeContext cc)
{
  GumArm64Writer * cw;

  cw = gc->code_writer;

  gum_exec_block_open_prolog (block, GUM_PROLOG_MINIMAL, gc);

  gum_exec_block_write_event_init_code (block, GUM_BLOCK, gc);

  gum_arm64_writer_put_ldr_reg_address (cw, ARM64_REG_X14,
      GUM_ADDRESS (gc->relocator->input_start));
  STALKER_STORE_REG_INTO_CTX_WITH_AO (ARM64_REG_X14, tmp_event,
      G_STRUCT_OFFSET (GumBlockEvent, begin));

  gum_arm64_writer_put_ldr_reg_address (cw, ARM64_REG_X14,
      GUM_ADDRESS (gc->relocator->input_cur));
  STALKER_STORE_REG_INTO_CTX_WITH_AO (ARM64_REG_X14, tmp_event,
      G_STRUCT_OFFSET (GumBlockEvent, end));

  gum_exec_block_write_event_submit_code (block, gc, cc);
}

static void
gum_exec_block_write_event_init_code (GumExecBlock * block,
                                      GumEventType type,
                                      GumGeneratorContext * gc)
{
  GumArm64Writer * cw;

  cw = gc->code_writer;

  /* save the type of event */
  gum_arm64_writer_put_instruction (cw, 0xCB0E01CE);
  gum_arm64_writer_put_add_reg_reg_imm (cw, ARM64_REG_X14, ARM64_REG_X14, type);
  STALKER_STORE_REG_INTO_CTX_WITH_AO (ARM64_REG_X14, tmp_event,
      G_STRUCT_OFFSET (GumAnyEvent, type));
}

static void
gum_exec_block_write_event_submit_code (GumExecBlock * block,
                                        GumGeneratorContext * gc,
                                        GumCodeContext cc)
{
  GumExecCtx * ctx;
  GumArm64Writer * cw;
  gconstpointer beach_label;
  GumPrologType opened_prolog;

  ctx = block->ctx;
  cw = gc->code_writer;
  beach_label = cw->code + 1;

  /* in order to keep using STALKER_REG_CTX we have to save them from this */
  gum_arm64_writer_put_push_reg_reg (cw, STALKER_REG_CTX, ARM64_REG_X15);
  gum_arm64_writer_put_add_reg_reg_imm (cw, ARM64_REG_X15,
      STALKER_REG_CTX, G_STRUCT_OFFSET (
      GumExecCtx,
      tmp_event));
  gum_arm64_writer_put_call_address_with_arguments (cw,
      GUM_ADDRESS (block->ctx->sink_process_impl), 2,
      GUM_ARG_ADDRESS, block->ctx->sink,
      GUM_ARG_REGISTER, ARM64_REG_X15);
  gum_arm64_writer_put_pop_reg_reg (cw, STALKER_REG_CTX, ARM64_REG_X15);

  if (cc == GUM_CODE_INTERRUPTIBLE)
  {
    /* check if we've been asked to unfollow */
    STALKER_LOAD_REG_FROM_CTX (ARM64_REG_X14, state);
    gum_arm64_writer_put_sub_reg_reg_imm (cw, ARM64_REG_X14, ARM64_REG_X14,
        GUM_EXEC_CTX_UNFOLLOW_PENDING);
    gum_arm64_writer_put_cbnz_reg_label (cw, ARM64_REG_X14, beach_label);

    gum_arm64_writer_put_call_address_with_arguments (cw,
        GUM_ADDRESS (gum_exec_ctx_unfollow), 2,
        GUM_ARG_ADDRESS, ctx,
        GUM_ARG_ADDRESS, gc->instruction->begin);

    opened_prolog = gc->opened_prolog;
    gum_exec_block_close_prolog (block, gc);
    gc->opened_prolog = opened_prolog;

    gum_arm64_writer_put_ldr_reg_address (cw, ARM64_REG_X16,
        GUM_ADDRESS (&block->ctx->resume_at));
    gum_arm64_writer_put_ldr_reg_reg_offset (cw, ARM64_REG_X17, ARM64_REG_X16,
        0);
    gum_arm64_writer_put_br_reg (cw, ARM64_REG_X17);

    gum_arm64_writer_put_label (cw, beach_label);
  }
}

static void
gum_exec_block_invoke_call_probes_for_target (GumExecBlock * block,
                                              gpointer location,
                                              gpointer target_address,
                                              GumCpuContext * cpu_context)
{
  GumStalkerPrivate * priv = block->ctx->stalker->priv;
  GArray * probes;

  gum_spinlock_acquire (&priv->probe_lock);

  probes = (GArray *)
      g_hash_table_lookup (priv->probe_array_by_address, target_address);
  if (probes != NULL)
  {
    GumCallSite call_site;
    guint probe_index;

    call_site.block_address = block->real_begin;
    call_site.stack_data = GSIZE_TO_POINTER (cpu_context->sp);
    call_site.cpu_context = cpu_context;

    cpu_context->pc = GPOINTER_TO_SIZE (location);

    for (probe_index = 0; probe_index != probes->len; probe_index++)
    {
      GumCallProbe * probe = &g_array_index (probes, GumCallProbe, probe_index);

      probe->callback (&call_site, probe->user_data);
    }
  }

  gum_spinlock_release (&priv->probe_lock);
}

static void
gum_exec_block_write_call_probe_code (GumExecBlock * block,
                                      const GumBranchTarget * target,
                                      GumGeneratorContext * gc)
{
  GumArm64Writer * cw;
  gboolean skip_probing = FALSE;

  cw = gc->code_writer;

  if (!target->is_indirect && target->base == ARM64_REG_INVALID)
  {
    GumStalkerPrivate * priv = block->ctx->stalker->priv;

    gum_spinlock_acquire (&priv->probe_lock);
    skip_probing = g_hash_table_lookup (priv->probe_array_by_address,
        target->absolute_address) == NULL;
    gum_spinlock_release (&priv->probe_lock);
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
