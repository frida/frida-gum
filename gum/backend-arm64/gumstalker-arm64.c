/*
 * Copyright (C) 2014 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
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

#define GUM_STALKER_LOCK(o) g_mutex_lock (&(o)->priv->mutex)
#define GUM_STALKER_UNLOCK(o) g_mutex_unlock (&(o)->priv->mutex)

#define GUM_STALKER_GET_PRIVATE(o) ((o)->priv)

/*
 * 10: everything
 *  9: new instructions
 *  8: read instructions
 *  7: ad-hoc
 */
#define STALKER_DEBUG_LEVEL 0

typedef struct _GumInfectContext GumInfectContext;
typedef struct _GumDisinfectContext GumDisinfectContext;

typedef struct _GumCallProbe GumCallProbe;
typedef struct _GumSlab GumSlab;

typedef struct _GumExecCtx GumExecCtx;
typedef struct _GumExecBlock GumExecBlock;

typedef guint GumPrologType;
typedef guint GumCodeContext;
typedef struct _GumGeneratorContext GumGeneratorContext;
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
};

struct _GumInstruction
{
  cs_insn * ci;
  guint8 * begin;
  guint8 * end;
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
  GUM_REQUIRE_NOTHING         = 0,
  GUM_REQUIRE_RELOCATION      = 1 << 0,
};

static void gum_stalker_finalize (GObject * object);

G_GNUC_INTERNAL gpointer _gum_stalker_do_follow_me (GumStalker * self,
    GumEventSink * sink, volatile gpointer ret_addr);

static void gum_stalker_infect (GumThreadId thread_id,
    GumCpuContext * cpu_context, gpointer user_data);
static void gum_stalker_disinfect (GumThreadId thread_id,
    GumCpuContext * cpu_context, gpointer user_data);

static void gum_stalker_free_probe_array (gpointer data);

static GumExecCtx * gum_stalker_create_exec_ctx (GumStalker * self,
    GumThreadId thread_id, GumEventSink * sink);
static GumExecCtx * gum_stalker_get_exec_ctx (GumStalker * self);

static void gum_exec_ctx_free (GumExecCtx * ctx);
static void gum_exec_ctx_unfollow (GumExecCtx * ctx, gpointer resume_at);
static gboolean gum_exec_ctx_has_executed (GumExecCtx * ctx);
static gpointer gum_exec_ctx_replace_current_block_with (GumExecCtx * ctx,
    gpointer start_address);
static void gum_exec_ctx_create_thunks (GumExecCtx * ctx);
static void gum_exec_ctx_destroy_thunks (GumExecCtx * ctx);

static GumExecBlock * gum_exec_ctx_obtain_block_for (GumExecCtx * ctx,
    gpointer real_address, gpointer * code_address);
static void gum_exec_ctx_write_prolog (GumExecCtx * ctx, GumPrologType type,
    gpointer ip, GumArm64Writer * cw);
static void gum_exec_ctx_write_epilog (GumExecCtx * ctx, GumPrologType type,
    GumArm64Writer * cw);
static void gum_exec_ctx_write_push_branch_target_address (GumExecCtx * ctx,
    const GumBranchTarget * target, GumGeneratorContext * gc);
static void gum_exec_ctx_load_real_register_into (GumExecCtx * ctx,
    arm64_reg target_register, arm64_reg source_register, gpointer ip,
    GumGeneratorContext * gc);

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

#if STALKER_DEBUG_LEVEL > 0

static void
gum_print_pointer (gpointer pointer)
{
  g_print ("# pointer: %p #\n", pointer);
}

static void
gum_put_debug_print_pointer (GumArm64Writer * cw,
                             gpointer pointer)
{
  gum_arm64_writer_put_push_all_x_registers (cw);
  gum_arm64_writer_put_call_address_with_arguments (cw,
      GUM_FUNCPTR_TO_POINTER (gum_print_pointer), 1,
      GUM_ARG_ADDRESS, GUM_ADDRESS (pointer));
  gum_arm64_writer_put_pop_all_x_registers (cw);
}

static void
gum_put_debug_print_reg (GumArm64Writer * cw,
                         arm64_reg reg)
{
  gum_arm64_writer_put_push_all_x_registers (cw);
  gum_arm64_writer_put_call_address_with_arguments (cw,
      GUM_FUNCPTR_TO_POINTER (gum_print_pointer), 1,
      GUM_ARG_REGISTER, reg);
  gum_arm64_writer_put_pop_all_x_registers (cw);
}

#endif

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
                           GumEventSink * sink,
                           volatile gpointer ret_addr)
{
  GumExecCtx * ctx;
  gpointer code_address;

#if STALKER_DEBUG_LEVEL == 10
  g_print ("_gum_stalker_do_follow_me - enter\n");
  g_print ("\tret_addr_ptr: %p\n", ret_addr);
  g_print ("\tnext actual instruction to execute after\n");
#endif

  ctx = gum_stalker_create_exec_ctx (self, gum_process_get_current_thread_id (),
      sink);
  gum_tls_key_set_value (self->priv->exec_ctx, ctx);

  ctx->current_block = gum_exec_ctx_obtain_block_for (ctx, ret_addr,
      &code_address);

  gum_event_sink_start (sink);

#if STALKER_DEBUG_LEVEL == 10
  g_print ("_gum_stalker_do_follow_me - exit\n");
  g_print ("\tcode_address: %p\n", code_address);
  g_print ("\tnext stalker instruction to execute after!\n");
  g_print ("self %p\n", self);
#endif

  g_assert (ctx != NULL);
  g_assert (gum_stalker_get_exec_ctx (self) != NULL);

  return code_address;
}

void
gum_stalker_unfollow_me (GumStalker * self)
{
  GumExecCtx * ctx;

#if STALKER_DEBUG_LEVEL == 10
  g_print ("gum_stalker_unfollow_me - enter\n");
#endif

  ctx = gum_stalker_get_exec_ctx (self);
  g_assert (ctx != NULL);

  gum_event_sink_stop (ctx->sink);

  if (ctx->current_block != NULL &&
      ctx->current_block->has_call_to_excluded_range)
  {
#if STALKER_DEBUG_LEVEL == 10
    g_print ("\t- setting unfollow pending\n");
#endif
    ctx->state = GUM_EXEC_CTX_UNFOLLOW_PENDING;
  }
  else
  {
#if STALKER_DEBUG_LEVEL == 10
    g_print ("\t- otherwise\n");
#endif

    g_assert (ctx->unfollow_called_while_still_following);

    gum_tls_key_set_value (self->priv->exec_ctx, NULL);

    GUM_STALKER_LOCK (self);
    self->priv->contexts = g_slist_remove (self->priv->contexts, ctx);
    GUM_STALKER_UNLOCK (self);

    gum_exec_ctx_free (ctx);
  }

#if STALKER_DEBUG_LEVEL == 10
  g_print ("gum_stalker_unfollow_me - exit\n");
#endif
}

gboolean
gum_stalker_is_following_me (GumStalker * self)
{
  return gum_stalker_get_exec_ctx (self) != NULL;
}

void
gum_stalker_follow (GumStalker * self,
                    GumThreadId thread_id,
                    GumEventSink * sink)
{
  if (thread_id == gum_process_get_current_thread_id ())
  {
    gum_stalker_follow_me (self, sink);
  }
  else
  {
    GumInfectContext ctx;
    ctx.stalker = self;
    ctx.sink = sink;
    gum_process_modify_thread (thread_id, gum_stalker_infect, &ctx);
  }
}

void
gum_stalker_unfollow (GumStalker * self,
                      GumThreadId thread_id)
{
#if STALKER_DEBUG_LEVEL == 10
  g_print ("gum_stalker_unfollow - enter\n");
#endif

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
        gum_event_sink_stop (ctx->sink);

        if (gum_exec_ctx_has_executed (ctx))
        {
#if STALKER_DEBUG_LEVEL == 10
          g_print ("setting ctx->state = GUM_EXEC_CTX_UNFOLLOW_PENDING\n");
#endif
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

#if STALKER_DEBUG_LEVEL == 10
  g_print ("gum_stalker_infect - enter\n");
#endif

  infect_context = user_data;
  self = infect_context->stalker;
  ctx = gum_stalker_create_exec_ctx (self, thread_id, infect_context->sink);

  ctx->current_block = gum_exec_ctx_obtain_block_for (ctx,
      GSIZE_TO_POINTER (cpu_context->pc), &code_address);
  cpu_context->pc = GPOINTER_TO_SIZE (ctx->infect_thunk);

  gum_arm64_writer_init (&cw, ctx->infect_thunk);

  gum_exec_ctx_write_prolog (ctx, GUM_PROLOG_MINIMAL,
      ctx->current_block->real_begin, &cw);
  gum_arm64_writer_put_call_address_with_arguments (&cw,
      GUM_ADDRESS (gum_tls_key_set_value), 2,
      GUM_ARG_ADDRESS, self->priv->exec_ctx,
      GUM_ARG_ADDRESS, ctx);
  gum_exec_ctx_write_epilog (ctx, GUM_PROLOG_MINIMAL, &cw);

  gum_arm64_writer_put_branch_address (&cw, GUM_ADDRESS (code_address + 4));

  gum_arm64_writer_free (&cw);

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

#if STALKER_DEBUG_LEVEL == 10
  g_print ("gum_stalker_disinfect - enter\n");
#endif

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
  g_assert ("" == "NOT IMPLEMENTED");

  return 0;
}

void
gum_stalker_remove_call_probe (GumStalker * self,
                               GumProbeId id)
{
  g_assert ("" == "NOT IMPLEMENTED");
}

static void
gum_stalker_free_probe_array (gpointer data)
{
  g_assert ("" == "NOT IMPLEMENTED");
}

static GumExecCtx *
gum_stalker_create_exec_ctx (GumStalker * self,
                             GumThreadId thread_id,
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

  ctx->sink = (GumEventSink *) g_object_ref (sink);
  ctx->sink_mask = gum_event_sink_query_mask (sink);
  ctx->sink_process_impl = GUM_FUNCPTR_TO_POINTER (
      GUM_EVENT_SINK_GET_INTERFACE (sink)->process);

#if STALKER_DEBUG_LEVEL == 10
  g_print ("sink mask= %ld\n", ctx->sink_mask);
#endif

  gum_exec_ctx_create_thunks (ctx);

  GUM_STALKER_LOCK (self);
  self->priv->contexts = g_slist_prepend (self->priv->contexts, ctx);
  GUM_STALKER_UNLOCK (self);

  return ctx;
}

static GumExecCtx *
gum_stalker_get_exec_ctx (GumStalker * self)
{
  return (GumExecCtx *) gum_tls_key_get_value (self->priv->exec_ctx);
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

  gum_arm64_relocator_free (&ctx->relocator);
  gum_arm64_writer_free (&ctx->code_writer);

  g_object_unref (ctx->stalker);

  gum_free_pages (ctx);
}

static void
gum_exec_ctx_unfollow (GumExecCtx * ctx,
                       gpointer resume_at)
{
#if STALKER_DEBUG_LEVEL == 10
  g_print ("gum_exec_ctx_unfollow - enter\n");
#endif

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
#if STALKER_DEBUG_LEVEL == 10
  g_print ("gum_exec_ctx_replace_current_block_with - enter\n");
  g_print ("\tstart_address (real_address) %p:\n", start_address);
  g_print ("\tresume_at (code_address) %p:\n", ctx->resume_at);
  g_print ("\tgum_stalker_unfollow_me: %p\n", gum_stalker_unfollow_me);
#endif

  if (ctx->invalidate_pending)
  {
#if STALKER_DEBUG_LEVEL == 10
    g_print ("gum_exec_ctx_replace_current_block_with - invalidate pending\n");
#endif
    gum_metal_hash_table_remove_all (ctx->mappings);

    ctx->invalidate_pending = FALSE;
  }

  if (start_address == gum_stalker_unfollow_me)
  {
#if STALKER_DEBUG_LEVEL == 10
    g_print (
        "gum_exec_ctx_replace_current_block_with - unfollow me\n");
#endif

    ctx->unfollow_called_while_still_following = TRUE;
    ctx->current_block = NULL;

    ctx->resume_at = start_address;
  }
  else if (ctx->state == GUM_EXEC_CTX_UNFOLLOW_PENDING)
  {
#if STALKER_DEBUG_LEVEL == 10
    g_print (
        "gum_exec_ctx_replace_current_block_with - unfollow pending\n");
#endif
    gum_exec_ctx_unfollow (ctx, start_address);
  }
  else
  {
#if STALKER_DEBUG_LEVEL == 10
    g_print (
        "gum_exec_ctx_replace_current_block_with - obtain block\n");
    g_print ("\tstart_address (real_address) %p:\n", start_address);
    g_print ("\tresume_at (code_address) %p:\n", ctx->resume_at);
#endif

    ctx->current_block = gum_exec_ctx_obtain_block_for (ctx, start_address,
        &ctx->resume_at);
  }

#if STALKER_DEBUG_LEVEL == 10
  g_print ("\treturn ctx->resume_at %p\n", ctx->resume_at);
  g_print ("\treturn start_address %p\n", start_address);
  g_print ("gum_exec_ctx_replace_current_block_with - exit\n");
#endif

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

  gum_arm64_writer_free (&cw);
}

static void
gum_exec_ctx_destroy_thunks (GumExecCtx * ctx)
{
  gum_free_pages (ctx->thunks);
}

#if STALKER_DEBUG_LEVEL > 0

static void
gum_disasm (guint8 * code,
            guint size,
            const gchar * prefix)
{
  csh capstone;
  cs_err err;
  cs_insn * insn;
  gint count, i, j;

  err = cs_open (CS_ARCH_ARM64, CS_MODE_ARM, &capstone);
  g_assert_cmpint (err, ==, CS_ERR_OK);

  count = cs_disasm (capstone, code, size, GPOINTER_TO_SIZE (code), 0, &insn);
  g_assert (insn != NULL);

  for (i = 0; i != count; i++)
  {
    g_print ("%s0x%" G_GINT64_MODIFIER "x\t(0x", prefix, insn[i].address);

    for (j = 0; j != insn[i].size; j++)
      g_print ("%02X", (guint) insn[i].bytes[j]);

    g_print (")\t%s %s\x1b[0m\n", insn[i].mnemonic, insn[i].op_str);
  }

  cs_free (insn, count);

  cs_close (&capstone);
}

#endif

static GumExecBlock *
gum_exec_ctx_obtain_block_for (GumExecCtx * ctx,
                               gpointer real_address,
                               gpointer * code_address_ptr)
{
  GumExecBlock * block;
  GumArm64Writer * cw;
  GumArm64Relocator * rl;
  GumGeneratorContext gc;

#if STALKER_DEBUG_LEVEL == 10
  g_print ("gum_exec_ctx_obtain_block_for - enter\n");
  g_print ("\treal_address (former ret_address): %p\n", real_address);
  g_print ("\tcode_address_ptr: %p\n", code_address_ptr);
  g_print ("\tcode_address: %p\n", *code_address_ptr);
#endif

  cw = &ctx->code_writer;
  rl = &ctx->relocator;

  if (ctx->stalker->priv->trust_threshold >= 0)
  {
#if STALKER_DEBUG_LEVEL == 10
    g_print ("ctx->stalker->priv->trust_threshold >= 0\n");
#endif

    block = gum_exec_block_obtain (ctx, real_address, code_address_ptr);
    if (block != NULL)
    {
      if (block->recycle_count >= ctx->stalker->priv->trust_threshold ||
          memcmp (real_address, block->real_snapshot,
            block->real_end - block->real_begin) == 0)
      {
        block->recycle_count++;
#if STALKER_DEBUG_LEVEL == 10
        g_print ("gum_exec_ctx_obtain_block_for - fast exit\n");
#endif
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

#if STALKER_DEBUG_LEVEL == 10
  g_print ("new block!\n");
  g_print ("\tcode_address_ptr: %p\n", code_address_ptr);
  g_print ("\tcode_address: %p\n", *code_address_ptr);
#endif

  if (ctx->stalker->priv->trust_threshold >= 0)
    gum_metal_hash_table_insert (ctx->mappings, real_address, block);
  gum_arm64_writer_reset (cw, block->code_begin);
  gum_arm64_relocator_reset (rl, real_address, cw);

  gc.instruction = NULL;
  gc.relocator = rl;
  gc.code_writer = cw;
  gc.continuation_real_address = NULL;
  gc.opened_prolog = GUM_PROLOG_NONE;

#if STALKER_DEBUG_LEVEL == 10
  g_print (
      "\n\n*********************\n\nCreating block for %p (real_address):\n",
      real_address);
  int i = 0;
#endif

  /* this may trash the red zone, if any... */
  gum_arm64_writer_put_pop_reg_reg (cw, ARM64_REG_X16, ARM64_REG_X17);

  while (TRUE)
  {
    guint n_read;
    GumInstruction insn;
    GumVirtualizationRequirements requirements = GUM_REQUIRE_NOTHING;

    n_read = gum_arm64_relocator_read_one (rl, NULL);
    g_assert_cmpuint (n_read, !=, 0);

    insn.ci = gum_arm64_relocator_peek_next_write_insn (rl);
    insn.begin = gum_arm64_relocator_peek_next_write_source (rl);
    insn.end = insn.begin + insn.ci->size;

    g_assert (insn.ci != NULL && insn.begin != NULL);

#if STALKER_DEBUG_LEVEL >= 8
    gum_disasm (insn.begin, insn.ci->size, "\x1b[31mINS > ");
#endif

    gc.instruction = &insn;

    if ((ctx->sink_mask & GUM_EXEC) != 0)
      gum_exec_block_write_exec_event_code (block, &gc, GUM_CODE_INTERRUPTIBLE);

    switch (insn.ci->id)
    {
      case ARM64_INS_BL:
      case ARM64_INS_B:
      case ARM64_INS_BLR:
      case ARM64_INS_BR:
      case ARM64_INS_CBZ:
      case ARM64_INS_CBNZ:
      case ARM64_INS_TBZ:
      case ARM64_INS_TBNZ:
#if STALKER_DEBUG_LEVEL == 10
        g_print ("gum_exec_ctx_obtain_block_for - switch branch ins\n");
#endif
        requirements = gum_exec_block_virtualize_branch_insn (block, &gc);
        break;
      case ARM64_INS_RET:
#if STALKER_DEBUG_LEVEL == 10
        g_print ("gum_exec_ctx_obtain_block_for - switch ret ins\n");
#endif
        requirements = gum_exec_block_virtualize_ret_insn (block, &gc);
        break;
      case ARM64_INS_SVC:
        requirements = gum_exec_block_virtualize_sysenter_insn (block, &gc);
        break;
      case ARM64_INS_SMC:
      case ARM64_INS_HVC:
        g_assert ("" == "not implemented");
      default:
        requirements = GUM_REQUIRE_RELOCATION;
    }

    gum_exec_block_close_prolog (block, &gc);

    if ((requirements & GUM_REQUIRE_RELOCATION) != 0)
      gum_arm64_relocator_write_one (rl);

#if STALKER_DEBUG_LEVEL >= 9
    {
      guint8 * begin = block->code_end;
      block->code_end = gum_arm64_writer_cur (cw);
      gum_disasm (begin, block->code_end - begin, "\x1b[34mNEW INS> ");
    }
#else
    block->code_end = gum_arm64_writer_cur (cw);
#endif

    if (gum_exec_block_is_full (block))
    {
      gc.continuation_real_address = insn.end;
#if STALKER_DEBUG_LEVEL == 10
      g_print ("gum_exec_ctx_obtain_block_for - block is full\n");
      g_print ("gc.continuation_real_address: %p", gc.continuation_real_address);
#endif
      break;
    }
    else if (insn.ci->id == ARM64_INS_BL)
    {
      /* We always stop on a call unless it's to an excluded range */
      if ((requirements & GUM_REQUIRE_RELOCATION) != 0)
      {
#if STALKER_DEBUG_LEVEL == 10
        g_print ("gum_exec_ctx_obtain_block_for - block is not full\n");
        g_print ("(requirements & GUM_REQUIRE_RELOCATION) != 0\n");
        g_print ("rl->eob = FALSE");
#endif
        rl->eob = FALSE;
      }
      else
      {
        break;
      }
    }
    else if (gum_arm64_relocator_eob (rl))
    {
      break;
    }
  }

  if (gc.continuation_real_address != NULL)
  {
    GumBranchTarget continue_target = { 0, };

    continue_target.is_indirect = FALSE;
    continue_target.absolute_address = gc.continuation_real_address;
#if STALKER_DEBUG_LEVEL == 10
    g_print ("continue_target.absolute_address: %p",
        continue_target.absolute_address);
#endif
    gum_exec_block_write_jmp_transfer_code (block, &continue_target, &gc);
  }

  gum_arm64_writer_put_brk_imm (cw, 14);

  gum_arm64_writer_flush (cw);

  block->code_end = (guint8 *) gum_arm64_writer_cur (cw);

  block->real_begin = (guint8 *) rl->input_start;
  block->real_end = (guint8 *) rl->input_cur;

  gum_exec_block_commit (block);

#if STALKER_DEBUG_LEVEL == 10
  g_print ("gum_exec_ctx_obtain_block_for - exit\n");
  g_print ("\tcode_address_ptr: %p\n", code_address_ptr);
  g_print ("\tcode_address: %p\n", *code_address_ptr);
  g_print ("\tblock->code_begin: %p\n", block->code_begin);
  g_print ("\tblock->code_end: %p\n", block->code_end);
  g_print ("\tblock->real_begin: %p\n", block->real_begin);
  g_print ("\tblock->real_end: %p\n", block->real_end);
#endif

  return block;
}

static void
gum_exec_ctx_write_prolog (GumExecCtx * ctx,
                           GumPrologType type,
                           gpointer ip,
                           GumArm64Writer * cw)
{
  gint immediate_for_sp;

#if STALKER_DEBUG_LEVEL == 10
  g_print ("+ gum_exec_ctx_write_prolog - type: %d\n",type);
#endif

  /* 1) move out of the red-zone */
  gum_arm64_writer_put_sub_reg_reg_imm (cw, ARM64_REG_SP, ARM64_REG_SP,
      GUM_RED_ZONE_SIZE);

  /* 2) push registers that are going to be clobbered */
  immediate_for_sp = GUM_RED_ZONE_SIZE;
  if (type == GUM_PROLOG_MINIMAL)
  {
    /* save the registers used by stalker's code */
    gum_arm64_writer_put_push_reg_reg (cw, ARM64_REG_X0, ARM64_REG_X1);
    gum_arm64_writer_put_push_reg_reg (cw, ARM64_REG_X2, ARM64_REG_X3);
    gum_arm64_writer_put_push_reg_reg (cw, ARM64_REG_X4, ARM64_REG_X5);
    gum_arm64_writer_put_push_reg_reg (cw, ARM64_REG_X6, ARM64_REG_X7);
    gum_arm64_writer_put_push_reg_reg (cw, ARM64_REG_X8, ARM64_REG_X9);
    gum_arm64_writer_put_push_reg_reg (cw, ARM64_REG_X10, ARM64_REG_X11);
    gum_arm64_writer_put_push_reg_reg (cw, ARM64_REG_X12, ARM64_REG_X13);
    gum_arm64_writer_put_push_reg_reg (cw, ARM64_REG_X14, ARM64_REG_X15);
    gum_arm64_writer_put_push_reg_reg (cw, ARM64_REG_X16, ARM64_REG_X17);
    gum_arm64_writer_put_push_reg_reg (cw, ARM64_REG_X18, STALKER_REG_CTX);
    /* X19 - X28 are callee-saved registers */
    gum_arm64_writer_put_push_reg_reg (cw, ARM64_REG_X29, ARM64_REG_X30);
    immediate_for_sp += 11 * 16;

    gum_arm64_writer_put_push_all_q_registers (cw);
    immediate_for_sp += 16 * 32;

    gum_arm64_writer_put_instruction (cw, 0xD53B420F); /* MRS X15, NZCV */
    gum_arm64_writer_put_push_reg_reg (cw, ARM64_REG_X30, ARM64_REG_X15);
    immediate_for_sp += 1 * 16;

  }
  else /* GUM_PROLOG_FULL */
  {
    gum_arm64_writer_put_push_all_x_registers (cw);
    immediate_for_sp += 16 * 16;

    gum_arm64_writer_put_push_all_q_registers (cw);
    immediate_for_sp += 16 * 32;
  }

  /* 3) save the stack pointer in context */
  gum_arm64_writer_put_ldr_reg_address (cw, STALKER_REG_CTX, GUM_ADDRESS (ctx));
  gum_arm64_writer_put_add_reg_reg_imm (cw, ARM64_REG_X14, ARM64_REG_SP,
      immediate_for_sp);
  STALKER_STORE_REG_INTO_CTX (ARM64_REG_X14, app_stack);

  if (type != GUM_PROLOG_MINIMAL)
  {
    /* 5) push the instruction pointer */
    gum_arm64_writer_put_ldr_reg_address (cw, ARM64_REG_X15, GUM_ADDRESS (ip));
    gum_arm64_writer_put_push_reg_reg (cw, ARM64_REG_X15, ARM64_REG_X15);

    /* 6) save the stack pointer in the GumCpuContex.sp? */
    STALKER_STORE_REG_INTO_CTX (ARM64_REG_X15, app_stack);
    gum_arm64_writer_put_ldr_reg_reg_offset (cw, ARM64_REG_X15, ARM64_REG_SP,
        G_STRUCT_OFFSET (GumCpuContext, sp));
  }
}

static void
gum_exec_ctx_write_epilog (GumExecCtx * ctx,
                           GumPrologType type,
                           GumArm64Writer * cw)
{
#if STALKER_DEBUG_LEVEL == 10
  g_print ("- gum_exec_ctx_write_epilog - type: %d\n", type);
#endif

  if (type != GUM_PROLOG_MINIMAL) /* GUM_PROLOG_FULL */
  {
    gum_arm64_writer_put_pop_reg_reg (cw, ARM64_REG_X15, ARM64_REG_X15);
  }

  if (type == GUM_PROLOG_MINIMAL)
  {
    gum_arm64_writer_put_pop_reg_reg (cw, ARM64_REG_X30, ARM64_REG_X15);
    gum_arm64_writer_put_instruction (cw, 0xD51B420F); /* MSR NZCV, X15 */

    gum_arm64_writer_put_pop_all_q_registers (cw);

    gum_arm64_writer_put_pop_reg_reg (cw, ARM64_REG_X29, ARM64_REG_X30);
    gum_arm64_writer_put_pop_reg_reg (cw, ARM64_REG_X18, STALKER_REG_CTX);
    gum_arm64_writer_put_pop_reg_reg (cw, ARM64_REG_X16, ARM64_REG_X17);
    gum_arm64_writer_put_pop_reg_reg (cw, ARM64_REG_X14, ARM64_REG_X15);
    gum_arm64_writer_put_pop_reg_reg (cw, ARM64_REG_X12, ARM64_REG_X13);
    gum_arm64_writer_put_pop_reg_reg (cw, ARM64_REG_X10, ARM64_REG_X11);
    gum_arm64_writer_put_pop_reg_reg (cw, ARM64_REG_X8, ARM64_REG_X9);
    gum_arm64_writer_put_pop_reg_reg (cw, ARM64_REG_X6, ARM64_REG_X7);
    gum_arm64_writer_put_pop_reg_reg (cw, ARM64_REG_X4, ARM64_REG_X5);
    gum_arm64_writer_put_pop_reg_reg (cw, ARM64_REG_X2, ARM64_REG_X3);
    gum_arm64_writer_put_pop_reg_reg (cw, ARM64_REG_X0, ARM64_REG_X1);
  }
  else /* GUM_PROLOG_FULL */
  {
    gum_arm64_writer_put_pop_all_q_registers (cw);
    gum_arm64_writer_put_pop_all_x_registers (cw);
  }

  /* restore the app_stack (with some tricks) */
  gum_arm64_writer_put_push_reg_reg (cw, ARM64_REG_X14, ARM64_REG_X15);
  gum_arm64_writer_put_mov_reg_reg (cw, ARM64_REG_X14, ARM64_REG_SP);

  gum_arm64_writer_put_ldr_reg_address (cw, ARM64_REG_X15,
      GUM_ADDRESS (&ctx->app_stack));
  gum_arm64_writer_put_ldr_reg_reg_offset (cw, ARM64_REG_X15, ARM64_REG_X15, 0);
  gum_arm64_writer_put_mov_reg_reg (cw, ARM64_REG_SP, ARM64_REG_X15);

  gum_arm64_writer_put_ldr_reg_reg_offset (cw, ARM64_REG_X15, ARM64_REG_X14, 8);
  gum_arm64_writer_put_ldr_reg_reg_offset (cw, ARM64_REG_X14, ARM64_REG_X14, 0);
}

static void
gum_exec_ctx_write_push_branch_target_address (GumExecCtx * ctx,
                                               const GumBranchTarget * target,
                                               GumGeneratorContext * gc)
{
  GumArm64Writer * cw = gc->code_writer;

#if STALKER_DEBUG_LEVEL == 10
  g_print ("gum_exec_ctx_write_push_branch_target_address - enter\n");
  g_print ("\ttarget is %sdirect\n", target->is_indirect ? "in" : "");
  g_print ("\ttarget->base is %svalid\n",
      (target->base == ARM64_REG_INVALID) ? "in" : "");
  g_print ("\ttarget->index  is %svalid\n",
      (target->index == ARM64_REG_INVALID) ? "in" : "");
#endif

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
  GumArm64Writer * cw;
  gint slot_in_the_stack;
  gint pos_in_the_slot;

  if (gc->opened_prolog != GUM_PROLOG_MINIMAL)
    g_assert ("" == "not implemented");

  cw = gc->code_writer;

  if (source_register >= ARM64_REG_X0 && source_register <= ARM64_REG_X18)
  {
    slot_in_the_stack = (source_register - ARM64_REG_X0) / 2 + 1;
    pos_in_the_slot = (source_register - ARM64_REG_X0) % 2;

    STALKER_LOAD_REG_FROM_CTX (ARM64_REG_X15, app_stack);
    gum_arm64_writer_put_sub_reg_reg_imm (cw, ARM64_REG_X15, ARM64_REG_X15,
        GUM_RED_ZONE_SIZE);
    gum_arm64_writer_put_ldp_reg_reg_reg_offset (cw, ARM64_REG_X14,
        ARM64_REG_X15, ARM64_REG_X15, -slot_in_the_stack * 16);
    if (pos_in_the_slot == 0)
      gum_arm64_writer_put_mov_reg_reg (cw, target_register, ARM64_REG_X14);
    else
      gum_arm64_writer_put_mov_reg_reg (cw, target_register, ARM64_REG_X15);
  }
  else if (source_register == ARM64_REG_X29 || source_register == ARM64_REG_X30)
  {
    slot_in_the_stack = 10 + 1;
    pos_in_the_slot = (source_register - ARM64_REG_X29) % 2;

    STALKER_LOAD_REG_FROM_CTX (ARM64_REG_X15, app_stack);
    gum_arm64_writer_put_sub_reg_reg_imm (cw, ARM64_REG_X15, ARM64_REG_X15,
        GUM_RED_ZONE_SIZE);
    gum_arm64_writer_put_ldp_reg_reg_reg_offset (cw, ARM64_REG_X14,
        ARM64_REG_X15, ARM64_REG_X15, -slot_in_the_stack * 16);

    if (pos_in_the_slot == 0)
      gum_arm64_writer_put_mov_reg_reg (cw, target_register, ARM64_REG_X14);
    else
      gum_arm64_writer_put_mov_reg_reg (cw, target_register, ARM64_REG_X15);
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

#if STALKER_DEBUG_LEVEL == 10
    g_print ("data: %p, offset: %d, size GumExecBlock: %d\n", slab->data,
        slab->offset, sizeof (GumExecBlock));
    g_print ("block->code_begin: %p\n", block->code_begin);
#endif

    return block;
  }

  if (ctx->stalker->priv->trust_threshold < 0)
  {
#if STALKER_DEBUG_LEVEL == 10
    g_print ("gum_exec_block_new - ctx->stalker->priv->trust_threshold < 0\n");
#endif

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

#if STALKER_DEBUG_LEVEL == 10
  g_print ("gum_exec_block_new - return gum_exec_block_new (ctx)\n");
#endif

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

#if STALKER_DEBUG_LEVEL == 10
  g_print ("gum_exec_block_obtain - exit\n");
  g_print ("code_address_ptr: %p\n", code_address_ptr);
  g_print ("code_address: %p\n", *code_address_ptr);
#endif

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

#if STALKER_DEBUG_LEVEL == 10
  g_print ("gum_exec_block_virtualize_branch_insn - enter\n");
#endif

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
#if STALKER_DEBUG_LEVEL == 10
  g_print ("\tconditional: %s\n", is_conditional ? "yes" : "no");
  g_print ("\ttarget.origin_ip = insn->end: %p\n", target.origin_ip);
#endif

  if (insn->ci->id == ARM64_INS_BL || insn->ci->id == ARM64_INS_B)
  {
    g_assert (op->type == ARM64_OP_IMM);

#if STALKER_DEBUG_LEVEL == 10
    g_print ("gum_exec_block_virtualize_branch_insn - BL & %sconditonal B\n",
        is_conditional ? "" : "in");
    g_print ("\top->imm: %p\n", op->imm);
    g_print ("\tinsn->ci->address: %p\n", insn->ci->address);
#endif

    target.absolute_address = GSIZE_TO_POINTER (op->imm);
    target.is_indirect = FALSE;
    target.base = ARM64_REG_INVALID;
    target.index = ARM64_REG_INVALID;
    target.disp = 0;
  }
  else if (insn->ci->id == ARM64_INS_BLR || insn->ci->id == ARM64_INS_BR)
  {
    g_assert (op->type == ARM64_OP_REG);

#if STALKER_DEBUG_LEVEL == 10
    g_print ("gum_exec_block_virtualize_branch_insn - BLR & %sconditonal BR\n",
        is_conditional ? "" : "in");
    g_print ("\ttarget.base: %d\n", op->reg);
#endif

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

#if STALKER_DEBUG_LEVEL == 10
    if (insn->ci->id == ARM64_INS_CBZ)
      g_print ("gum_exec_block_virtualize_branch_insn - CBZ\n");
    else
      g_print ("gum_exec_block_virtualize_branch_insn - CBNZ\n");
    g_print ("\ttarget.absolute_address: %d\n", op2->imm);
#endif

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

#if STALKER_DEBUG_LEVEL == 10
    if (insn->ci->id == ARM64_INS_CBZ)
      g_print ("gum_exec_block_virtualize_branch_insn - CBZ\n");
    else
      g_print ("gum_exec_block_virtualize_branch_insn - CBNZ\n");
    g_print ("\ttarget.absolute_address: %p\n", op3->imm);
    g_print ("\tbit: %d\n", op2->imm);
#endif

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
#if STALKER_DEBUG_LEVEL == 10
    if (insn->ci->id == ARM64_INS_BL)
      g_print ("gum_exec_block_virtualize_branch_insn - ARM64_INS_BL\n");
    else
      g_print ("gum_exec_block_virtualize_branch_insn - ARM64_INS_BLR\n");
#endif

    gboolean target_is_excluded = FALSE;

    if ((block->ctx->sink_mask & GUM_CALL) != 0)
    {
      gum_exec_block_write_call_event_code (block, &target, gc,
          GUM_CODE_INTERRUPTIBLE);
    }

    if (block->ctx->stalker->priv->any_probes_attached)
    {
#if STALKER_DEBUG_LEVEL == 10
      g_print ("\t - block->ctx->stalker->priv->any_probes_attached\n");
#endif
      gum_exec_block_write_call_probe_code (block, &target, gc);
    }

    if (!target.is_indirect && target.base == ARM64_REG_INVALID)
    {
#if STALKER_DEBUG_LEVEL == 10
      g_print ("\t - target is direct && target.base == ARM64_REG_INVALID\n");
#endif
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
#if STALKER_DEBUG_LEVEL == 10
      g_print ("\t - target_is_excluded\n");
#endif
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
        gum_arm64_writer_put_cbnz_reg_label (cw, op->reg,  is_false);
      }
      else if (insn->ci->id == ARM64_INS_CBNZ)
      {
        gum_arm64_writer_put_cbz_reg_label (cw, op->reg,  is_false);
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
#if STALKER_DEBUG_LEVEL == 10
        g_print ("cc (%d) and not_cc (%d)",cc, not_cc);
#endif
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

      gum_exec_block_write_jmp_transfer_code (block, &cond_target, gc);
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
  GumPrologType opened_prolog;

#if STALKER_DEBUG_LEVEL == 10
  g_print ("gum_exec_block_write_call_invoke_code - enter\n");
#endif

  cw = gc->code_writer;
  call_code_start = cw->code;
  opened_prolog = gc->opened_prolog;

  gum_exec_block_open_prolog (block, GUM_PROLOG_MINIMAL, gc);

#if STALKER_DEBUG_LEVEL == 10
  g_print ("\t> gum_exec_ctx_replace_current_block_with\n");
  g_print("\t\t(block->ctx: %p,\n\t\ttarget->absolute_address: %p|%d)\n",
      block->ctx, target->absolute_address, target->base);
#endif

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

#if STALKER_DEBUG_LEVEL == 10
  g_print ("> b to address pointed by block->ctx->resume_at: %p\n",
      &block->ctx->resume_at);
  g_print ("\t> gc->instruction->end (saving in placeholder : %p\n",
      gc->instruction->end);
#endif

  /* we need to save the return address outside the prolog-epilog */
  gum_arm64_writer_put_ldr_reg_address (cw, ARM64_REG_X30,
      GUM_ADDRESS (gc->instruction->end));

  /* execute the generated code */
  gum_exec_block_write_exec_generated_code (cw, block->ctx);

#if STALKER_DEBUG_LEVEL == 10
  g_print ("gum_exec_block_write_call_invoke_code - exit\n");
#endif
}

static void
gum_exec_block_write_jmp_transfer_code (GumExecBlock * block,
                                        const GumBranchTarget * target,
                                        GumGeneratorContext * gc)
{
  GumArm64Writer * cw;
  GumPrologType opened_prolog;

#if STALKER_DEBUG_LEVEL == 10
  g_print ("gum_exec_block_write_jmp_transfer_code - enter\n");
#endif

  cw = gc->code_writer;
  opened_prolog = gc->opened_prolog;

  gum_exec_block_open_prolog (block, GUM_PROLOG_MINIMAL, gc);

  gum_exec_ctx_write_push_branch_target_address (block->ctx, target, gc);

  gum_arm64_writer_put_pop_reg_reg (cw, ARM64_REG_X14, ARM64_REG_X15);
  gum_arm64_writer_put_call_address_with_arguments (cw,
      GUM_ADDRESS (gum_exec_ctx_replace_current_block_with), 2,
      GUM_ARG_ADDRESS, GUM_ADDRESS (block->ctx),
      GUM_ARG_REGISTER, ARM64_REG_X15);

  gum_exec_block_close_prolog (block, gc);

  gum_exec_block_write_exec_generated_code (cw, block->ctx);

#if STALKER_DEBUG_LEVEL == 10
  g_print ("gum_exec_block_write_jmp_transfer_code - exit\n");
  g_print ("> b to address pointed by block->ctx->resume_at: %p\n",
      &block->ctx->resume_at);
#endif
}

static void
gum_exec_block_write_ret_transfer_code (GumExecBlock * block,
                                        GumGeneratorContext * gc,
                                        arm64_reg ret_reg)
{
  GumArm64Writer * cw;
  gconstpointer resolve_dynamically_label;

#if STALKER_DEBUG_LEVEL == 10
  g_print ("gum_exec_block_write_ret_transfer_code - enter\n");
#endif

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

#if STALKER_DEBUG_LEVEL == 10
  g_print ("gum_exec_block_write_ret_transfer_code - exit\n");
#endif
}

static void
gum_exec_block_write_exec_generated_code (GumArm64Writer * cw,
                                          GumExecCtx * ctx)
{
  /* WE ARE OUTSIDE THE PROLOG-EPILOG */
  gconstpointer dont_pop_now_lbl = cw->code + 1;

  gum_arm64_writer_put_push_reg_reg (cw, ARM64_REG_X16, ARM64_REG_X17);

  gum_arm64_writer_put_ldr_reg_address (cw, ARM64_REG_X16,
      GUM_ADDRESS (&ctx->current_block));
  gum_arm64_writer_put_ldr_reg_reg_offset (cw, ARM64_REG_X17, ARM64_REG_X16, 0);
  gum_arm64_writer_put_cbnz_reg_label (cw, ARM64_REG_X17, dont_pop_now_lbl);
  gum_arm64_writer_put_pop_reg_reg (cw, ARM64_REG_X16, ARM64_REG_X17);

  gum_arm64_writer_put_label (cw, dont_pop_now_lbl);
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

#if STALKER_DEBUG_LEVEL == 10
  g_print ("gum_exec_block_write_call_event_code - enter\n");
#endif

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
  gum_arm64_writer_put_pop_reg_reg (cw, ARM64_REG_X14, ARM64_REG_X14);

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
#if STALKER_DEBUG_LEVEL == 10
  g_print ("gum_exec_block_write_ret_event_code - enter\n");
#endif

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

#if STALKER_DEBUG_LEVEL == 10
  g_print ("gum_exec_block_write_exec_event_code - enter\n");
#endif

  cw = gc->code_writer;

  gum_exec_block_open_prolog (block, GUM_PROLOG_MINIMAL, gc);

  gum_exec_block_write_event_init_code (block, GUM_EXEC, gc);

  /* save location */
  gum_arm64_writer_put_ldr_reg_address (cw, ARM64_REG_X14,
      GUM_ADDRESS (gc->instruction->begin));
  STALKER_STORE_REG_INTO_CTX_WITH_AO (ARM64_REG_X14, tmp_event,
      G_STRUCT_OFFSET (GumExecEvent, location));

  gum_exec_block_write_event_submit_code (block, gc, cc);

#if STALKER_DEBUG_LEVEL == 10
  g_print ("gum_exec_block_write_exec_event_code - exit\n");
#endif
}

static void
gum_exec_block_write_event_init_code (GumExecBlock * block,
                                      GumEventType type,
                                      GumGeneratorContext * gc)
{
  GumArm64Writer * cw;

#if STALKER_DEBUG_LEVEL == 10
  g_print ("gum_exec_block_write_event_init_code - enter\n");
#endif

  cw = gc->code_writer;

  /* save the type of event */
  gum_arm64_writer_put_instruction (cw, 0xCB0E01CE);
  gum_arm64_writer_put_add_reg_reg_imm (cw, ARM64_REG_X14, ARM64_REG_X14, type);
  STALKER_STORE_REG_INTO_CTX_WITH_AO (ARM64_REG_X14, tmp_event,
      G_STRUCT_OFFSET (GumAnyEvent, type));

#if STALKER_DEBUG_LEVEL == 10
  g_print ("gum_exec_block_write_event_init_code - exit\n");
#endif
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

#if STALKER_DEBUG_LEVEL == 10
  g_print ("gum_exec_block_write_event_submit_code - enter\n");
#endif

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

#if STALKER_DEBUG_LEVEL == 10
  g_print ("gum_exec_block_write_event_submit_code - exit\n");
#endif
}

static void
gum_exec_block_write_call_probe_code (GumExecBlock * block,
                                      const GumBranchTarget * target,
                                      GumGeneratorContext * gc)
{
  g_assert ("" == "NOT IMPLEMENTED");
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

#if STALKER_DEBUG_LEVEL == 10
  g_print ("+++ gum_exec_block_open_prolog - %d\n", type);
  g_print ("\tgc->instruction->begin (saved as ip) - %p\n",
      gc->instruction->begin);
#endif

  gc->opened_prolog = type;
  gum_exec_ctx_write_prolog (block->ctx, type, gc->instruction->begin,
      gc->code_writer);
}

static void
gum_exec_block_close_prolog (GumExecBlock * block,
                             GumGeneratorContext * gc)
{
  if (gc->opened_prolog == GUM_PROLOG_NONE)
    return;

  gum_exec_ctx_write_epilog (block->ctx, gc->opened_prolog, gc->code_writer);

#if STALKER_DEBUG_LEVEL == 10
  g_print ("--- gum_exec_block_close_prolog - %d\n", gc->opened_prolog);
#endif

  gc->opened_prolog = GUM_PROLOG_NONE;
}
