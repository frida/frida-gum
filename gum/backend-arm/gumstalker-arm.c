/*
 * Copyright (C) 2009-2020 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumstalker.h"

#include "gumarmreg.h"
#include "gumarmrelocator.h"
#include "gumarmwriter.h"
#include "gummemory.h"
#include "gummetalhash.h"
#include "gumspinlock.h"
#include "gumthumbrelocator.h"
#include "gumthumbwriter.h"
#include "gumtls.h"

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/syscall.h>

#define GUM_CODE_SLAB_MAX_SIZE  (4 * 1024 * 1024)
#define GUM_EXEC_BLOCK_MIN_SIZE 1024

#define GUM_INSTRUCTION_OFFSET_NONE (-1)

#define GUM_STALKER_LOCK(o) g_mutex_lock (&(o)->mutex)
#define GUM_STALKER_UNLOCK(o) g_mutex_unlock (&(o)->mutex)

typedef struct _GumInfectContext GumInfectContext;
typedef struct _GumDisinfectContext GumDisinfectContext;

typedef struct _GumSlab GumSlab;

typedef struct _GumExecFrame GumExecFrame;
typedef struct _GumExecCtx GumExecCtx;
typedef struct _GumExecBlock GumExecBlock;

typedef struct _GumGeneratorContext GumGeneratorContext;
typedef struct _GumCalloutEntry GumCalloutEntry;
typedef struct _GumInstruction GumInstruction;
typedef guint GumBranchTargetType;
typedef struct _GumBranchTarget GumBranchTarget;
typedef struct _GumBranchDirectAddress GumBranchDirectAddress;
typedef struct _GumBranchDirectRegOffset GumBranchDirectRegOffset;
typedef struct _GumBranchDirectRegShift GumBranchDirectRegShift;
typedef struct _GumBranchIndirectRegOffset GumBranchIndirectRegOffset;
typedef struct _GumBranchIndirectPcrelTable GumBranchIndirectPcrelTable;
typedef struct _GumWriteback GumWriteback;

typedef gboolean (* GumCheckExcludedFunc) (GumExecCtx * ctx,
    gconstpointer address);

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

struct _GumExecFrame
{
  gpointer real_address;
};

struct _GumExecCtx
{
  volatile gint state;
  gint64 destroy_pending_since;

  GumStalker * stalker;
  GumThreadId thread_id;

  GumArmWriter arm_writer;
  GumArmRelocator arm_relocator;

  GumThumbWriter thumb_writer;
  GumThumbRelocator thumb_relocator;

  GumStalkerTransformer * transformer;
  void (* transform_block_impl) (GumStalkerTransformer * self,
      GumStalkerIterator * iterator, GumStalkerOutput * output);
  GQueue callout_entries;
  GumSpinlock callout_lock;
  GumEventSink * sink;
  gboolean sink_started;
  GumEventType sink_mask;
  gpointer last_exec_location;
  void (* sink_process_impl) (GumEventSink * self, const GumEvent * ev);

  gboolean unfollow_called_while_still_following;
  GumExecBlock * current_block;
  gpointer pending_return_location;
  guint pending_calls;
  GumExecFrame * current_frame;
  GumExecFrame * first_frame;
  GumExecFrame * frames;

  gpointer resume_at;
  gpointer kuh_target;
  gconstpointer activation_target;

  gpointer infect_thunk;

  GumSlab * code_slab;
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

struct _GumGeneratorContext
{
  GumInstruction * instruction;
  gboolean is_thumb;

  GumArmRelocator * arm_relocator;
  GumArmWriter * arm_writer;

  GumThumbRelocator * thumb_relocator;
  GumThumbWriter * thumb_writer;

  gpointer continuation_real_address;
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
};

struct _GumCalloutEntry
{
  GumStalkerCallout callout;
  gpointer data;
  GDestroyNotify data_destroy;

  gpointer pc;

  GumExecCtx * exec_context;
};

enum _GumExecCtxState
{
  GUM_EXEC_CTX_ACTIVE,
  GUM_EXEC_CTX_UNFOLLOW_PENDING,
  GUM_EXEC_CTX_DESTROY_PENDING
};

enum _GumBranchTargetType
{
  GUM_TARGET_DIRECT_ADDRESS,
  GUM_TARGET_DIRECT_REG_OFFSET,
  GUM_TARGET_DIRECT_REG_SHIFT,
  GUM_TARGET_INDIRECT_REG_OFFSET,
  GUM_TARGET_INDIRECT_PCREL_TABLE
};

struct _GumBranchDirectAddress
{
  gpointer address;
};

struct _GumBranchDirectRegOffset
{
  arm_reg reg;
  gssize offset;
};

struct _GumBranchDirectRegShift
{
  arm_reg base;
  arm_reg index;
  arm_shifter shifter;
  guint32 shift_value;
};

struct _GumBranchIndirectRegOffset
{
  arm_reg reg;
  gssize offset;
};

struct _GumBranchIndirectPcrelTable
{
  arm_reg base;
  arm_reg index;
  guint element_size;
};

struct _GumBranchTarget
{
  GumBranchTargetType type;

  union
  {
    GumBranchDirectAddress direct_address;
    GumBranchDirectRegOffset direct_reg_offset;
    GumBranchDirectRegShift direct_reg_shift;
    GumBranchIndirectRegOffset indirect_reg_offset;
    GumBranchIndirectPcrelTable indirect_pcrel_table;
  } value;
};

struct _GumWriteback
{
  arm_reg target;
  gssize offset;
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

static GumExecCtx * gum_stalker_create_exec_ctx (GumStalker * self,
    GumThreadId thread_id, GumStalkerTransformer * transformer,
    GumEventSink * sink);
static void gum_stalker_destroy_exec_ctx (GumStalker * self, GumExecCtx * ctx);
static GumExecCtx * gum_stalker_get_exec_ctx (GumStalker * self);

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
static GumExecBlock * gum_exec_ctx_obtain_block_for (GumExecCtx * ctx,
    gpointer real_address, gpointer * code_address_ptr);
static GumExecBlock * gum_exec_ctx_obtain_arm_block_for (GumExecCtx * ctx,
    gpointer real_address, gpointer * code_address_ptr);
static GumExecBlock * gum_exec_ctx_obtain_thumb_block_for (GumExecCtx * ctx,
    gpointer real_address, gpointer * code_address_ptr);
static void gum_exec_ctx_begin_call (GumExecCtx * ctx, gpointer ret_addr);
static void gum_exec_ctx_end_call (GumExecCtx * ctx);

static gboolean gum_stalker_iterator_arm_next (GumStalkerIterator * self,
    const cs_insn ** insn);
static gboolean gum_stalker_iterator_thumb_next (GumStalkerIterator * self,
    const cs_insn ** insn);
static void gum_stalker_iterator_arm_keep (GumStalkerIterator * self);
static void gum_stalker_iterator_thumb_keep (GumStalkerIterator * self);
static void gum_stalker_iterator_handle_thumb_branch_insn (
    GumStalkerIterator * self, const cs_insn * insn);
static void gum_stalker_iterator_handle_thumb_it_insn (
    GumStalkerIterator * self);

static void gum_stalker_get_target_address (const cs_insn * insn,
    gboolean thumb, GumBranchTarget * target, guint16 * mask);
static void gum_stalker_arm_get_writeback (const cs_insn * insn,
    GumWriteback * writeback);

static void gum_stalker_invoke_callout (GumCpuContext * cpu_context,
    GumCalloutEntry * entry);

static void gum_exec_ctx_write_arm_prolog (GumExecCtx * ctx, GumArmWriter * cw);
static void gum_exec_ctx_write_arm_epilog (GumExecCtx * ctx, GumArmWriter * cw);

static void gum_exec_ctx_arm_load_real_register_into (GumExecCtx * ctx,
    arm_reg target_register, arm_reg source_register, GumGeneratorContext * gc);
static void gum_exec_ctx_thumb_load_real_register_into (GumExecCtx * ctx,
    arm_reg target_register, arm_reg source_register, GumGeneratorContext * gc);

static GumExecBlock * gum_exec_block_new (GumExecCtx * ctx);
static GumExecBlock * gum_exec_block_obtain (GumExecCtx * ctx,
    gpointer real_address, gpointer * code_address_ptr);
static GumExecBlock * gum_exec_block_obtain_trusted (GumExecCtx * ctx,
    gpointer real_address, gpointer * code_address_ptr);
static gboolean gum_exec_block_is_full (GumExecBlock * block);
static void gum_exec_block_commit_and_emit (GumExecBlock * block);

static void gum_exec_block_virtualize_arm_branch_insn (GumExecBlock * block,
    const GumBranchTarget * target, arm_cc cc, GumWriteback * writeback,
    GumGeneratorContext * gc);
static void gum_exec_block_virtualize_thumb_branch_insn (GumExecBlock * block,
    const GumBranchTarget * target, arm_cc cc, arm_reg cc_reg,
    GumGeneratorContext * gc);
static void gum_exec_block_virtualize_arm_call_insn (GumExecBlock * block,
    const GumBranchTarget * target, arm_cc cc, GumGeneratorContext * gc);
static void gum_exec_block_virtualize_thumb_call_insn (GumExecBlock * block,
    const GumBranchTarget * target, GumGeneratorContext * gc);
static void gum_exec_block_virtualize_arm_ret_insn (GumExecBlock * block,
    const GumBranchTarget * target, arm_cc cc, gboolean pop, guint16 mask,
    GumGeneratorContext * gc);
static void gum_exec_block_virtualize_thumb_ret_insn (GumExecBlock * block,
    const GumBranchTarget * target, guint16 mask, GumGeneratorContext * gc);
static void gum_exec_block_virtualize_arm_svc_insn (GumExecBlock * block,
    GumGeneratorContext * gc);
static void gum_exec_block_virtualize_thumb_svc_insn (GumExecBlock * block,
    GumGeneratorContext * gc);

static void gum_exec_block_write_arm_handle_kuser_helper (GumExecBlock * block,
    const GumBranchTarget * target, GumGeneratorContext * gc);
static void gum_exec_block_write_thumb_handle_kuser_helper (
    GumExecBlock * block, const GumBranchTarget * target,
    GumGeneratorContext * gc);
static void gum_exec_block_write_arm_call_replace_block (GumExecBlock * block,
    const GumBranchTarget * target, GumGeneratorContext * gc);
static void gum_exec_block_write_thumb_call_replace_block (GumExecBlock * block,
    const GumBranchTarget * target, GumGeneratorContext * gc);

static void gum_exec_block_dont_virtualize_arm_insn (GumExecBlock * block,
    GumGeneratorContext * gc);
static void gum_exec_block_dont_virtualize_thumb_insn (GumExecBlock * block,
    GumGeneratorContext * gc);

static void gum_exec_block_write_arm_handle_excluded (GumExecBlock * block,
    const GumBranchTarget * target, gboolean call, GumGeneratorContext * gc);
static void gum_exec_block_write_thumb_handle_excluded (GumExecBlock * block,
    const GumBranchTarget * target, gboolean call, GumGeneratorContext * gc);
static void gum_exec_block_write_arm_handle_not_taken (GumExecBlock * block,
    const GumBranchTarget * target, arm_cc cc, GumGeneratorContext * gc);
static void gum_exec_block_write_thumb_handle_not_taken (GumExecBlock * block,
    const GumBranchTarget * target, arm_cc cc, arm_reg cc_reg,
    GumGeneratorContext * gc);
static void gum_exec_block_write_arm_handle_continue (GumExecBlock * block,
    GumGeneratorContext * gc);
static void gum_exec_block_write_thumb_handle_continue (GumExecBlock * block,
    GumGeneratorContext * gc);
static void gum_exec_block_write_arm_handle_writeback (GumExecBlock * block,
    const GumWriteback * writeback, GumGeneratorContext * gc);
static void gum_exec_block_write_arm_exec_generated_code (GumArmWriter * cw,
    GumExecCtx * ctx);
static void gum_exec_block_write_thumb_exec_generated_code (GumThumbWriter * cw,
    GumExecCtx * ctx);

static void gum_exec_block_write_arm_call_event_code (GumExecBlock * block,
    const GumBranchTarget * target, GumGeneratorContext * gc);
static void gum_exec_block_write_thumb_call_event_code (GumExecBlock * block,
    const GumBranchTarget * target, GumGeneratorContext * gc);
static void gum_exec_block_write_arm_ret_event_code (GumExecBlock * block,
    const GumBranchTarget * target, GumGeneratorContext * gc);
static void gum_exec_block_write_thumb_ret_event_code (GumExecBlock * block,
    const GumBranchTarget * target, GumGeneratorContext * gc);
static void gum_exec_block_write_arm_exec_event_code (GumExecBlock * block,
    GumGeneratorContext * gc);
static void gum_exec_block_write_thumb_exec_event_code (GumExecBlock * block,
    GumGeneratorContext * gc);
static void gum_exec_block_write_arm_block_event_code (GumExecBlock * block,
    GumGeneratorContext * gc);
static void gum_exec_block_write_thumb_block_event_code (GumExecBlock * block,
    GumGeneratorContext * gc);

static void gum_exec_block_write_arm_push_stack_frame (GumExecBlock * block,
    gpointer ret_real_address, GumGeneratorContext * gc);
static void gum_exec_block_write_thumb_push_stack_frame (GumExecBlock * block,
    gpointer ret_real_address, GumGeneratorContext * gc);
static void gum_exec_block_push_stack_frame (GumExecCtx * ctx,
    gpointer ret_real_address);
static void gum_exec_block_write_arm_pop_stack_frame (GumExecBlock * block,
    const GumBranchTarget * target, GumGeneratorContext * gc);
static void gum_exec_block_write_thumb_pop_stack_frame (GumExecBlock * block,
    const GumBranchTarget * target, GumGeneratorContext * gc);
static void gum_exec_block_pop_stack_frame (GumExecCtx * ctx,
    gpointer ret_real_address);

static void gum_exec_block_arm_open_prolog (GumExecBlock * block,
    GumGeneratorContext * gc);
static void gum_exec_block_thumb_open_prolog (GumExecBlock * block,
    GumGeneratorContext * gc);
static void gum_exec_block_arm_close_prolog (GumExecBlock * block,
    GumGeneratorContext * gc);
static void gum_exec_block_thumb_close_prolog (GumExecBlock * block,
    GumGeneratorContext * gc);

static gboolean gum_generator_context_is_timing_sensitive (
    GumGeneratorContext * gc);
static void gum_generator_context_advance_exclusive_load_offset (
    GumGeneratorContext * gc);

static gboolean gum_stalker_is_thumb (gconstpointer address);
static gboolean gum_stalker_is_kuser_helper (gconstpointer address);

static gboolean gum_is_exclusive_load_insn (const cs_insn * insn);
static gboolean gum_is_exclusive_store_insn (const cs_insn * insn);

G_DEFINE_TYPE (GumStalker, gum_stalker, G_TYPE_OBJECT)

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
}

static void
gum_stalker_init (GumStalker * self)
{
  self->exclusions = g_array_new (FALSE, FALSE, sizeof (GumMemoryRange));
  self->trust_threshold = 1;

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
gum_stalker_is_call_excluding (GumExecCtx * ctx,
                               gconstpointer address)
{
  GArray * exclusions = ctx->stalker->exclusions;
  guint i;

  if (ctx->activation_target != NULL)
    return FALSE;

  if (gum_stalker_is_kuser_helper (address))
    return TRUE;

  for (i = 0; i != exclusions->len; i++)
  {
    GumMemoryRange * r = &g_array_index (exclusions, GumMemoryRange, i);

    if (GUM_MEMORY_RANGE_INCLUDES (r, GUM_ADDRESS (address)))
      return TRUE;
  }

  return FALSE;
}

static gboolean
gum_stalker_is_branch_excluding (GumExecCtx * ctx,
                                 gconstpointer address)
{
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

  return code_address;
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
  GumInfectContext * infect_context = user_data;
  GumStalker * self = infect_context->stalker;
  GumExecCtx * ctx;
  GumArmWriter cw;

  ctx = gum_stalker_create_exec_ctx (self, thread_id,
      infect_context->transformer, infect_context->sink);

  ctx->current_block = gum_exec_ctx_obtain_block_for (ctx,
      GSIZE_TO_POINTER (cpu_context->pc), &ctx->resume_at);

  if (gum_exec_ctx_maybe_unfollow (ctx, NULL))
  {
    gum_stalker_destroy_exec_ctx (self, ctx);
    return;
  }

  cpu_context->pc = GPOINTER_TO_SIZE (ctx->infect_thunk);

  gum_stalker_thaw (self, ctx->infect_thunk, self->page_size);
  gum_arm_writer_init (&cw, ctx->infect_thunk);

  gum_exec_ctx_write_arm_prolog (ctx, &cw);
  gum_arm_writer_put_call_address_with_arguments (&cw,
      GUM_ADDRESS (gum_tls_key_set_value), 2,
      GUM_ARG_ADDRESS, GUM_ADDRESS (self->exec_ctx),
      GUM_ARG_ADDRESS, GUM_ADDRESS (ctx));
  gum_exec_ctx_write_arm_epilog (ctx, &cw);

  gum_exec_block_write_arm_exec_generated_code (&cw, ctx);

  gum_arm_writer_flush (&cw);
  gum_stalker_freeze (self, cw.base, gum_arm_writer_offset (&cw));
  gum_arm_writer_clear (&cw);

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

  ctx->unfollow_called_while_still_following = FALSE;
  ctx->activation_target = target;

  if (!gum_exec_ctx_contains (ctx, ret_addr))
  {
    gpointer code_address;

    ctx->current_block =
        gum_exec_ctx_obtain_block_for (ctx, ret_addr, &code_address);

    if (gum_exec_ctx_maybe_unfollow (ctx, ret_addr))
      return ret_addr;

    return code_address;
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

  ctx->unfollow_called_while_still_following = TRUE;
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
  /*
   * At present call probes are not supported for ARM32. One complexity for
   * adding these is that there is no clear CALL or RET instruction on ARM32 and
   * in many cases whether an instruction represents a CALL, BRANCH or RET is
   * not very clear, it is only by tying the target address to the stored return
   * address in a GumExecFrame that we identify the call frames. An alternative
   * method may be necessary if call probes are supported if the user is to be
   * permitted to modify the PC, or otherwise affect control flow.
   */
  g_warning ("Call probes unsupported");

  if (notify != NULL)
    notify (data);

  return 0;
}

void
gum_stalker_remove_call_probe (GumStalker * self,
                               GumProbeId id)
{
  g_warning ("Call probes unsupported");
}

static GumExecCtx *
gum_stalker_create_exec_ctx (GumStalker * self,
                             GumThreadId thread_id,
                             GumStalkerTransformer * transformer,
                             GumEventSink * sink)
{
  GumExecCtx * ctx;
  gsize page_size;

  ctx = g_slice_new0 (GumExecCtx);

  ctx->state = GUM_EXEC_CTX_ACTIVE;

  ctx->stalker = g_object_ref (self);
  ctx->thread_id = thread_id;

  gum_arm_writer_init (&ctx->arm_writer, NULL);
  gum_arm_relocator_init (&ctx->arm_relocator, NULL, &ctx->arm_writer);

  gum_thumb_writer_init (&ctx->thumb_writer, NULL);
  gum_thumb_relocator_init (&ctx->thumb_relocator, NULL, &ctx->thumb_writer);
  gum_thumb_relocator_set_it_branch_type (&ctx->thumb_relocator,
      GUM_IT_BRANCH_LONG);

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

  page_size = ctx->stalker->page_size;

  ctx->infect_thunk = gum_memory_allocate (NULL, page_size, page_size,
      ctx->stalker->is_rwx_supported ? GUM_PAGE_RWX : GUM_PAGE_RW);

  GUM_STALKER_LOCK (self);
  self->contexts = g_slist_prepend (self->contexts, ctx);
  GUM_STALKER_UNLOCK (self);

  gum_exec_ctx_add_slab (ctx);

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
  return gum_tls_key_get_value (self->exec_ctx);
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

  gum_memory_free (ctx->infect_thunk, ctx->stalker->page_size);

  gum_memory_free (ctx->frames, stalker->page_size);

  g_object_unref (ctx->sink);
  gum_exec_ctx_finalize_callouts (ctx);
  g_object_unref (ctx->transformer);

  gum_thumb_relocator_clear (&ctx->thumb_relocator);
  gum_thumb_writer_clear (&ctx->thumb_writer);

  gum_arm_relocator_clear (&ctx->arm_relocator);
  gum_arm_writer_clear (&ctx->arm_writer);

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

static gpointer
gum_exec_ctx_replace_block (GumExecCtx * ctx,
                            gpointer start_address)
{
  if (start_address == gum_stalker_unfollow_me ||
      start_address == gum_stalker_deactivate)
  {
    ctx->unfollow_called_while_still_following = TRUE;
    ctx->current_block = NULL;
    ctx->resume_at = start_address;
  }
  else if (start_address == NULL)
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
    {
      ctx->activation_target = NULL;
    }

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

static GumExecBlock *
gum_exec_ctx_obtain_block_for (GumExecCtx * ctx,
                               gpointer real_address,
                               gpointer * code_address_ptr)
{
  if (gum_stalker_is_thumb (real_address))
  {
    return gum_exec_ctx_obtain_thumb_block_for (ctx, real_address,
        code_address_ptr);
  }
  else
  {
    return gum_exec_ctx_obtain_arm_block_for (ctx, real_address,
        code_address_ptr);
  }
}

static GumExecBlock *
gum_exec_ctx_obtain_arm_block_for (GumExecCtx * ctx,
                                   gpointer real_address,
                                   gpointer * code_address_ptr)
{
  GumExecBlock * block;
  GumArmWriter * cw;
  GumArmRelocator * rl;
  GumGeneratorContext gc;
  GumStalkerIterator iterator;
  GumStalkerOutput output;
  gboolean all_labels_resolved;

  block = gum_exec_block_obtain_trusted (ctx, real_address, code_address_ptr);
  if (block != NULL)
    return block;

  block = gum_exec_block_new (ctx);
  block->real_begin = real_address;
  *code_address_ptr = block->code_begin;

  if (ctx->stalker->trust_threshold >= 0)
    gum_metal_hash_table_insert (ctx->mappings, real_address, block);

  cw = &ctx->arm_writer;
  rl = &ctx->arm_relocator;

  gum_arm_writer_reset (cw, block->code_begin);
  gum_arm_relocator_reset (rl, real_address, cw);

  gum_ensure_code_readable (real_address, ctx->stalker->page_size);

  gc.instruction = NULL;
  gc.is_thumb = FALSE;
  gc.arm_relocator = rl;
  gc.arm_writer = cw;
  gc.continuation_real_address = NULL;
  gc.exclusive_load_offset = GUM_INSTRUCTION_OFFSET_NONE;

  iterator.exec_context = ctx;
  iterator.exec_block = block;
  iterator.generator_context = &gc;

  iterator.instruction.ci = NULL;
  iterator.instruction.begin = NULL;
  iterator.instruction.end = NULL;

  output.writer.arm = cw;
  output.encoding = GUM_INSTRUCTION_DEFAULT;

  ctx->pending_calls++;

  ctx->transform_block_impl (ctx->transformer, &iterator, &output);

  ctx->pending_calls--;

  if (gc.continuation_real_address != NULL)
  {
    /*
     * This is required to support the situation where the amount of code
     * emitted to instrument a block exceeds the minimum we check for before we
     * start instrumenting a block and it needs to be split. This is only likely
     * to be of concern for very long linear execution blocks.
     */
    g_error ("continuation_real_address unsupported");
  }

  gum_arm_writer_put_breakpoint (cw);

  all_labels_resolved = gum_arm_writer_flush (cw);
  if (!all_labels_resolved)
    g_error ("Failed to resolve labels");

  block->code_end = gum_arm_writer_cur (cw);
  block->real_end = (guint8 *) rl->input_cur;

  gum_exec_block_commit_and_emit (block);

  return block;
}

static GumExecBlock *
gum_exec_ctx_obtain_thumb_block_for (GumExecCtx * ctx,
                                     gpointer real_address,
                                     gpointer * code_address_ptr)
{
  GumExecBlock * block;
  gpointer aligned_address;
  GumThumbWriter * cw;
  GumThumbRelocator * rl;
  GumGeneratorContext gc;
  GumStalkerIterator iterator;
  GumStalkerOutput output;
  gboolean all_labels_resolved;

  block = gum_exec_block_obtain_trusted (ctx, real_address, code_address_ptr);
  if (block != NULL)
    return block;

  block = gum_exec_block_new (ctx);
  aligned_address = GSIZE_TO_POINTER (GPOINTER_TO_SIZE (real_address) & ~0x1);
  block->real_begin = aligned_address;
  *code_address_ptr = block->code_begin + 1;

  if (ctx->stalker->trust_threshold >= 0)
    gum_metal_hash_table_insert (ctx->mappings, real_address, block);

  cw = &ctx->thumb_writer;
  rl = &ctx->thumb_relocator;

  gum_thumb_writer_reset (cw, block->code_begin);
  gum_thumb_relocator_reset (rl, aligned_address, cw);

  gum_ensure_code_readable (aligned_address, ctx->stalker->page_size);

  gc.instruction = NULL;
  gc.is_thumb = TRUE;
  gc.thumb_relocator = rl;
  gc.thumb_writer = cw;
  gc.continuation_real_address = NULL;
  gc.exclusive_load_offset = GUM_INSTRUCTION_OFFSET_NONE;

  iterator.exec_context = ctx;
  iterator.exec_block = block;
  iterator.generator_context = &gc;

  iterator.instruction.ci = NULL;
  iterator.instruction.begin = NULL;
  iterator.instruction.end = NULL;

  output.writer.thumb = cw;
  output.encoding = GUM_INSTRUCTION_SPECIAL;

  ctx->pending_calls++;

  ctx->transform_block_impl (ctx->transformer, &iterator, &output);

  ctx->pending_calls--;

  if (gc.continuation_real_address != NULL)
  {
    /*
     * This is required to support the situation where the amount of code
     * emitted to instrument a block exceeds the minimum we check for before we
     * start instrumenting a block and it needs to be split. This is only likely
     * to be of concern for very long linear execution blocks.
     */
    g_error ("continuation_real_address unsupported");
  }

  gum_thumb_writer_put_breakpoint (cw);

  all_labels_resolved = gum_thumb_writer_flush (cw);
  if (!all_labels_resolved)
    g_error ("Failed to resolve labels");

  block->code_end = gum_thumb_writer_cur (cw);
  block->real_end = (guint8 *) rl->input_cur;

  gum_exec_block_commit_and_emit (block);

  return block;
}

gboolean
gum_stalker_iterator_next (GumStalkerIterator * self,
                           const cs_insn ** insn)
{
  GumGeneratorContext * gc = self->generator_context;

  if (gc->is_thumb)
    return gum_stalker_iterator_thumb_next (self, insn);
  else
    return gum_stalker_iterator_arm_next (self, insn);
}

static gboolean
gum_stalker_iterator_arm_next (GumStalkerIterator * self,
                               const cs_insn ** insn)
{
  GumGeneratorContext * gc = self->generator_context;
  GumArmRelocator * rl = gc->arm_relocator;
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
      gum_arm_relocator_skip_one (rl);
    }

    block->code_end = gum_arm_writer_cur (gc->arm_writer);

    if (gum_exec_block_is_full (block))
    {
      gc->continuation_real_address = instruction->end;
      return FALSE;
    }

    if (gum_arm_relocator_eob (rl) &&
        gc->exclusive_load_offset == GUM_INSTRUCTION_OFFSET_NONE)
    {
      return FALSE;
    }

    if (gum_is_exclusive_store_insn (instruction->ci))
      gc->exclusive_load_offset = GUM_INSTRUCTION_OFFSET_NONE;

    gum_generator_context_advance_exclusive_load_offset (gc);
  }

  instruction = &self->instruction;

  n_read = gum_arm_relocator_read_one (rl, &instruction->ci);
  if (n_read == 0)
    return FALSE;

  instruction->begin = GSIZE_TO_POINTER (instruction->ci->address);
  instruction->end = (guint8 *) rl->input_cur;

  self->generator_context->instruction = instruction;

  if (insn != NULL)
    *insn = instruction->ci;

  return TRUE;
}

static gboolean
gum_stalker_iterator_thumb_next (GumStalkerIterator * self,
                                 const cs_insn ** insn)
{
  GumGeneratorContext * gc = self->generator_context;
  GumThumbRelocator * rl = gc->thumb_relocator;
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
      gum_thumb_relocator_skip_one (rl);
    }

    block->code_end = gum_thumb_writer_cur (gc->thumb_writer);

    if (gum_exec_block_is_full (block))
    {
      gc->continuation_real_address = instruction->end;
      return FALSE;
    }

    if (gum_thumb_relocator_eob (rl) &&
        gc->exclusive_load_offset == GUM_INSTRUCTION_OFFSET_NONE)
    {
      return FALSE;
    }

    if (gum_is_exclusive_store_insn (instruction->ci))
      gc->exclusive_load_offset = GUM_INSTRUCTION_OFFSET_NONE;

    gum_generator_context_advance_exclusive_load_offset (gc);
  }

  instruction = &self->instruction;

  n_read = gum_thumb_relocator_read_one (rl, &instruction->ci);
  if (n_read == 0)
    return FALSE;

  instruction->begin = GSIZE_TO_POINTER (instruction->ci->address);
  instruction->end = (guint8 *) rl->input_cur;

  self->generator_context->instruction = instruction;

  if (insn != NULL)
    *insn = instruction->ci;

  return TRUE;
}

void
gum_stalker_iterator_keep (GumStalkerIterator * self)
{
  GumGeneratorContext * gc = self->generator_context;

  if (gum_is_exclusive_load_insn (gc->instruction->ci))
      gc->exclusive_load_offset = 0;

  if (gc->is_thumb)
    gum_stalker_iterator_thumb_keep (self);
  else
    gum_stalker_iterator_arm_keep (self);
}

static void
gum_stalker_iterator_arm_keep (GumStalkerIterator * self)
{
  GumExecBlock * block = self->exec_block;
  GumGeneratorContext * gc = self->generator_context;
  const cs_insn * insn = gc->instruction->ci;

  if (gum_arm_relocator_eob (gc->arm_relocator))
  {
    GumBranchTarget target;
    guint16 mask;
    cs_arm * arm = &insn->detail->arm;
    GumWriteback writeback = { .target = ARM_REG_INVALID };

    mask = 0;

    gum_stalker_get_target_address (insn, FALSE, &target, &mask);

    switch (insn->id)
    {
      case ARM_INS_LDR:
        gum_stalker_arm_get_writeback (insn, &writeback);
        /* Deliberate fall-through */
      case ARM_INS_SUB:
      case ARM_INS_ADD:
      case ARM_INS_B:
      case ARM_INS_BX:
        gum_exec_block_virtualize_arm_branch_insn (block, &target, arm->cc,
            &writeback, gc);
        break;
      case ARM_INS_BL:
      case ARM_INS_BLX:
        gum_exec_block_virtualize_arm_call_insn (block, &target, arm->cc, gc);
        break;
      case ARM_INS_MOV:
        gum_exec_block_virtualize_arm_ret_insn (block, &target, arm->cc, FALSE,
            0, gc);
        break;
      case ARM_INS_POP:
      case ARM_INS_LDM:
        gum_exec_block_virtualize_arm_ret_insn (block, &target, arm->cc, TRUE,
            mask, gc);
        break;
      case ARM_INS_SMC:
      case ARM_INS_HVC:
        g_error ("not implemented");
        break;
      default:
        g_assert_not_reached ();
        break;
    }
  }
  else if (insn->id == ARM_INS_SVC)
  {
    gum_exec_block_virtualize_arm_svc_insn (block, gc);
  }
  else
  {
    gum_exec_block_dont_virtualize_arm_insn (block, gc);
  }
}

static void
gum_stalker_iterator_thumb_keep (GumStalkerIterator * self)
{
  GumExecBlock * block = self->exec_block;
  GumGeneratorContext * gc = self->generator_context;
  const cs_insn * insn = gc->instruction->ci;

  if (gum_thumb_relocator_eob (gc->thumb_relocator))
    gum_stalker_iterator_handle_thumb_branch_insn (self, insn);
  else
    gum_exec_block_dont_virtualize_thumb_insn (block, gc);
}

static void
gum_stalker_iterator_handle_thumb_branch_insn (GumStalkerIterator * self,
                                               const cs_insn * insn)
{
  GumExecBlock * block = self->exec_block;
  GumGeneratorContext * gc = self->generator_context;
  GumBranchTarget target;
  guint16 mask;
  cs_arm * arm = &insn->detail->arm;

  switch (insn->id)
  {
    case ARM_INS_B:
    case ARM_INS_BX:
    case ARM_INS_LDR:
    case ARM_INS_TBB:
    case ARM_INS_TBH:
      gum_stalker_get_target_address (insn, TRUE, &target, &mask);
      gum_exec_block_virtualize_thumb_branch_insn (block, &target, arm->cc,
          ARM_REG_INVALID, gc);
      break;
    case ARM_INS_CBZ:
      g_assert (arm->operands[0].type == ARM_OP_REG);
      gum_stalker_get_target_address (insn, TRUE, &target, &mask);
      gum_exec_block_virtualize_thumb_branch_insn (block, &target, ARM_CC_EQ,
          arm->operands[0].reg, gc);
      break;
    case ARM_INS_CBNZ:
      g_assert (arm->operands[0].type == ARM_OP_REG);
      gum_stalker_get_target_address (insn, TRUE, &target, &mask);
      gum_exec_block_virtualize_thumb_branch_insn (block, &target, ARM_CC_NE,
          arm->operands[0].reg, gc);
      break;
    case ARM_INS_BL:
    case ARM_INS_BLX:
      gum_stalker_get_target_address (insn, TRUE, &target, &mask);
      gum_exec_block_virtualize_thumb_call_insn (block, &target, gc);
      break;
    case ARM_INS_MOV:
    case ARM_INS_POP:
    case ARM_INS_LDM:
      gum_stalker_get_target_address (insn, TRUE, &target, &mask);
      gum_exec_block_virtualize_thumb_ret_insn (block, &target, mask, gc);
      break;
    case ARM_INS_SMC:
    case ARM_INS_HVC:
      g_error ("Unsupported");
      break;
    case ARM_INS_SVC:
      gum_exec_block_virtualize_thumb_svc_insn (block, gc);
      break;
    case ARM_INS_IT:
      gum_stalker_iterator_handle_thumb_it_insn (self);
      break;
    default:
      g_assert_not_reached ();
      break;
  }
}

static void
gum_stalker_iterator_handle_thumb_it_insn (GumStalkerIterator * self)
{
  GumExecBlock * block = self->exec_block;
  GumGeneratorContext * gc = self->generator_context;
  GumThumbRelocator * rl = gc->thumb_relocator;
  const cs_insn * insn;

  /*
   * This function needs only to handle IT blocks which terminate with a branch
   * instruction. Those which contain no branches will not set the EOB condition
   * when read by the relocator and will be handled without the need for
   * virtualization. The block will simply be processed as usual by the
   * relocator.
   */

  /*
   * We emit a single EXEC event for an IT block. Execution of a final branch
   * instruction contained within it can result in additional events being
   * generated. We cannot emit one event for each instruction that is contained
   * within the IT block since they are re-ordered by the relocator. This is
   * necessary since the original IT block must be replaced with branches and
   * labels as individual instructions may need to be replaced by multiple
   * instructions as a result of relocation.
   */
  if ((block->ctx->sink_mask & GUM_EXEC) != 0)
  {
    gum_exec_block_thumb_open_prolog (block, gc);
    gum_exec_block_write_thumb_exec_event_code (block, gc);
    gum_exec_block_thumb_close_prolog (block, gc);
  }

  for (insn = gum_thumb_relocator_peek_next_write_insn (rl);
      insn != NULL;
      insn = gum_thumb_relocator_peek_next_write_insn (rl))
  {
    if (gum_thumb_relocator_is_eob_instruction (insn))
    {
      /*
       * Remove unnecessary conditional execution of the instruction since it is
       * wrapped within a series of branches by the relocator to handle the
       * if/then/else conditional execution.
       */
      insn->detail->arm.cc = ARM_CC_AL;
      gum_stalker_iterator_handle_thumb_branch_insn (self, insn);

      /*
       * Put a breakpoint to trap and detect any errant continued execution (the
       * branch should handle any possible continuation). Skip the original
       * branch instruction.
       */
      gum_thumb_writer_put_breakpoint (gc->thumb_writer);
      gum_thumb_relocator_skip_one (gc->thumb_relocator);
    }
    else
    {
      /*
       * If the instruction in the IT block is not a branch, then just emit the
       * relocated instruction as normal.
       */
      gum_thumb_relocator_write_one (gc->thumb_relocator);
    }
  }

  /*
   * Should we reach the end of the IT block (e.g. we did not take the branch)
   * we write code here to continue with the next instruction after the IT block
   * just as we do following a branch or call instruction. (We do this for
   * branches too as we cannot detect tail-calls and we can't be sure the callee
   * won't return). This results in the continuation code being written twice,
   * which is not strictly necessary. However, attempting to optimize this is
   * likely to be quite tricky.
   */
  gum_exec_block_thumb_open_prolog (block, gc);
  gum_exec_block_write_thumb_handle_continue (block, gc);
}

static void
gum_stalker_get_target_address (const cs_insn * insn,
                                gboolean thumb,
                                GumBranchTarget * target,
                                guint16 * mask)
{
  cs_arm * arm = &insn->detail->arm;
  cs_arm_op * op1 = &arm->operands[0];

  /*
   * The complex nature of the ARM32 instruction set means that determining the
   * target address for an instruction which affects control flow is also
   * complex.
   *
   * Instructions such as 'BL label' will make use of the absolute_address
   * field. 'BL reg' and 'BLX' reg will make use of the reg field. 'LDR pc,
   * [reg]' however makes use of the reg field and sets is_indirect to TRUE.
   * This means that the reg field doesn't contain the target itself, but the
   * address in memory where the target is stored. 'LDR pc, [reg, #x]'
   * additionally sets the offset field which needs to be added to the register
   * before it is dereferenced.
   *
   * The POP and LDM instructions both read multiple values from where a base
   * register points, and store them into a listed set of registers. In the case
   * of the POP instruction, this base register is always SP, i.e. the stack
   * pointer. Again the is_indirect field is set and the value of the offset
   * field is determined by how many registers are included in the register list
   * before PC.
   *
   * Finally, ADD and SUB instructions can be used to modify control flow. ADD
   * instructions have two main forms. Firstly 'ADD pc, reg, #x', in this case
   * the reg and offset fields are both set accordingly. Secondly, if the form
   * 'ADD pc, reg, reg2' is used, then the values of reg and reg2 are set
   * accordingly. This form has the additional complexity of allowing a suffix
   * which can describe a shift operation (one of 4 types) and a value
   * indicating how many places to shift to be applied to reg2 before it is
   * added. This information is encoded in the shifter and shift_value fields
   * accordingly. Lastly the SUB instruction is identical to ADD except the
   * offset is negative, to indicate that reg2 should be subtracted rather than
   * added.
   *
   * This complex target field is processed by write_$mode_mov_branch_target()
   * in order to write instructions into the instrumented block to recover the
   * target address from these different forms of instruction.
   *
   * Lastly, we should note that many of these instructions can be conditionally
   * executed depending on the status of processor flags. For example, BLEQ will
   * only take affect if the previous instruction which set the flags indicated
   * the result of the operation was equal.
   */

  /*
   * The mask is used when POP or LDMIA instructions are encountered. This is
   * used to encode the other registers which are included in the operation.
   * Note, however, that the register PC is omitted from this mask.
   *
   * This is processed by virtualize_ret_insn() so that after the epilogue has
   * been executed and the application registers are restored. A replacement POP
   * or LDMIA instruction can be generated to restore the values of the other
   * registers from the stack. Note that we don't restore the value of PC from
   * the stack and instead simply increment the stack pointer since we instead
   * want to pass control back into Stalker to instrument the next block.
   */
  *mask = 0;

  switch (insn->id)
  {
    case ARM_INS_B:
    case ARM_INS_BL:
    {
      GumBranchDirectAddress * value = &target->value.direct_address;

      g_assert (op1->type == ARM_OP_IMM);

      target->type = GUM_TARGET_DIRECT_ADDRESS;

      /*
       * If the case of the B and BL instructions, the instruction mode never
       * changes from ARM to Thumb or vice-versa and hence the low bit of the
       * target address should be retained.
       */
      if (thumb)
        value->address = GSIZE_TO_POINTER (op1->imm + 1);
      else
        value->address = GSIZE_TO_POINTER (op1->imm);

      break;
    }
    case ARM_INS_BX:
    case ARM_INS_BLX:
    {
      if (op1->type == ARM_OP_REG)
      {
        GumBranchDirectRegOffset * value = &target->value.direct_reg_offset;

        target->type = GUM_TARGET_DIRECT_REG_OFFSET;

        value->reg = op1->reg;
        value->offset = 0;
      }
      else
      {
        GumBranchDirectAddress * value = &target->value.direct_address;

        target->type = GUM_TARGET_DIRECT_ADDRESS;

        /*
         * In the case of the BX and BLX instructions, the instruction mode
         * always changes from ARM to Thumb or vice-versa and hence the low
         * bit of the target address should be inverted.
         */
        if (thumb)
          value->address = GSIZE_TO_POINTER (op1->imm);
        else
          value->address = GSIZE_TO_POINTER (op1->imm) + 1;
      }

      break;
    }
    case ARM_INS_CBZ:
    case ARM_INS_CBNZ:
    {
      GumBranchDirectAddress * value = &target->value.direct_address;
      cs_arm_op * op2 = &arm->operands[1];

      /*
       * If the case of the CBZ and CBNZ instructions, the instruction mode
       * never changes and hence the low bit of the target address should be
       * retained. These are only supported in Thumb mode.
       */
      g_assert (thumb);

      target->type = GUM_TARGET_DIRECT_ADDRESS;

      value->address = GSIZE_TO_POINTER (op2->imm + 1);

      break;
    }
    case ARM_INS_POP:
    {
      GumBranchIndirectRegOffset * value = &target->value.indirect_reg_offset;
      guint8 i;

      target->type = GUM_TARGET_INDIRECT_REG_OFFSET;

      value->reg = ARM_REG_SP;
      value->offset = 0;

      for (i = 0; i != insn->detail->arm.op_count; i++)
      {
        cs_arm_op * op = &arm->operands[i];

        if (op->reg == ARM_REG_PC)
        {
          value->offset = i * 4;
        }
        else
        {
          GumArmRegInfo ri;
          gum_arm_reg_describe (op->reg, &ri);
          *mask |= 1 << ri.index;
        }
      }

      break;
    }
    case ARM_INS_LDM:
    {
      GumBranchIndirectRegOffset * value = &target->value.indirect_reg_offset;
      guint8 i;

      target->type = GUM_TARGET_INDIRECT_REG_OFFSET;

      value->reg = op1->reg;
      value->offset = 0;

      for (i = 1; i != insn->detail->arm.op_count; i++)
      {
        cs_arm_op * op = &arm->operands[i];

        if (op->reg == ARM_REG_PC)
        {
          value->offset = (i - 1) * 4;
        }
        else
        {
          GumArmRegInfo ri;
          gum_arm_reg_describe (op->reg, &ri);
          *mask |= 1 << ri.index;
        }
      }

      break;
    }
    case ARM_INS_LDR:
    {
      GumBranchIndirectRegOffset * value = &target->value.indirect_reg_offset;
      cs_arm_op * op2 = &arm->operands[1];

      g_assert (op2->type == ARM_OP_MEM);
      g_assert (op2->mem.index == ARM_REG_INVALID);

      target->type = GUM_TARGET_INDIRECT_REG_OFFSET;

      value->reg = op2->mem.base;
      value->offset = op2->mem.disp;

      break;
    }
    case ARM_INS_MOV:
    {
      GumBranchDirectRegOffset * value = &target->value.direct_reg_offset;

      cs_arm_op * op2 = &arm->operands[1];

      target->type = GUM_TARGET_DIRECT_REG_OFFSET;

      value->reg = op2->reg;
      value->offset = 0;

      break;
    }
    case ARM_INS_ADD:
    case ARM_INS_SUB:
    {
      cs_arm_op * base = &arm->operands[1];
      cs_arm_op * index = &arm->operands[2];

      g_assert (base->type == ARM_OP_REG);

      if (index->type == ARM_OP_REG)
      {
        GumBranchDirectRegShift * value = &target->value.direct_reg_shift;

        target->type = GUM_TARGET_DIRECT_REG_SHIFT;

        value->base = base->reg;
        value->index = index->reg;
        value->shifter = index->shift.type;
        value->shift_value = index->shift.value;
      }
      else
      {
        GumBranchDirectRegOffset * value = &target->value.direct_reg_offset;

        target->type = GUM_TARGET_DIRECT_REG_OFFSET;

        value->reg = base->reg;
        value->offset = (insn->id == ARM_INS_SUB) ? -index->imm : index->imm;
      }

      break;
    }
    case ARM_INS_TBB:
    case ARM_INS_TBH:
    {
      arm_op_mem * op = &arm->operands[0].mem;
      GumBranchIndirectPcrelTable * value = &target->value.indirect_pcrel_table;

      target->type = GUM_TARGET_INDIRECT_PCREL_TABLE;

      value->base = op->base;
      value->index = op->index;

      value->element_size = (insn->id == ARM_INS_TBB)
          ? sizeof (guint8)
          : sizeof (guint16);

      break;
    }
    default:
      g_assert_not_reached ();
  }
}

static void
gum_stalker_arm_get_writeback (const cs_insn * insn,
                               GumWriteback * writeback)
{
  cs_arm * arm = &insn->detail->arm;
  cs_arm_op * op2 = &arm->operands[1];

  writeback->target = ARM_REG_INVALID;
  writeback->offset = 0;

  if (!arm->writeback)
    return;

  if (insn->id != ARM_INS_LDR)
    g_error ("Writeback for unexpected op-code: %d", insn->id);

  if (op2->type != ARM_OP_MEM)
    g_error ("Writeback for unexpected operand");

  if (op2->mem.index != ARM_REG_INVALID)
    g_error ("Writeback for register operands not supported");

  writeback->target = op2->mem.base;

  switch (arm->op_count)
  {
    case 2: /* pre-increment/decrement */
    {
      writeback->offset = op2->mem.disp;
      break;
    }
    case 3: /* post-increment/decrement */
    {
      cs_arm_op * op3 = &arm->operands[2];

      g_assert (op3->type == ARM_OP_IMM);

      writeback->offset = op3->subtracted ? -op3->imm : op3->imm;

      break;
    }
    default:
    {
      g_assert_not_reached ();
    }
  }
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

  /*
   * Suppress generation of multiple EXEC events for IT blocks. An exec event
   * is already generated for the IT block, but a subsequent one may be
   * generated by the handling of a virtualized branch instruction if it is
   * taken. We simply ignore the request if the location is the same as the
   * previously emitted event.
   */
  if (location == ctx->last_exec_location)
    return;

  ctx->last_exec_location = location;

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

  if (gc->is_thumb)
  {
    gum_exec_block_thumb_open_prolog (block, gc);

    gum_thumb_writer_put_call_address_with_arguments (gc->thumb_writer,
        GUM_ADDRESS (gum_stalker_invoke_callout), 2,
        GUM_ARG_REGISTER, ARM_REG_R10,
        GUM_ARG_ADDRESS, GUM_ADDRESS (entry));

    gum_exec_block_thumb_close_prolog (block, gc);
  }
  else
  {
    gum_exec_block_arm_open_prolog (block, gc);

    gum_arm_writer_put_call_address_with_arguments (gc->arm_writer,
        GUM_ADDRESS (gum_stalker_invoke_callout), 2,
        GUM_ARG_REGISTER, ARM_REG_R10,
        GUM_ARG_ADDRESS, GUM_ADDRESS (entry));

    gum_exec_block_arm_close_prolog (block, gc);
  }

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
gum_exec_ctx_write_arm_prolog (GumExecCtx * ctx,
                               GumArmWriter * cw)
{
  gint immediate_for_sp = 0;

  /*
   * For our context, we want to build up the following structure so that
   * Stalker can read the register state of the application.
   *
   * struct _GumArmCpuContext
   * {
   *   guint32 cpsr;
   *   guint32 pc;
   *   guint32 sp;
   *
   *   guint32 r8;
   *   guint32 r9;
   *   guint32 r10;
   *   guint32 r11;
   *   guint32 r12;
   *
   *   guint32 r[8];
   *   guint32 lr;
   * };
   */

  /* Store R0 through R7 and LR */
  gum_arm_writer_put_push_registers (cw, 9,
      ARM_REG_R0, ARM_REG_R1, ARM_REG_R2,
      ARM_REG_R3, ARM_REG_R4, ARM_REG_R5,
      ARM_REG_R6, ARM_REG_R7, ARM_REG_LR);
  immediate_for_sp += 9 * 4;

  /* Store R8 through R12 */
  gum_arm_writer_put_push_registers (cw, 5,
      ARM_REG_R8, ARM_REG_R9, ARM_REG_R10,
      ARM_REG_R11, ARM_REG_R12);
  immediate_for_sp += 5 * 4;

  /*
   * Calculate the original value that SP would have held prior to this function
   * by adding on the amount of registers pushed so far and store it in R2.
   */
  gum_arm_writer_put_add_reg_reg_imm (cw, ARM_REG_R2, ARM_REG_SP,
      immediate_for_sp);

  /*
   * Zero the register R1. This will be used to store the value of PC. If a
   * function inside Stalker wants to retrieve the value of PC according to the
   * guest then it must interrogate the iterator being used to process the
   * original instruction stream. Since the guest will be executing instrumented
   * code, the value of PC if we pushed it here would not be the value of PC
   * within the original block anyway.
   *
   * The data within this context block is read by the instrumented instructions
   * emitted by load_real_register_into() and this takes this edge case into
   * account.
   */
  gum_arm_writer_put_sub_reg_reg_reg (cw, ARM_REG_R1, ARM_REG_R1, ARM_REG_R1);

  /* Read the flags register CPSR into R0 */
  gum_arm_writer_put_mov_reg_cpsr (cw, ARM_REG_R0);

  /*
   * Push the values of R0, R1 and R2 containing the CPSR, zeroed PC and
   * adjusted stack pointer respectively.
   */
  gum_arm_writer_put_push_registers (cw, 3,
      ARM_REG_R0, ARM_REG_R1, ARM_REG_R2);

  /*
   * Now that the context structure has been pushed onto the stack, we store the
   * address of this structure on the stack into register R10. This register can
   * be chosen fairly arbitrarily but it should be a callee saved register so
   * that any C code called from our instrumented code is obliged by the calling
   * convention to preserve its value across the function call. In particular
   * register R12 is a caller saved register and as such any C function can
   * modify its value and not restore it. Similary registers R0 through R3
   * contain the arguments to the function and the return result and are
   * accordingly not preserved.
   *
   * We have elected not to use R11 since this can be used as a frame pointer by
   * some compilers and as such can confuse some debuggers. The function
   * load_real_register_into() makes use of this register R10 in order to access
   * this context structure.
   */
  gum_arm_writer_put_mov_reg_reg (cw, ARM_REG_R10, ARM_REG_SP);

  /*
   * We must now ensure that the stack is 8 byte aligned, since this is expected
   * by the ABI. Since the context was on the top of the stack and we retain
   * this address in R10, we don't need to save the original stack pointer for
   * re-alignment in the epilogue since we can simply restore SP from R10.
   */
  gum_arm_writer_put_ands_reg_reg_imm (cw, ARM_REG_R0, ARM_REG_SP, 7);
  gum_arm_writer_put_sub_reg_reg_reg (cw, ARM_REG_SP, ARM_REG_SP, ARM_REG_R0);
}

static void
gum_exec_ctx_write_thumb_prolog (GumExecCtx * ctx,
                                 GumThumbWriter * cw)
{
  gint immediate_for_sp = 0;

  gum_thumb_writer_put_push_regs (cw, 9,
      ARM_REG_R0, ARM_REG_R1, ARM_REG_R2,
      ARM_REG_R3, ARM_REG_R4, ARM_REG_R5,
      ARM_REG_R6, ARM_REG_R7, ARM_REG_LR);
  immediate_for_sp += 9 * 4;

  gum_thumb_writer_put_push_regs (cw, 5,
      ARM_REG_R8, ARM_REG_R9, ARM_REG_R10,
      ARM_REG_R11, ARM_REG_R12);
  immediate_for_sp += 5 * 4;

  /*
   * Note that we stash the CPSR (flags) here first since the Thumb instruction
   * set doesn't support short form instructions for SUB. Hence, the calculation
   * for the adjusted SP below is actually a SUBS and will clobber the flags.
   */
  gum_thumb_writer_put_mov_reg_cpsr (cw, ARM_REG_R0);

  gum_thumb_writer_put_sub_reg_reg_reg (cw, ARM_REG_R1, ARM_REG_R1,
      ARM_REG_R1);

  gum_thumb_writer_put_add_reg_reg_imm (cw, ARM_REG_R2, ARM_REG_SP,
      immediate_for_sp);

  gum_thumb_writer_put_push_regs (cw, 3,
      ARM_REG_R0, ARM_REG_R1, ARM_REG_R2);

  gum_thumb_writer_put_mov_reg_reg (cw, ARM_REG_R10, ARM_REG_SP);

  /*
   * Like in the ARM prolog we must now ensure that the stack is 8 byte aligned.
   * Note that unlike the ARM prolog, which simply rounds down the stack
   * pointer, the Thumb instruction set often requires wide, or Thumb v2
   * instructions to work with registers other than R0-R7. We therefore retard
   * the stack by 8, before rounding back up. This works as we know the stack
   * must be 4 byte aligned since ARM architecture does not support unaligned
   * data access. e.g. if the stack was already aligned, we simply retard the
   * pointer by 8 (although wasting a few bytes of stack space, this still
   * retains alignment), if it was misaligned, we retard the pointer by 8 before
   * advancing back 4 bytes.
   */
  gum_thumb_writer_put_and_reg_reg_imm (cw, ARM_REG_R0, ARM_REG_SP, 7);
  gum_thumb_writer_put_sub_reg_reg_imm (cw, ARM_REG_SP, ARM_REG_SP, 8);
  gum_thumb_writer_put_add_reg_reg_reg (cw, ARM_REG_SP, ARM_REG_SP, ARM_REG_R0);
}

static void
gum_exec_ctx_write_arm_epilog (GumExecCtx * ctx,
                               GumArmWriter * cw)
{
  /*
   * We know that the context structure was at the top of the stack at the end
   * of the prolog, before the stack was aligned. Rather than working out how
   * much alignment was needed, we can simply restore R10 back into SP to
   * retrieve our stack pointer pre-alignment before we continue restoring the
   * rest of the context.
   */
  gum_arm_writer_put_mov_reg_reg (cw, ARM_REG_SP, ARM_REG_R10);

  gum_arm_writer_put_pop_registers (cw, 3,
      ARM_REG_R0, ARM_REG_R1, ARM_REG_R2);

  gum_arm_writer_put_mov_cpsr_reg (cw, ARM_REG_R0);

  gum_arm_writer_put_pop_registers (cw, 5,
      ARM_REG_R8, ARM_REG_R9, ARM_REG_R10,
      ARM_REG_R11, ARM_REG_R12);

  gum_arm_writer_put_pop_registers (cw, 9,
      ARM_REG_R0, ARM_REG_R1, ARM_REG_R2,
      ARM_REG_R3, ARM_REG_R4, ARM_REG_R5,
      ARM_REG_R6, ARM_REG_R7, ARM_REG_LR);
}

static void
gum_exec_ctx_write_thumb_epilog (GumExecCtx * ctx,
                                 GumThumbWriter * cw)
{
  gum_thumb_writer_put_mov_reg_reg (cw, ARM_REG_SP, ARM_REG_R10);

  gum_thumb_writer_put_pop_regs (cw, 3,
      ARM_REG_R0, ARM_REG_R1, ARM_REG_R2);

  gum_thumb_writer_put_mov_cpsr_reg (cw, ARM_REG_R0);

  gum_thumb_writer_put_pop_regs (cw, 5,
      ARM_REG_R8, ARM_REG_R9, ARM_REG_R10,
      ARM_REG_R11, ARM_REG_R12);

  gum_thumb_writer_put_pop_regs (cw, 9,
      ARM_REG_R0, ARM_REG_R1, ARM_REG_R2,
      ARM_REG_R3, ARM_REG_R4, ARM_REG_R5,
      ARM_REG_R6, ARM_REG_R7, ARM_REG_LR);
}

static void
gum_exec_ctx_write_arm_mov_branch_target (GumExecCtx * ctx,
                                          const GumBranchTarget * target,
                                          arm_reg reg,
                                          GumGeneratorContext * gc)
{
  GumArmWriter * cw = gc->arm_writer;

  switch (target->type)
  {
    case GUM_TARGET_DIRECT_ADDRESS: /* E.g. 'B #1234' */
    {
      const GumBranchDirectAddress * value = &target->value.direct_address;

      gum_arm_writer_put_ldr_reg_address (cw, reg,
          GUM_ADDRESS (value->address));

      break;
    }
    case GUM_TARGET_DIRECT_REG_OFFSET: /* E.g. 'ADD/SUB pc, r1, #32' */
    {
      const GumBranchDirectRegOffset * value = &target->value.direct_reg_offset;

      gum_exec_ctx_arm_load_real_register_into (ctx, reg, value->reg, gc);

      if (value->offset >= 0)
        gum_arm_writer_put_add_reg_reg_imm (cw, reg, reg, value->offset);
      else
        gum_arm_writer_put_sub_reg_reg_imm (cw, reg, reg, -value->offset);

      break;
    }
    case GUM_TARGET_DIRECT_REG_SHIFT: /* E.g. 'ADD pc, r1, r2 lsl #4' */
    {
      const GumBranchDirectRegShift * value = &target->value.direct_reg_shift;

      gum_exec_ctx_arm_load_real_register_into (ctx, reg, value->base, gc);

      /*
       * Here we are going to use R12 as additional scratch space for our
       * calculation since it is the only register which is not callee saved.
       * Thus since we are already using 'reg' as our output register, we cannot
       * have the two collide. This should not be an issue since the callers of
       * this funtion are all instrumented code generated by the Stalker and the
       * value of the branch target address is usually used as an argument to
       * another function and hence is generally loaded into one of the
       * registers used to hold arguments defined by the ABI (R0-R3).
       */
      if (reg == ARM_REG_R12)
      {
        g_error ("Cannot support ADD/SUB reg, reg, reg when target is "
            "ARM_REG_R12");
      }

      /*
       * Load the second register value from the context into R12 before adding
       * to the original and applying any necessary shift.
       */
      gum_exec_ctx_arm_load_real_register_into (ctx, ARM_REG_R12, value->index,
          gc);

      gum_arm_writer_put_add_reg_reg_reg_shift (cw, reg, reg, ARM_REG_R12,
          value->shifter, value->shift_value);

      break;
    }
    case GUM_TARGET_INDIRECT_REG_OFFSET: /* E.g. 'LDR pc, [r3, #4]' */
    {
      const GumBranchIndirectRegOffset * value =
          &target->value.indirect_reg_offset;

      gum_exec_ctx_arm_load_real_register_into (ctx, reg, value->reg, gc);

      /*
       * If the target is indirect, then we need to dereference it.
       * E.g. LDR pc, [r3, #4]
       */
      gum_arm_writer_put_ldr_reg_reg_offset (cw, reg, reg, value->offset);

      break;
    }
    default:
      g_assert_not_reached ();
  }
}

static void
gum_exec_ctx_write_thumb_mov_branch_target (GumExecCtx * ctx,
                                            const GumBranchTarget * target,
                                            arm_reg reg,
                                            GumGeneratorContext * gc)
{
  GumThumbWriter * cw = gc->thumb_writer;

  switch (target->type)
  {
    case GUM_TARGET_DIRECT_ADDRESS:
    {
      const GumBranchDirectAddress * value = &target->value.direct_address;

      gum_thumb_writer_put_ldr_reg_address (cw, reg,
          GUM_ADDRESS (value->address));

      break;
    }
    case GUM_TARGET_DIRECT_REG_OFFSET:
    {
      const GumBranchDirectRegOffset * value = &target->value.direct_reg_offset;

      g_assert (value->offset >= 0);

      gum_exec_ctx_thumb_load_real_register_into (ctx, reg, value->reg, gc);

      gum_thumb_writer_put_add_reg_reg_imm (cw, reg, reg, value->offset);

      break;
    }
    case GUM_TARGET_DIRECT_REG_SHIFT:
    {
      g_assert_not_reached ();
      break;
    }
    case GUM_TARGET_INDIRECT_REG_OFFSET:
    {
      const GumBranchIndirectRegOffset * value =
          &target->value.indirect_reg_offset;

      g_assert (value->offset >= 0);

      gum_exec_ctx_thumb_load_real_register_into (ctx, reg, value->reg, gc);

      /*
       * If the target is indirect, then we need to dereference it.
       * E.g. LDR pc, [r3, #4]
       */
      gum_thumb_writer_put_ldr_reg_reg_offset (cw, reg, reg, value->offset);

      break;
    }
    case GUM_TARGET_INDIRECT_PCREL_TABLE:
    {
      const GumBranchIndirectPcrelTable * value =
          &target->value.indirect_pcrel_table;
      arm_reg offset_reg;

      gum_exec_ctx_thumb_load_real_register_into (ctx, reg, value->base, gc);

      offset_reg = (reg != ARM_REG_R0) ? ARM_REG_R0 : ARM_REG_R1;
      gum_thumb_writer_put_push_regs (cw, 1, offset_reg);

      gum_exec_ctx_thumb_load_real_register_into (ctx, offset_reg, value->index,
          gc);
      if (value->element_size == 2)
      {
        /* Transform index to offset. */
        gum_thumb_writer_put_lsls_reg_reg_imm (cw, offset_reg, offset_reg, 1);
      }

      /* Add base address. */
      gum_thumb_writer_put_add_reg_reg (cw, offset_reg, reg);

      /* Read the uint8 or uint16 at the given index. */
      if (value->element_size == 1)
        gum_thumb_writer_put_ldrb_reg_reg (cw, offset_reg, offset_reg);
      else
        gum_thumb_writer_put_ldrh_reg_reg (cw, offset_reg, offset_reg);
      /* Transform index to offset. */
      gum_thumb_writer_put_lsls_reg_reg_imm (cw, offset_reg, offset_reg, 1);

      /* Add Thumb bit. */
      gum_thumb_writer_put_add_reg_imm (cw, offset_reg, 1);

      /* Now we have an offset we can add to the base. */
      gum_thumb_writer_put_add_reg_reg_reg (cw, reg, reg, offset_reg);

      gum_thumb_writer_put_pop_regs (cw, 1, offset_reg);

      break;
    }
    default:
      g_assert_not_reached ();
  }
}

static void
gum_exec_ctx_arm_load_real_register_into (GumExecCtx * ctx,
                                          arm_reg target_register,
                                          arm_reg source_register,
                                          GumGeneratorContext * gc)
{
  GumArmWriter * cw = gc->arm_writer;

  /*
   * For the most part, we simply need to identify the offset of the
   * source_register within the GumCpuContext structure and load the value
   * accordingly. However, in the case of the PC, we instead load the address of
   * the current instruction in the iterator. Note that we add the fixed offset
   * of 8 since the value of PC is always interpreted in ARM32 as being 8 bytes
   * past the start of the instruction.
   */
  if (source_register >= ARM_REG_R0 && source_register <= ARM_REG_R7)
  {
    gum_arm_writer_put_ldr_reg_reg_offset (cw, target_register, ARM_REG_R10,
        G_STRUCT_OFFSET (GumCpuContext, r) +
        ((source_register - ARM_REG_R0) * 4));
  }
  else if (source_register >= ARM_REG_R8 && source_register <= ARM_REG_R12)
  {
    gum_arm_writer_put_ldr_reg_reg_offset (cw, target_register, ARM_REG_R10,
        G_STRUCT_OFFSET (GumCpuContext, r8) +
        ((source_register - ARM_REG_R8) * 4));
  }
  else if (source_register == ARM_REG_LR)
  {
    gum_arm_writer_put_ldr_reg_reg_offset (cw, target_register, ARM_REG_R10,
        G_STRUCT_OFFSET (GumCpuContext, lr));
  }
  else if (source_register == ARM_REG_SP)
  {
    gum_arm_writer_put_ldr_reg_reg_offset (cw, target_register, ARM_REG_R10,
        G_STRUCT_OFFSET (GumCpuContext, sp));
  }
  else if (source_register == ARM_REG_PC)
  {
    gum_arm_writer_put_ldr_reg_address (cw, target_register,
        GUM_ADDRESS (gc->instruction->begin + 8));
  }
  else
  {
    g_assert_not_reached ();
  }
}

static void
gum_exec_ctx_thumb_load_real_register_into (GumExecCtx * ctx,
                                            arm_reg target_register,
                                            arm_reg source_register,
                                            GumGeneratorContext * gc)
{
  GumThumbWriter * cw = gc->thumb_writer;

  if (source_register >= ARM_REG_R0 && source_register <= ARM_REG_R7)
  {
    gum_thumb_writer_put_ldr_reg_reg_offset (cw, target_register, ARM_REG_R10,
        G_STRUCT_OFFSET (GumCpuContext, r) +
        ((source_register - ARM_REG_R0) * 4));
  }
  else if (source_register >= ARM_REG_R8 && source_register <= ARM_REG_R12)
  {
    gum_thumb_writer_put_ldr_reg_reg_offset (cw, target_register, ARM_REG_R10,
        G_STRUCT_OFFSET (GumCpuContext, r8) +
        ((source_register - ARM_REG_R8) * 4));
  }
  else if (source_register == ARM_REG_LR)
  {
    gum_thumb_writer_put_ldr_reg_reg_offset (cw, target_register, ARM_REG_R10,
        G_STRUCT_OFFSET (GumCpuContext, lr));
  }
  else if (source_register == ARM_REG_SP)
  {
    gum_thumb_writer_put_ldr_reg_reg_offset (cw, target_register, ARM_REG_R10,
        G_STRUCT_OFFSET (GumCpuContext, sp));
  }
  else if (source_register == ARM_REG_PC)
  {
    gum_thumb_writer_put_ldr_reg_address (cw, target_register,
        GUM_ADDRESS (gc->instruction->begin + 4));
  }
  else
  {
    g_assert_not_reached ();
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

    /*
     * Instrumented ARM code needs to be 4 byte aligned. We will make all code
     * blocks (both ARM and Thumb) 4 byte aligned for simplicity.
     */
    block->code_begin =
        GUM_ALIGN_POINTER (guint8 *, slab->data + slab->offset, 4);
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
  {
    gpointer aligned_address;

    aligned_address = GSIZE_TO_POINTER (GPOINTER_TO_SIZE (real_address) & ~0x1);
    if (aligned_address == real_address)
      *code_address_ptr = block->code_begin;
    else
      *code_address_ptr = block->code_begin + 1;
  }

  return block;
}

static GumExecBlock *
gum_exec_block_obtain_trusted (GumExecCtx * ctx,
                               gpointer real_address,
                               gpointer * code_address_ptr)
{
  GumExecBlock * block;

  if (ctx->stalker->trust_threshold < 0)
    return NULL;

  block = gum_exec_block_obtain (ctx, real_address, code_address_ptr);
  if (block == NULL)
    return NULL;

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
    return NULL;
  }
}

static gboolean
gum_exec_block_is_full (GumExecBlock * block)
{
  guint8 * slab_end = block->slab->data + block->slab->size;

  return slab_end - block->code_end < GUM_EXEC_BLOCK_MIN_SIZE;
}

static void
gum_exec_block_commit_and_emit (GumExecBlock * block)
{
  GumExecCtx * ctx = block->ctx;
  gsize code_size, real_size;

  code_size = block->code_end - block->code_begin;
  block->slab->offset += code_size;

  real_size = block->real_end - block->real_begin;
  block->real_snapshot = block->code_end;
  memcpy (block->real_snapshot, block->real_begin, real_size);
  block->slab->offset += real_size;

  gum_stalker_freeze (ctx->stalker, block->code_begin, code_size);

  if ((ctx->sink_mask & GUM_COMPILE) != 0)
  {
    GumEvent ev;

    ev.type = GUM_COMPILE;
    ev.compile.begin = block->real_begin;
    ev.compile.end = block->real_end;

    gum_event_sink_process (ctx->sink, &ev);
  }
}

static void
gum_exec_block_virtualize_arm_branch_insn (GumExecBlock * block,
                                           const GumBranchTarget * target,
                                           arm_cc cc,
                                           GumWriteback * writeback,
                                           GumGeneratorContext * gc)
{
  GumExecCtx * ec = block->ctx;

  gum_exec_block_write_arm_handle_not_taken (block, target, cc, gc);

  gum_exec_block_arm_open_prolog (block, gc);

  if ((ec->sink_mask & GUM_EXEC) != 0)
    gum_exec_block_write_arm_exec_event_code (block, gc);

  if ((ec->sink_mask & GUM_BLOCK) != 0)
    gum_exec_block_write_arm_block_event_code (block, gc);

  gum_exec_block_write_arm_handle_excluded (block, target, FALSE, gc);
  gum_exec_block_write_arm_handle_kuser_helper (block, target, gc);
  gum_exec_block_write_arm_call_replace_block (block, target, gc);
  gum_exec_block_write_arm_pop_stack_frame (block, target, gc);

  gum_exec_block_arm_close_prolog (block, gc);

  gum_exec_block_write_arm_handle_writeback (block, writeback, gc);
  gum_exec_block_write_arm_exec_generated_code (gc->arm_writer, block->ctx);
}

static void
gum_exec_block_virtualize_thumb_branch_insn (GumExecBlock * block,
                                             const GumBranchTarget * target,
                                             arm_cc cc,
                                             arm_reg cc_reg,
                                             GumGeneratorContext * gc)
{
  GumExecCtx * ec = block->ctx;

  gum_exec_block_write_thumb_handle_not_taken (block, target, cc, cc_reg, gc);

  gum_exec_block_thumb_open_prolog (block, gc);

  if ((ec->sink_mask & GUM_EXEC) != 0)
    gum_exec_block_write_thumb_exec_event_code (block, gc);

  if ((ec->sink_mask & GUM_BLOCK) != 0)
    gum_exec_block_write_thumb_block_event_code (block, gc);

  gum_exec_block_write_thumb_handle_excluded (block, target, FALSE, gc);
  gum_exec_block_write_thumb_handle_kuser_helper (block, target, gc);
  gum_exec_block_write_thumb_call_replace_block (block, target, gc);
  gum_exec_block_write_thumb_pop_stack_frame (block, target, gc);

  gum_exec_block_thumb_close_prolog (block, gc);

  gum_exec_block_write_thumb_exec_generated_code (gc->thumb_writer, block->ctx);
}

static void
gum_exec_block_virtualize_arm_call_insn (GumExecBlock * block,
                                         const GumBranchTarget * target,
                                         arm_cc cc,
                                         GumGeneratorContext * gc)
{
  GumExecCtx * ec = block->ctx;
  gpointer ret_real_address = gc->instruction->end;

  gum_exec_block_write_arm_handle_not_taken (block, target, cc, gc);

  gum_exec_block_arm_open_prolog (block, gc);

  if ((ec->sink_mask & GUM_EXEC) != 0)
    gum_exec_block_write_arm_exec_event_code (block, gc);

  if ((ec->sink_mask & GUM_CALL) != 0)
    gum_exec_block_write_arm_call_event_code (block, target, gc);

  gum_exec_block_write_arm_handle_excluded (block, target, TRUE, gc);
  gum_exec_block_write_arm_push_stack_frame (block, ret_real_address, gc);
  gum_exec_block_write_arm_call_replace_block (block, target, gc);

  gum_exec_block_arm_close_prolog (block, gc);

  gum_arm_writer_put_ldr_reg_address (gc->arm_writer, ARM_REG_LR,
      GUM_ADDRESS (ret_real_address));
  gum_exec_block_write_arm_exec_generated_code (gc->arm_writer, block->ctx);
}

static void
gum_exec_block_virtualize_thumb_call_insn (GumExecBlock * block,
                                           const GumBranchTarget * target,
                                           GumGeneratorContext * gc)
{
  GumExecCtx * ec = block->ctx;
  gpointer ret_real_address = gc->instruction->end + 1;

  gum_exec_block_thumb_open_prolog (block, gc);

  if ((ec->sink_mask & GUM_EXEC) != 0)
    gum_exec_block_write_thumb_exec_event_code (block, gc);

  if ((ec->sink_mask & GUM_CALL) != 0)
    gum_exec_block_write_thumb_call_event_code (block, target, gc);

  gum_exec_block_write_thumb_handle_excluded (block, target, TRUE, gc);
  gum_exec_block_write_thumb_push_stack_frame (block, ret_real_address, gc);
  gum_exec_block_write_thumb_call_replace_block (block, target, gc);

  gum_exec_block_thumb_close_prolog (block, gc);

  gum_thumb_writer_put_ldr_reg_address (gc->thumb_writer, ARM_REG_LR,
      GUM_ADDRESS (ret_real_address));
  gum_exec_block_write_thumb_exec_generated_code (gc->thumb_writer, block->ctx);
}

static void
gum_exec_block_virtualize_arm_ret_insn (GumExecBlock * block,
                                        const GumBranchTarget * target,
                                        arm_cc cc,
                                        gboolean pop,
                                        guint16 mask,
                                        GumGeneratorContext * gc)
{
  GumExecCtx * ec = block->ctx;

  gum_exec_block_write_arm_handle_not_taken (block, target, cc, gc);

  gum_exec_block_arm_open_prolog (block, gc);

  if ((ec->sink_mask & GUM_EXEC) != 0)
    gum_exec_block_write_arm_exec_event_code (block, gc);

  gum_exec_block_write_arm_pop_stack_frame (block, target, gc);

  if ((ec->sink_mask & GUM_RET) != 0)
    gum_exec_block_write_arm_ret_event_code (block, target, gc);

  gum_exec_block_write_arm_call_replace_block (block, target, gc);

  gum_exec_block_arm_close_prolog (block, gc);

  /*
   * If the instruction we are virtualizing is a POP (or indeed LDMIA)
   * instruction, then as well as determining the location at which control flow
   * should continue, we must ensure we load any other registers in the register
   * list of the instruction from the stack. Lastly, we must increment that
   * stack pointer to remove the value of PC which would have been restored,
   * since we will instead control PC to continue execution of instrumented
   * code.
   */
  if (pop)
  {
    const GumBranchIndirectRegOffset * tv = &target->value.indirect_reg_offset;

    g_assert (target->type == GUM_TARGET_INDIRECT_REG_OFFSET);

    if (mask != 0)
      gum_arm_writer_put_ldmia_reg_mask (gc->arm_writer, tv->reg, mask);

    gum_arm_writer_put_add_reg_reg_imm (gc->arm_writer, tv->reg, tv->reg, 4);
  }

  gum_exec_block_write_arm_exec_generated_code (gc->arm_writer, block->ctx);
}

static void
gum_exec_block_virtualize_thumb_ret_insn (GumExecBlock * block,
                                          const GumBranchTarget * target,
                                          guint16 mask,
                                          GumGeneratorContext * gc)
{
  GumExecCtx * ec = block->ctx;
  const GumBranchIndirectRegOffset * tv = &target->value.indirect_reg_offset;

  g_assert (target->type == GUM_TARGET_INDIRECT_REG_OFFSET);

  gum_exec_block_thumb_open_prolog (block, gc);

  if ((ec->sink_mask & GUM_EXEC) != 0)
    gum_exec_block_write_thumb_exec_event_code (block, gc);

  gum_exec_block_write_thumb_pop_stack_frame (block, target, gc);

  if ((ec->sink_mask & GUM_RET) != 0)
    gum_exec_block_write_thumb_ret_event_code (block, target, gc);

  gum_exec_block_write_thumb_call_replace_block (block, target, gc);

  gum_exec_block_thumb_close_prolog (block, gc);

  if (mask != 0)
    gum_thumb_writer_put_ldmia_reg_mask (gc->thumb_writer, tv->reg, mask);

  gum_thumb_writer_put_add_reg_reg_imm (gc->thumb_writer, tv->reg, tv->reg, 4);

  gum_exec_block_write_thumb_exec_generated_code (gc->thumb_writer, block->ctx);
}

static void
gum_exec_block_virtualize_arm_svc_insn (GumExecBlock * block,
                                        GumGeneratorContext * gc)
{
  gum_exec_block_dont_virtualize_arm_insn (block, gc);

#ifdef HAVE_LINUX
  {
    GumArmWriter * cw = gc->arm_writer;
    gconstpointer not_cloned_child = cw->code + 1;

    /* Save the flags */
    gum_arm_writer_put_push_registers (cw, 1, ARM_REG_R1);
    gum_arm_writer_put_mov_reg_cpsr (cw, ARM_REG_R1);

    /* Check the SVC number */
    gum_arm_writer_put_cmp_reg_imm (cw, ARM_REG_R7, __NR_clone);
    gum_arm_writer_put_b_cond_label (cw, ARM_CC_NE, not_cloned_child);

    /* Check the returned TID */
    gum_arm_writer_put_cmp_reg_imm (cw, ARM_REG_R0, 0);
    gum_arm_writer_put_b_cond_label (cw, ARM_CC_NE, not_cloned_child);

    /* Restore the flags */
    gum_arm_writer_put_mov_cpsr_reg (cw, ARM_REG_R1);
    gum_arm_writer_put_pop_registers (cw, 1, ARM_REG_R1);

    /* Vector to the original next instruction */
    gum_arm_writer_put_push_registers (cw, 2, ARM_REG_R0, ARM_REG_PC);
    gum_arm_writer_put_ldr_reg_address (cw, ARM_REG_R0,
        GUM_ADDRESS (gc->instruction->end));
    gum_arm_writer_put_str_reg_reg_offset (cw, ARM_REG_R0, ARM_REG_SP, 4);
    gum_arm_writer_put_pop_registers (cw, 2, ARM_REG_R0, ARM_REG_PC);

    gum_arm_writer_put_label (cw, not_cloned_child);

    /* Restore the flags */
    gum_arm_writer_put_mov_cpsr_reg (cw, ARM_REG_R1);
    gum_arm_writer_put_pop_registers (cw, 1, ARM_REG_R1);
  }
#endif
}

static void
gum_exec_block_virtualize_thumb_svc_insn (GumExecBlock * block,
                                          GumGeneratorContext * gc)
{
  gum_exec_block_dont_virtualize_thumb_insn (block, gc);

#ifdef HAVE_LINUX
  {
    GumThumbWriter * cw = gc->thumb_writer;
    gconstpointer goto_not_cloned_child = cw->code + 1;
    gconstpointer cloned_child = cw->code + 2;
    gconstpointer not_cloned_child = cw->code + 3;

    /* Save the SVC number */
    gum_thumb_writer_put_push_regs (cw, 1, ARM_REG_R7);

    /* Check the SVC number */
    gum_thumb_writer_put_sub_reg_imm (cw, ARM_REG_R7, __NR_clone);
    gum_thumb_writer_put_cbnz_reg_label (cw, ARM_REG_R7, goto_not_cloned_child);

    /* Check the returned TID */
    gum_thumb_writer_put_cbnz_reg_label (cw, ARM_REG_R0, goto_not_cloned_child);
    gum_thumb_writer_put_b_label (cw, cloned_child);

    gum_thumb_writer_put_label (cw, goto_not_cloned_child);
    gum_thumb_writer_put_b_label (cw, not_cloned_child);

    gum_thumb_writer_put_label (cw, cloned_child);
    /* Restore the SVC number */
    gum_thumb_writer_put_pop_regs (cw, 1, ARM_REG_R7);

    /* Vector to the original next instruction */

    /*
     * We can't push PC in Thumb encoding without Thumb 2, and we clobber the
     * value so it doesn't matter what we push. It ends up popped back into PC.
     */
    gum_thumb_writer_put_push_regs (cw, 2, ARM_REG_R0, ARM_REG_R1);
    gum_thumb_writer_put_ldr_reg_address (cw, ARM_REG_R0,
        GUM_ADDRESS (gc->instruction->end));
    gum_thumb_writer_put_str_reg_reg_offset (cw, ARM_REG_R0, ARM_REG_SP, 4);
    gum_thumb_writer_put_pop_regs (cw, 2, ARM_REG_R0, ARM_REG_PC);

    gum_thumb_writer_put_label (cw, not_cloned_child);

    /* Restore the SVC number */
    gum_thumb_writer_put_pop_regs (cw, 1, ARM_REG_R7);
  }
#endif
}

static void
gum_exec_block_write_arm_handle_kuser_helper (GumExecBlock * block,
                                              const GumBranchTarget * target,
                                              GumGeneratorContext * gc)
{
#ifdef HAVE_LINUX
  GumExecCtx * ctx = block->ctx;
  GumArmWriter * cw = gc->arm_writer;
  gconstpointer not_kuh = cw->code + 1;
  GumBranchTarget ret_target;

  /*
   * The kuser_helper is a mechanism implemented by the Linux kernel to expose a
   * page of code into the user address space so that it can be used by glibc in
   * order to carry out a number of heavily architecture specific operations
   * without having to perform architecture detection of its own (see
   * https://www.kernel.org/doc/Documentation/arm/kernel_user_helpers.txt).
   *
   * When running in qemu-user (which is useful for running target code on the
   * bench, or simply testing when you don't have access to a target), since
   * qemu-user is emulating the ARM instructions on an alterative architecture
   * (likely x86_64) then the code page exposed by the host kernel will be of
   * the native architecture accordingly. Rather than attempting to emulate this
   * very machine specific code, QEMU instead detects when the application
   * attempts to execute one of these handlers (see the function do_kernel_trap
   * in https://github.com/qemu/qemu/blob/master/linux-user/arm/cpu_loop.c) and
   * performs the necessary emulation on behalf of the application. Thus it is
   * not possible to read the page at this address and retrieve ARM code to be
   * instrumented.
   *
   * Rather than attempt to detect the target on which we are running, as it is
   * vanishingly unlikely that a user will care to stalk this platform specific
   * code we simply execute it outside of the Stalker engine, similar to the way
   * in which an excluded range is handled.
   */

  /*
   * If the branch target is deterministic (e.g. not based on register
   * contents), we can perform the check during instrumentation rather than at
   * runtime and omit this code if we can determine we will not enter a
   * kuser_helper.
   */
  if (target->type == GUM_TARGET_DIRECT_ADDRESS)
  {
    if (!gum_stalker_is_kuser_helper (target->value.direct_address.address))
      return;
  }

  if (target->type != GUM_TARGET_DIRECT_ADDRESS)
  {
    gum_exec_ctx_write_arm_mov_branch_target (block->ctx, target, ARM_REG_R0,
        gc);
    gum_arm_writer_put_call_address_with_arguments (cw,
        GUM_ADDRESS (gum_stalker_is_kuser_helper), 1,
        GUM_ARG_REGISTER, ARM_REG_R0);
    gum_arm_writer_put_cmp_reg_imm (cw, ARM_REG_R0, 0);
    gum_arm_writer_put_b_cond_label (cw, ARM_CC_EQ, not_kuh);
  }

  gum_exec_ctx_write_arm_mov_branch_target (block->ctx, target, ARM_REG_R0, gc);
  gum_arm_writer_put_ldr_reg_address (cw, ARM_REG_R1,
      GUM_ADDRESS (&ctx->kuh_target));
  gum_arm_writer_put_str_reg_reg_offset (cw, ARM_REG_R0, ARM_REG_R1, 0);

  gum_exec_block_arm_close_prolog (block, gc);

  gum_arm_writer_put_ldr_reg_address (cw, ARM_REG_R12,
      GUM_ADDRESS (&ctx->kuh_target));
  gum_arm_writer_put_ldr_reg_reg_offset (cw, ARM_REG_R12, ARM_REG_R12, 0);

  /*
   * Unlike an excluded range, where the function is executed by a call
   * instruction. It is quite common for kuser_helpers to instead be executed by
   * the following instruction sequence.
   *
   * mvn r0, #0xf000
   * sub pc, r0, #0x1f
   *
   * This is effectively a tail call within a thunk function. But as we can see
   * when we vector to the kuser_helper we actually find a branch instruction
   * and not a call and hence were we to simply emit it, then we would not be
   * able to return to the Stalker engine after it has completed in order to
   * continue stalking. We must therefore emit a call instead.
   *
   * Note, however that per the documentation at kernel.org, the helpers are in
   * fact functions and so we can simply call and they will return control back
   * to the address contained in LR. One last thing to note here, is that we
   * store and restore the application LR value either side of our call so that
   * we can preserve it. This does have the effect of changing the normal
   * application stack pointer during the duration of the call, but the
   * documentation states that all of the input and output make use of registers
   * rather than the stack.
   */
  gum_arm_writer_put_push_registers (cw, 1, ARM_REG_LR);
  gum_arm_writer_put_blx_reg (cw, ARM_REG_R12);
  gum_arm_writer_put_pop_registers (cw, 1, ARM_REG_LR);

  gum_exec_block_arm_open_prolog (block, gc);

  ret_target.type = GUM_TARGET_DIRECT_REG_OFFSET;
  ret_target.value.direct_reg_offset.reg = ARM_REG_LR;
  ret_target.value.direct_reg_offset.offset = 0;

  /*
   * We pop the stack frame here since the actual kuser_helper will have been
   * called by a thunk which looks like this:
   *
   * thunk_EXT_FUN_ffff0fe0:
   *     mvn r0, #0xf000
   *     sub pc => SUB_ffff0fe0, r0, #0x1f
   *
   * This will result in the stack frame being pushed for the call to this
   * thunk. Since this performs a tail call, and we don't stalk the actual
   * helper, we don't instrument the eventual return instruction and hence
   * include the stack pop at that point. We therefore pop the stack here
   * to make things line up.
   */
  gum_exec_block_write_arm_pop_stack_frame (block, &ret_target, gc);
  gum_exec_block_write_arm_call_replace_block (block, &ret_target, gc);
  gum_exec_block_arm_close_prolog (block, gc);

  gum_exec_block_write_arm_exec_generated_code (cw, block->ctx);

  gum_arm_writer_put_breakpoint (cw);

  /*
   * This label is only required if we weren't able to determine at
   * instrumentation time whether the target was a kuser_helper. If we could
   * then we either emit the handler if it is, or do nothing if not.
   */
  if (target->type != GUM_TARGET_DIRECT_ADDRESS)
    gum_arm_writer_put_label (cw, not_kuh);
#endif
}

static void
gum_exec_block_write_thumb_handle_kuser_helper (GumExecBlock * block,
                                                const GumBranchTarget * target,
                                                GumGeneratorContext * gc)
{
#ifdef HAVE_LINUX
  GumExecCtx * ctx = block->ctx;
  GumThumbWriter * cw = gc->thumb_writer;
  gconstpointer kuh = cw->code + 1;
  gconstpointer not_kuh = cw->code + 2;
  GumBranchTarget ret_target;

  if (target->type == GUM_TARGET_DIRECT_ADDRESS)
  {
    if (!gum_stalker_is_kuser_helper (target->value.direct_address.address))
      return;
  }

  if (target->type != GUM_TARGET_DIRECT_ADDRESS)
  {
    gum_exec_ctx_write_thumb_mov_branch_target (block->ctx,
        target, ARM_REG_R0, gc);
    gum_thumb_writer_put_call_address_with_arguments (cw,
        GUM_ADDRESS (gum_stalker_is_kuser_helper), 1,
        GUM_ARG_REGISTER, ARM_REG_R0);
    gum_thumb_writer_put_cbnz_reg_label (cw, ARM_REG_R0, kuh);
    gum_thumb_writer_put_b_label (cw, not_kuh);
    gum_thumb_writer_put_label (cw, kuh);
  }

  gum_exec_ctx_write_thumb_mov_branch_target (block->ctx, target, ARM_REG_R0,
      gc);
  gum_thumb_writer_put_ldr_reg_address (cw, ARM_REG_R1,
      GUM_ADDRESS (&ctx->kuh_target));
  gum_thumb_writer_put_str_reg_reg_offset (cw, ARM_REG_R0, ARM_REG_R1, 0);

  gum_exec_block_thumb_close_prolog (block, gc);

  gum_thumb_writer_put_ldr_reg_address (cw, ARM_REG_R12,
      GUM_ADDRESS (&ctx->kuh_target));
  gum_thumb_writer_put_ldr_reg_reg_offset (cw, ARM_REG_R12, ARM_REG_R12, 0);

  gum_thumb_writer_put_push_regs (cw, 1, ARM_REG_LR);
  gum_thumb_writer_put_bx_reg (cw, ARM_REG_R12);
  gum_thumb_writer_put_pop_regs (cw, 1, ARM_REG_LR);

  gum_exec_block_thumb_open_prolog (block, gc);

  ret_target.type = GUM_TARGET_DIRECT_REG_OFFSET;
  ret_target.value.direct_reg_offset.reg = ARM_REG_LR;
  ret_target.value.direct_reg_offset.offset = 0;

  gum_exec_block_write_thumb_pop_stack_frame (block, &ret_target, gc);
  gum_exec_block_write_thumb_call_replace_block (block, &ret_target,
      gc);
  gum_exec_block_thumb_close_prolog (block, gc);

  gum_exec_block_write_thumb_exec_generated_code (cw, block->ctx);

  gum_thumb_writer_put_breakpoint (cw);

  if (target->type != GUM_TARGET_DIRECT_ADDRESS)
    gum_thumb_writer_put_label (cw, not_kuh);
#endif
}

static void
gum_exec_block_write_arm_call_replace_block (GumExecBlock * block,
                                             const GumBranchTarget * target,
                                             GumGeneratorContext * gc)
{
  gum_exec_ctx_write_arm_mov_branch_target (block->ctx, target, ARM_REG_R1, gc);
  gum_arm_writer_put_call_address_with_arguments (gc->arm_writer,
      GUM_ADDRESS (gum_exec_ctx_replace_block), 2,
      GUM_ARG_ADDRESS, GUM_ADDRESS (block->ctx),
      GUM_ARG_REGISTER, ARM_REG_R1);
}

static void
gum_exec_block_write_thumb_call_replace_block (GumExecBlock * block,
                                               const GumBranchTarget * target,
                                               GumGeneratorContext * gc)
{
  gum_exec_ctx_write_thumb_mov_branch_target (block->ctx, target, ARM_REG_R1,
      gc);
  gum_thumb_writer_put_call_address_with_arguments (gc->thumb_writer,
      GUM_ADDRESS (gum_exec_ctx_replace_block), 2,
      GUM_ARG_ADDRESS, GUM_ADDRESS (block->ctx),
      GUM_ARG_REGISTER, ARM_REG_R1);
}

static void
gum_exec_block_dont_virtualize_arm_insn (GumExecBlock * block,
                                         GumGeneratorContext * gc)
{
  GumExecCtx * ec = block->ctx;

  if ((ec->sink_mask & GUM_EXEC) != 0)
  {
    gum_exec_block_arm_open_prolog (block, gc);
    gum_exec_block_write_arm_exec_event_code (block, gc);
    gum_exec_block_arm_close_prolog (block, gc);
  }

  gum_arm_relocator_write_all (gc->arm_relocator);
}

static void
gum_exec_block_dont_virtualize_thumb_insn (GumExecBlock * block,
                                           GumGeneratorContext * gc)
{
  GumExecCtx * ec = block->ctx;

  if ((ec->sink_mask & GUM_EXEC) != 0)
  {
    gum_exec_block_thumb_open_prolog (block, gc);
    gum_exec_block_write_thumb_exec_event_code (block, gc);
    gum_exec_block_thumb_close_prolog (block, gc);
  }

  gum_thumb_relocator_write_all (gc->thumb_relocator);
}

static void
gum_exec_block_write_arm_handle_excluded (GumExecBlock * block,
                                          const GumBranchTarget * target,
                                          gboolean call,
                                          GumGeneratorContext * gc)
{
  GumArmWriter * cw = gc->arm_writer;
  gconstpointer not_excluded = cw->code + 1;
  GumCheckExcludedFunc check;

  if (call)
    check = gum_stalker_is_call_excluding;
  else
    check = gum_stalker_is_branch_excluding;

  /*
   * If the branch target is deterministic (e.g. not based on register
   * contents). We can perform the check during instrumentation rather than at
   * runtime and omit this code if we can determine we will not enter an
   * excluded range.
   */
  if (target->type == GUM_TARGET_DIRECT_ADDRESS)
  {
    if (!check (block->ctx, target->value.direct_address.address))
      return;
  }

  if (target->type != GUM_TARGET_DIRECT_ADDRESS)
  {
    gum_exec_ctx_write_arm_mov_branch_target (block->ctx, target, ARM_REG_R1,
        gc);
    gum_arm_writer_put_call_address_with_arguments (cw,
        GUM_ADDRESS (check), 2,
        GUM_ARG_ADDRESS, GUM_ADDRESS (block->ctx),
        GUM_ARG_REGISTER, ARM_REG_R1);
    gum_arm_writer_put_cmp_reg_imm (cw, ARM_REG_R0, 0);
    gum_arm_writer_put_b_cond_label (cw, ARM_CC_EQ, not_excluded);
  }

  if (call)
  {
    gum_arm_writer_put_call_address_with_arguments (cw,
        GUM_ADDRESS (gum_exec_ctx_begin_call), 2,
        GUM_ARG_ADDRESS, GUM_ADDRESS (block->ctx),
        GUM_ARG_ADDRESS, GUM_ADDRESS (gc->instruction->end));
  }

  gum_exec_block_arm_close_prolog (block, gc);

  /* Emit the original instruction (relocated) */
  gum_arm_relocator_write_one (gc->arm_relocator);

  gum_exec_block_arm_open_prolog (block, gc);

  if (call)
  {
    gum_arm_writer_put_call_address_with_arguments (cw,
        GUM_ADDRESS (gum_exec_ctx_end_call), 1,
        GUM_ARG_ADDRESS, GUM_ADDRESS (block->ctx));
  }

  gum_exec_block_write_arm_handle_continue (block, gc);

  if (target->type != GUM_TARGET_DIRECT_ADDRESS)
    gum_arm_writer_put_label (cw, not_excluded);
}

static void
gum_exec_block_write_thumb_handle_excluded (GumExecBlock * block,
                                            const GumBranchTarget * target,
                                            gboolean call,
                                            GumGeneratorContext * gc)
{
  GumThumbWriter * cw = gc->thumb_writer;
  gconstpointer not_excluded = cw->code + 1;
  GumCheckExcludedFunc check;

  if (call)
    check = gum_stalker_is_call_excluding;
  else
    check = gum_stalker_is_branch_excluding;

  if (target->type == GUM_TARGET_DIRECT_ADDRESS)
  {
    if (!check (block->ctx, target->value.direct_address.address))
      return;
  }

  if (target->type != GUM_TARGET_DIRECT_ADDRESS)
  {
    gum_exec_ctx_write_thumb_mov_branch_target (block->ctx, target, ARM_REG_R1,
        gc);
    gum_thumb_writer_put_call_address_with_arguments (cw,
        GUM_ADDRESS (check), 2,
        GUM_ARG_ADDRESS, GUM_ADDRESS (block->ctx),
        GUM_ARG_REGISTER, ARM_REG_R1);
    gum_thumb_writer_put_cbz_reg_label (cw, ARM_REG_R0, not_excluded);
  }

  if (call)
  {
    gum_thumb_writer_put_call_address_with_arguments (cw,
        GUM_ADDRESS (gum_exec_ctx_begin_call), 2,
        GUM_ARG_ADDRESS, GUM_ADDRESS (block->ctx),
        GUM_ARG_ADDRESS, GUM_ADDRESS (gc->instruction->end + 1));
  }

  gum_exec_block_thumb_close_prolog (block, gc);

  gum_thumb_relocator_copy_one (gc->thumb_relocator);

  gum_exec_block_thumb_open_prolog (block, gc);

  if (call)
  {
    gum_thumb_writer_put_call_address_with_arguments (cw,
        GUM_ADDRESS (gum_exec_ctx_end_call), 1,
        GUM_ARG_ADDRESS, GUM_ADDRESS (block->ctx));
  }

  gum_exec_block_write_thumb_handle_continue (block, gc);

  if (target->type != GUM_TARGET_DIRECT_ADDRESS)
    gum_thumb_writer_put_label (cw, not_excluded);
}

static void
gum_exec_block_write_arm_handle_not_taken (GumExecBlock * block,
                                           const GumBranchTarget * target,
                                           arm_cc cc,
                                           GumGeneratorContext * gc)
{
  GumExecCtx * ec = block->ctx;
  GumArmWriter * cw = gc->arm_writer;
  gconstpointer taken = cw->code + 1;

  /*
   * Many ARM instructions can be conditionally executed based upon the state of
   * register flags. If our instruction is not always executed (ARM_CC_AL), we
   * emit a branch with the same condition code as the original instruction to
   * bypass the continuation handler.
   */

  if (cc == ARM_CC_AL)
    return;

  gum_arm_writer_put_b_cond_label (cw, cc, taken);

  /*
   * If the branch is not taken on account that the instruction is conditionally
   * executed, then emit any necessary events and continue execution by
   * instrumenting and vectoring to the block immediately after the conditional
   * instruction.
   */
  gum_exec_block_arm_open_prolog (block, gc);

  if ((ec->sink_mask & GUM_EXEC) != 0)
    gum_exec_block_write_arm_exec_event_code (block, gc);

  if ((ec->sink_mask & GUM_BLOCK) != 0)
    gum_exec_block_write_arm_block_event_code (block, gc);

  gum_exec_block_write_arm_handle_continue (block, gc);

  gum_arm_writer_put_label (cw, taken);
}

static void
gum_exec_block_write_thumb_handle_not_taken (GumExecBlock * block,
                                             const GumBranchTarget * target,
                                             arm_cc cc,
                                             arm_reg cc_reg,
                                             GumGeneratorContext * gc)
{
  GumExecCtx * ec = block->ctx;
  GumThumbWriter * cw = gc->thumb_writer;
  gconstpointer cb_not_taken = cw->code + 1;
  gconstpointer taken = cw->code + 2;

  if (cc_reg != ARM_REG_INVALID)
  {
    if (cc == ARM_CC_EQ)
      gum_thumb_writer_put_cbnz_reg_label (cw, cc_reg, cb_not_taken);
    else if (cc == ARM_CC_NE)
      gum_thumb_writer_put_cbz_reg_label (cw, cc_reg, cb_not_taken);
    else
      g_assert_not_reached ();

    gum_thumb_writer_put_b_label_wide (cw, taken);

    gum_thumb_writer_put_label (cw, cb_not_taken);
  }
  else if (cc != ARM_CC_AL)
  {
    gum_thumb_writer_put_b_cond_label_wide (cw, cc, taken);
  }

  if (cc != ARM_CC_AL)
  {
    gum_exec_block_thumb_open_prolog (block, gc);

    if ((ec->sink_mask & GUM_EXEC) != 0)
      gum_exec_block_write_thumb_exec_event_code (block, gc);

    if ((ec->sink_mask & GUM_BLOCK) != 0)
      gum_exec_block_write_thumb_block_event_code (block, gc);

    gum_exec_block_write_thumb_handle_continue (block, gc);

    gum_thumb_writer_put_label (cw, taken);
  }
}

static void
gum_exec_block_write_arm_handle_continue (GumExecBlock * block,
                                          GumGeneratorContext * gc)
{
  /*
   * Use the address of the end of the current instruction as the address of the
   * next block to execute. This is the case after handling a call instruction
   * to an excluded range whereby upon return you want to continue with the next
   * instruction, or when a conditional instruction is not executed resulting in
   * a branch not being taken. Instrument the block and then vector to it.
   */

  gum_arm_writer_put_call_address_with_arguments (gc->arm_writer,
      GUM_ADDRESS (gum_exec_ctx_replace_block), 2,
      GUM_ARG_ADDRESS, GUM_ADDRESS (block->ctx),
      GUM_ARG_ADDRESS, GUM_ADDRESS (gc->instruction->end));

  gum_exec_block_arm_close_prolog (block, gc);

  gum_exec_block_write_arm_exec_generated_code (gc->arm_writer, block->ctx);
}

static void
gum_exec_block_write_thumb_handle_continue (GumExecBlock * block,
                                            GumGeneratorContext * gc)
{
  gum_thumb_writer_put_call_address_with_arguments (gc->thumb_writer,
      GUM_ADDRESS (gum_exec_ctx_replace_block), 2,
      GUM_ARG_ADDRESS, GUM_ADDRESS (block->ctx),
      GUM_ARG_ADDRESS, GUM_ADDRESS (gc->instruction->end + 1));

  gum_exec_block_thumb_close_prolog (block, gc);

  gum_exec_block_write_thumb_exec_generated_code (gc->thumb_writer, block->ctx);
}

static void
gum_exec_block_write_arm_handle_writeback (GumExecBlock * block,
                                           const GumWriteback * writeback,
                                           GumGeneratorContext * gc)
{
  GumArmWriter * cw = gc->arm_writer;
  gssize offset;

  if (writeback->target == ARM_REG_INVALID)
    return;

  offset = writeback->offset;
  if (offset >= 0)
    gum_arm_writer_put_add_reg_u32 (cw, writeback->target, offset);
  else
    gum_arm_writer_put_sub_reg_u32 (cw, writeback->target, -offset);
}

static void
gum_exec_block_write_arm_exec_generated_code (GumArmWriter * cw,
                                              GumExecCtx * ctx)
{
  /*
   * This function writes code to vector to the address of the last instrumented
   * block. Given that this code is emitted before the block is actually
   * instrumented, the value of ctx->resume_at will change between this code
   * being emitted and it being executed. It must therefore use &ctx->resume_at
   * and re-read the value from memory at runtime.
   *
   * This however means that we must use a scratch register to calculate the
   * final address. Given that this is also used to transition between blocks
   * within a function, we cannot rely upon the fact the R12 is a callee saved
   * register and clobber the value since it may be being used within the
   * function scope. We therefore push and pop this register to and from the
   * stack.
   */

  /*
   * Here we push the values of R0 which we will use as scratch space and PC we
   * will overwrite the value of PC on the stack at (SP+4) with the value from
   * resume_at before we subsequently pop both registers. This allows us to
   * branch to an arbitrary address without clobbering any registers.
   */
  gum_arm_writer_put_push_registers (cw, 2, ARM_REG_R0, ARM_REG_PC);
  gum_arm_writer_put_ldr_reg_address (cw, ARM_REG_R0,
      GUM_ADDRESS (&ctx->resume_at));
  gum_arm_writer_put_ldr_reg_reg_offset (cw, ARM_REG_R0, ARM_REG_R0, 0);

  gum_arm_writer_put_str_reg_reg_offset (cw, ARM_REG_R0, ARM_REG_SP, 4);
  gum_arm_writer_put_pop_registers (cw, 2, ARM_REG_R0, ARM_REG_PC);
}

static void
gum_exec_block_write_thumb_exec_generated_code (GumThumbWriter * cw,
                                                GumExecCtx * ctx)
{
  /*
   * We can't push PC in Thumb encoding without Thumb 2, and we clobber the
   * value so it doesn't matter what we push. It ends up popped back into PC.
   */
  gum_thumb_writer_put_push_regs (cw, 2, ARM_REG_R0, ARM_REG_R1);
  gum_thumb_writer_put_ldr_reg_address (cw, ARM_REG_R0,
      GUM_ADDRESS (&ctx->resume_at));
  gum_thumb_writer_put_ldr_reg_reg_offset (cw, ARM_REG_R0, ARM_REG_R0, 0);
  gum_thumb_writer_put_str_reg_reg_offset (cw, ARM_REG_R0, ARM_REG_SP, 4);
  gum_thumb_writer_put_pop_regs (cw, 2, ARM_REG_R0, ARM_REG_PC);
}

static void
gum_exec_block_write_arm_call_event_code (GumExecBlock * block,
                                          const GumBranchTarget * target,
                                          GumGeneratorContext * gc)
{
  gum_exec_ctx_write_arm_mov_branch_target (block->ctx, target, ARM_REG_R2, gc);
  gum_arm_writer_put_call_address_with_arguments (gc->arm_writer,
      GUM_ADDRESS (gum_exec_ctx_emit_call_event), 3,
      GUM_ARG_ADDRESS, GUM_ADDRESS (block->ctx),
      GUM_ARG_ADDRESS, GUM_ADDRESS (gc->instruction->begin),
      GUM_ARG_REGISTER, ARM_REG_R2);
}

static void
gum_exec_block_write_thumb_call_event_code (GumExecBlock * block,
                                            const GumBranchTarget * target,
                                            GumGeneratorContext * gc)
{
  gum_exec_ctx_write_thumb_mov_branch_target (block->ctx, target, ARM_REG_R2,
      gc);
  gum_thumb_writer_put_call_address_with_arguments (gc->thumb_writer,
      GUM_ADDRESS (gum_exec_ctx_emit_call_event), 3,
      GUM_ARG_ADDRESS, GUM_ADDRESS (block->ctx),
      GUM_ARG_ADDRESS, GUM_ADDRESS (gc->instruction->begin),
      GUM_ARG_REGISTER, ARM_REG_R2);
}

static void
gum_exec_block_write_arm_ret_event_code (GumExecBlock * block,
                                         const GumBranchTarget * target,
                                         GumGeneratorContext * gc)
{
  gum_exec_ctx_write_arm_mov_branch_target (block->ctx, target, ARM_REG_R2, gc);
  gum_arm_writer_put_call_address_with_arguments (gc->arm_writer,
      GUM_ADDRESS (gum_exec_ctx_emit_ret_event), 3,
      GUM_ARG_ADDRESS, GUM_ADDRESS (block->ctx),
      GUM_ARG_ADDRESS, GUM_ADDRESS (gc->instruction->begin),
      GUM_ARG_REGISTER, ARM_REG_R2);
}

static void
gum_exec_block_write_thumb_ret_event_code (GumExecBlock * block,
                                           const GumBranchTarget * target,
                                           GumGeneratorContext * gc)
{
  gum_exec_ctx_write_thumb_mov_branch_target (block->ctx, target, ARM_REG_R2,
      gc);
  gum_thumb_writer_put_call_address_with_arguments (gc->thumb_writer,
      GUM_ADDRESS (gum_exec_ctx_emit_ret_event), 3,
      GUM_ARG_ADDRESS, GUM_ADDRESS (block->ctx),
      GUM_ARG_ADDRESS, GUM_ADDRESS (gc->instruction->begin),
      GUM_ARG_REGISTER, ARM_REG_R2);
}

static void
gum_exec_block_write_arm_exec_event_code (GumExecBlock * block,
                                          GumGeneratorContext * gc)
{
  if (gum_generator_context_is_timing_sensitive (gc))
    return;

  gum_arm_writer_put_call_address_with_arguments (gc->arm_writer,
      GUM_ADDRESS (gum_exec_ctx_emit_exec_event), 2,
      GUM_ARG_ADDRESS, GUM_ADDRESS (block->ctx),
      GUM_ARG_ADDRESS, GUM_ADDRESS (gc->instruction->begin));
}

static void
gum_exec_block_write_thumb_exec_event_code (GumExecBlock * block,
                                            GumGeneratorContext * gc)
{
  if (gum_generator_context_is_timing_sensitive (gc))
    return;

  gum_thumb_writer_put_call_address_with_arguments (gc->thumb_writer,
      GUM_ADDRESS (gum_exec_ctx_emit_exec_event), 2,
      GUM_ARG_ADDRESS, GUM_ADDRESS (block->ctx),
      GUM_ARG_ADDRESS, GUM_ADDRESS (gc->instruction->begin));
}

static void
gum_exec_block_write_arm_block_event_code (GumExecBlock * block,
                                           GumGeneratorContext * gc)
{
  if (gum_generator_context_is_timing_sensitive (gc))
    return;

  gum_arm_writer_put_call_address_with_arguments (gc->arm_writer,
      GUM_ADDRESS (gum_exec_ctx_emit_block_event), 3,
      GUM_ARG_ADDRESS, GUM_ADDRESS (block->ctx),
      GUM_ARG_ADDRESS, GUM_ADDRESS (gc->arm_relocator->input_start),
      GUM_ARG_ADDRESS, GUM_ADDRESS (gc->arm_relocator->input_cur));
}

static void
gum_exec_block_write_thumb_block_event_code (GumExecBlock * block,
                                             GumGeneratorContext * gc)
{
  if (gum_generator_context_is_timing_sensitive (gc))
    return;

  gum_thumb_writer_put_call_address_with_arguments (gc->thumb_writer,
      GUM_ADDRESS (gum_exec_ctx_emit_block_event), 3,
      GUM_ARG_ADDRESS, GUM_ADDRESS (block->ctx),
      GUM_ARG_ADDRESS, GUM_ADDRESS (gc->thumb_relocator->input_start),
      GUM_ARG_ADDRESS, GUM_ADDRESS (gc->thumb_relocator->input_cur));
}

static void
gum_exec_block_write_arm_push_stack_frame (GumExecBlock * block,
                                           gpointer ret_real_address,
                                           GumGeneratorContext * gc)
{
  gum_arm_writer_put_call_address_with_arguments (gc->arm_writer,
      GUM_ADDRESS (gum_exec_block_push_stack_frame), 2,
      GUM_ARG_ADDRESS, GUM_ADDRESS (block->ctx),
      GUM_ARG_ADDRESS, GUM_ADDRESS (ret_real_address));
}

static void
gum_exec_block_write_thumb_push_stack_frame (GumExecBlock * block,
                                             gpointer ret_real_address,
                                             GumGeneratorContext * gc)
{
  gum_thumb_writer_put_call_address_with_arguments (gc->thumb_writer,
      GUM_ADDRESS (gum_exec_block_push_stack_frame), 2,
      GUM_ARG_ADDRESS, GUM_ADDRESS (block->ctx),
      GUM_ARG_ADDRESS, GUM_ADDRESS (ret_real_address));
}

static void
gum_exec_block_push_stack_frame (GumExecCtx * ctx,
                                 gpointer ret_real_address)
{
  if (ctx->current_frame != ctx->frames)
  {
    ctx->current_frame->real_address = ret_real_address;
    ctx->current_frame--;
  }
}

static void
gum_exec_block_write_arm_pop_stack_frame (GumExecBlock * block,
                                          const GumBranchTarget * target,
                                          GumGeneratorContext * gc)
{
  gum_exec_ctx_write_arm_mov_branch_target (block->ctx, target, ARM_REG_R1, gc);
  gum_arm_writer_put_call_address_with_arguments (gc->arm_writer,
      GUM_ADDRESS (gum_exec_block_pop_stack_frame), 2,
      GUM_ARG_ADDRESS, GUM_ADDRESS (block->ctx),
      GUM_ARG_REGISTER, ARM_REG_R1);
}

static void
gum_exec_block_write_thumb_pop_stack_frame (GumExecBlock * block,
                                            const GumBranchTarget * target,
                                            GumGeneratorContext * gc)
{
  gum_exec_ctx_write_thumb_mov_branch_target (block->ctx, target, ARM_REG_R1,
      gc);
  gum_thumb_writer_put_call_address_with_arguments (gc->thumb_writer,
      GUM_ADDRESS (gum_exec_block_pop_stack_frame), 2,
      GUM_ARG_ADDRESS, GUM_ADDRESS (block->ctx),
      GUM_ARG_REGISTER, ARM_REG_R1);
}

static void
gum_exec_block_pop_stack_frame (GumExecCtx * ctx,
                                gpointer ret_real_address)
{
  /*
   * Since with ARM32, there is no clear CALL and RET instructions, it is
   * difficult to determine the difference between instructions being used to
   * perform a CALL, a BRANCH or a RETURN. We therefore check to see if the
   * target address is the return address from a previous call instruction to
   * determine whether to pop the frame from the stack. Note, however, that this
   * approach may not work in the event that the user be allowed to make
   * call-outs to modify the control flow.
   */
  if (ctx->current_frame != ctx->first_frame)
  {
    GumExecFrame * next_frame = ctx->current_frame + 1;
    if (next_frame->real_address == ret_real_address)
      ctx->current_frame = next_frame;
  }
}

static void
gum_exec_block_arm_open_prolog (GumExecBlock * block,
                                GumGeneratorContext * gc)
{
  gum_exec_ctx_write_arm_prolog (block->ctx, gc->arm_writer);
}

static void
gum_exec_block_thumb_open_prolog (GumExecBlock * block,
                                  GumGeneratorContext * gc)
{
  gum_exec_ctx_write_thumb_prolog (block->ctx, gc->thumb_writer);
}

static void
gum_exec_block_arm_close_prolog (GumExecBlock * block,
                                 GumGeneratorContext * gc)
{
  gum_exec_ctx_write_arm_epilog (block->ctx, gc->arm_writer);
}

static void
gum_exec_block_thumb_close_prolog (GumExecBlock * block,
                                   GumGeneratorContext * gc)
{
  gum_exec_ctx_write_thumb_epilog (block->ctx, gc->thumb_writer);
}

static gboolean
gum_generator_context_is_timing_sensitive (GumGeneratorContext * gc)
{
  return gc->exclusive_load_offset != GUM_INSTRUCTION_OFFSET_NONE;
}

static void
gum_generator_context_advance_exclusive_load_offset (GumGeneratorContext * gc)
{
  if (gc->exclusive_load_offset == GUM_INSTRUCTION_OFFSET_NONE)
    return;

  gc->exclusive_load_offset++;

  if (gc->exclusive_load_offset == 4)
    gc->exclusive_load_offset = GUM_INSTRUCTION_OFFSET_NONE;
}

static gboolean
gum_stalker_is_thumb (gconstpointer address)
{
  return (GPOINTER_TO_SIZE (address) & 0x1) != 0;
}

static gboolean
gum_stalker_is_kuser_helper (gconstpointer address)
{
#ifdef HAVE_LINUX
  switch (GPOINTER_TO_SIZE (address))
  {
    case 0xffff0fa0: /* __kernel_memory_barrier */
    case 0xffff0fc0: /* __kernel_cmpxchg */
    case 0xffff0fe0: /* __kernel_get_tls */
    case 0xffff0f60: /* __kernel_cmpxchg64 */
      return TRUE;
    default:
      return FALSE;
  }
#else
  return FALSE;
#endif
}

static gboolean
gum_is_exclusive_load_insn (const cs_insn * insn)
{
  switch (insn->id)
  {
    case ARM_INS_LDAEX:
    case ARM_INS_LDAEXB:
    case ARM_INS_LDAEXD:
    case ARM_INS_LDAEXH:
    case ARM_INS_LDREX:
    case ARM_INS_LDREXB:
    case ARM_INS_LDREXD:
    case ARM_INS_LDREXH:
      return TRUE;
    default:
      return FALSE;
  }
}

static gboolean
gum_is_exclusive_store_insn (const cs_insn * insn)
{
  switch (insn->id)
  {
    case ARM_INS_STREX:
    case ARM_INS_STREXB:
    case ARM_INS_STREXD:
    case ARM_INS_STREXH:
    case ARM_INS_STLEX:
    case ARM_INS_STLEXB:
    case ARM_INS_STLEXD:
    case ARM_INS_STLEXH:
      return TRUE;
    default:
      return FALSE;
  }
}
