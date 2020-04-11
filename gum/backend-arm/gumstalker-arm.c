/*
 * Copyright (C) 2009-2019 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumstalker.h"

#include "gumarmreader.h"
#include "gumarmreg.h"
#include "gumarmrelocator.h"
#include "gumarmwriter.h"
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

#define GUM_STALKER_LOCK(o) g_mutex_lock (&(o)->mutex)
#define GUM_STALKER_UNLOCK(o) g_mutex_unlock (&(o)->mutex)

struct _GumStalker
{
  GObject parent;

  guint page_size;
  guint slab_size;
  guint slab_header_size;
  guint slab_max_blocks;

  GMutex mutex;
  GSList * contexts;
  GumTlsKey exec_ctx;

  GArray * exclusions;
};

G_DEFINE_TYPE (GumStalker, gum_stalker, G_TYPE_OBJECT)
typedef struct _GumSlab GumSlab;
typedef struct _GumExecFrame GumExecFrame;
typedef struct _GumExecCtx GumExecCtx;
typedef struct _GumExecBlock GumExecBlock;
typedef struct _GumGeneratorContext GumGeneratorContext;
typedef struct _GumInstruction GumInstruction;
typedef struct _GumBranchTarget GumBranchTarget;

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

  GumArmWriter code_writer;
  GumArmRelocator relocator;

  GumStalkerTransformer * transformer;
  void (* transform_block_impl) (GumStalkerTransformer * self,
      GumStalkerIterator * iterator, GumStalkerWriter * output);
  GumEventSink * sink;
  gboolean sink_started;
  GumEventType sink_mask;
  void (* sink_process_impl) (GumEventSink * self, const GumEvent * ev);

  gboolean unfollow_called_while_still_following;
  GumExecBlock * current_block;
  guint pending_calls;
  GumExecFrame * current_frame;
  GumExecFrame * first_frame;
  GumExecFrame * frames;

  gpointer resume_at;

  GumSlab * code_slab;
  GumMetalHashTable * mappings;
};

struct _GumExecBlock
{
  GumExecCtx * ctx;
  GumSlab * slab;

  guint8 * real_begin;
  guint8 * real_end;

  guint8 * code_begin;
  guint8 * code_end;
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
  GumArmRelocator * relocator;
  GumArmWriter * code_writer;
  gpointer continuation_real_address;
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

enum _GumExecCtxState
{
  GUM_EXEC_CTX_ACTIVE,
  GUM_EXEC_CTX_UNFOLLOW_PENDING,
  GUM_EXEC_CTX_DESTROY_PENDING
};

struct _GumBranchTarget
{
  gpointer absolute_address;
  gssize offset;
  gboolean is_indirect;
  arm_reg reg;
  arm_reg reg2;
  GumArmIndexMode mode;
  arm_shifter shifter;
  guint32 shift_value;
};

static void gum_stalker_class_init (GumStalkerClass * klass);

static void gum_stalker_init (GumStalker * self);

static void gum_stalker_finalize (GObject * object);

static gboolean gum_stalker_is_excluding (GumExecCtx * ctx,
    gconstpointer address);

static gboolean gum_stalker_is_thumb (gconstpointer address);

static GumExecCtx * gum_stalker_create_exec_ctx (GumStalker * self,
    GumThreadId thread_id, GumStalkerTransformer * transformer,
    GumEventSink * sink);

static void gum_stalker_destroy_exec_ctx (GumStalker * self,
    GumExecCtx * ctx);

static void gum_stalker_thaw (GumStalker * self,
    gpointer code, gsize size);

static void gum_stalker_freeze (GumStalker * self,
    gpointer code, gsize size);

static void gum_exec_ctx_free (GumExecCtx * ctx);

static GumSlab * gum_exec_ctx_add_slab (GumExecCtx * ctx);

static gboolean gum_exec_ctx_maybe_unfollow (GumExecCtx * ctx,
    gpointer resume_at);

static void gum_exec_ctx_unfollow (GumExecCtx * ctx,
    gpointer resume_at);

static gboolean gum_exec_ctx_contains (GumExecCtx * ctx,
    gconstpointer address);

static gpointer gum_exec_ctx_replace_current_block_with (GumExecCtx * ctx,
    gpointer start_address);

static void gum_exec_ctx_begin_call (GumExecCtx * ctx);

static void gum_exec_ctx_end_call (GumExecCtx * ctx);

static GumExecBlock * gum_exec_ctx_obtain_block_for (GumExecCtx * ctx,
    gpointer real_address, gpointer * code_address_ptr);

static void gum_exec_ctx_emit_call_event (GumExecCtx * ctx,
    gpointer location, gpointer target);

static void gum_exec_ctx_emit_ret_event (GumExecCtx * ctx,
    gpointer location, gpointer target);

static void gum_exec_ctx_emit_exec_event (GumExecCtx * ctx,
    gpointer location);

static void gum_exec_ctx_emit_block_event (GumExecCtx * ctx,
    gpointer begin, gpointer end);

static void gum_exec_ctx_write_prolog (GumExecCtx * ctx,
    GumArmWriter * cw);

static void gum_exec_ctx_write_epilog (GumExecCtx * ctx,
    GumArmWriter * cw);

static void gum_exec_ctx_write_mov_branch_target_address (GumExecCtx * ctx,
    const GumBranchTarget * target, arm_reg reg, GumGeneratorContext * gc);

static void gum_exec_ctx_load_real_register_into (GumExecCtx * ctx,
    arm_reg target_register, arm_reg source_register, GumGeneratorContext * gc);

static GumExecBlock * gum_exec_block_new (GumExecCtx * ctx);

static GumExecBlock * gum_exec_block_obtain (GumExecCtx * ctx,
    gpointer real_address, gpointer * code_address_ptr);

static gboolean gum_exec_block_is_full (GumExecBlock * block);

static void gum_exec_block_commit (GumExecBlock * block);

static void gum_exec_block_virtualize_branch_insn (GumExecBlock * block,
    const GumBranchTarget * target, arm_cc cc, GumGeneratorContext * gc);

static void gum_exec_block_virtualize_call_insn (GumExecBlock * block,
    const GumBranchTarget * target, arm_cc cc, GumGeneratorContext * gc);

static void gum_exec_block_virtualize_ret_insn (GumExecBlock * block,
    const GumBranchTarget * target, arm_cc cc, gboolean pop, gushort mask,
    GumGeneratorContext * gc);

static void gum_exec_block_write_handle_kuser_helper (GumExecBlock * block,
    const GumBranchTarget * target, arm_cc cc, GumGeneratorContext * gc);

static void gum_exec_block_write_call_replace_current_block_with (
    GumExecBlock * block, const GumBranchTarget * target,
    GumGeneratorContext * gc);

static void gum_exec_block_dont_virtualize_insn (GumExecBlock * block,
    const GumBranchTarget * target, GumGeneratorContext * gc);

static void gum_exec_block_write_handle_excluded (GumExecBlock * block,
    const GumBranchTarget * target, gboolean call, GumGeneratorContext * gc);

static void gum_exec_block_write_handle_not_taken (GumExecBlock * block,
    const GumBranchTarget * target, arm_cc cc, GumGeneratorContext * gc);

static void gum_exec_block_write_handle_continue (GumExecBlock * block,
    const GumBranchTarget * target, GumGeneratorContext * gc);

static void gum_exec_block_write_exec_generated_code (GumArmWriter * cw,
    GumExecCtx * ctx);

static void gum_exec_block_write_call_event_code (GumExecBlock * block,
    const GumBranchTarget * target, GumGeneratorContext * gc);

static void gum_exec_block_write_ret_event_code (GumExecBlock * block,
    const GumBranchTarget * target, GumGeneratorContext * gc);

static void gum_exec_block_write_exec_event_code (GumExecBlock * block,
    GumGeneratorContext * gc);

static void gum_exec_block_write_block_event_code (GumExecBlock * block,
    GumGeneratorContext * gc);

static void gum_exec_block_write_push_stack_frame (GumExecBlock * block,
    gpointer ret_real_address, GumGeneratorContext * gc);

static void gum_exec_block_push_stack_frame (GumExecCtx * ctx,
    gpointer ret_real_address);

static void gum_exec_block_write_pop_stack_frame (GumExecBlock * block,
    const GumBranchTarget * target, GumGeneratorContext * gc);

static void gum_exec_block_pop_stack_frame (GumExecCtx * ctx,
    gpointer ret_real_address);

static gboolean
gum_stalker_is_kuser_helper (gconstpointer address);

static void gum_exec_block_open_prolog (GumExecBlock * block,
    GumGeneratorContext * gc);

static void gum_exec_block_close_prolog (GumExecBlock * block,
    GumGeneratorContext * gc);

static gboolean g_debug = FALSE;
static guint32 g_count = 0;
static guint32 g_events = 0;
static gpointer gum_unfollow_me_address;

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

  gum_unfollow_me_address = gum_strip_code_pointer (gum_stalker_unfollow_me);
}

static void
gum_stalker_init (GumStalker * self)
{
  self->exclusions = g_array_new (FALSE, FALSE, sizeof (GumMemoryRange));

  self->page_size = gum_query_page_size ();
  self->slab_size =
      GUM_ALIGN_SIZE (GUM_CODE_SLAB_MAX_SIZE, self->page_size);
  self->slab_header_size =
      GUM_ALIGN_SIZE (GUM_CODE_SLAB_MAX_SIZE / 12, self->page_size);
  self->slab_max_blocks = (self->slab_header_size -
      G_STRUCT_OFFSET (GumSlab, blocks)) / sizeof (GumExecBlock);

  /*
   * Due to the load store architecture of ARM32. In order to perform any sort
   * of calculation, data must be loaded into a register. In many cases,
   * however, we need to maintain the contents of registers in order to avoid
   * affecting the operation of the stalked application. Therefore we need to
   * use a scratch register and store and restore it's value on the stack.
   *
   * However, if for example, we need to branch to a calculated address we will
   * need to restore the scratch register value from the stack before we perform
   * the branch. Thus we need to store the calculated value somewhere where it
   * can be referenced again first. When the LDMIA instruction operates on a
   * number of registers including PC, the value of PC is expected to be popped
   * from the stack last, hence we cannot push the scratch register, then the
   * calculated address and use an LDMIA to restore the register and branch as
   * the registers will be in the wrong order.
   *
   * We could consider using space above the stack pointer (and any red-zone),
   * or some other asymmetric stack usage, but in order to keep things simple,
   * we store our calculated address in the code stream using the label support
   * of the gumarmwriter. This means that the code page needs to be RWX. This
   * isn't expected to be a problem since it is expected that most systems which
   * prevent the use of RWX memory as a security feature will have already
   * adopted AARCH64 architecture in order to benefit from other security
   * features and hence this should not affect ARM32.
   */
  if (gum_query_rwx_support () == GUM_RWX_NONE)
  {
    g_error ("Target must support RWX pages");
  }

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
gum_stalker_is_excluding (GumExecCtx * ctx,
                          gconstpointer address)
{
  GArray * exclusions = ctx->stalker->exclusions;
  guint i;

  /*
   * We haven't implemented stalker on ARM32 to handle thumb instructions yet.
   * Frankly, the normal instruction set is complex enough with a whole host of
   * instructions which can affect control flow and many with different options
   * to control how they operate.
   *
   * For now, we will treat any transition to thumb code to be one to an
   * excluded range and treat it accordingly. Stalking should contrinue from the
   * point that control returns back to normal ARM32 code.
   */
  if (gum_stalker_is_thumb (address))
  {
    return TRUE;
  }

  for (i = 0; i != exclusions->len; i++)
  {
    GumMemoryRange * r = &g_array_index (exclusions, GumMemoryRange, i);

    if (GUM_MEMORY_RANGE_INCLUDES (r, GUM_ADDRESS (address)))
      return TRUE;
  }

  return FALSE;
}

static gboolean
gum_stalker_is_thumb (gconstpointer address)
{
  /* When branching to thumb code, the low bit of the address is set. */
  if ((GUM_ADDRESS (address) & 0x1) != 0)
  {
    return TRUE;
  }

  return FALSE;
}

gint
gum_stalker_get_trust_threshold (GumStalker * self)
{
  return 0;
}

void
gum_stalker_set_trust_threshold (GumStalker * self,
                                 gint trust_threshold)
{
  g_warning ("Trust threshold unsupported");
}

void
gum_stalker_flush (GumStalker * self)
{
}

void
gum_stalker_stop (GumStalker * self)
{
}

gboolean
gum_stalker_garbage_collect (GumStalker * self)
{
  return FALSE;
}

gpointer
_gum_stalker_do_follow_me (GumStalker * self,
                           GumStalkerTransformer * transformer,
                           GumEventSink * sink,
                           gpointer ret_addr)
{
  g_count = 0;
  g_events = 0;
  GumEventType mask = gum_event_sink_query_mask (sink);

  /*
   * For the moment we don't implement compile events. Since we only ever
   * instrument a block immediately before execution, these blocks will generate
   * CALL or BLOCK events in any case when executed.
   */
  if (mask & GUM_COMPILE)
  {
    g_warning ("Compile events unsupported");
  }

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
}

gboolean
gum_stalker_is_following_me (GumStalker * self)
{
  return FALSE;
}

void
gum_stalker_follow (GumStalker * self,
                    GumThreadId thread_id,
                    GumStalkerTransformer * transformer,
                    GumEventSink * sink)
{
  /*
   * At present, we only support the stalking of the current thread. Stalking of
   * other threads is deferred until a subsequent release.
   */
  g_warning ("Follow unsupported");
}

void
gum_stalker_unfollow (GumStalker * self,
                      GumThreadId thread_id)
{
  g_warning ("Unfollow unsupported");
}

void
gum_stalker_activate (GumStalker * self,
                      gconstpointer target)
{
  /*
   * At present, we also do not support activate/deactivate functionality. Thus
   * it will not be possible to use stalker on ARM32 to insepct the execution of
   * NativeFunctions invoked through the runtime.
   */
  g_warning ("Activate/deactivate unsupported");
}

void
gum_stalker_deactivate (GumStalker * self)
{
  g_warning ("Activate/deactivate unsupported");
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

  ctx = g_slice_new0 (GumExecCtx);

  ctx->state = GUM_EXEC_CTX_ACTIVE;

  ctx->stalker = g_object_ref (self);
  ctx->thread_id = thread_id;

  gum_arm_writer_init (&ctx->code_writer, NULL);
  gum_arm_relocator_init (&ctx->relocator, NULL, &ctx->code_writer);

  if (transformer != NULL)
    ctx->transformer = g_object_ref (transformer);
  else
    ctx->transformer = gum_stalker_transformer_make_default ();
  ctx->transform_block_impl =
      GUM_STALKER_TRANSFORMER_GET_IFACE (ctx->transformer)->transform_block;

  ctx->sink = g_object_ref (sink);
  ctx->sink_mask = gum_event_sink_query_mask (sink);
  ctx->sink_process_impl = GUM_EVENT_SINK_GET_IFACE (sink)->process;

  ctx->frames =
      gum_memory_allocate (NULL, self->page_size, self->page_size, GUM_PAGE_RW);
  ctx->first_frame = (GumExecFrame *) ((guint8 *) ctx->frames +
      self->page_size - sizeof (GumExecFrame));
  ctx->current_frame = ctx->first_frame;

  ctx->mappings = gum_metal_hash_table_new (NULL, NULL);

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

  if (ctx->sink_started)
  {
    gum_event_sink_stop (ctx->sink);

    ctx->sink_started = FALSE;
  }

  gum_exec_ctx_free (ctx);
}

static void
gum_stalker_thaw (GumStalker * self,
                  gpointer code,
                  gsize size)
{

}

static void
gum_stalker_freeze (GumStalker * self,
                    gpointer code,
                    gsize size)
{
  gum_clear_cache (code, size);
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

  gum_memory_free (ctx->frames, stalker->page_size);

  g_object_unref (ctx->sink);
  g_object_unref (ctx->transformer);

  gum_arm_relocator_clear (&ctx->relocator);
  gum_arm_writer_clear (&ctx->code_writer);

  g_object_unref (stalker);

  g_slice_free (GumExecCtx, ctx);
}

static GumSlab *
gum_exec_ctx_add_slab (GumExecCtx * ctx)
{
  GumSlab * slab;
  GumStalker * stalker = ctx->stalker;

  slab = gum_memory_allocate (NULL, stalker->slab_size, stalker->page_size,
      GUM_PAGE_RWX);

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
gum_exec_ctx_replace_current_block_with (GumExecCtx * ctx,
                                         gpointer start_address)
{
  if (start_address == gum_unfollow_me_address)
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

    gum_exec_ctx_maybe_unfollow (ctx, start_address);
  }

  return ctx->resume_at;
}

static void
gum_exec_ctx_begin_call (GumExecCtx * ctx)
{
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
  GumExecBlock * block;
  GumArmWriter * cw;
  GumArmRelocator * rl;
  GumGeneratorContext gc;
  GumStalkerIterator iterator;
  gboolean all_labels_resolved;

  block = gum_exec_block_obtain (ctx, real_address, code_address_ptr);
  if (block != NULL)
  {
    return block;
  }

  block = gum_exec_block_new (ctx);

  block->real_begin = real_address;
  *code_address_ptr = block->code_begin;

  gum_metal_hash_table_insert (ctx->mappings, real_address, block);

  cw = &ctx->code_writer;
  rl = &ctx->relocator;

  gum_arm_writer_reset (cw, block->code_begin);
  gum_arm_relocator_reset (rl, real_address, cw);

  gum_ensure_code_readable (real_address, ctx->stalker->page_size);

  gc.instruction = NULL;
  gc.relocator = rl;
  gc.code_writer = cw;
  gc.continuation_real_address = NULL;

  iterator.exec_context = ctx;
  iterator.exec_block = block;
  iterator.generator_context = &gc;

  iterator.instruction.ci = NULL;
  iterator.instruction.begin = NULL;
  iterator.instruction.end = NULL;

  ctx->pending_calls++;

  ctx->transform_block_impl (ctx->transformer, &iterator,
      (GumStalkerWriter *) cw);

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

  gum_arm_writer_put_brk_imm (cw, 14);

  all_labels_resolved = gum_arm_writer_flush (cw);
  if (!all_labels_resolved)
    g_error ("Failed to resolve labels");

  block->code_end = (guint8 *) gum_arm_writer_cur (cw);
  block->real_end = (guint8 *) rl->input_cur;

  gum_exec_block_commit (block);

  return block;
}

gboolean
gum_stalker_iterator_next (GumStalkerIterator * self,
                           const cs_insn ** insn)
{
  GumGeneratorContext * gc = self->generator_context;
  GumArmRelocator * rl = gc->relocator;
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

    block->code_end = gum_arm_writer_cur (gc->code_writer);

    if (gum_exec_block_is_full (block))
    {
      gc->continuation_real_address = instruction->end;
      return FALSE;
    }

    if (gum_arm_relocator_eob (rl))
    {
      return FALSE;
    }
  }

  instruction = &self->instruction;

  n_read = gum_arm_relocator_read_one (rl, &instruction->ci);
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
  GumExecBlock * block = self->exec_block;
  GumGeneratorContext * gc = self->generator_context;
  const cs_insn * insn = gc->instruction->ci;
  cs_arm * arm = &insn->detail->arm;
  cs_arm_op * op = &arm->operands[0];
  cs_arm_op * op2 = &arm->operands[1];
  cs_arm_op * op3;

  /*
   * The complex nature of the ARM32 instruction set means that determining the
   * * target address for an instruction which affects control flow is also
   * complex.
   *
   * Instructions such as 'BL label' will make use of the absolute_address
   * field. 'BL reg' and 'BLX' reg will make use of the reg field. 'LDR pc,
   * [reg]' however makes use of the reg field and sets is_indirect to TRUE.
   * This means that the reg field doesn't contain the target itself, by the
   * address in memory where the target is stored. 'LDR pc, [reg, #x]'
   * additionally sets the offset field which needs to be added to the register
   * before it is dereferenced.
   *
   * The POP and LDM instructions both read multiple values from a base register
   * and store them into a listed set of registers. In the case of the POP
   * instruction, this base register is always SP (the stack pointer). Again the
   * is_indirect field is set and the value of the offset field is determine by
   * how many registers are included in the register list before PC.
   *
   * Finally, ADD and SUB instructions can be used to modify control flow. ADD
   * instructions have two main forms. Firstly 'ADD pc, reg, #x', in this case
   * the reg and offset fields are both set accordingly Secondly, if the form
   * 'ADD pc, reg, reg2' is used, then the values of reg and reg2 are set
   * accordingly. This form has the additional complexity of allowing a suffix
   * which can describe a shift operation (one of 4 types) and a value
   * indicating how many places to shift to be applied to reg2 before it is
   * added. This information is encoded in the shifter and shift_value fields
   * accordingly. Lastly the SUB instruction is identical to ADD except the mode
   * field is set to GUM_INDEX_NEG to indicate that reg2 should be subtracted
   * rather than added.
   *
   * This complex target field is processed by
   * gum_exec_ctx_write_mov_branch_target_address in order to wrte instructions
   * into the instrumented block to recover the target address from these
   * different forms of instruction.
   *
   * Lastly, we should note that many of these instructions can be conditionally
   * executed depending on the status of processor flags. For example, BLEQ will
   * only take affect if the previous instruction which set the flags indicated
   * the result of the operationg was equal.
   */
  GumBranchTarget target =
  {
    .absolute_address = 0,
    .offset = 0,
    .is_indirect = FALSE,
    .reg = ARM_REG_INVALID,
    .reg2 = ARM_REG_INVALID,
    .mode = GUM_INDEX_POS,
    .shifter = ARM_SFT_INVALID,
    .shift_value = 0
  };
  GumArmRegInfo ri;

  /*
   * The mask field is set when the POP or LDMIA instructions are encountered.
   * This is used to encode the other registers which are included in the
   * operation. Note, however, that the register PC is omitted from this mask.
   *
   *  This is processed by gum_exec_block_virtualize_ret_insn so that after the
   *  epilogue has been executed and the application registers are restored. A
   *  replacement POP or LDMIA instruction can be generated to restore the
   *  values of the other registers from the stack. Note that we don't restore
   *  the value of PC from the stack and instead simply increment the stack
   *  pointer since we instead want to pass control back into stalker to
   *  instrument the next block.
   */
  gushort mask = 0;

  if (g_debug)
  {
    g_print ("%08d - %p: %s\t%s = 0x%08x, id: %d\n",
        ++g_count, gc->instruction->begin, insn->mnemonic,
        insn->op_str, *(guint*)gc->instruction->begin, insn->id);
  }

  if (gum_arm_relocator_eob (gc->relocator))
  {
    if (g_debug)
    {
      g_print ("\n");
    }

    switch (insn->id)
    {
      case ARM_INS_B:
      case ARM_INS_BL:
        g_assert (op->type == ARM_OP_IMM);
        target.absolute_address = GSIZE_TO_POINTER (op->imm);
        break;
      case ARM_INS_BX:
      case ARM_INS_BLX:
        if (op->type == ARM_OP_REG)
        {
          target.reg = op->reg;
        }
        else
        {
          /*
           * In the case of the BX and BLX instructions, the instruction mode
           * always changes from ARM to thumb or vice-versa and hence the low
           * bit of the target address should be set. Note that since we only
           * support stalking of ARM code for now, we don't need to cater for
           * the reverse.
           */
          target.absolute_address = GSIZE_TO_POINTER (op->imm) + 1;
        }
        break;
      case ARM_INS_MOV:
        target.reg = op2->reg;
        break;
      case ARM_INS_POP:
        target.reg = ARM_REG_SP;
        target.is_indirect = TRUE;
        for (uint8_t idx = 0; idx < insn->detail->arm.op_count; idx++)
        {
          op = &arm->operands[idx];
          if (op->reg == ARM_REG_PC)
          {
            target.offset = idx * 4;
          }
          else
          {
            gum_arm_reg_describe (op->reg, &ri);
            mask |= 1 << ri.index;
          }
        }
        break;
      case ARM_INS_LDM:
        target.reg = op->reg;
        target.is_indirect = TRUE;
        for (uint8_t idx = 1; idx < insn->detail->arm.op_count; idx++)
        {
          op = &arm->operands[idx];
          if (op->reg == ARM_REG_PC)
          {
            target.offset = (idx - 1) * 4;
          }
          else
          {
            gum_arm_reg_describe (op->reg, &ri);
            mask |= 1 << ri.index;
          }
        }
        break;
      case ARM_INS_LDR:
        g_assert (op2->type == ARM_OP_MEM);
        target.reg = op2->mem.base;
        target.is_indirect = TRUE;
        target.offset = op2->mem.disp;
        break;
      case ARM_INS_SUB:
        g_assert (op2->type == ARM_OP_REG);
        target.reg = op2->reg;
        target.mode = GUM_INDEX_NEG;

        op3 = &arm->operands[2];
        target.shifter = op3->shift.type;
        target.shift_value = op3->shift.value;

        if (op3->type == ARM_OP_REG)
        {
          target.reg2 = op3->reg;
          target.offset = 0;
        }
        else
        {
          target.reg2 = ARM_REG_INVALID;
          target.offset = op3->imm;
        }

        break;
      case ARM_INS_ADD:
        g_assert (op2->type == ARM_OP_REG);
        target.reg = op2->reg;
        target.mode = GUM_INDEX_POS;

        op3 = &arm->operands[2];
        target.shifter = op3->shift.type;
        target.shift_value = op3->shift.value;

        if (op3->type == ARM_OP_REG)
        {
          target.reg2 = op3->reg;
          target.offset = 0;
        }
        else
        {
          target.reg2 = ARM_REG_INVALID;
          target.offset = op3->imm;
        }
        break;
      default:
        g_assert_not_reached ();
    }

    switch (insn->id)
    {
      case ARM_INS_SMC:
      case ARM_INS_HVC:
        g_assert ("" == "not implemented");
        break;
      case ARM_INS_SUB:
      case ARM_INS_ADD:
      case ARM_INS_B:
      case ARM_INS_BX:
      case ARM_INS_LDR:
        gum_exec_block_virtualize_branch_insn (block, &target, arm->cc, gc);
        break;
      case ARM_INS_BL:
      case ARM_INS_BLX:
        gum_exec_block_virtualize_call_insn (block, &target, arm->cc, gc);
        break;
      case ARM_INS_MOV:
        gum_exec_block_virtualize_ret_insn (block, &target, arm->cc, FALSE,
            0, gc);
        break;
      case ARM_INS_POP:
      case ARM_INS_LDM:
        gum_exec_block_virtualize_ret_insn (block, &target, arm->cc, TRUE,
            mask, gc);
        break;
      default:
        g_assert_not_reached ();
        break;
    }
  }
  else
  {
    gum_exec_block_dont_virtualize_insn (block, &target, gc);
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
  if (g_debug)
  {
    g_print ("%3d: { type: %s, location: 0x%08x, "
        "target: 0x%08x, depth: %u }\n",
          ++g_events, "GUM_CALL", (guint)call->location, (guint)call->target, call->depth);
  }
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

  if (g_debug)
  {
    g_print ("%3d: { type: %s, location: 0x%08x, "
        "target: 0x%08x, depth: %u }\n",
        ++g_events, "GUM_RET", (guint)ret->location, (guint)ret->target, ret->depth);
  }
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
  if (g_debug)
  {
    g_print ("%3d: { type: %s, location: 0x%08x }\n", ++g_events,
          "GUM_EXEC", (guint)exec->location);
  }
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
  if (g_debug)
  {
    g_print ("%3d: { type: %s, begin: 0x%08x, end: 0x%08x }\n", ++g_events,
        "GUM_BLOCK",    (guint)block->begin, (guint)block->end);
  }
}

void
gum_stalker_iterator_put_callout (GumStalkerIterator * self,
                                  GumStalkerCallout callout,
                                  gpointer data,
                                  GDestroyNotify data_destroy)
{
}

static void
gum_exec_ctx_write_prolog (GumExecCtx * ctx,
                           GumArmWriter * cw)
{
  gint immediate_for_sp = 0;

  /*
   * For our context, we want to build up the following structure so that
   * stalker can read the register state of the application.
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
    ARM_REG_R0, ARM_REG_R1, ARM_REG_R2, ARM_REG_R3,
    ARM_REG_R4, ARM_REG_R5, ARM_REG_R6, ARM_REG_R7,
    ARM_REG_LR);

  immediate_for_sp += 9 * 4;

  /* Push R8 through R12 */
  gum_arm_writer_put_push_registers (cw, 5,
    ARM_REG_R8, ARM_REG_R9, ARM_REG_R10, ARM_REG_R11,
    ARM_REG_R12);

  immediate_for_sp += 5 * 4;

  /*
   * Calculate the original value that SP would have held prior to this function
   * by adding on the amount of registers pushed so far and store it in R2.
   */
  gum_arm_writer_put_add_reg_reg_imm (cw, ARM_REG_R2, ARM_REG_SP,
                                     immediate_for_sp);

  /*
   * Zero the register R1. This will be used to store the value of PC. If a
   * function inside stalker wants to retrieve the value of PC according to the
   * guest then it must interrogate the iterator being used to process the
   * original instruction stream. Since the guest will be executing instrumented
   * code, the value of PC if we pushed it here would not be the value of PC
   * within the original block anyway.
   *
   * The data within this context block is read by the instrumented instructions
   * emitted by the function gum_exec_ctx_load_real_register_into and this takes
   * this edge case into account.
   */
  gum_arm_writer_put_sub_reg_reg_reg (cw, ARM_REG_R1, ARM_REG_R1,
                                     ARM_REG_R1);

  /* Read the flags register cpsr into R0 */
  gum_arm_writer_put_mov_cpsr_to_reg (cw, ARM_REG_R0);

  /*
   * Push the values of R0, R1 and R2 containing the cpsr, zeroed PC and
   * adjusted stackpointer respectively.
   */
  gum_arm_writer_put_push_registers (cw, 3,
    ARM_REG_R0, ARM_REG_R1, ARM_REG_R2);

  /*
   * Now that the context structure has been pushed onto the stack, we store the
   * address of this structure on the stack into register R10. This register can
   * be chosen fairly arbitrarily but it should be a callee saved register so
   * that any C code called from our instrumented code is obliged by the calling
   * convention to preserve its value accross the function call. In particul
   * register R12 is a caller saved register and as such any C function can
   * modify its value and not restore it. Similary registers R0 through R3
   * contain the arguments to the function and the return result and are
   * accordingly not preserved.
   *
   * We have elected not to use R11 since this can be used a a frame pointer by
   * some compilers and as such can confuse some debuggers. The function
   * gum_exec_ctx_load_real_register_into makes use of this register R10 in
   * order to access this context structure.
   */
  gum_arm_writer_put_mov_reg_reg (cw, ARM_REG_R10, ARM_REG_SP);
}

static void
gum_exec_ctx_write_epilog (GumExecCtx * ctx,
                           GumArmWriter * cw)
{
  gum_arm_writer_put_pop_registers (cw, 3,
    ARM_REG_R0, ARM_REG_R1, ARM_REG_R2);
  gum_arm_writer_put_mov_reg_to_cpsr (cw, ARM_REG_R0);

  gum_arm_writer_put_pop_registers (cw, 5,
    ARM_REG_R8, ARM_REG_R9, ARM_REG_R10, ARM_REG_R11,
    ARM_REG_R12);

  gum_arm_writer_put_pop_registers (cw, 9,
    ARM_REG_R0, ARM_REG_R1, ARM_REG_R2, ARM_REG_R3,
    ARM_REG_R4, ARM_REG_R5, ARM_REG_R6, ARM_REG_R7,
    ARM_REG_LR);
}

static void
gum_exec_ctx_write_mov_branch_target_address (GumExecCtx * ctx,
                                              const GumBranchTarget * target,
                                              arm_reg reg,
                                              GumGeneratorContext * gc)
{
  GumArmWriter * cw = gc->code_writer;

  if (target->reg == ARM_REG_INVALID)
  {
    gum_arm_writer_put_ldr_reg_address (cw, reg,
        GUM_ADDRESS (target->absolute_address));
  }
  else
  {
    gum_exec_ctx_load_real_register_into (ctx, reg, target->reg, gc);
    if (target->is_indirect)
    {
      /*
       * If the target is indirect, then we need to dereference it.
       * e.g. LDR pc, [r3, #4]
       */
      gum_arm_writer_put_ldr_reg_reg_offset (cw, reg, reg, target->mode,
          target->offset);
    }
    else if (target->reg2 != ARM_REG_INVALID)
    {

      /* This block handles instructions such as 'ADD pc, r1, r2 lsl #4' */

      /*
       * Here we are going to use R12 as additional scratch space for our
       * calculation since it is the only register which is not callee saved.
       * Thus since we are already using 'reg' as our output register, we cannot
       * have the two collide. This should not be an issue since the callers of
       * this funtion are all instrumented code generated by the stalker and the
       * value of the branch target address is usually used as an argument to
       * another function and hence is generally loaded into one of the
       * registers used to hold arguments defined by the ABI (R0-R3).
       */
      if (reg == ARM_REG_R12)
      {
        g_error ("Cannot support ADD/SUB reg, reg, reg when target is"
            "ARM_REG_R12");
      }

      /*
       * Load the second register value from the context into R12 before adding
       * to the original and applying any necessary shift.
       */
      gum_exec_ctx_load_real_register_into (ctx, ARM_REG_R12, target->reg2, gc);

      gum_arm_writer_put_add_reg_reg_reg_sft (cw, reg, reg, ARM_REG_R12,
          target->shifter, target->shift_value);
    }
    else if (target->offset != 0)
    {
      /* This block handles instructions of the form 'ADD/SUB pc, r1, #32' */
      if (target->shifter != ARM_SFT_INVALID || target->shift_value != 0)
      {
        g_error ("Shifter not supported for immediate offset");
      }

      if (target->mode == GUM_INDEX_POS)
      {
        gum_arm_writer_put_add_reg_reg_imm (cw, reg, reg, target->offset);
      }
      else
      {
        gum_arm_writer_put_sub_reg_reg_imm (cw, reg, reg, target->offset);
      }
    }
  }
}

static void
gum_exec_ctx_load_real_register_into (GumExecCtx * ctx,
                                      arm_reg target_register,
                                      arm_reg source_register,
                                      GumGeneratorContext * gc)
{
  GumArmWriter * cw;

  cw = gc->code_writer;
  /*
   * For the most part, we simply need to identify the offset of the
   * source_register within the GumCpuContext structure and load the value
   * accordingly. However, in the case of the PC, we instead load the address of
   * the current instruction in the iterator. Note that we add the fixed offset
   * of 8 since the value of PC is alway interpreted in ARM32 as being 8 bytes
   * past the start of the instruction.
   */
  if (source_register >= ARM_REG_R0 && source_register <= ARM_REG_R7)
  {
    gum_arm_writer_put_ldr_reg_reg_offset (cw, target_register, ARM_REG_R10,
        GUM_INDEX_POS,
        G_STRUCT_OFFSET (GumCpuContext, r) +
        ((source_register - ARM_REG_R0) * 4));
  }
  else if (source_register >= ARM_REG_R8 && source_register <= ARM_REG_R12)
  {
    gum_arm_writer_put_ldr_reg_reg_offset (cw, target_register, ARM_REG_R10,
        GUM_INDEX_POS,
        G_STRUCT_OFFSET (GumCpuContext, r8) +
        ((source_register - ARM_REG_R8) * 4));
  }
  else if (source_register == ARM_REG_LR)
  {
    gum_arm_writer_put_ldr_reg_reg_offset (cw, target_register, ARM_REG_R10,
        GUM_INDEX_POS,
        G_STRUCT_OFFSET (GumCpuContext, lr));
  }
  else if (source_register == ARM_REG_SP)
  {
    gum_arm_writer_put_ldr_reg_reg_offset (cw, target_register, ARM_REG_R10,
        GUM_INDEX_POS,
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

    gum_stalker_thaw (stalker, block->code_begin, available);
    slab->num_blocks++;

    return block;
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
  gsize code_size, real_size;

  code_size = block->code_end - block->code_begin;
  block->slab->offset += code_size;

  real_size = block->real_end - block->real_begin;
  block->slab->offset += real_size;

  gum_stalker_freeze (block->ctx->stalker, block->code_begin, code_size);
}

static void
gum_exec_block_virtualize_branch_insn (GumExecBlock * block,
                                       const GumBranchTarget * target,
                                       arm_cc cc,
                                       GumGeneratorContext * gc)
{
  GumExecCtx * ec = block->ctx;

  gum_exec_block_write_handle_not_taken (block, target, cc, gc);

  gum_exec_block_open_prolog (block, gc);

  if ((ec->sink_mask & GUM_EXEC) != 0)
  {
    gum_exec_block_write_exec_event_code (block, gc);
  }

  if ((ec->sink_mask & GUM_BLOCK) != 0)
  {
    gum_exec_block_write_block_event_code (block, gc);
  }

  gum_exec_block_write_handle_excluded (block, target, FALSE, gc);
  gum_exec_block_write_handle_kuser_helper (block, target, cc, gc);

  gum_exec_block_write_call_replace_current_block_with (block, target, gc);
  gum_exec_block_write_pop_stack_frame (block, target, gc);
  gum_exec_block_close_prolog (block, gc);
  gum_exec_block_write_exec_generated_code (gc->code_writer, block->ctx);
}

static void
gum_exec_block_virtualize_call_insn (GumExecBlock * block,
                                     const GumBranchTarget * target,
                                     arm_cc cc,
                                     GumGeneratorContext * gc)
{
  GumExecCtx * ec = block->ctx;
  gpointer ret_real_address = gc->instruction->end;

  gum_exec_block_write_handle_not_taken (block, target, cc, gc);

  gum_exec_block_open_prolog (block, gc);

  if ((ec->sink_mask & GUM_EXEC) != 0)
  {
    gum_exec_block_write_exec_event_code (block, gc);
  }

  if ((ec->sink_mask & GUM_CALL) != 0)
  {
    gum_exec_block_write_call_event_code (block, target, gc);
  }

  gum_exec_block_write_handle_excluded (block, target, TRUE, gc);
  gum_exec_block_write_call_replace_current_block_with (block, target, gc);
  gum_exec_block_write_push_stack_frame (block, ret_real_address, gc);
  gum_exec_block_close_prolog (block, gc);
  gum_arm_writer_put_ldr_reg_address (gc->code_writer, ARM_REG_LR,
    GUM_ADDRESS (ret_real_address));
  gum_exec_block_write_exec_generated_code (gc->code_writer, block->ctx);
}

static void
gum_exec_block_virtualize_ret_insn (GumExecBlock * block,
                                    const GumBranchTarget * target,
                                    arm_cc cc,
                                    gboolean pop,
                                    gushort mask,
                                    GumGeneratorContext * gc)
{
  GumExecCtx * ec = block->ctx;

  gum_exec_block_write_handle_not_taken (block, target, cc, gc);

  gum_exec_block_open_prolog (block, gc);

  if ((ec->sink_mask & GUM_EXEC) != 0)
  {
    gum_exec_block_write_exec_event_code (block, gc);
  }

  if ((ec->sink_mask & GUM_RET) != 0)
  {
    gum_exec_block_write_ret_event_code (block, target, gc);
  }

  gum_exec_block_write_call_replace_current_block_with (block, target, gc);
  gum_exec_block_write_pop_stack_frame (block, target, gc);
  gum_exec_block_close_prolog (block, gc);

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
    if (mask != 0)
    {
      gum_arm_write_put_ldmia_registers_by_mask (gc->code_writer, target->reg,
          mask);
    }
    gum_arm_writer_put_add_reg_reg_imm (gc->code_writer, target->reg,
        target->reg, 4);
  }

  gum_exec_block_write_exec_generated_code (gc->code_writer, block->ctx);
}

static void
gum_exec_block_write_handle_kuser_helper (GumExecBlock * block,
                                          const GumBranchTarget * target,
                                          arm_cc cc,
                                          GumGeneratorContext * gc)
{
  GumArmWriter * cw = gc->code_writer;
  gconstpointer not_kuh = cw->code + 1;
  gconstpointer kuh_label = cw->code + 2;

  GumArgument args[] =
  {
    { GUM_ARG_REGISTER, { .reg = ARM_REG_R0}},
  };

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
   * very machine sepecific code, qemu instead detects when the application
   * attempts to execute one of these handlers (see the function do_kernel_trap
   * in https://github.com/qemu/qemu/blob/master/linux-user/arm/cpu_loop.c) and
   * performs the necessary emulation on behalf of the application. Thus it is
   * not possible to read the page at this address and retrieve ARM code to be
   * instrumented.
   *
   * Rather than attempt to detect the target on which we are running, as it is
   * vanishingly unlikely that a user will care to stalk this platform specific
   * code we simply execute is outside of the stalker engine, similar to the way
   * in which an excluded range is handled.
   */

  /*
   * If the branch target is deterministic (e.g. not based on register
   * contents). We can perform the check during instrumentation rather than at
   * runtime and omit this code if we can determine we will not enter a
   * kuser_helper.
   */
  if (target->reg == ARM_REG_INVALID)
  {
    if (gum_stalker_is_kuser_helper (target->absolute_address) == FALSE)
    {
      return;
    }
  }

  if (target->reg != ARM_REG_INVALID)
  {
    gum_exec_ctx_write_mov_branch_target_address (block->ctx,
                                              target,
                                              ARM_REG_R0,
                                              gc);

    gum_arm_writer_put_call_address_with_arguments_array (cw,
      GUM_ADDRESS (gum_stalker_is_kuser_helper), 1, args);

    gum_arm_writer_put_cmp_reg_imm (cw, ARM_REG_R0, 0);
    gum_arm_writer_put_bcc_label (cw, ARM_CC_EQ, not_kuh);
  }

  gum_exec_ctx_write_mov_branch_target_address (block->ctx,
                                          target,
                                          ARM_REG_R0,
                                          gc);

  gum_arm_writer_put_strcc_reg_label (gc->code_writer, ARM_CC_AL, ARM_REG_R0,
      kuh_label);
  gum_exec_block_close_prolog (block, gc);
  gum_arm_writer_put_ldrcc_reg_label (gc->code_writer, ARM_CC_AL, ARM_REG_R12,
      kuh_label);

  /*
   * Unlike an excluded range, where the function is executed by a call
   * instruction. It is quite common for kuser_helpers to instead be executed by
   * the following instruction sequence.
   *
   * mvn r0,#0xf000
   * sub pc,r0,#0x1f
   *
   * This is effectively a tail call within a thunk function. But as we can see
   * * when we vector to the kuser_helper we actually find a branch instruction
   * and not a call and hence were we to simply emit it, then we would not be
   * able to return to the stalker engine after it has completed in order to
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
  gum_arm_writer_put_push_registers (gc->code_writer, 1, ARM_REG_LR);
  gum_arm_writer_put_blr_reg (gc->code_writer, ARM_REG_R12);
  gum_arm_writer_put_pop_registers (gc->code_writer, 1, ARM_REG_LR);

  gum_exec_block_open_prolog (block, gc);

  GumBranchTarget ret_target =
  {
    .absolute_address = 0,
    .offset = 0,
    .is_indirect = FALSE,
    .reg = ARM_REG_LR,
    .reg2 = ARM_REG_INVALID,
    .mode = GUM_INDEX_POS,
    .shifter = ARM_SFT_INVALID,
    .shift_value = 0
  };
  gum_exec_block_write_call_replace_current_block_with (block, &ret_target, gc);
   gum_exec_block_close_prolog (block, gc);

  gum_exec_block_write_exec_generated_code (gc->code_writer, block->ctx);

  gum_arm_writer_put_brk_imm (gc->code_writer, 15);

  gum_arm_writer_put_label (gc->code_writer, kuh_label);
  gum_arm_writer_put_instruction (gc->code_writer, 0xdeadface);

  /*
   * This label is only required if we weren't able to determine at
   * instrumentation time whether the target was a kuser_helper. If we could
   * then we either emit the handler if it is, or do nothing if not.
   */
  if (target->reg != ARM_REG_INVALID)
  {
    gum_arm_writer_put_label (cw, not_kuh);
  }
}

static void
gum_exec_block_write_call_replace_current_block_with (GumExecBlock * block,
                                                      const GumBranchTarget * target,
                                                      GumGeneratorContext * gc)
{
  GumArmWriter * cw = gc->code_writer;
  GumArgument args[] =
  {
    { GUM_ARG_ADDRESS, { .address = GUM_ADDRESS (block->ctx)}},
    { GUM_ARG_REGISTER, { .reg = ARM_REG_R1}},
  };

  gum_exec_ctx_write_mov_branch_target_address (block->ctx, target,
                                                ARM_REG_R1, gc);

  gum_arm_writer_put_call_address_with_arguments_array (cw,
    GUM_ADDRESS (gum_exec_ctx_replace_current_block_with), 2, args);
}

static void
gum_exec_block_dont_virtualize_insn (GumExecBlock * block,
                                     const GumBranchTarget * target,
                                     GumGeneratorContext * gc)
{
  GumExecCtx * ec = block->ctx;

  if ((ec->sink_mask & GUM_EXEC) != 0)
  {
    gum_exec_block_open_prolog (block, gc);
    gum_exec_block_write_exec_event_code (block, gc);
    gum_exec_block_close_prolog (block, gc);
  }
  gum_arm_relocator_write_one (gc->relocator);
}

static void
gum_exec_block_write_handle_excluded (GumExecBlock * block,
                                      const GumBranchTarget * target,
                                      gboolean call,
                                      GumGeneratorContext * gc)
{
  GumArmWriter * cw = gc->code_writer;
  gconstpointer not_excluded = cw->code + 1;

  GumArgument args[] =
  {
    { GUM_ARG_ADDRESS, { .address = GUM_ADDRESS (block->ctx)}},
    { GUM_ARG_REGISTER, { .reg = ARM_REG_R1}},
  };

  /*
   * If the branch target is deterministic (e.g. not based on register
   * contents). We can perform the check during instrumentation rather than at
   * runtime and omit this code if we can determine we will not enter an
   * excluded range.
   */
  if (target->reg == ARM_REG_INVALID)
  {
    if (gum_stalker_is_excluding (block->ctx, target->absolute_address) ==
        FALSE)
    {
      return;
    }
  }

  if (target->reg != ARM_REG_INVALID)
  {
    gum_exec_ctx_write_mov_branch_target_address (block->ctx,
                                              target,
                                              ARM_REG_R1,
                                              gc);

    gum_arm_writer_put_call_address_with_arguments_array (cw,
      GUM_ADDRESS (gum_stalker_is_excluding), 2, args);

    gum_arm_writer_put_cmp_reg_imm (cw, ARM_REG_R0, 0);
    gum_arm_writer_put_bcc_label (cw, ARM_CC_EQ, not_excluded);
  }

  if (call)
  {
    gum_arm_writer_put_call_address_with_arguments_array (cw,
        GUM_ADDRESS (gum_exec_ctx_begin_call), 2, args);
  }

  gum_exec_block_close_prolog (block, gc);

  /* Emit the original call instruction (relocated) */
  gum_arm_relocator_write_one (gc->relocator);

  gum_exec_block_open_prolog (block, gc);

  if (call)
  {
    gum_arm_writer_put_call_address_with_arguments_array (cw,
        GUM_ADDRESS (gum_exec_ctx_end_call), 1, args);
  }

  gum_exec_block_write_handle_continue (block, target, gc);

  /*
   * This label is only required if we weren't able to determine at
   * instrumentation time whether the target was an excluded range. If we could
   * then we either emit the handler if it is, or do nothing if not.
   */
  if (target->reg != ARM_REG_INVALID)
  {
    gum_arm_writer_put_label (cw, not_excluded);
  }
}

static void
gum_exec_block_write_handle_not_taken (GumExecBlock * block,
                                      const GumBranchTarget * target,
                                      arm_cc cc,
                                      GumGeneratorContext * gc)
{
  GumExecCtx * ec = block->ctx;
  GumArmWriter * cw = gc->code_writer;
  gconstpointer taken = cw->code + 1;

  /*
   * Many arm instructions can be conditionally executed based upon the state of
   * register flags. If our instruction is not always executed (ARM_CC_AL), we
   * emit a branch with the same condition code as the original instruction to
   * by pass the continuation handler.
   */
  if (cc != ARM_CC_AL)
  {
    gum_arm_writer_put_bcc_label (gc->code_writer, cc, taken);

    /*
     * If the branch is not taken on account that the instruction is
     * conditionally executed, then emit any necessary events and continue
     * execution by instrumenting and vectoring to the block immediately after
     * the conditional instruction.
     */
    gum_exec_block_open_prolog (block, gc);

    if ((ec->sink_mask & GUM_EXEC) != 0)
    {
      gum_exec_block_write_exec_event_code (block, gc);
    }

    if ((ec->sink_mask & GUM_BLOCK) != 0)
    {
      gum_exec_block_write_block_event_code (block, gc);
    }

    gum_exec_block_write_handle_continue (block, target, gc);

    gum_arm_writer_put_label (cw, taken);
  }
}

static void
gum_exec_block_write_handle_continue (GumExecBlock * block,
                                      const GumBranchTarget * target,
                                      GumGeneratorContext * gc)
{

  GumArgument args[] =
  {
    { GUM_ARG_ADDRESS, { .address = GUM_ADDRESS (block->ctx)}},
    { GUM_ARG_ADDRESS, { .address = GUM_ADDRESS (gc->instruction->end)}},
  };

  /*
   * Use the address of the end of the current instruction as the address of the
   * next block to execute. This is the case after handling a call instruction
   * to an excluded range whereby upon return you want to continue with the next
   * instruction, or when a conditional instruction is not executed resulting in
   * a branch not being taken. Instrument the block and then vector to it.
   */
  gum_arm_writer_put_call_address_with_arguments_array (gc->code_writer,
    GUM_ADDRESS (gum_exec_ctx_replace_current_block_with), 2, args);
  gum_exec_block_close_prolog (block, gc);

  gum_exec_block_write_exec_generated_code (gc->code_writer, block->ctx);

  gum_arm_writer_put_brk_imm (gc->code_writer, 15);
}

static void
gum_exec_block_write_exec_generated_code (GumArmWriter * cw,
                                          GumExecCtx * ctx)
{
  gconstpointer dest_label;

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
   *
   * However, we  need to restore the scratch register value from the stack
   * before we perform the branch. Thus we need to store the calculated value
   * somewhere where it can be referenced again first. When the LDMIA
   * instruction operates on a number of registers including PC, the value of PC
   * is expected to be popped from the stack last, hence we cannot push the
   * scratch register, then the calculated address and use an LDMIA to restore
   * the register and branch as the registers will be in the wrong order.
   *
   * We could consider using space above the stack pointer (and any red-zone),
   * or some other asymmetric stack usage, but in order to keep things simple,
   * we store our calculated address in the code stream using the label support
   * of the gumarmwriter. This means that the code page needs to be RWX. This
   * isn't expected to be a problem since it is expected that most systems which
   * prevent the use of RWX memory as a security feature will have already
   * adopted AARCH64 architecture in order to benefit from other security
   * features and hence this should not affect ARM32.
   */
  gum_arm_writer_put_push_registers (cw, 1, ARM_REG_R12);
  gum_arm_writer_put_ldr_reg_address (cw, ARM_REG_R12,
      GUM_ADDRESS (&ctx->resume_at));
  gum_arm_writer_put_ldrcc_reg_reg_offset (cw, ARM_CC_AL, ARM_REG_R12,
      ARM_REG_R12, GUM_INDEX_POS, 0);

  dest_label = cw->code + 1;

  gum_arm_writer_put_strcc_reg_label (cw, ARM_CC_AL, ARM_REG_R12,
      dest_label);
  gum_arm_writer_put_pop_registers (cw, 1, ARM_REG_R12);

  gum_arm_writer_put_ldrcc_reg_label (cw, ARM_CC_AL, ARM_REG_PC,
      dest_label);

  gum_arm_writer_put_brk_imm (cw, 0x17);

  gum_arm_writer_put_label (cw, dest_label);
  gum_arm_writer_put_instruction (cw, 0xcafedead);
}

static void
gum_exec_block_write_call_event_code (GumExecBlock * block,
                                      const GumBranchTarget * target,
                                      GumGeneratorContext * gc)
{
  GumArmWriter * cw = gc->code_writer;
  GumArgument args[] =
  {
    { GUM_ARG_ADDRESS, { .address = GUM_ADDRESS (block->ctx)}},
    { GUM_ARG_ADDRESS, { .address = GUM_ADDRESS (gc->instruction->begin)}},
    { GUM_ARG_REGISTER, { .reg = ARM_REG_R2}},
  };

  gum_exec_ctx_write_mov_branch_target_address (block->ctx, target,
                                                ARM_REG_R2, gc);

  gum_arm_writer_put_call_address_with_arguments_array (cw,
      GUM_ADDRESS (gum_exec_ctx_emit_call_event), 3, args);
}

static void
gum_exec_block_write_ret_event_code (GumExecBlock * block,
                                     const GumBranchTarget * target,
                                     GumGeneratorContext * gc)
{
  GumArmWriter * cw = gc->code_writer;
  GumArgument args[] =
  {
    { GUM_ARG_ADDRESS, { .address = GUM_ADDRESS (block->ctx)}},
    { GUM_ARG_ADDRESS, { .address = GUM_ADDRESS (gc->instruction->begin)}},
    { GUM_ARG_REGISTER, { .reg = ARM_REG_R2}},
  };

  gum_exec_ctx_write_mov_branch_target_address (block->ctx, target,
                                                ARM_REG_R2, gc);

  gum_arm_writer_put_call_address_with_arguments_array (cw,
      GUM_ADDRESS (gum_exec_ctx_emit_ret_event), 3, args);
}

static void
gum_exec_block_write_exec_event_code (GumExecBlock * block,
                                      GumGeneratorContext * gc)
{
  GumArgument args[] =
  {
    { GUM_ARG_ADDRESS, { .address = GUM_ADDRESS (block->ctx)}},
    { GUM_ARG_ADDRESS, { .address = GUM_ADDRESS (gc->instruction->begin)}},
  };

  gum_arm_writer_put_call_address_with_arguments_array (
      gc->code_writer,
      GUM_ADDRESS (gum_exec_ctx_emit_exec_event), 2, args);
}

static void
gum_exec_block_write_block_event_code (GumExecBlock * block,
                                       GumGeneratorContext * gc)
{
  GumArgument args[] =
  {
    { GUM_ARG_ADDRESS, { .address = GUM_ADDRESS (block->ctx)}},
    { GUM_ARG_ADDRESS, { .address = GUM_ADDRESS (gc->relocator->input_start)}},
    { GUM_ARG_ADDRESS, { .address = GUM_ADDRESS (gc->relocator->input_cur)}},
  };

  gum_arm_writer_put_call_address_with_arguments_array (gc->code_writer,
      GUM_ADDRESS (gum_exec_ctx_emit_block_event), 3, args);
}

static void
gum_exec_block_write_push_stack_frame (GumExecBlock * block,
                                       gpointer ret_real_address,
                                       GumGeneratorContext * gc)
{
  GumArmWriter * cw = gc->code_writer;
  GumArgument args[] =
  {
    { GUM_ARG_ADDRESS, { .address = GUM_ADDRESS (block->ctx)}},
    { GUM_ARG_ADDRESS, { .address = GUM_ADDRESS (ret_real_address)}}
  };

  gum_arm_writer_put_call_address_with_arguments_array (cw,
    GUM_ADDRESS (gum_exec_block_push_stack_frame), 2, args);
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
gum_exec_block_write_pop_stack_frame (GumExecBlock * block,
                                      const GumBranchTarget * target,
                                      GumGeneratorContext * gc)
{
  GumArmWriter * cw = gc->code_writer;
  GumArgument args[] =
  {
    { GUM_ARG_ADDRESS, { .address = GUM_ADDRESS (block->ctx)}},
    { GUM_ARG_REGISTER, { .reg = ARM_REG_R1}},
  };

  gum_exec_ctx_write_mov_branch_target_address (block->ctx, target,
                                                ARM_REG_R1, gc);

  gum_arm_writer_put_call_address_with_arguments_array (cw,
    GUM_ADDRESS (gum_exec_block_pop_stack_frame), 2, args);
}

static void
gum_exec_block_pop_stack_frame (GumExecCtx * ctx,
                                gpointer ret_real_address)
{
  GumExecFrame * next_frame;
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
    next_frame = ctx->current_frame + 1;
    if (next_frame->real_address == ret_real_address)
    {
      ctx->current_frame = next_frame;
    }
  }
}

static gboolean
gum_stalker_is_kuser_helper (gconstpointer address)
{
  switch (GUM_ADDRESS (address))
  {
    case 0xffff0fa0: /* __kernel_memory_barrier */
    case 0xffff0fc0: /* __kernel_cmpxchg */
    case 0xffff0fe0: /* __kernel_get_tls */
    case 0xffff0f60: /* __kernel_cmpxchg64 */
      return TRUE;
    default:
      return FALSE;
  }
}

static void
gum_exec_block_open_prolog (GumExecBlock * block,
                            GumGeneratorContext * gc)
{
  gum_exec_ctx_write_prolog (block->ctx, gc->code_writer);
}

static void
gum_exec_block_close_prolog (GumExecBlock * block,
                             GumGeneratorContext * gc)
{
  gum_exec_ctx_write_epilog (block->ctx, gc->code_writer);
}