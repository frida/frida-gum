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
  gboolean is_rwx_supported;

  GMutex mutex;
  GSList * contexts;
  GumTlsKey exec_ctx;

  GArray * exclusions;
};

G_DEFINE_TYPE (GumStalker, gum_stalker, G_TYPE_OBJECT)
typedef struct _GumExecBlock GumExecBlock;
typedef struct _GumSlab GumSlab;
typedef struct _GumExecCtx GumExecCtx;
typedef struct _GumExecFrame GumExecFrame;
typedef struct _GumGeneratorContext GumGeneratorContext;
typedef struct _GumInstruction GumInstruction;
typedef struct _GumBranchTarget GumBranchTarget;

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

struct _GumExecFrame
{
  gpointer real_address;
};

static void gum_stalker_finalize (GObject * object);

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
  gssize relative_offset;
  gboolean is_relative;
  arm_reg reg;
};

gboolean
gum_stalker_is_supported (void)
{
  return TRUE;
}

static gpointer gum_unfollow_me_address;


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

static void
gum_stalker_class_init (GumStalkerClass * klass)
{
  GObjectClass * object_class = G_OBJECT_CLASS (klass);

  object_class->finalize = gum_stalker_finalize;

  gum_unfollow_me_address = gum_strip_code_pointer (gum_stalker_unfollow_me);
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
  self->is_rwx_supported = gum_query_rwx_support () != GUM_RWX_NONE;

  g_mutex_init (&self->mutex);
  self->contexts = NULL;
  self->exec_ctx = gum_tls_key_new ();
}

GumStalker *
gum_stalker_new (void)
{
  return g_object_new (GUM_TYPE_STALKER, NULL);
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
  g_warning("Trust threshold unsupported");
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
gum_exec_block_commit (GumExecBlock * block)
{
  gsize code_size, real_size;

  code_size = block->code_end - block->code_begin;
  block->slab->offset += code_size;

  real_size = block->real_end - block->real_begin;
  block->slab->offset += real_size;

  gum_stalker_freeze (block->ctx->stalker, block->code_begin, code_size);
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
    // GumBranchTarget continue_target = { 0, };

    // continue_target.absolute_address = gc.continuation_real_address;
    // continue_target.reg = ARM64_REG_INVALID;
    g_error("Need to implement this!!!");
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


gpointer
_gum_stalker_do_follow_me (GumStalker * self,
                           GumStalkerTransformer * transformer,
                           GumEventSink * sink,
                           gpointer ret_addr)
{

  GumEventType mask = gum_event_sink_query_mask(sink);
  if (mask & GUM_COMPILE)
  {
    g_warning("Compile events unsupported");
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
  g_warning("Follow unsupported");
}

void
gum_stalker_unfollow (GumStalker * self,
                      GumThreadId thread_id)
{
  g_warning("Unfollow unsupported");
}

void
gum_stalker_activate (GumStalker * self,
                      gconstpointer target)
{
  g_warning("Activate/deactivate unsupported");
}

void
gum_stalker_deactivate (GumStalker * self)
{
  g_warning("Activate/deactivate unsupported");
}

GumProbeId
gum_stalker_add_call_probe (GumStalker * self,
                            gpointer target_address,
                            GumCallProbeCallback callback,
                            gpointer data,
                            GDestroyNotify notify)
{
  g_warning("Call probes unsupported");
  return 0;
}

void
gum_stalker_remove_call_probe (GumStalker * self,
                               GumProbeId id)
{
  g_warning("Call probes unsupported");
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
gum_exec_ctx_write_prolog (GumExecCtx * ctx,
                           GumArmWriter * cw)
{
  gint immediate_for_sp = 0;

  gum_arm_writer_put_push_registers(cw, 9,
    ARM_REG_R0, ARM_REG_R1, ARM_REG_R2, ARM_REG_R3,
    ARM_REG_R4, ARM_REG_R5, ARM_REG_R6, ARM_REG_R7,
    ARM_REG_LR);

  immediate_for_sp += 9 * 4;

  gum_arm_writer_put_push_registers(cw, 5,
    ARM_REG_R8, ARM_REG_R9, ARM_REG_R10, ARM_REG_R11,
    ARM_REG_R12);

  immediate_for_sp += 5 * 4;

  gum_arm_writer_put_add_reg_reg_imm(cw, ARM_REG_R2, ARM_REG_SP,
                                     immediate_for_sp);
  gum_arm_writer_put_sub_reg_reg_reg(cw, ARM_REG_R1, ARM_REG_R1,
                                     ARM_REG_R1);
  gum_arm_writer_put_mov_cpsr_to_reg(cw, ARM_REG_R0);
  gum_arm_writer_put_push_registers(cw, 3,
    ARM_REG_R0, ARM_REG_R1, ARM_REG_R2);

  gum_arm_writer_put_mov_reg_reg(cw, ARM_REG_R11, ARM_REG_SP);
}

static void
gum_exec_ctx_write_epilog (GumExecCtx * ctx,
                           GumArmWriter * cw)
{
  gum_arm_writer_put_pop_registers(cw, 1, ARM_REG_R0);
  gum_arm_writer_put_mov_reg_to_cpsr(cw, ARM_REG_R0);

  gum_arm_writer_put_add_reg_reg_imm(cw, ARM_REG_SP, ARM_REG_SP, 8);

  gum_arm_writer_put_pop_registers(cw, 5,
    ARM_REG_R8, ARM_REG_R9, ARM_REG_R10, ARM_REG_R11,
    ARM_REG_R12);

  gum_arm_writer_put_pop_registers(cw, 9,
    ARM_REG_R0, ARM_REG_R1, ARM_REG_R2, ARM_REG_R3,
    ARM_REG_R4, ARM_REG_R5, ARM_REG_R6, ARM_REG_R7,
    ARM_REG_LR);
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
gum_exec_ctx_load_real_register_into (GumExecCtx * ctx,
                                      arm_reg target_register,
                                      arm_reg source_register,
                                      GumGeneratorContext * gc)
{
  GumArmWriter * cw;

  cw = gc->code_writer;
  if (source_register >= ARM_REG_R0 && source_register <= ARM_REG_R7)
  {
    gum_arm_writer_put_ldr_reg_reg_imm (cw, target_register, ARM_REG_R11,
        G_STRUCT_OFFSET (GumCpuContext, r) +
        ((source_register - ARM_REG_R0) * 4));
  }
  else if (source_register >= ARM_REG_R8 && source_register <= ARM_REG_R12)
  {
    gum_arm_writer_put_ldr_reg_reg_imm (cw, target_register, ARM_REG_R11,
        G_STRUCT_OFFSET (GumCpuContext, r8) +
        ((source_register - ARM_REG_R8) * 4));
  }
  else if (source_register == ARM_REG_LR)
  {
    gum_arm_writer_put_ldr_reg_reg_imm (cw, target_register, ARM_REG_R11,
        G_STRUCT_OFFSET (GumCpuContext, lr));
  }
  else if (source_register == ARM_REG_SP)
  {
    gum_arm_writer_put_ldr_reg_reg_imm (cw, target_register, ARM_REG_R11,
        G_STRUCT_OFFSET (GumCpuContext, sp));
  }
  else
  {
    g_assert_not_reached ();
  }
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
    if (target->is_relative)
    {
      gum_arm_writer_put_ldr_reg_reg_imm(cw, reg, reg, target->relative_offset);
    }
  }
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


static gboolean
gum_exec_block_is_full (GumExecBlock * block)
{
  guint8 * slab_end = block->slab->data + block->slab->size;

  return slab_end - block->code_end < GUM_EXEC_BLOCK_MIN_SIZE;
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
gum_exec_block_write_jmp_generated_code (GumArmWriter * cw,
                                         arm_cc cc,
                                         GumExecCtx * ctx)
{
  gum_arm_writer_put_ldr_reg_address (cw, ARM_REG_R12,
      GUM_ADDRESS (&ctx->resume_at));
  gum_arm_writer_put_ldr_reg_reg_imm (cw, ARM_REG_R12, ARM_REG_R12, 0);
  gum_arm_writer_put_bxcc_reg (cw, cc, ARM_REG_R12);
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
gum_exec_block_pop_stack_frame (GumExecCtx * ctx,
                                 gpointer ret_real_address)
{
  ctx->current_frame++;
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
gum_exec_ctx_begin_call (GumExecCtx * ctx)
{
  ctx->pending_calls++;
}

static void
gum_exec_ctx_end_call (GumExecCtx * ctx)
{
  ctx->pending_calls--;
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

  for (i = 0; i != exclusions->len; i++)
  {
    GumMemoryRange * r = &g_array_index (exclusions, GumMemoryRange, i);

    if (GUM_MEMORY_RANGE_INCLUDES (r, GUM_ADDRESS (address)))
      return TRUE;
  }

  return FALSE;
}

void
gum_exec_block_write_handle_excluded (GumExecBlock * block,
                                      const GumBranchTarget * target,
                                      GumGeneratorContext * gc)
{
  GumInstruction * insn = gc->instruction;
  GumArmWriter * cw = gc->code_writer;
  gconstpointer not_excluded = cw->code + 1;

  GumArgument args[] =
  {
    { GUM_ARG_ADDRESS, { .address = GUM_ADDRESS (block->ctx)}},
    { GUM_ARG_REGISTER, { .reg = ARM_REG_R1}},
  };

  gum_exec_ctx_write_mov_branch_target_address (block->ctx,
                                            target,
                                            ARM_REG_R1,
                                            gc);

  gum_arm_writer_put_call_address_with_arguments_array (cw,
    GUM_ADDRESS (gum_stalker_is_excluding), 2, args);

  gum_arm_writer_put_cmp_reg_imm(cw, ARM_REG_R0, 0);
  gum_arm_writer_put_beq_label(cw, not_excluded);

  gum_arm_writer_put_call_address_with_arguments_array (cw,
      GUM_ADDRESS (gum_exec_ctx_begin_call), 2, args);
  gum_exec_block_close_prolog (block, gc);

  gum_arm_relocator_write_one (gc->relocator);

  gum_exec_block_open_prolog (block, gc);
  gum_arm_writer_put_call_address_with_arguments_array (cw,
      GUM_ADDRESS (gum_exec_ctx_end_call), 1, args);

  GumArgument jmp_args[] =
  {
    { GUM_ARG_ADDRESS, { .address = GUM_ADDRESS (block->ctx)}},
    { GUM_ARG_ADDRESS, { .address = GUM_ADDRESS (insn->end)}},
  };

  gum_arm_writer_put_call_address_with_arguments_array (cw,
    GUM_ADDRESS (gum_exec_ctx_replace_current_block_with), 2, jmp_args);
  gum_exec_block_close_prolog (block, gc);

  gum_exec_block_write_jmp_generated_code(gc->code_writer, ARM_CC_AL,
      block->ctx);

  gum_arm_writer_put_brk_imm(cw, 15);

  gum_arm_writer_put_label (cw, not_excluded);
}

static void gum_exec_block_virtualize_branch_insn (
    GumExecBlock * block, const GumBranchTarget * target,
    arm_cc cc, GumGeneratorContext * gc)
{
    GumExecCtx * ec = block->ctx;
    gum_arm_relocator_skip_one (gc->relocator);
    gum_exec_block_open_prolog (block, gc);

    if ((ec->sink_mask & GUM_EXEC) != 0)
    {
      gum_exec_block_write_exec_event_code (block, gc);
    }

    if ((ec->sink_mask & GUM_BLOCK) != 0)
    {
      gum_exec_block_write_block_event_code (block, gc);
    }

    gum_exec_block_write_call_replace_current_block_with (block, target, gc);
    gum_exec_block_close_prolog (block, gc);
    gum_exec_block_write_jmp_generated_code(gc->code_writer, cc, block->ctx);
}

static void gum_exec_block_virtualize_call_insn (
    GumExecBlock * block, const GumBranchTarget * target,
    arm_cc cc, GumGeneratorContext * gc)
{
  GumExecCtx * ec = block->ctx;
  gpointer ret_real_address;

  gum_exec_block_open_prolog (block, gc);
  ret_real_address = gc->instruction->end;

  if ((ec->sink_mask & GUM_EXEC) != 0)
  {
    gum_exec_block_write_exec_event_code (block, gc);
  }

  if ((ec->sink_mask & GUM_CALL) != 0)
  {
    gum_exec_block_write_call_event_code (block, target, gc);
  }

  gum_exec_block_write_handle_excluded (block, target, gc);
  gum_exec_block_write_call_replace_current_block_with (block, target, gc);
  gum_exec_block_write_push_stack_frame(block, ret_real_address, gc);
  gum_exec_block_close_prolog (block, gc);
  gum_arm_writer_put_ldr_reg_address (gc->code_writer, ARM_REG_LR,
    GUM_ADDRESS (ret_real_address));
  gum_exec_block_write_jmp_generated_code(gc->code_writer, cc, block->ctx);
}

static void gum_exec_block_virtualize_ret_insn (
    GumExecBlock * block, const GumBranchTarget * target,
    gboolean pop, gushort mask, GumGeneratorContext * gc)
{
  GumExecCtx * ec = block->ctx;
  gum_arm_relocator_skip_one (gc->relocator);
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
  gum_exec_block_write_pop_stack_frame(block, target, gc);
  gum_exec_block_close_prolog (block, gc);

  if (pop)
  {
    if (mask != 0)
    {
      gum_arm_write_put_ldmia_registers_by_mask(gc->code_writer, target->reg,
          mask);
    }
    gum_arm_writer_put_add_reg_reg_imm(gc->code_writer, target->reg,
        target->reg, 4);
  }

  gum_exec_block_write_jmp_generated_code(gc->code_writer, ARM_CC_AL,
      block->ctx);
}

static void gum_exec_block_dont_virtualize_insn (
    GumExecBlock * block, const GumBranchTarget * target,
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

void
gum_stalker_iterator_keep (GumStalkerIterator * self)
{
  GumExecBlock * block = self->exec_block;
  GumGeneratorContext * gc = self->generator_context;
  const cs_insn * insn = gc->instruction->ci;
  cs_arm * arm = &insn->detail->arm;
  cs_arm_op * op = &arm->operands[0];
  cs_arm_op * op2 = &arm->operands[1];
  GumBranchTarget target = { 0, };
  GumArmRegInfo ri;
  gushort mask = 0;

  g_print("%p: %s\t%s = 0x%08x, id: %d\n", gc->instruction->begin, insn->mnemonic,
    insn->op_str, *(guint*)gc->instruction->begin, insn->id);
  if (gum_arm_relocator_eob (gc->relocator))
  {
    switch (insn->id)
    {
      case ARM_INS_B:
      case ARM_INS_BL:
        g_assert (op->type == ARM_OP_IMM);
        target.absolute_address = GSIZE_TO_POINTER (op->imm);
        target.reg = ARM_REG_INVALID;
        target.is_relative = FALSE;
        target.relative_offset = 0;
        break;
      case ARM_INS_BX:
      case ARM_INS_BLX:
        g_assert (op->type == ARM_OP_REG);
        target.absolute_address = 0;
        target.reg = op->reg;
        target.is_relative = FALSE;
        target.relative_offset = 0;
        break;
      case ARM_INS_MOV:
        target.absolute_address = 0;
        target.reg = op2->reg;
        target.is_relative = FALSE;
        target.relative_offset = 0;
        break;
      case ARM_INS_POP:
        target.absolute_address = 0;
        target.reg = ARM_REG_SP;
        target.is_relative = TRUE;
        for (uint8_t idx = 0; idx < insn->detail->arm.op_count; idx++)
        {
          op = &arm->operands[idx];
          if(op->reg == ARM_REG_PC)
          {
            target.relative_offset = idx * 4;
          }
          else
          {
            gum_arm_reg_describe (op->reg, &ri);
            mask |= 1 << ri.index;
          }
        }
        break;
      case ARM_INS_LDM:
        target.absolute_address = 0;
        target.reg = op->reg;
        target.is_relative = TRUE;
        for (uint8_t idx = 1; idx < insn->detail->arm.op_count; idx++)
        {
          op = &arm->operands[idx];
          if(op->reg == ARM_REG_PC)
          {
            target.relative_offset = (idx - 1) * 4;
          }
          else
          {
            gum_arm_reg_describe (op->reg, &ri);
            mask |= 1 << ri.index;
          }
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
      case ARM_INS_B:
      case ARM_INS_BX:
        if (arm->cc)
        {
          g_print("CC: %d\n", arm->cc);
        }
        gum_exec_block_virtualize_branch_insn(block, &target, ARM_CC_AL, gc);
        break;
      case ARM_INS_BL:
      case ARM_INS_BLX:
        gum_exec_block_virtualize_call_insn(block, &target, ARM_CC_AL, gc);
        break;
      case ARM_INS_MOV:
        gum_exec_block_virtualize_ret_insn(block, &target, FALSE, 0, gc);
        break;
      case ARM_INS_POP:
      case ARM_INS_LDM:
        gum_exec_block_virtualize_ret_insn(block, &target, TRUE, mask, gc);
        break;
      default:
        g_assert_not_reached ();
        break;
    }
  }
  else
  {
    gum_exec_block_dont_virtualize_insn(block, &target, gc);
  }
}

void
gum_stalker_iterator_put_callout (GumStalkerIterator * self,
                                  GumStalkerCallout callout,
                                  gpointer data,
                                  GDestroyNotify data_destroy)
{
}