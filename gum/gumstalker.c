/*
 * Copyright (C) 2009 Ole André Vadla Ravnås <ole.andre.ravnas@tandberg.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU Library General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 02111-1307, USA.
 */

#include "gumstalker.h"

#include "gumcodewriter.h"
#include "gummemory.h"
#include "gumrelocator.h"
#include "gumudis86.h"

#define GUM_MAX_EXEC_BLOCKS         1024
#define GUM_EXEC_BLOCK_MAX_MAPPINGS  128

G_DEFINE_TYPE (GumStalker, gum_stalker, G_TYPE_OBJECT)

typedef struct _GumExecCtx GumExecCtx;
typedef struct _GumExecBlock GumExecBlock;

typedef struct _GumAddressMapping GumAddressMapping;
typedef struct _GumInstruction GumInstruction;
typedef struct _GumBranchTarget GumBranchTarget;

struct _GumStalkerPrivate
{
  guint page_size;

  GPrivate * exec_ctx;
};

struct _GumExecCtx
{
  GumStalker * stalker;

  GumCodeWriter code_writer;
  GumRelocator relocator;

  GumEventSink * sink;
  GumEventType sink_mask;
  gpointer sink_process_impl; /* cached */
  GumEvent tmp_event;

  GumExecBlock * block_stack[GUM_MAX_EXEC_BLOCKS];
  guint block_stack_len;

  gpointer thunks;
  gpointer jmp_block_thunk;
  gpointer ret_block_thunk;

  guint8 * block_pool;
  guint block_size;
  guint block_code_offset;
  guint block_code_maxsize;
};

struct _GumAddressMapping
{
  gpointer replica_address;
  gpointer real_address;
};

struct _GumExecBlock
{
  GumExecCtx * ctx;

  guint8 * code_begin;
  guint8 * code_end;

  gpointer * ret_addr_ptr;
  GumAddressMapping mappings[GUM_EXEC_BLOCK_MAX_MAPPINGS];
  guint mappings_len;

  gpointer tmp_func_addr;
};

struct _GumInstruction
{
  ud_t * ud;
  guint8 * begin;
  guint8 * end;
};

struct _GumBranchTarget
{
  gpointer address;

  gboolean is_indirect;
  uint8_t pfx_seg;
  enum ud_type base;
};

#define GUM_STALKER_GET_PRIVATE(o) ((o)->priv)

#define CDECL_PRESERVE_SIZE (4 * sizeof (gpointer))

static GumExecCtx * gum_stalker_create_exec_ctx (GumStalker * self,
    GumEventSink * sink);
static void gum_stalker_destroy_exec_ctx (GumStalker * self, GumExecCtx * ctx);
static GumExecCtx * gum_stalker_get_exec_ctx (GumStalker * self);
static gpointer gum_exec_ctx_create_and_push_block (GumExecCtx * ctx,
    gpointer start_address);
static gpointer GUM_STDCALL gum_exec_ctx_create_and_switch_block (
    GumExecCtx * ctx, gpointer start_address);
static gpointer GUM_STDCALL gum_exec_ctx_create_and_return_to_block (
    GumExecCtx * ctx, gpointer start_address);
static void gum_exec_ctx_create_thunks (GumExecCtx * ctx);
static void gum_exec_ctx_destroy_thunks (GumExecCtx * ctx);
static void gum_exec_ctx_create_block_pool (GumExecCtx * ctx);
static void gum_exec_ctx_destroy_block_pool (GumExecCtx * ctx);

static GumExecBlock * gum_exec_ctx_peek_top (GumExecCtx * ctx);
static GumExecBlock * gum_exec_ctx_replace_top (GumExecCtx * ctx,
    GumExecBlock * replacement);
static GumExecBlock * gum_exec_ctx_create_block_for (GumExecCtx * ctx,
    gpointer address);
static void gum_exec_ctx_write_call_event_code (GumExecCtx * ctx,
    gpointer location, const GumBranchTarget * target, GumCodeWriter * cw);
static void gum_exec_ctx_write_ret_event_code (GumExecCtx * ctx,
    gpointer location, GumCodeWriter * cw);
static void gum_exec_ctx_write_exec_event_code (GumExecCtx * ctx,
    gpointer location, GumCodeWriter * cw);
static void gum_exec_ctx_write_event_init_code (GumExecCtx * ctx,
    GumEventType type, GumCodeWriter * cw);
static void gum_exec_ctx_write_event_submit_code (GumExecCtx * ctx,
    GumCodeWriter * cw);
static void gum_exec_ctx_write_cdecl_preserve_prolog (GumExecCtx * ctx,
    GumCodeWriter * cw);
static void gum_exec_ctx_write_cdecl_preserve_epilog (GumExecCtx * ctx,
    GumCodeWriter * cw);

static GumExecBlock * gum_exec_block_new (GumExecCtx * ctx);
static void gum_exec_block_free (GumExecBlock * block);
static void gum_exec_block_revert_retaddr (GumExecBlock * block);
static gboolean gum_exec_block_handle_branch_insn (GumExecBlock * block,
    GumInstruction * insn, GumRelocator * rl, GumCodeWriter * cw);
static gboolean gum_exec_block_handle_ret_insn (GumExecBlock * block,
    GumInstruction * insn, GumRelocator * rl, GumCodeWriter * cw);
static void gum_exec_block_write_call_invoke_code (GumExecBlock * block,
    GumInstruction * insn, const GumBranchTarget * target, GumCodeWriter * cw);
static void gum_exec_block_write_jmp_transfer_code (GumExecBlock * block,
    GumInstruction * insn, const GumBranchTarget * target, GumCodeWriter * cw);
static void gum_exec_block_write_ret_transfer_code (GumExecBlock * block,
    gpointer orig_ret_insn, GumCodeWriter * cw);
static void gum_exec_block_add_address_mapping (GumExecBlock * block,
    gpointer replica_address, gpointer real_address);
static gpointer gum_exec_block_get_real_address_of (GumExecBlock * block,
    gpointer address);

static void gum_write_push_branch_target_address (
    const GumBranchTarget * target, enum ud_type working_register,
    guint cdecl_preserve_stack_offset, GumCodeWriter * cw);

static void
gum_stalker_class_init (GumStalkerClass * klass)
{
  g_type_class_add_private (klass, sizeof (GumStalkerPrivate));
}

static void
gum_stalker_init (GumStalker * self)
{
  GumStalkerPrivate * priv;

  self->priv = G_TYPE_INSTANCE_GET_PRIVATE (self,
      GUM_TYPE_STALKER, GumStalkerPrivate);
  priv = GUM_STALKER_GET_PRIVATE (self);

  priv->page_size = gum_query_page_size ();
  priv->exec_ctx = g_private_new (NULL);
}

GumStalker *
gum_stalker_new (void)
{
  return GUM_STALKER (g_object_new (GUM_TYPE_STALKER, NULL));
}

void
gum_stalker_follow_me (GumStalker * self,
                       GumEventSink * sink)
{
  gpointer * ret_addr_ptr, start_address;
  GumExecCtx * ctx;

  ret_addr_ptr = (gpointer *) (((gssize) &self) - sizeof (GumStalker *));
  start_address = *ret_addr_ptr;

  ctx = gum_stalker_create_exec_ctx (self, sink);
  *ret_addr_ptr = gum_exec_ctx_create_and_push_block (ctx, start_address);
}

void
gum_stalker_unfollow_me (GumStalker * self)
{
  gpointer * ret_addr_ptr, ret_addr;
  GumExecCtx * ctx;
  guint i;
  GumExecBlock * block;

  ret_addr_ptr = (gpointer *) (((gssize) &self) - sizeof (GumStalker *));
  ret_addr = *ret_addr_ptr;

  ctx = gum_stalker_get_exec_ctx (self);

  for (i = 0; i < ctx->block_stack_len; ++i)
    gum_exec_block_revert_retaddr (ctx->block_stack[i]);

  block = gum_exec_ctx_peek_top (ctx);
  g_assert (ret_addr >= (gpointer) block->code_begin
      && ret_addr < (gpointer) block->code_end);

  *ret_addr_ptr = gum_exec_block_get_real_address_of (block, ret_addr);

  gum_stalker_destroy_exec_ctx (self, ctx);
}

static GumExecCtx *
gum_stalker_create_exec_ctx (GumStalker * self,
                             GumEventSink * sink)
{
  GumStalkerPrivate * priv = GUM_STALKER_GET_PRIVATE (self);
  GumExecCtx * ctx;

  ctx = g_new0 (GumExecCtx, 1);

  ctx->stalker = g_object_ref (self);

  gum_code_writer_init (&ctx->code_writer, NULL);
  gum_relocator_init (&ctx->relocator, NULL, &ctx->code_writer);

  ctx->sink = g_object_ref (sink);
  ctx->sink_mask = gum_event_sink_query_mask (sink);
  ctx->sink_process_impl = GUM_EVENT_SINK_GET_INTERFACE (sink)->process;

  gum_exec_ctx_create_thunks (ctx);
  gum_exec_ctx_create_block_pool (ctx);

  g_private_set (priv->exec_ctx, ctx);

  return ctx;
}

static void
gum_stalker_destroy_exec_ctx (GumStalker * self,
                              GumExecCtx * ctx)
{
  gum_exec_ctx_destroy_block_pool (ctx);
  gum_exec_ctx_destroy_thunks (ctx);

  g_object_unref (ctx->sink);

  gum_relocator_free (&ctx->relocator);
  gum_code_writer_free (&ctx->code_writer);

  g_object_unref (ctx->stalker);

  g_free (ctx);
}

static GumExecCtx *
gum_stalker_get_exec_ctx (GumStalker * self)
{
  return g_private_get (self->priv->exec_ctx);
}

static gpointer
gum_exec_ctx_create_and_push_block (GumExecCtx * ctx,
                                    gpointer start_address)
{
  GumExecBlock * block;

  block = gum_exec_ctx_create_block_for (ctx, start_address);

  ctx->block_stack[ctx->block_stack_len++] = block;
  g_assert_cmpuint (ctx->block_stack_len, <=, G_N_ELEMENTS (ctx->block_stack));

  return block->code_begin;
}

static gpointer GUM_STDCALL
gum_exec_ctx_create_and_switch_block (GumExecCtx * ctx,
                                      gpointer start_address)
{
  GumExecBlock * old_block, * new_block;

  new_block = gum_exec_ctx_create_block_for (ctx, start_address);
  old_block = gum_exec_ctx_replace_top (ctx, new_block);
  gum_exec_block_free (old_block);

  return new_block->code_begin;
}

static gpointer GUM_STDCALL
gum_exec_ctx_create_and_return_to_block (GumExecCtx * ctx,
                                         gpointer start_address)
{
  if (ctx->block_stack_len == 1)
  {
    GumExecBlock * new_block, * old_block;

    new_block = gum_exec_ctx_create_block_for (ctx, start_address);
    old_block = gum_exec_ctx_replace_top (ctx, new_block);
    gum_exec_block_free (old_block);

    return new_block->code_begin;
  }
  else
  {
    return start_address;
  }
}

static void
gum_exec_ctx_create_thunks (GumExecCtx * ctx)
{
  GumCodeWriter cw;

  g_assert (ctx->thunks == NULL);

  ctx->thunks = gum_alloc_n_pages (1, GUM_PAGE_RWX);
  gum_code_writer_init (&cw, ctx->thunks);

  ctx->jmp_block_thunk = gum_code_writer_cur (&cw);
  gum_code_writer_put_mov_esp_offset_ptr_eax (&cw, CDECL_PRESERVE_SIZE);
  gum_exec_ctx_write_cdecl_preserve_epilog (ctx, &cw);
  gum_code_writer_put_ret (&cw);

  ctx->ret_block_thunk = gum_code_writer_cur (&cw);
  gum_code_writer_put_mov_esp_offset_ptr_eax (&cw,
      sizeof (gpointer) + CDECL_PRESERVE_SIZE);
  gum_exec_ctx_write_cdecl_preserve_epilog (ctx, &cw);
  gum_code_writer_put_ret (&cw);

  gum_code_writer_free (&cw);
}

static void
gum_exec_ctx_destroy_thunks (GumExecCtx * ctx)
{
  gum_free_pages (ctx->thunks);
}

static void
gum_exec_ctx_create_block_pool (GumExecCtx * ctx)
{
  ctx->block_pool = gum_alloc_n_pages (GUM_MAX_EXEC_BLOCKS * 2, GUM_PAGE_RWX);
  ctx->block_size = 2 * ctx->stalker->priv->page_size;
  ctx->block_code_offset = ((sizeof (GumExecBlock) + (64 - 1)) & ~(64 - 1));
  ctx->block_code_maxsize = ctx->block_size - ctx->block_code_offset;
}

static void
gum_exec_ctx_destroy_block_pool (GumExecCtx * ctx)
{
  gum_free_pages (ctx->block_pool);
}

static void
gum_exec_ctx_pop_block (GumExecCtx * ctx)
{
  GumExecBlock * block;

  block = gum_exec_ctx_peek_top (ctx);
  g_assert (block != NULL);

  ctx->block_stack_len--;

  gum_exec_block_free (block);
}

static GumExecBlock *
gum_exec_ctx_peek_top (GumExecCtx * ctx)
{
  if (ctx->block_stack_len > 0)
    return ctx->block_stack[ctx->block_stack_len - 1];
  else
    return NULL;
}

static GumExecBlock *
gum_exec_ctx_replace_top (GumExecCtx * ctx,
                          GumExecBlock * replacement)
{
  guint idx;
  gpointer prev;

  g_assert_cmpuint (ctx->block_stack_len, >, 0);

  idx = ctx->block_stack_len - 1;
  prev = ctx->block_stack[idx];
  ctx->block_stack[idx] = replacement;

  return prev;
}

static gpointer
gum_exec_ctx_resolve_code_address (GumExecCtx * ctx,
                                   gpointer address)
{
  guint8 * addr = address;
  guint i;

  for (i = 0; i < ctx->block_stack_len; ++i)
  {
    GumExecBlock * block = ctx->block_stack[i];

    if (addr >= block->code_begin && addr < block->code_end)
      return gum_exec_block_get_real_address_of (block, address);
  }

  return address;
}

static GumExecBlock *
gum_exec_ctx_create_block_for (GumExecCtx * ctx,
                               gpointer address)
{
  GumExecBlock * block;
  GumCodeWriter * cw = &ctx->code_writer;
  GumRelocator * rl = &ctx->relocator;

  block = gum_exec_block_new (ctx);
  gum_code_writer_reset (cw, block->code_begin);
  gum_relocator_reset (rl, address, cw);

  do
  {
    guint n_read;

    n_read = gum_relocator_read_one (rl, NULL);
    g_assert_cmpuint (n_read, !=, 0);
  }
  while (!gum_relocator_eob (rl));

  do
  {
    GumInstruction insn;
    gboolean handled = FALSE;

    insn.ud = gum_relocator_peek_next_write_insn (rl);
    if (insn.ud == NULL)
      break;
    insn.begin = gum_relocator_peek_next_write_source (rl);
    insn.end = insn.begin + ud_insn_len (insn.ud);

    if ((ctx->sink_mask & GUM_EXEC) != 0)
      gum_exec_ctx_write_exec_event_code (ctx, insn.begin, cw);

    switch (insn.ud->mnemonic)
    {
      case UD_Icall:
      case UD_Ijmp:
        handled = gum_exec_block_handle_branch_insn (block, &insn, rl, cw);
        break;
      case UD_Iret:
        handled = gum_exec_block_handle_ret_insn (block, &insn, rl, cw);
        break;
      default:
        if (gum_mnemonic_is_jcc (insn.ud->mnemonic))
          handled = gum_exec_block_handle_branch_insn (block, &insn, rl, cw);
        break;
    }

    if (!handled)
    {
      gum_exec_block_add_address_mapping (block, gum_code_writer_cur (cw),
          insn.begin);
      gum_relocator_write_one (rl);
      gum_exec_block_add_address_mapping (block, gum_code_writer_cur (cw),
          insn.end);
    }
  }
  while (TRUE);

  gum_code_writer_flush (cw);

  block->code_end = gum_code_writer_cur (cw);

  g_assert_cmpuint (gum_code_writer_offset (cw), <=, ctx->block_code_maxsize);

  return block;
}

static void
gum_exec_ctx_write_call_event_code (GumExecCtx * ctx,
                                    gpointer location,
                                    const GumBranchTarget * target,
                                    GumCodeWriter * cw)
{
  gum_exec_ctx_write_cdecl_preserve_prolog (ctx, cw);

  gum_exec_ctx_write_event_init_code (ctx, GUM_CALL, cw);
  gum_code_writer_put_mov_eax_offset_ptr (cw,
      G_STRUCT_OFFSET (GumCallEvent, location), (guint32) location);

  gum_write_push_branch_target_address (target, UD_R_EDX, 0, cw);
  gum_code_writer_put_pop_ecx (cw);
  gum_code_writer_put_mov_eax_offset_ptr_ecx (cw,
      G_STRUCT_OFFSET (GumCallEvent, target));

  gum_exec_ctx_write_event_submit_code (ctx, cw);

  gum_exec_ctx_write_cdecl_preserve_epilog (ctx, cw);
}

static void
gum_exec_ctx_write_ret_event_code (GumExecCtx * ctx,
                                   gpointer location,
                                   GumCodeWriter * cw)
{
  gum_exec_ctx_write_cdecl_preserve_prolog (ctx, cw);

  gum_code_writer_put_mov_ecx_esp_offset_ptr (cw, CDECL_PRESERVE_SIZE);
  gum_code_writer_put_push_ecx (cw);
  gum_code_writer_put_push (cw, (guint32) ctx);
  gum_code_writer_put_call (cw, gum_exec_ctx_resolve_code_address);
  gum_code_writer_put_add_esp_u32 (cw, 2 * sizeof (gpointer));
  gum_code_writer_put_mov_ecx_eax (cw);

  gum_exec_ctx_write_event_init_code (ctx, GUM_RET, cw);
  gum_code_writer_put_mov_eax_offset_ptr (cw,
      G_STRUCT_OFFSET (GumRetEvent, location), (guint32) location);
  gum_code_writer_put_mov_eax_offset_ptr_ecx (cw,
      G_STRUCT_OFFSET (GumRetEvent, target));

  gum_exec_ctx_write_event_submit_code (ctx, cw);

  gum_exec_ctx_write_cdecl_preserve_epilog (ctx, cw);
}

static void
gum_exec_ctx_write_exec_event_code (GumExecCtx * ctx,
                                    gpointer location,
                                    GumCodeWriter * cw)
{
  gum_exec_ctx_write_cdecl_preserve_prolog (ctx, cw);

  gum_exec_ctx_write_event_init_code (ctx, GUM_EXEC, cw);
  gum_code_writer_put_mov_eax_offset_ptr (cw,
      G_STRUCT_OFFSET (GumExecEvent, location), (guint32) location);

  gum_exec_ctx_write_event_submit_code (ctx, cw);

  gum_exec_ctx_write_cdecl_preserve_epilog (ctx, cw);
}

static void
gum_exec_ctx_write_event_init_code (GumExecCtx * ctx,
                                    GumEventType type,
                                    GumCodeWriter * cw)
{
  gum_code_writer_put_mov_eax (cw, (guint32) &ctx->tmp_event);
  gum_code_writer_put_mov_eax_offset_ptr (cw,
      G_STRUCT_OFFSET (GumAnyEvent, type), type);
}

static void
gum_exec_ctx_write_event_submit_code (GumExecCtx * ctx,
                                      GumCodeWriter * cw)
{
  gum_code_writer_put_push_eax (cw);
  gum_code_writer_put_push (cw, (guint32) ctx->sink);
  gum_code_writer_put_call (cw, ctx->sink_process_impl);
  gum_code_writer_put_add_esp_u32 (cw, 2 * sizeof (gpointer));
}

static void
gum_exec_ctx_write_cdecl_preserve_prolog (GumExecCtx * ctx,
                                          GumCodeWriter * cw)
{
  gum_code_writer_put_pushfd (cw);
  gum_code_writer_put_push_eax (cw);
  gum_code_writer_put_push_ecx (cw);
  gum_code_writer_put_push_edx (cw);
}

static void
gum_exec_ctx_write_cdecl_preserve_epilog (GumExecCtx * ctx,
                                          GumCodeWriter * cw)
{
  gum_code_writer_put_pop_edx (cw);
  gum_code_writer_put_pop_ecx (cw);
  gum_code_writer_put_pop_eax (cw);
  gum_code_writer_put_popfd (cw);
}

static GumExecBlock *
gum_exec_block_new (GumExecCtx * ctx)
{
  guint8 * cur;
  guint i;

  cur = ctx->block_pool;

  for (i = 0; i < GUM_MAX_EXEC_BLOCKS; ++i)
  {
    GumExecBlock * block = (GumExecBlock *) cur;

    if (block->ctx == NULL)
    {
      block->ctx = ctx;

      block->code_end = block->code_begin = cur + ctx->block_code_offset;

      block->mappings_len = 0;

      return block;
    }

    cur += ctx->block_size;
  }

  g_assert_not_reached ();
  return NULL;
}

static void
gum_exec_block_free (GumExecBlock * block)
{
  block->ctx = NULL;
}

static void
gum_exec_block_revert_retaddr (GumExecBlock * block)
{
  if (block->ret_addr_ptr != NULL)
  {
    *(block->ret_addr_ptr) = gum_exec_block_get_real_address_of (block,
        *(block->ret_addr_ptr));
  }
}

static gboolean
gum_exec_block_handle_branch_insn (GumExecBlock * block,
                                   GumInstruction * insn,
                                   GumRelocator * rl,
                                   GumCodeWriter * cw)
{
  gboolean is_conditional;
  ud_operand_t * op = &insn->ud->operand[0];
  GumBranchTarget target = { 0, };

  is_conditional =
      (insn->ud->mnemonic != UD_Icall && insn->ud->mnemonic != UD_Ijmp);

  target.pfx_seg = UD_NONE;
  target.base = op->base;

  if (op->type == UD_OP_JIMM && op->base == UD_NONE)
  {
    if (op->size == 8)
      target.address = insn->end + op->lval.sbyte;
    else if (op->size == 32)
      target.address = insn->end + op->lval.sdword;
    else
      g_assert_not_reached ();
    target.is_indirect = FALSE;
  }
  else if (op->type == UD_OP_MEM)
  {
    g_assert (op->size == 32);
    g_assert (op->base == UD_NONE ||
        (op->base >= UD_R_EAX && op->base <= UD_R_EDI));
    g_assert (op->offset == 8 || op->offset == 32);

#ifdef G_OS_WIN32
    /* Don't follow WoW64 for now */
    if (insn->ud->pfx_seg == UD_R_FS && op->lval.udword == 0xc0)
      return FALSE;
#endif

    if (op->offset == 8)
      target.address = GSIZE_TO_POINTER (op->lval.ubyte);
    else
      target.address = GSIZE_TO_POINTER (op->lval.udword);
    target.is_indirect = TRUE;
    target.pfx_seg = insn->ud->pfx_seg;
  }
  else if (op->type == UD_OP_REG)
  {
    target.address = NULL;
    target.is_indirect = TRUE;
  }
  else
  {
    g_assert_not_reached ();
  }

  if (target.address == gum_stalker_unfollow_me)
    return FALSE;

  gum_relocator_skip_one (rl);

  if (insn->ud->mnemonic == UD_Icall)
  {
    if ((block->ctx->sink_mask & GUM_CALL) != 0)
      gum_exec_ctx_write_call_event_code (block->ctx, insn->begin, &target, cw);
    gum_exec_block_write_call_invoke_code (block, insn, &target, cw);
  }
  else
  {
    gpointer cond_false_lbl_id;
    
    cond_false_lbl_id =
        GUINT_TO_POINTER ((GPOINTER_TO_UINT (insn->begin) << 16) | 0xbeef);

    if (is_conditional)
    {
      g_assert (!target.is_indirect);

      gum_code_writer_put_jcc_short_label (cw,
          gum_jcc_opcode_negate (gum_jcc_insn_to_short_opcode (insn->begin)),
          cond_false_lbl_id);
    }

    gum_exec_block_write_jmp_transfer_code (block, insn, &target, cw);

    if (is_conditional)
    {
      GumBranchTarget cond_target;

      cond_target.address = insn->end;
      cond_target.is_indirect = FALSE;
      cond_target.pfx_seg = UD_NONE;

      gum_code_writer_put_label (cw, cond_false_lbl_id);
      gum_exec_block_write_jmp_transfer_code (block, insn, &cond_target, cw);
    }
  }

  return TRUE;
}

static gboolean
gum_exec_block_handle_ret_insn (GumExecBlock * block,
                                GumInstruction * insn,
                                GumRelocator * rl,
                                GumCodeWriter * cw)
{
  if ((block->ctx->sink_mask & GUM_RET) != 0)
  {
    guint8 * insn_start;

    insn_start = gum_relocator_peek_next_write_source (rl);

    gum_exec_ctx_write_ret_event_code (block->ctx, insn_start, cw);
  }

  gum_relocator_skip_one (rl);

  gum_exec_block_write_ret_transfer_code (block, insn->begin, cw);

  return TRUE;
}

static void
gum_exec_block_write_call_invoke_code (GumExecBlock * block,
                                       GumInstruction * insn,
                                       const GumBranchTarget * target,
                                       GumCodeWriter * cw)
{
  gum_exec_ctx_write_cdecl_preserve_prolog (block->ctx, cw);

  gum_write_push_branch_target_address (target, UD_R_EAX, 0, cw);
  gum_code_writer_put_push (cw, (guint32) block->ctx);
  gum_code_writer_put_call (cw, gum_exec_ctx_create_and_push_block);
  gum_code_writer_put_add_esp_u32 (cw, 2 * sizeof (gpointer));
  gum_code_writer_put_mov_mem_reg (cw, &block->tmp_func_addr, GUM_REG_EAX);

  gum_code_writer_put_mov_ecx_esp (cw);
  gum_code_writer_put_sub_ecx (cw, sizeof (gpointer) - CDECL_PRESERVE_SIZE);
  gum_code_writer_put_mov_mem_reg (cw, &block->ret_addr_ptr, GUM_REG_ECX);

  gum_exec_ctx_write_cdecl_preserve_epilog (block->ctx, cw);

  gum_exec_block_add_address_mapping (block, gum_code_writer_cur (cw),
      insn->begin);
  gum_code_writer_put_call_indirect (cw, &block->tmp_func_addr);
  gum_exec_block_add_address_mapping (block, gum_code_writer_cur (cw),
      insn->end);

  gum_exec_ctx_write_cdecl_preserve_prolog (block->ctx, cw);

  gum_code_writer_put_mov_ecx (cw, 0);
  gum_code_writer_put_mov_mem_reg (cw, &block->ret_addr_ptr, GUM_REG_ECX);

  gum_code_writer_put_push (cw, (guint32) block->ctx);
  gum_code_writer_put_call (cw, gum_exec_ctx_pop_block);
  gum_code_writer_put_add_esp_u32 (cw, sizeof (gpointer));

  gum_exec_ctx_write_cdecl_preserve_epilog (block->ctx, cw);
}

static void
gum_exec_block_write_jmp_transfer_code (GumExecBlock * block,
                                        GumInstruction * insn,
                                        const GumBranchTarget * target,
                                        GumCodeWriter * cw)
{
  gum_code_writer_put_push_eax (cw); /* placeholder */
  gum_exec_ctx_write_cdecl_preserve_prolog (block->ctx, cw);

  gum_write_push_branch_target_address (target, UD_R_EAX, 0, cw);
  gum_code_writer_put_push (cw, (guint32) block->ctx);

  gum_code_writer_put_push (cw, (guint32) block->ctx->jmp_block_thunk);
  gum_code_writer_put_jmp (cw, gum_exec_ctx_create_and_switch_block);
}

static void
gum_exec_block_write_ret_transfer_code (GumExecBlock * block,
                                        gpointer orig_ret_insn,
                                        GumCodeWriter * cw)
{
  gum_code_writer_put_push (cw, (guint32) orig_ret_insn);
  gum_exec_ctx_write_cdecl_preserve_prolog (block->ctx, cw);

  gum_code_writer_put_mov_ecx_esp_offset_ptr (cw,
      CDECL_PRESERVE_SIZE + sizeof (gpointer));
  gum_code_writer_put_push_ecx (cw);
  gum_code_writer_put_push (cw, (guint32) block->ctx);

  gum_code_writer_put_push (cw, (guint32) block->ctx->ret_block_thunk);
  gum_code_writer_put_jmp (cw, gum_exec_ctx_create_and_return_to_block);
}

static void
gum_exec_block_add_address_mapping (GumExecBlock * block,
                                    gpointer replica_address,
                                    gpointer real_address)
{
  GumAddressMapping * map = &block->mappings[block->mappings_len++];
  g_assert_cmpuint (block->mappings_len, <=, G_N_ELEMENTS (block->mappings));
  map->replica_address = replica_address;
  map->real_address = real_address;
}

static gpointer
gum_exec_block_get_real_address_of (GumExecBlock * block,
                                    gpointer address)
{
  guint i;

  for (i = 0; i < block->mappings_len; ++i)
  {
    const GumAddressMapping * cur = &block->mappings[i];
    if (cur->replica_address == address)
      return cur->real_address;
  }

  g_assert_not_reached ();
  return NULL;
}

static void
gum_write_push_branch_target_address (const GumBranchTarget * target,
                                      enum ud_type working_register,
                                      guint cdecl_preserve_stack_offset,
                                      GumCodeWriter * cw)
{
  if (!target->is_indirect)
  {
    gum_code_writer_put_push (cw, (guint32) target->address);
  }
  else
  {
    enum ud_type actual_base;

    switch (target->pfx_seg)
    {
      case UD_NONE: break;

      case UD_R_CS: gum_code_writer_put_byte (cw, 0x2e); break;
      case UD_R_SS: gum_code_writer_put_byte (cw, 0x36); break;
      case UD_R_DS: gum_code_writer_put_byte (cw, 0x3e); break;
      case UD_R_ES: gum_code_writer_put_byte (cw, 0x26); break;
      case UD_R_FS: gum_code_writer_put_byte (cw, 0x64); break;
      case UD_R_GS: gum_code_writer_put_byte (cw, 0x65); break;

      default:
        g_assert_not_reached ();
        break;
    }

    if (target->base >= UD_R_EAX && target->base <= UD_R_EDX)
    {
      const guint8 reg_selector[] = { 0x44, 0x4c, 0x54 };

      actual_base = working_register;

      gum_code_writer_put_byte (cw, 0x8b);
      gum_code_writer_put_byte (cw, reg_selector[actual_base - UD_R_EAX]);
      gum_code_writer_put_byte (cw, 0x24);
      gum_code_writer_put_byte (cw, cdecl_preserve_stack_offset + 8 - ((target->base - UD_R_EAX) * 4));
    }
    else
    {
      actual_base = target->base;
    }

    if (target->address == NULL)
    {
      g_assert (actual_base >= UD_R_EAX && actual_base <= UD_R_EDI);
      gum_code_writer_put_byte (cw, 0x50 + actual_base - UD_R_EAX);
    }
    else if (actual_base == UD_NONE)
    {
      gum_code_writer_put_byte (cw, 0xff);
      gum_code_writer_put_byte (cw, 0x35);
      gum_code_writer_put_bytes (cw, (guint8 *) &target->address,
          sizeof (target->address));
    }
    else
    {
      gum_code_writer_put_byte (cw, 0xff);
      gum_code_writer_put_byte (cw, 0xb0 + actual_base - UD_R_EAX);
      gum_code_writer_put_bytes (cw, (guint8 *) &target->address,
          sizeof (target->address));
    }
  }
}
