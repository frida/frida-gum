/*
 * Copyright (C) 2009-2011 Ole André Vadla Ravnås <ole.andre.ravnas@tandberg.com>
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

#include "gumx86relocator.h"

#include "gummemory.h"
#include "gumudis86.h"

#include <string.h>

#define GUM_MAX_INPUT_INSN_COUNT (100)

typedef struct _GumCodeGenCtx GumCodeGenCtx;

struct _GumCodeGenCtx
{
  ud_t * insn;
  guint8 * start;
  guint8 * end;
  guint len;

  GumX86Writer * code_writer;
};

static gboolean gum_x86_relocator_write_one_instruction (GumX86Relocator * self);
static void gum_x86_relocator_put_label_for (GumX86Relocator * self,
    ud_t * insn);

static gboolean gum_x86_relocator_rewrite_unconditional_branch (
    GumX86Relocator * self, GumCodeGenCtx * ctx);
static gboolean gum_x86_relocator_rewrite_conditional_branch (GumX86Relocator * self,
    GumCodeGenCtx * ctx);
static gboolean gum_x86_relocator_rewrite_if_rip_relative (GumX86Relocator * self,
    GumCodeGenCtx * ctx);

static gboolean gum_x86_call_is_to_next_instruction (ud_t * insn);

void
gum_x86_relocator_init (GumX86Relocator * relocator,
                        const guint8 * input_code,
                        GumX86Writer * output)
{
  relocator->input_insns = gum_new (ud_t, GUM_MAX_INPUT_INSN_COUNT);

  gum_x86_relocator_reset (relocator, input_code, output);
}

void
gum_x86_relocator_reset (GumX86Relocator * relocator,
                         const guint8 * input_code,
                         GumX86Writer * output)
{
  relocator->input_start = relocator->input_cur = input_code;
  relocator->output = output;

  relocator->inpos = relocator->outpos = 0;

  relocator->eob = FALSE;
  relocator->eoi = FALSE;
}

void
gum_x86_relocator_free (GumX86Relocator * relocator)
{
  gum_free (relocator->input_insns);
}

static guint
gum_x86_relocator_inpos (GumX86Relocator * self)
{
  return self->inpos % GUM_MAX_INPUT_INSN_COUNT;
}

static guint
gum_x86_relocator_outpos (GumX86Relocator * self)
{
  return self->outpos % GUM_MAX_INPUT_INSN_COUNT;
}

static void
gum_x86_relocator_increment_inpos (GumX86Relocator * self)
{
  self->inpos++;
  g_assert_cmpint (self->inpos, >, self->outpos);
}

static void
gum_x86_relocator_increment_outpos (GumX86Relocator * self)
{
  self->outpos++;
  g_assert_cmpint (self->outpos, <=, self->inpos);
}

guint
gum_x86_relocator_read_one (GumX86Relocator * self,
                            const ud_t ** insn)
{
  const guint buf_size = 4096;
  ud_t * ud;
  guint in_size;

  if (self->eoi)
    return 0;

  ud = &self->input_insns[gum_x86_relocator_inpos (self)];
  gum_x86_relocator_increment_inpos (self);

  ud_init (ud);
  ud_set_mode (ud, GUM_CPU_MODE);
  /*ud_set_syntax (ud, UD_SYN_INTEL);*/

  ud_set_pc (ud, GPOINTER_TO_SIZE (self->input_cur));
  ud_set_input_buffer (ud, (guint8 *) self->input_cur, buf_size);

  in_size = ud_disassemble (ud);
  g_assert (in_size != 0);

  switch (ud->mnemonic)
  {
    case UD_Ijcxz:
    case UD_Ijecxz:
    case UD_Ijrcxz:
      return 0; /* FIXME: not supported */
      break;

    case UD_Ijmp:
    case UD_Iret:
    case UD_Iretf:
      self->eob = TRUE;
      self->eoi = TRUE;
      break;

    case UD_Icall:
      self->eob = !gum_x86_call_is_to_next_instruction (ud);
      self->eoi = FALSE;
      break;

    default:
      if (gum_mnemonic_is_jcc (ud->mnemonic))
        self->eob = TRUE;
      break;
  }

  if (insn != NULL)
    *insn = ud;

  self->input_cur += in_size;

  return self->input_cur - self->input_start;
}

ud_t *
gum_x86_relocator_peek_next_write_insn (GumX86Relocator * self)
{
  if (self->outpos == self->inpos)
    return NULL;

  return &self->input_insns[gum_x86_relocator_outpos (self)];
}

gpointer
gum_x86_relocator_peek_next_write_source (GumX86Relocator * self)
{
  ud_t * next;

  next = gum_x86_relocator_peek_next_write_insn (self);
  if (next == NULL)
    return NULL;

  return GSIZE_TO_POINTER (ud_insn_off (next));
}

void
gum_x86_relocator_skip_one (GumX86Relocator * self)
{
  ud_t * next;

  next = gum_x86_relocator_peek_next_write_insn (self);
  g_assert (next != NULL);
  gum_x86_relocator_increment_outpos (self);

  gum_x86_relocator_put_label_for (self, next);
}

void
gum_x86_relocator_skip_one_no_label (GumX86Relocator * self)
{
  ud_t * next;

  next = gum_x86_relocator_peek_next_write_insn (self);
  g_assert (next != NULL);
  gum_x86_relocator_increment_outpos (self);
}

gboolean
gum_x86_relocator_write_one (GumX86Relocator * self)
{
  ud_t * cur;

  if ((cur = gum_x86_relocator_peek_next_write_insn (self)) == NULL)
    return FALSE;

  gum_x86_relocator_put_label_for (self, cur);

  return gum_x86_relocator_write_one_instruction (self);
}

gboolean
gum_x86_relocator_write_one_no_label (GumX86Relocator * self)
{
  return gum_x86_relocator_write_one_instruction (self);
}

static gboolean
gum_x86_relocator_write_one_instruction (GumX86Relocator * self)
{
  GumCodeGenCtx ctx;
  gboolean rewritten = FALSE;

  if ((ctx.insn = gum_x86_relocator_peek_next_write_insn (self)) == NULL)
    return FALSE;
  gum_x86_relocator_increment_outpos (self);

  ctx.len = ud_insn_len (ctx.insn);
  ctx.start = (guint8 *) GPOINTER_TO_SIZE (ud_insn_off (ctx.insn));
  ctx.end = ctx.start + ctx.len;

  ctx.code_writer = self->output;

  switch (ctx.insn->mnemonic)
  {
    case UD_Icall:
    case UD_Ijmp:
      rewritten = gum_x86_relocator_rewrite_unconditional_branch (self, &ctx);
      break;

    default:
      if (gum_mnemonic_is_jcc (ctx.insn->mnemonic))
        rewritten = gum_x86_relocator_rewrite_conditional_branch (self, &ctx);
      else
        rewritten = gum_x86_relocator_rewrite_if_rip_relative (self, &ctx);
      break;
  }

  if (!rewritten)
    gum_x86_writer_put_bytes (ctx.code_writer, ctx.start, ctx.len);

  return TRUE;
}

void
gum_x86_relocator_write_all (GumX86Relocator * self)
{
  guint count = 0;

  while (gum_x86_relocator_write_one (self))
    count++;

  g_assert_cmpuint (count, >, 0);
}

gboolean
gum_x86_relocator_eob (GumX86Relocator * self)
{
  return self->eob;
}

gboolean
gum_x86_relocator_eoi (GumX86Relocator * self)
{
  return self->eoi;
}

static void
gum_x86_relocator_put_label_for (GumX86Relocator * self,
                                 ud_t * insn)
{
  gum_x86_writer_put_label (self->output,
      GSIZE_TO_POINTER (ud_insn_off (insn)));
}

gboolean
gum_x86_relocator_can_relocate (gpointer address,
                                guint min_bytes)
{
  guint8 * buf;
  GumX86Writer cw;
  GumX86Relocator rl;
  guint reloc_bytes;

  buf = g_alloca (3 * min_bytes);
  gum_x86_writer_init (&cw, buf);

  gum_x86_relocator_init (&rl, address, &cw);

  do
  {
    reloc_bytes = gum_x86_relocator_read_one (&rl, NULL);
    if (reloc_bytes == 0)
      return FALSE;
  }
  while (reloc_bytes < min_bytes);

  gum_x86_relocator_free (&rl);

  gum_x86_writer_free (&cw);

  return TRUE;
}

guint
gum_x86_relocator_relocate (gpointer from,
                            guint min_bytes,
                            gpointer to)
{
  GumX86Writer cw;
  GumX86Relocator rl;
  guint reloc_bytes;

  gum_x86_writer_init (&cw, to);

  gum_x86_relocator_init (&rl, from, &cw);

  do
  {
    reloc_bytes = gum_x86_relocator_read_one (&rl, NULL);
    g_assert_cmpuint (reloc_bytes, !=, 0);
  }
  while (reloc_bytes < min_bytes);

  gum_x86_relocator_write_all (&rl);

  gum_x86_relocator_free (&rl);
  gum_x86_writer_free (&cw);

  return reloc_bytes;
}

static gboolean
gum_x86_relocator_rewrite_unconditional_branch (GumX86Relocator * self,
                                                GumCodeGenCtx * ctx)
{
  ud_operand_t * op = &ctx->insn->operand[0];
  GumX86Writer * cw = ctx->code_writer;

  (void) self;
  (void) ctx;

  if (gum_x86_call_is_to_next_instruction (ctx->insn))
  {
    if (cw->target_cpu == GUM_CPU_AMD64)
    {
      gum_x86_writer_put_push_reg (cw, GUM_REG_XAX);
      gum_x86_writer_put_mov_reg_address (cw, GUM_REG_XAX,
          GUM_ADDRESS (ctx->end));
      gum_x86_writer_put_xchg_reg_reg_ptr (cw, GUM_REG_XAX, GUM_REG_XSP);
    }
    else
    {
      gum_x86_writer_put_push_u32 (cw, GPOINTER_TO_SIZE (ctx->end));
    }

    return TRUE;
  }

  if (op->type == UD_OP_JIMM && op->base == UD_NONE)
  {
    const guint8 * target = NULL;

    if (op->size == 8)
      target = ctx->end + op->lval.sbyte;
    else if (op->size == 32)
      target = ctx->end + op->lval.sdword;
    else
      g_assert_not_reached ();

    if (ctx->insn->mnemonic == UD_Icall)
      gum_x86_writer_put_call (cw, target);
    else
      gum_x86_writer_put_jmp (cw, target);

    return TRUE;
  }
  else if ((ctx->insn->mnemonic == UD_Icall && op->type == UD_OP_MEM) ||
      (ctx->insn->mnemonic == UD_Ijmp && op->type == UD_OP_JIMM
          && op->size == 8))
  {
    return FALSE;
  }
  else if (op->type == UD_OP_REG)
  {
    return FALSE;
  }
  else
  {
    /* FIXME */
    g_assert_not_reached ();
  }
}

static gboolean
gum_x86_relocator_rewrite_conditional_branch (GumX86Relocator * self,
                                              GumCodeGenCtx * ctx)
{
  ud_operand_t * op = &ctx->insn->operand[0];
  if (op->type == UD_OP_JIMM && op->base == UD_NONE)
  {
    const guint8 * target = NULL;

    if (op->size == 8)
      target = ctx->end + op->lval.sbyte;
    else if (op->size == 32)
      target = ctx->end + op->lval.sdword;
    else
      g_assert_not_reached ();

    if (target >= self->input_start && target < self->input_cur)
    {
      gum_x86_writer_put_jcc_short_label (ctx->code_writer, ctx->start[0],
          GUINT_TO_POINTER (target), GUM_NO_HINT);
    }
    else
    {
      gum_x86_writer_put_jcc_near (ctx->code_writer,
          gum_jcc_insn_to_short_opcode (ctx->start), target, GUM_NO_HINT);
    }
  }
  else
  {
    /* FIXME */
    g_assert_not_reached ();
  }

  return TRUE;
}

static gboolean
gum_x86_relocator_rewrite_if_rip_relative (GumX86Relocator * self,
                                           GumCodeGenCtx * ctx)
{
#if GLIB_SIZEOF_VOID_P == 4
  (void) self;
  (void) ctx;

  return FALSE;
#else
  ud_t * insn = ctx->insn;
  guint mod, reg, rm;
  gboolean is_rip_relative;
  GumCpuReg target_reg, rip_reg;
  guint8 code[16];

  (void) self;

  if (!insn->have_modrm)
    return FALSE;

  mod = (insn->modrm & 0xc0) >> 6;
  reg = (insn->modrm & 0x38) >> 3;
  rm  = (insn->modrm & 0x07) >> 0;

  is_rip_relative = (mod == 0 && rm == 5);
  if (!is_rip_relative)
    return FALSE;

  mod = 2;

  target_reg = (GumCpuReg) (GUM_REG_RAX + reg);
  if (target_reg != GUM_REG_RAX)
  {
    rip_reg = GUM_REG_RAX;
    rm = 0;
  }
  else
  {
    rip_reg = GUM_REG_RCX;
    rm = 1;
  }

  if (insn->mnemonic == UD_Ipush)
  {
    gum_x86_writer_put_push_reg (ctx->code_writer, GUM_REG_RAX);
  }

  gum_x86_writer_put_push_reg (ctx->code_writer, rip_reg);
  gum_x86_writer_put_mov_reg_address (ctx->code_writer, rip_reg,
      GUM_ADDRESS (ctx->end));

  if (insn->mnemonic == UD_Ipush)
  {
    gum_x86_writer_put_mov_reg_reg_offset_ptr (ctx->code_writer, rip_reg,
        rip_reg, insn->operand[0].lval.sdword);
    gum_x86_writer_put_mov_reg_offset_ptr_reg (ctx->code_writer,
        GUM_REG_RSP, 0x08, rip_reg);
  }
  else
  {
    memcpy (code, ctx->start, ctx->len);
    code[ctx->insn->modrm_offset] = (mod << 6) | (reg << 3) | rm;
    gum_x86_writer_put_bytes (ctx->code_writer, code, ctx->len);
  }

  gum_x86_writer_put_pop_reg (ctx->code_writer, rip_reg);

  return TRUE;
#endif
}

static gboolean
gum_x86_call_is_to_next_instruction (ud_t * insn)
{
  ud_operand_t * op = &insn->operand[0];

  return (op->type == UD_OP_JIMM && op->base == UD_NONE &&
      op->lval.sdword == 0);
}
