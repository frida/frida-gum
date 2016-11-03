/*
 * Copyright (C) 2010-2014 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumarmrelocator.h"

#include "gummemory.h"

#define GUM_MAX_INPUT_INSN_COUNT (100)

typedef struct _GumCodeGenCtx GumCodeGenCtx;

struct _GumCodeGenCtx
{
  const cs_insn * insn;
  cs_arm * detail;
  GumAddress pc;

  GumArmWriter * output;
};

static gboolean gum_arm_branch_is_unconditional (const cs_insn * insn);

static gboolean gum_arm_relocator_rewrite_ldr (GumArmRelocator * self,
    GumCodeGenCtx * ctx);
static gboolean gum_arm_relocator_rewrite_add (GumArmRelocator * self,
    GumCodeGenCtx * ctx);
static gboolean gum_arm_relocator_rewrite_b (GumArmRelocator * self,
    cs_mode target_mode, GumCodeGenCtx * ctx);
static gboolean gum_arm_relocator_rewrite_bl (GumArmRelocator * self,
    cs_mode target_mode, GumCodeGenCtx * ctx);

void
gum_arm_relocator_init (GumArmRelocator * relocator,
                        gconstpointer input_code,
                        GumArmWriter * output)
{
  cs_err err;

  err = cs_open (CS_ARCH_ARM, CS_MODE_ARM, &relocator->capstone);
  g_assert_cmpint (err, ==, CS_ERR_OK);
  err = cs_option (relocator->capstone, CS_OPT_DETAIL, CS_OPT_ON);
  g_assert_cmpint (err, ==, CS_ERR_OK);
  relocator->input_insns = g_new0 (cs_insn *, GUM_MAX_INPUT_INSN_COUNT);

  gum_arm_relocator_reset (relocator, input_code, output);
}

void
gum_arm_relocator_reset (GumArmRelocator * relocator,
                         gconstpointer input_code,
                         GumArmWriter * output)
{
  guint i;

  relocator->input_start = input_code;
  relocator->input_cur = input_code;
  relocator->input_pc = GUM_ADDRESS (input_code);
  for (i = 0; i != GUM_MAX_INPUT_INSN_COUNT; i++)
  {
    cs_insn * insn = relocator->input_insns[i];
    if (insn != NULL)
    {
      cs_free (insn, 1);
      relocator->input_insns[i] = NULL;
    }
  }
  relocator->output = output;

  relocator->inpos = 0;
  relocator->outpos = 0;

  relocator->eob = FALSE;
  relocator->eoi = FALSE;
}

void
gum_arm_relocator_free (GumArmRelocator * relocator)
{
  gum_arm_relocator_reset (relocator, relocator->input_start,
      relocator->output);

  g_free (relocator->input_insns);

  cs_close (&relocator->capstone);
}

static guint
gum_arm_relocator_inpos (GumArmRelocator * self)
{
  return self->inpos % GUM_MAX_INPUT_INSN_COUNT;
}

static guint
gum_arm_relocator_outpos (GumArmRelocator * self)
{
  return self->outpos % GUM_MAX_INPUT_INSN_COUNT;
}

static void
gum_arm_relocator_increment_inpos (GumArmRelocator * self)
{
  self->inpos++;
  g_assert_cmpint (self->inpos, >, self->outpos);
}

static void
gum_arm_relocator_increment_outpos (GumArmRelocator * self)
{
  self->outpos++;
  g_assert_cmpint (self->outpos, <=, self->inpos);
}

guint
gum_arm_relocator_read_one (GumArmRelocator * self,
                            const cs_insn ** instruction)
{
  cs_insn ** insn_ptr, * insn;

  if (self->eoi)
    return 0;

  insn_ptr = &self->input_insns[gum_arm_relocator_inpos (self)];

  if (*insn_ptr != NULL)
  {
    cs_free (*insn_ptr, 1);
    *insn_ptr = NULL;
  }

  if (cs_disasm (self->capstone, self->input_cur, 4, self->input_pc, 1,
      insn_ptr) != 1)
  {
    return 0;
  }

  insn = *insn_ptr;

  switch (insn->id)
  {
    case ARM_INS_B:
    case ARM_INS_BX:
      self->eob = TRUE;
      self->eoi = gum_arm_branch_is_unconditional (insn);
      break;
    case ARM_INS_BL:
    case ARM_INS_BLX:
      self->eob = TRUE;
      self->eoi = FALSE;
      break;
    case ARM_INS_POP:
      if (cs_reg_read (self->capstone, insn, ARM_REG_PC))
      {
        self->eob = TRUE;
        self->eoi = TRUE;
      }
      break;
  }

  gum_arm_relocator_increment_inpos (self);

  if (instruction != NULL)
    *instruction = insn;

  self->input_cur += insn->size;
  self->input_pc += insn->size;

  return self->input_cur - self->input_start;
}

cs_insn *
gum_arm_relocator_peek_next_write_insn (GumArmRelocator * self)
{
  if (self->outpos == self->inpos)
    return NULL;

  return self->input_insns[gum_arm_relocator_outpos (self)];
}

gpointer
gum_arm_relocator_peek_next_write_source (GumArmRelocator * self)
{
  cs_insn * next;

  next = gum_arm_relocator_peek_next_write_insn (self);
  if (next == NULL)
    return NULL;

  return GSIZE_TO_POINTER (next->address);
}

void
gum_arm_relocator_skip_one (GumArmRelocator * self)
{
  cs_insn * next;

  next = gum_arm_relocator_peek_next_write_insn (self);
  g_assert (next != NULL);
  gum_arm_relocator_increment_outpos (self);
}

gboolean
gum_arm_relocator_write_one (GumArmRelocator * self)
{
  const cs_insn * insn;
  GumCodeGenCtx ctx;
  gboolean rewritten;

  if ((insn = gum_arm_relocator_peek_next_write_insn (self)) == NULL)
    return FALSE;
  gum_arm_relocator_increment_outpos (self);
  ctx.insn = insn;
  ctx.detail = &ctx.insn->detail->arm;
  ctx.pc = insn->address + 8;
  ctx.output = self->output;

  switch (insn->id)
  {
    case ARM_INS_LDR:
      rewritten = gum_arm_relocator_rewrite_ldr (self, &ctx);
      break;
    case ARM_INS_ADD:
      rewritten = gum_arm_relocator_rewrite_add (self, &ctx);
      break;
    case ARM_INS_B:
      rewritten = gum_arm_relocator_rewrite_b (self, CS_MODE_ARM, &ctx);
      break;
    case ARM_INS_BX:
      rewritten = gum_arm_relocator_rewrite_b (self, CS_MODE_THUMB, &ctx);
      break;
    case ARM_INS_BL:
      rewritten = gum_arm_relocator_rewrite_bl (self, CS_MODE_ARM, &ctx);
      break;
    case ARM_INS_BLX:
      rewritten = gum_arm_relocator_rewrite_bl (self, CS_MODE_THUMB, &ctx);
      break;
    default:
      rewritten = FALSE;
      break;
  }

  if (!rewritten)
    gum_arm_writer_put_bytes (ctx.output, insn->bytes, insn->size);

  return TRUE;
}

void
gum_arm_relocator_write_all (GumArmRelocator * self)
{
  guint count = 0;

  while (gum_arm_relocator_write_one (self))
    count++;

  g_assert_cmpuint (count, >, 0);
}

gboolean
gum_arm_relocator_eob (GumArmRelocator * self)
{
  return self->eob;
}

gboolean
gum_arm_relocator_eoi (GumArmRelocator * self)
{
  return self->eoi;
}

gboolean
gum_arm_relocator_can_relocate (gpointer address,
                                guint min_bytes,
                                guint * maximum)
{
  guint n = 0;
  guint8 * buf;
  GumArmWriter cw;
  GumArmRelocator rl;
  guint reloc_bytes;

  buf = g_alloca (3 * min_bytes);
  gum_arm_writer_init (&cw, buf);

  gum_arm_relocator_init (&rl, address, &cw);

  do
  {
    reloc_bytes = gum_arm_relocator_read_one (&rl, NULL);
    if (reloc_bytes == 0)
      break;

    n = reloc_bytes;
  }
  while (reloc_bytes < min_bytes);

  gum_arm_relocator_free (&rl);

  gum_arm_writer_free (&cw);

  if (maximum != NULL)
    *maximum = n;

  return n >= min_bytes;
}

guint
gum_arm_relocator_relocate (gpointer from,
                            guint min_bytes,
                            gpointer to)
{
  GumArmWriter cw;
  GumArmRelocator rl;
  guint reloc_bytes;

  gum_arm_writer_init (&cw, to);

  gum_arm_relocator_init (&rl, from, &cw);

  do
  {
    reloc_bytes = gum_arm_relocator_read_one (&rl, NULL);
    g_assert_cmpuint (reloc_bytes, !=, 0);
  }
  while (reloc_bytes < min_bytes);

  gum_arm_relocator_write_all (&rl);

  gum_arm_relocator_free (&rl);
  gum_arm_writer_free (&cw);

  return reloc_bytes;
}

static gboolean
gum_arm_branch_is_unconditional (const cs_insn * insn)
{
  switch (insn->detail->arm.cc)
  {
    case ARM_CC_INVALID:
    case ARM_CC_AL:
      return TRUE;
    default:
      return FALSE;
  }
}

static gboolean
gum_arm_relocator_rewrite_ldr (GumArmRelocator * self,
                               GumCodeGenCtx * ctx)
{
  const cs_arm_op * dst = &ctx->detail->operands[0];
  const cs_arm_op * src = &ctx->detail->operands[1];
  gint disp;

  if (src->type != ARM_OP_MEM || src->mem.base != ARM_REG_PC)
    return FALSE;

  disp = src->mem.disp;

  gum_arm_writer_put_ldr_reg_address (ctx->output, dst->reg, ctx->pc);
  if (disp > 0xff)
  {
    gum_arm_writer_put_add_reg_reg_imm (ctx->output, dst->reg, dst->reg,
        0xc00 | ((disp >> 8) & 0xff));
  }
  gum_arm_writer_put_add_reg_reg_imm (ctx->output, dst->reg, dst->reg,
      disp & 0xff);
  gum_arm_writer_put_ldr_reg_reg_imm (ctx->output, dst->reg, dst->reg, 0);

  return TRUE;
}

static gboolean
gum_arm_relocator_rewrite_add (GumArmRelocator * self,
                               GumCodeGenCtx * ctx)
{
  const cs_arm_op * dst = &ctx->detail->operands[0];
  const cs_arm_op * left = &ctx->detail->operands[1];
  const cs_arm_op * right = &ctx->detail->operands[2];

  if (left->reg != ARM_REG_PC || right->type != ARM_OP_REG)
    return FALSE;

  if (right->reg == dst->reg)
  {
    gum_arm_writer_put_add_reg_reg_imm (ctx->output, dst->reg, dst->reg,
        ctx->pc & 0xff);
    gum_arm_writer_put_add_reg_reg_imm (ctx->output, dst->reg, dst->reg,
        0xc00 | ((ctx->pc >> 8) & 0xff));
    gum_arm_writer_put_add_reg_reg_imm (ctx->output, dst->reg, dst->reg,
        0x800 | ((ctx->pc >> 16) & 0xff));
    gum_arm_writer_put_add_reg_reg_imm (ctx->output, dst->reg, dst->reg,
        0x400 | ((ctx->pc >> 24) & 0xff));
  }
  else
  {
    gum_arm_writer_put_ldr_reg_address (ctx->output, dst->reg, ctx->pc);
    gum_arm_writer_put_add_reg_reg_imm (ctx->output, dst->reg, right->reg, 0);
  }

  return TRUE;
}

static gboolean
gum_arm_relocator_rewrite_b (GumArmRelocator * self,
                             cs_mode target_mode,
                             GumCodeGenCtx * ctx)
{
  const cs_arm_op * target = &ctx->detail->operands[0];

  if (target->type != ARM_OP_IMM)
    return FALSE;

  gum_arm_writer_put_ldr_reg_address (ctx->output, ARM_REG_PC,
      (target_mode == CS_MODE_THUMB) ? target->imm | 1 : target->imm);
  return TRUE;
}

static gboolean
gum_arm_relocator_rewrite_bl (GumArmRelocator * self,
                              cs_mode target_mode,
                              GumCodeGenCtx * ctx)
{
  const cs_arm_op * target = &ctx->detail->operands[0];

  if (target->type != ARM_OP_IMM)
    return FALSE;

  gum_arm_writer_put_ldr_reg_address (ctx->output, ARM_REG_LR,
      ctx->output->pc + (2 * 4));
  gum_arm_writer_put_ldr_reg_address (ctx->output, ARM_REG_PC,
      (target_mode == CS_MODE_THUMB) ? target->imm | 1 : target->imm);
  return TRUE;
}
