/*
 * Copyright (C) 2014 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

/* Useful reference: C4.1 A64 instruction index by encoding */

#include "gumarm64relocator.h"

#include "gummemory.h"

#define GUM_MAX_INPUT_INSN_COUNT (100)

typedef struct _GumCodeGenCtx GumCodeGenCtx;

struct _GumCodeGenCtx
{
  const GumArm64Instruction * insn;
  guint32 raw_insn;
  const guint8 * start;
  const guint8 * end;
  guint len;

  GumArm64Writer * output;
};

static gboolean gum_arm64_relocator_rewrite_adr (GumArm64Relocator * self,
    GumCodeGenCtx * ctx);
static gboolean gum_arm64_relocator_rewrite_unconditional_branch (
    GumArm64Relocator * self, GumCodeGenCtx * ctx);
static gboolean gum_arm64_relocator_rewrite_conditional_branch (
    GumArm64Relocator * self, GumCodeGenCtx * ctx);

void
gum_arm64_relocator_init (GumArm64Relocator * relocator,
                          gconstpointer input_code,
                          GumArm64Writer * output)
{
  relocator->input_insns = gum_new (GumArm64Instruction,
      GUM_MAX_INPUT_INSN_COUNT);

  gum_arm64_relocator_reset (relocator, input_code, output);
}

void
gum_arm64_relocator_reset (GumArm64Relocator * relocator,
                           gconstpointer input_code,
                           GumArm64Writer * output)
{
  relocator->input_start = input_code;
  relocator->input_cur = input_code;
  relocator->input_pc = GUM_ADDRESS (input_code);
  relocator->output = output;

  relocator->inpos = 0;
  relocator->outpos = 0;

  relocator->eob = FALSE;
  relocator->eoi = FALSE;
}

void
gum_arm64_relocator_free (GumArm64Relocator * relocator)
{
  gum_free (relocator->input_insns);
}

static guint
gum_arm64_relocator_inpos (GumArm64Relocator * self)
{
  return self->inpos % GUM_MAX_INPUT_INSN_COUNT;
}

static guint
gum_arm64_relocator_outpos (GumArm64Relocator * self)
{
  return self->outpos % GUM_MAX_INPUT_INSN_COUNT;
}

static void
gum_arm64_relocator_increment_inpos (GumArm64Relocator * self)
{
  self->inpos++;
  g_assert_cmpint (self->inpos, >, self->outpos);
}

static void
gum_arm64_relocator_increment_outpos (GumArm64Relocator * self)
{
  self->outpos++;
  g_assert_cmpint (self->outpos, <=, self->inpos);
}

guint
gum_arm64_relocator_read_one (GumArm64Relocator * self,
                              const GumArm64Instruction ** instruction)
{
  guint32 raw_insn;
  GumArm64Instruction * insn;

  if (self->eoi)
    return 0;

  raw_insn = GUINT32_FROM_LE (*((guint32 *) self->input_cur));
  insn = &self->input_insns[gum_arm64_relocator_inpos (self)];

  insn->mnemonic = GUM_ARM64_UNKNOWN;
  insn->address = self->input_cur;
  insn->length = 4;
  insn->pc = self->input_pc;

  if ((raw_insn & 0x7c000000) == 0x14000000)
  {
    if ((raw_insn & 0x80000000) != 0)
    {
      insn->mnemonic = GUM_ARM64_BL;
      self->eob = TRUE;
      self->eoi = FALSE;
    }
    else
    {
      insn->mnemonic = GUM_ARM64_B;
      self->eob = TRUE;
      self->eoi = TRUE;
    }
  }
  else if ((raw_insn & 0xff000010) == 0x54000000)
  {
    insn->mnemonic = GUM_ARM64_B_COND;
    self->eob = TRUE;
    self->eoi = FALSE;
  }
  else if ((raw_insn & 0xff9ffc1f) == 0xd61f0000)
  {
    switch ((raw_insn >> 21) & 3)
    {
      case 0:
        insn->mnemonic = GUM_ARM64_BR;
        self->eob = TRUE;
        self->eoi = TRUE;
        break;
      case 1:
        insn->mnemonic = GUM_ARM64_BLR;
        self->eob = TRUE;
        self->eoi = FALSE;
        break;
      case 2:
        insn->mnemonic = GUM_ARM64_RET;
        self->eob = TRUE;
        self->eoi = TRUE;
        break;
      default:
        g_assert_not_reached ();
    }
  }
  else
  {
    guint32 adr_bits;

    adr_bits = raw_insn & 0x9f000000;
    if (adr_bits == 0x10000000)
      insn->mnemonic = GUM_ARM64_ADR;
    else if (adr_bits == 0x90000000)
      insn->mnemonic = GUM_ARM64_ADRP;
  }

  gum_arm64_relocator_increment_inpos (self);

  if (instruction != NULL)
    *instruction = insn;

  self->input_cur += insn->length;
  self->input_pc += insn->length;

  return self->input_cur - self->input_start;
}

GumArm64Instruction *
gum_arm64_relocator_peek_next_write_insn (GumArm64Relocator * self)
{
  if (self->outpos == self->inpos)
    return NULL;

  return &self->input_insns[gum_arm64_relocator_outpos (self)];
}

gpointer
gum_arm64_relocator_peek_next_write_source (GumArm64Relocator * self)
{
  GumArm64Instruction * next;

  next = gum_arm64_relocator_peek_next_write_insn (self);
  if (next == NULL)
    return NULL;

  g_assert_not_reached ();
  return NULL;
}

void
gum_arm64_relocator_skip_one (GumArm64Relocator * self)
{
  GumArm64Instruction * next;

  next = gum_arm64_relocator_peek_next_write_insn (self);
  g_assert (next != NULL);
  gum_arm64_relocator_increment_outpos (self);
}

gboolean
gum_arm64_relocator_write_one (GumArm64Relocator * self)
{
  GumArm64Instruction * cur;
  GumCodeGenCtx ctx;
  gboolean rewritten = FALSE;

  if ((cur = gum_arm64_relocator_peek_next_write_insn (self)) == NULL)
    return FALSE;

  if ((ctx.insn = gum_arm64_relocator_peek_next_write_insn (self)) == NULL)
    return FALSE;
  gum_arm64_relocator_increment_outpos (self);

  ctx.len = ctx.insn->length;
  ctx.raw_insn = GUINT32_FROM_LE (*((guint32 *) ctx.insn->address));
  ctx.start = ctx.insn->address;
  ctx.end = ctx.start + ctx.len;

  ctx.output = self->output;

  switch (ctx.insn->mnemonic)
  {
    case GUM_ARM64_ADR:
    case GUM_ARM64_ADRP:
      rewritten = gum_arm64_relocator_rewrite_adr (self, &ctx);
      break;
    case GUM_ARM64_B:
    case GUM_ARM64_BL:
      rewritten = gum_arm64_relocator_rewrite_unconditional_branch (self, &ctx);
      break;
    case GUM_ARM64_B_COND:
      rewritten = gum_arm64_relocator_rewrite_conditional_branch (self, &ctx);
      break;
    default:
      break;
  }

  if (!rewritten)
    gum_arm64_writer_put_bytes (ctx.output, ctx.start, ctx.len);

  return TRUE;
}

void
gum_arm64_relocator_write_all (GumArm64Relocator * self)
{
  guint count = 0;

  while (gum_arm64_relocator_write_one (self))
    count++;

  g_assert_cmpuint (count, >, 0);
}

gboolean
gum_arm64_relocator_eob (GumArm64Relocator * self)
{
  return self->eob;
}

gboolean
gum_arm64_relocator_eoi (GumArm64Relocator * self)
{
  return self->eoi;
}

gboolean
gum_arm64_relocator_can_relocate (gpointer address,
                                  guint min_bytes)
{
  guint8 * buf;
  GumArm64Writer cw;
  GumArm64Relocator rl;
  guint reloc_bytes;

  buf = g_alloca (3 * min_bytes);
  gum_arm64_writer_init (&cw, buf);

  gum_arm64_relocator_init (&rl, address, &cw);

  do
  {
    reloc_bytes = gum_arm64_relocator_read_one (&rl, NULL);
    if (reloc_bytes == 0)
      return FALSE;
  }
  while (reloc_bytes < min_bytes);

  gum_arm64_relocator_free (&rl);

  gum_arm64_writer_free (&cw);

  return TRUE;
}

guint
gum_arm64_relocator_relocate (gpointer from,
                              guint min_bytes,
                              gpointer to)
{
  GumArm64Writer cw;
  GumArm64Relocator rl;
  guint reloc_bytes;

  gum_arm64_writer_init (&cw, to);

  gum_arm64_relocator_init (&rl, from, &cw);

  do
  {
    reloc_bytes = gum_arm64_relocator_read_one (&rl, NULL);
    g_assert_cmpuint (reloc_bytes, !=, 0);
  }
  while (reloc_bytes < min_bytes);

  gum_arm64_relocator_write_all (&rl);

  gum_arm64_relocator_free (&rl);
  gum_arm64_writer_free (&cw);

  return reloc_bytes;
}

static gboolean
gum_arm64_relocator_rewrite_adr (GumArm64Relocator * self,
                                 GumCodeGenCtx * ctx)
{
  GumArm64Reg reg;
  guint64 imm_hi, imm_lo;
  guint64 negative_mask;
  union
  {
    gint64 i;
    guint64 u;
  } distance;
  GumAddress absolute_target;

  (void) self;

  reg = ctx->raw_insn & 0x1f;
  imm_hi = (ctx->raw_insn >> 5) & 0x7ffff;
  imm_lo = (ctx->raw_insn >> 29) & 3;

  if (ctx->insn->mnemonic == GUM_ARM64_ADR)
  {
    negative_mask = G_GUINT64_CONSTANT (0xffffffffffe00000);

    if ((imm_hi & 0x40000) != 0)
      distance.u = negative_mask | (imm_hi << 2) | imm_lo;
    else
      distance.u = (imm_hi << 2) | imm_lo;
  }
  else if (ctx->insn->mnemonic == GUM_ARM64_ADRP)
  {
    negative_mask = G_GUINT64_CONSTANT (0xfffffffe00000000);

    if ((imm_hi & 0x40000) != 0)
      distance.u = negative_mask | (imm_hi << 14) | (imm_lo << 12);
    else
      distance.u = (imm_hi << 14) | (imm_lo << 12);
  }
  else
  {
    distance.u = 0;

    g_assert_not_reached ();
  }

  absolute_target = ctx->insn->pc + distance.i;

  gum_arm64_writer_put_ldr_reg_address (ctx->output, reg, absolute_target);

  return TRUE;
}

static gboolean
gum_arm64_relocator_rewrite_unconditional_branch (GumArm64Relocator * self,
                                                  GumCodeGenCtx * ctx)
{
  union
  {
    gint32 i;
    guint32 u;
  } distance;
  GumAddress absolute_target;

  (void) self;

  if ((ctx->raw_insn & 0x2000000) != 0)
    distance.u = 0xfc000000 | (ctx->raw_insn & 0x3ffffff);
  else
    distance.u = ctx->raw_insn & 0x3ffffff;

  absolute_target = ctx->insn->pc + (distance.i * 4);

  if (ctx->insn->mnemonic == GUM_ARM64_B)
  {
    gum_arm64_writer_put_ldr_reg_address (ctx->output, GUM_A64REG_X16,
        absolute_target);
    gum_arm64_writer_put_br_reg (ctx->output, GUM_A64REG_X16);
  }
  else
  {
    gum_arm64_writer_put_ldr_reg_address (ctx->output, GUM_A64REG_LR,
        absolute_target);
    gum_arm64_writer_put_blr_reg (ctx->output, GUM_A64REG_LR);
  }

  return TRUE;
}

static gboolean
gum_arm64_relocator_rewrite_conditional_branch (GumArm64Relocator * self,
                                                GumCodeGenCtx * ctx)
{
  union
  {
    gint32 i;
    guint32 u;
  } distance;
  GumAddress absolute_target;
  guint32 insn;

  (void) self;

  if ((ctx->raw_insn & 0x800000) != 0)
    distance.u = 0xfff80000 | ((ctx->raw_insn >> 5) & 0x7ffff);
  else
    distance.u = (ctx->raw_insn >> 5) & 0x7ffff;

  absolute_target = ctx->insn->pc + (distance.i * 4);

  /* Rewrite to b.cond going 3 instructions ahead */
  insn = (ctx->raw_insn & 0xff00001f) | (3 << 5);
  gum_arm64_writer_put_bytes (ctx->output, (guint8 *) &insn, sizeof (insn));

  /* If false */
  gum_arm64_writer_put_ldr_reg_address (ctx->output, GUM_A64REG_X16,
      GUM_ADDRESS (ctx->output + 4));
  gum_arm64_writer_put_br_reg (ctx->output, GUM_A64REG_X16);

  /* If true */
  gum_arm64_writer_put_ldr_reg_address (ctx->output, GUM_A64REG_X16,
      absolute_target);
  gum_arm64_writer_put_br_reg (ctx->output, GUM_A64REG_X16);

  return TRUE;
}
