/*
 * Copyright (C) 2014-2015 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

/* Useful reference: C4.1 A64 instruction index by encoding */

#include "gumarm64relocator.h"

#include "gummemory.h"

#include <capstone/capstone.h>

#define GUM_MAX_INPUT_INSN_COUNT (100)

typedef struct _GumCodeGenCtx GumCodeGenCtx;

struct _GumCodeGenCtx
{
  const cs_insn * insn;
  cs_arm64 * detail;
  guint32 raw_insn;

  GumArm64Writer * output;
};

static gboolean gum_arm64_branch_is_unconditional (const cs_insn * insn);
static gboolean gum_arm64_relocator_rewrite_ldr (GumArm64Relocator * self,
    GumCodeGenCtx * ctx);
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
  cs_err err;

  err = cs_open (CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN, &relocator->capstone);
  g_assert_cmpint (err, ==, CS_ERR_OK);
  err = cs_option (relocator->capstone, CS_OPT_DETAIL, CS_OPT_ON);
  g_assert_cmpint (err, ==, CS_ERR_OK);
  relocator->input_insns = gum_new0 (cs_insn *, GUM_MAX_INPUT_INSN_COUNT);

  gum_arm64_relocator_reset (relocator, input_code, output);
}

void
gum_arm64_relocator_reset (GumArm64Relocator * relocator,
                           gconstpointer input_code,
                           GumArm64Writer * output)
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
gum_arm64_relocator_free (GumArm64Relocator * relocator)
{
  gum_arm64_relocator_reset (relocator, relocator->input_start,
      relocator->output);

  gum_free (relocator->input_insns);

  cs_close (&relocator->capstone);
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
                              const cs_insn ** instruction)
{
  cs_insn ** insn_ptr, * insn;

  if (self->eoi)
    return 0;

  insn_ptr = &self->input_insns[gum_arm64_relocator_inpos (self)];

  if (*insn_ptr != NULL)
  {
    cs_free (*insn_ptr, 1);
    *insn_ptr = NULL;
  }

  if (cs_disasm (self->capstone, self->input_cur, 16, self->input_pc, 1,
      insn_ptr) != 1)
  {
    return 0;
  }

  insn = *insn_ptr;

  switch (insn->id)
  {
    case ARM64_INS_B:
      self->eob = TRUE;
      self->eoi = gum_arm64_branch_is_unconditional (insn);
      break;
    case ARM64_INS_BR:
    case ARM64_INS_RET:
      self->eob = TRUE;
      self->eoi = TRUE;
      break;
    case ARM64_INS_BL:
    case ARM64_INS_BLR:
      self->eob = TRUE;
      self->eoi = FALSE;
      break;
  }

  gum_arm64_relocator_increment_inpos (self);

  if (instruction != NULL)
    *instruction = insn;

  self->input_cur += insn->size;
  self->input_pc += insn->size;

  return self->input_cur - self->input_start;
}

cs_insn *
gum_arm64_relocator_peek_next_write_insn (GumArm64Relocator * self)
{
  if (self->outpos == self->inpos)
    return NULL;

  return self->input_insns[gum_arm64_relocator_outpos (self)];
}

gpointer
gum_arm64_relocator_peek_next_write_source (GumArm64Relocator * self)
{
  cs_insn * next;

  next = gum_arm64_relocator_peek_next_write_insn (self);
  if (next == NULL)
    return NULL;

  return GSIZE_TO_POINTER (next->address);
}

void
gum_arm64_relocator_skip_one (GumArm64Relocator * self)
{
  cs_insn * next;

  next = gum_arm64_relocator_peek_next_write_insn (self);
  g_assert (next != NULL);
  gum_arm64_relocator_increment_outpos (self);
}

gboolean
gum_arm64_relocator_write_one (GumArm64Relocator * self)
{
  const cs_insn * insn;
  GumCodeGenCtx ctx;
  gboolean rewritten = FALSE;

  if ((insn = gum_arm64_relocator_peek_next_write_insn (self)) == NULL)
    return FALSE;
  ctx.insn = insn;
  ctx.detail = &ctx.insn->detail->arm64;
  ctx.raw_insn = GUINT32_FROM_LE (*((guint32 *) ctx.insn->bytes));
  gum_arm64_relocator_increment_outpos (self);
  ctx.output = self->output;

  switch (ctx.insn->id)
  {
    case ARM64_INS_LDR:
      rewritten = gum_arm64_relocator_rewrite_ldr (self, &ctx);
      break;
    case ARM64_INS_ADR:
    case ARM64_INS_ADRP:
      rewritten = gum_arm64_relocator_rewrite_adr (self, &ctx);
      break;
    case ARM64_INS_B:
    {
      if (gum_arm64_branch_is_unconditional (ctx.insn))
      {
        rewritten = gum_arm64_relocator_rewrite_unconditional_branch (self,
            &ctx);
      }
      else
      {
        rewritten = gum_arm64_relocator_rewrite_conditional_branch (self, &ctx);
      }
      break;
    }
    case ARM64_INS_BL:
      rewritten = gum_arm64_relocator_rewrite_unconditional_branch (self, &ctx);
      break;
    case ARM64_INS_CBZ:
    case ARM64_INS_CBNZ:
      rewritten = gum_arm64_relocator_rewrite_conditional_branch (self, &ctx);
      break;
    default:
      break;
  }

  if (!rewritten)
    gum_arm64_writer_put_instruction (ctx.output, ctx.raw_insn);

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
                                  guint min_bytes,
                                  guint * maximum)
{
  guint n = 0;
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
    if (reloc_bytes != 0)
      n = reloc_bytes;
    else
      break;
  }
  while (reloc_bytes < min_bytes);

  if (!rl.eoi)
  {
    csh capstone;
    cs_err err;
    cs_insn * insn;
    size_t count, i;
    gboolean eoi;

    err = cs_open (CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN, &capstone);
    g_assert_cmpint (err, == , CS_ERR_OK);
    err = cs_option (capstone, CS_OPT_DETAIL, CS_OPT_ON);
    g_assert_cmpint (err, ==, CS_ERR_OK);

    count = cs_disasm (capstone, rl.input_cur, 1024, rl.input_pc, 0, &insn);
    g_assert (insn != NULL);

    eoi = FALSE;
    for (i = 0; i != count && !eoi; i++)
    {
      cs_arm64 * d = &insn[i].detail->arm64;

      switch (insn[i].id)
      {
        case ARM64_INS_B:
        {
          cs_arm64_op * op = &d->operands[0];
          g_assert (op->type == ARM64_OP_IMM);
          gssize offset =
              (gssize) op->imm - (gssize) GPOINTER_TO_SIZE (address);
          if (offset >= 0 && offset < n)
            n = offset;
          eoi = d->cc == ARM64_CC_INVALID || d->cc == ARM64_CC_AL ||
              d->cc == ARM64_CC_NV;
          break;
        }
        case ARM64_INS_CBZ:
        case ARM64_INS_CBNZ:
        {
          cs_arm64_op * op = &d->operands[1];
          g_assert (op->type == ARM64_OP_IMM);
          gssize offset =
              (gssize) op->imm - (gssize) GPOINTER_TO_SIZE (address);
          if (offset >= 0 && offset < n)
            n = offset;
          break;
        }
        case ARM64_INS_BR:
        case ARM64_INS_RET:
          eoi = TRUE;
          break;
        default:
          break;
      }
    }

    cs_free (insn, count);

    cs_close (&capstone);
  }

  gum_arm64_relocator_free (&rl);

  gum_arm64_writer_free (&cw);

  if (maximum != NULL)
    *maximum = n;

  return n >= min_bytes;
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
gum_arm64_branch_is_unconditional (const cs_insn * insn)
{
  switch (insn->detail->arm64.cc)
  {
    case ARM64_CC_INVALID:
    case ARM64_CC_AL:
    case ARM64_CC_NV:
      return TRUE;
    default:
      return FALSE;
  }
}

static gboolean
gum_arm64_relocator_rewrite_ldr (GumArm64Relocator * self,
                                 GumCodeGenCtx * ctx)
{
  const cs_arm64_op * dst = &ctx->detail->operands[0];
  const cs_arm64_op * src = &ctx->detail->operands[1];

  (void) self;

  if (src->type != ARM64_OP_IMM)
    return FALSE;

  gum_arm64_writer_put_ldr_reg_address (ctx->output, dst->reg, src->imm);
  gum_arm64_writer_put_ldr_reg_reg_offset (ctx->output, dst->reg, dst->reg, 0);
  return TRUE;
}

static gboolean
gum_arm64_relocator_rewrite_adr (GumArm64Relocator * self,
                                 GumCodeGenCtx * ctx)
{
  const cs_arm64_op * dst = &ctx->detail->operands[0];
  const cs_arm64_op * label = &ctx->detail->operands[1];

  (void) self;

  gum_arm64_writer_put_ldr_reg_address (ctx->output, dst->reg, label->imm);
  return TRUE;
}

static gboolean
gum_arm64_relocator_rewrite_unconditional_branch (GumArm64Relocator * self,
                                                  GumCodeGenCtx * ctx)
{
  const cs_arm64_op * target = &ctx->detail->operands[0];

  (void) self;

  if (ctx->insn->id == ARM64_INS_B)
  {
    gum_arm64_writer_put_ldr_reg_address (ctx->output, ARM64_REG_X16,
        target->imm);
    gum_arm64_writer_put_br_reg (ctx->output, ARM64_REG_X16);
  }
  else
  {
    gum_arm64_writer_put_ldr_reg_address (ctx->output, ARM64_REG_LR,
        target->imm);
    gum_arm64_writer_put_blr_reg (ctx->output, ARM64_REG_LR);
  }

  return TRUE;
}

static gboolean
gum_arm64_relocator_rewrite_conditional_branch (GumArm64Relocator * self,
                                                GumCodeGenCtx * ctx)
{
  const cs_arm64_op * target = &ctx->detail->operands[0];

  (void) self;

  /* Rewrite to b.cond/cbz going 3 instructions ahead */
  gum_arm64_writer_put_instruction (ctx->output,
      (ctx->raw_insn & 0xff00001f) | (3 << 5));

  /* If false */
  gum_arm64_writer_put_ldr_reg_address (ctx->output, ARM64_REG_X16,
      GUM_ADDRESS (ctx->output->code + 4));
  gum_arm64_writer_put_br_reg (ctx->output, ARM64_REG_X16);

  /* If true */
  gum_arm64_writer_put_ldr_reg_address (ctx->output, ARM64_REG_X16,
      target->imm);
  gum_arm64_writer_put_br_reg (ctx->output, ARM64_REG_X16);

  return TRUE;
}
