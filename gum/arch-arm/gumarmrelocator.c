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
  const GumArmInstruction * insn;
  guint32 raw_insn;
  cs_insn * capstone_insn;

  GumArmWriter * output;
};

static gboolean gum_arm_relocator_rewrite_branch_imm (GumArmRelocator * self,
    GumCodeGenCtx * ctx);
static gboolean gum_arm_relocator_rewrite_pc_relative_ldr (
    GumArmRelocator * self, GumCodeGenCtx * ctx);
static gboolean gum_arm_relocator_rewrite_pc_relative_add (
    GumArmRelocator * self, GumCodeGenCtx * ctx);

static gint gum_capstone_reg_to_arm_reg (gint cs_reg);

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

  relocator->input_insns = gum_new (GumArmInstruction,
      GUM_MAX_INPUT_INSN_COUNT);

  gum_arm_relocator_reset (relocator, input_code, output);
}

void
gum_arm_relocator_reset (GumArmRelocator * relocator,
                         gconstpointer input_code,
                         GumArmWriter * output)
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
gum_arm_relocator_free (GumArmRelocator * relocator)
{
  gum_free (relocator->input_insns);

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
                            const GumArmInstruction ** instruction)
{
  cs_insn * ci = NULL;
  guint32 raw_insn;
  guint category;
  GumArmInstruction * insn;

  if (self->eoi)
    return 0;

  if (cs_disasm (self->capstone, self->input_cur, 4, self->input_pc, 1,
      &ci) != 1)
  {
    return 0;
  }
  g_assert (ci != NULL);

  raw_insn = GUINT32_FROM_LE (*((guint32 *) self->input_cur));
  insn = &self->input_insns[gum_arm_relocator_inpos (self)];

  category = (raw_insn >> 25) & 7;

  insn->mnemonic = GUM_ARM_UNKNOWN;
  insn->address = self->input_cur;
  insn->length = ci->size;
  insn->pc = self->input_pc + 8;

  switch (category)
  {
    case 0: /* data processing */
    case 1:
    {
      guint opcode = (raw_insn >> 21) & 0xf;
      switch (opcode)
      {
        case 0xd:
          insn->mnemonic = GUM_ARM_MOV;
          break;
      }

      if (ci->id == ARM_INS_ADD &&
          ci->detail->arm.operands[1].type == ARM_OP_REG &&
          ci->detail->arm.operands[1].imm == ARM_REG_PC)
      {
        insn->mnemonic = GUM_ARM_ADDPC;
      }
      break;
    }

    case 2: /* load/store */
      if (ci->id == ARM_INS_LDR)
        insn->mnemonic = GUM_ARM_LDR;
      break;

    case 4: /* load/store multiple */
    {
      guint base_register = (raw_insn >> 16) & 0xf;
      guint is_load = (raw_insn >> 20) & 1;
      if (base_register == GUM_AREG_SP)
        insn->mnemonic = is_load ? GUM_ARM_POP : GUM_ARM_PUSH;
      break;
    }

    case 5: /* control */
      if (((raw_insn >> 28) & 0xf) == 0xf)
      {
        insn->mnemonic = GUM_ARM_BLX_IMM_A2;
      }
      else
      {
        insn->mnemonic = ((raw_insn & 0x1000000) == 0) ?
            GUM_ARM_B_IMM_A1 : GUM_ARM_BL_IMM_A1;
      }
      break;
  }

  gum_arm_relocator_increment_inpos (self);

  if (instruction != NULL)
    *instruction = insn;

  self->input_cur += insn->length;
  self->input_pc += insn->length;

  cs_free (ci, 1);

  return self->input_cur - self->input_start;
}

GumArmInstruction *
gum_arm_relocator_peek_next_write_insn (GumArmRelocator * self)
{
  if (self->outpos == self->inpos)
    return NULL;

  return &self->input_insns[gum_arm_relocator_outpos (self)];
}

gpointer
gum_arm_relocator_peek_next_write_source (GumArmRelocator * self)
{
  GumArmInstruction * next;

  next = gum_arm_relocator_peek_next_write_insn (self);
  if (next == NULL)
    return NULL;

  /* FIXME */
  g_assert_not_reached ();
  return NULL;
}

void
gum_arm_relocator_skip_one (GumArmRelocator * self)
{
  GumArmInstruction * next;

  next = gum_arm_relocator_peek_next_write_insn (self);
  g_assert (next != NULL);
  gum_arm_relocator_increment_outpos (self);
}

gboolean
gum_arm_relocator_write_one (GumArmRelocator * self)
{
  GumCodeGenCtx ctx;
  cs_insn * ci;
  gboolean rewritten = FALSE;

  if ((ctx.insn = gum_arm_relocator_peek_next_write_insn (self)) == NULL)
    return FALSE;
  gum_arm_relocator_increment_outpos (self);

  if (cs_disasm (self->capstone, ctx.insn->address, 4,
      GPOINTER_TO_SIZE (ctx.insn->address), 1, &ci) != 1)
  {
    return 0;
  }
  g_assert (ci != NULL);

  ctx.raw_insn = GUINT32_FROM_LE (*((guint32 *) ctx.insn->address));
  ctx.capstone_insn = ci;

  ctx.output = self->output;

  switch (ctx.insn->mnemonic)
  {
    case GUM_ARM_B_IMM_A1:
    case GUM_ARM_BL_IMM_A1:
    case GUM_ARM_BLX_IMM_A2:
      rewritten = gum_arm_relocator_rewrite_branch_imm (self, &ctx);
      break;

    case GUM_ARM_LDR:
      rewritten = gum_arm_relocator_rewrite_pc_relative_ldr (self, &ctx);
      break;

    case GUM_ARM_ADDPC:
      rewritten = gum_arm_relocator_rewrite_pc_relative_add (self, &ctx);
    default:
      break;
  }

  if (!rewritten)
    gum_arm_writer_put_bytes (ctx.output, ctx.insn->address, ctx.insn->length);

  cs_free (ci, 1);

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
                                guint min_bytes)
{
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
      return FALSE;
  }
  while (reloc_bytes < min_bytes);

  gum_arm_relocator_free (&rl);

  gum_arm_writer_free (&cw);

  return TRUE;
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
gum_arm_relocator_rewrite_branch_imm (GumArmRelocator * self,
                                      GumCodeGenCtx * ctx)
{
  union
  {
    gint32 i;
    guint32 u;
  } distance;
  GumAddress absolute_target;

  (void) self;

  if ((ctx->raw_insn & 0x00800000) != 0)
    distance.u = 0xfc000000 | ((ctx->raw_insn & 0x00ffffff) << 2);
  else
    distance.u = ((ctx->raw_insn & 0x007fffff) << 2);

  if (ctx->insn->mnemonic == GUM_ARM_BLX_IMM_A2 &&
      (ctx->raw_insn & 0x01000000) != 0)
  {
    distance.u |= 2;
  }

  absolute_target = ctx->insn->pc + distance.i;
  if (ctx->insn->mnemonic == GUM_ARM_BLX_IMM_A2)
    absolute_target |= 1;

  switch (ctx->insn->mnemonic)
  {
    case GUM_ARM_BL_IMM_A1:
    case GUM_ARM_BLX_IMM_A2:
      gum_arm_writer_put_ldr_reg_address (ctx->output, GUM_AREG_LR,
          ctx->output->pc + 4 + 4);
      break;

    default:
      break;
  }

  gum_arm_writer_put_ldr_reg_address (ctx->output, GUM_AREG_PC,
      absolute_target);

  return TRUE;
}

static gboolean
gum_arm_relocator_rewrite_pc_relative_ldr (GumArmRelocator * self,
                                           GumCodeGenCtx * ctx)
{
  cs_insn * ci = ctx->capstone_insn;
  gint dest_reg, base_reg, disp;

  dest_reg = gum_capstone_reg_to_arm_reg (ci->detail->arm.operands[0].reg);
  base_reg = ci->detail->arm.operands[1].mem.base;
  disp = ci->detail->arm.operands[1].mem.disp;

  if (base_reg != ARM_REG_PC)
    return FALSE;

  gum_arm_writer_put_ldr_reg_address (ctx->output, dest_reg, ctx->insn->pc);
  if (disp > 0xff)
  {
    gum_arm_writer_put_add_reg_reg_imm (ctx->output, dest_reg, dest_reg,
        0xc00 | ((disp >> 8) & 0xff));
  }
  gum_arm_writer_put_add_reg_reg_imm (ctx->output, dest_reg, dest_reg,
      disp & 0xff);
  gum_arm_writer_put_ldr_reg_reg_imm (ctx->output, dest_reg, dest_reg, 0);

  return TRUE;
}

static gboolean
gum_arm_relocator_rewrite_pc_relative_add (GumArmRelocator * self,
                                           GumCodeGenCtx * ctx)
{
  cs_insn * ci = ctx->capstone_insn;
  gint dest_reg, src_reg, val;

  dest_reg = gum_capstone_reg_to_arm_reg (ci->detail->arm.operands[0].reg);
  src_reg = gum_capstone_reg_to_arm_reg (ci->detail->arm.operands[2].reg);

  val = ctx->insn->pc;

  if (dest_reg == src_reg)
  {
    gum_arm_writer_put_add_reg_reg_imm (ctx->output, dest_reg, dest_reg,
        val & 0xff);
    gum_arm_writer_put_add_reg_reg_imm (ctx->output, dest_reg, dest_reg,
        0xc00 | ((val >> 8) & 0xff));
    gum_arm_writer_put_add_reg_reg_imm (ctx->output, dest_reg, dest_reg,
        0x800 | ((val >> 16) & 0xff));
    gum_arm_writer_put_add_reg_reg_imm (ctx->output, dest_reg, dest_reg,
        0x400 | ((val >> 24) & 0xff));
  }
  else
  {
    gum_arm_writer_put_ldr_reg_address (ctx->output, dest_reg, val);
    gum_arm_writer_put_add_reg_reg_imm (ctx->output, dest_reg, src_reg, 0);
  }

  return TRUE;
}

static gint
gum_capstone_reg_to_arm_reg (gint cs_reg)
{
  return cs_reg - ARM_REG_R0;
}
