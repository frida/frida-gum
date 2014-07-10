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

  GumArmWriter * output;
};

static gboolean gum_arm_relocator_rewrite_branch_imm (GumArmRelocator * self,
    GumCodeGenCtx * ctx);

void
gum_arm_relocator_init (GumArmRelocator * relocator,
                        gconstpointer input_code,
                        GumArmWriter * output)
{
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
  guint32 raw_insn;
  guint category;
  GumArmInstruction * insn;

  if (self->eoi)
    return 0;

  raw_insn = GUINT32_FROM_LE (*((guint32 *) self->input_cur));
  insn = &self->input_insns[gum_arm_relocator_inpos (self)];

  category = (raw_insn >> 25) & 7;

  insn->mnemonic = GUM_ARM_UNKNOWN;
  insn->address = self->input_cur;
  insn->length = 4;
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
      break;
    }

    case 2: /* load/store */
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
  gboolean rewritten = FALSE;

  if ((ctx.insn = gum_arm_relocator_peek_next_write_insn (self)) == NULL)
    return FALSE;
  gum_arm_relocator_increment_outpos (self);

  ctx.raw_insn = GUINT32_FROM_LE (*((guint32 *) ctx.insn->address));

  ctx.output = self->output;

  switch (ctx.insn->mnemonic)
  {
    case GUM_ARM_B_IMM_A1:
    case GUM_ARM_BL_IMM_A1:
    case GUM_ARM_BLX_IMM_A2:
      rewritten = gum_arm_relocator_rewrite_branch_imm (self, &ctx);
      break;

    default:
      break;
  }

  if (!rewritten)
    gum_arm_writer_put_bytes (ctx.output, ctx.insn->address, ctx.insn->length);

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
