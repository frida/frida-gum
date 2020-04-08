/*
 * Copyright (C) 2010-2019 Ole André Vadla Ravnås <oleavr@nowsecure.com>
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

static gboolean gum_arm_relocator_reg_dest_is_pc (const cs_insn * insn);

static gboolean gum_arm_relocator_reg_list_contains_pc (const cs_insn * insn,
    guint8 start_idx);

static gboolean gum_arm_relocator_rewrite_ldr (GumArmRelocator * self,
    GumCodeGenCtx * ctx);
static gboolean gum_arm_relocator_rewrite_add (GumArmRelocator * self,
    GumCodeGenCtx * ctx);
static gboolean gum_arm_relocator_rewrite_b (GumArmRelocator * self,
    cs_mode target_mode, GumCodeGenCtx * ctx);
static gboolean gum_arm_relocator_rewrite_bl (GumArmRelocator * self,
    cs_mode target_mode, GumCodeGenCtx * ctx);

GumArmRelocator *
gum_arm_relocator_new (gconstpointer input_code,
                       GumArmWriter * output)
{
  GumArmRelocator * relocator;

  relocator = g_slice_new (GumArmRelocator);

  gum_arm_relocator_init (relocator, input_code, output);

  return relocator;
}

GumArmRelocator *
gum_arm_relocator_ref (GumArmRelocator * relocator)
{
  g_atomic_int_inc (&relocator->ref_count);

  return relocator;
}

void
gum_arm_relocator_unref (GumArmRelocator * relocator)
{
  if (g_atomic_int_dec_and_test (&relocator->ref_count))
  {
    gum_arm_relocator_clear (relocator);

    g_slice_free (GumArmRelocator, relocator);
  }
}

void
gum_arm_relocator_init (GumArmRelocator * relocator,
                        gconstpointer input_code,
                        GumArmWriter * output)
{
  relocator->ref_count = 1;

  cs_open (CS_ARCH_ARM, CS_MODE_ARM, &relocator->capstone);
  cs_option (relocator->capstone, CS_OPT_DETAIL, CS_OPT_ON);
  relocator->input_insns = g_new0 (cs_insn *, GUM_MAX_INPUT_INSN_COUNT);

  relocator->output = NULL;

  gum_arm_relocator_reset (relocator, input_code, output);
}

void
gum_arm_relocator_clear (GumArmRelocator * relocator)
{
  guint i;

  gum_arm_relocator_reset (relocator, NULL, NULL);

  for (i = 0; i != GUM_MAX_INPUT_INSN_COUNT; i++)
  {
    cs_insn * insn = relocator->input_insns[i];
    if (insn != NULL)
    {
      cs_free (insn, 1);
      relocator->input_insns[i] = NULL;
    }
  }
  g_free (relocator->input_insns);

  cs_close (&relocator->capstone);
}

void
gum_arm_relocator_reset (GumArmRelocator * relocator,
                         gconstpointer input_code,
                         GumArmWriter * output)
{
  relocator->input_start = input_code;
  relocator->input_cur = input_code;
  relocator->input_pc = GUM_ADDRESS (input_code);

  if (output != NULL)
    gum_arm_writer_ref (output);
  if (relocator->output != NULL)
    gum_arm_writer_unref (relocator->output);
  relocator->output = output;

  relocator->inpos = 0;
  relocator->outpos = 0;

  relocator->eob = FALSE;
  relocator->eoi = FALSE;
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
  g_assert (self->inpos > self->outpos);
}

static void
gum_arm_relocator_increment_outpos (GumArmRelocator * self)
{
  self->outpos++;
  g_assert (self->outpos <= self->inpos);
}

guint
gum_arm_relocator_read_one (GumArmRelocator * self,
                            const cs_insn ** instruction)
{
  cs_insn ** insn_ptr, * insn;
  const uint8_t * code;
  size_t size;
  uint64_t address;

  if (self->eoi)
    return 0;

  insn_ptr = &self->input_insns[gum_arm_relocator_inpos (self)];

  if (*insn_ptr == NULL)
    *insn_ptr = cs_malloc (self->capstone);

  code = self->input_cur;
  size = 4;
  address = self->input_pc;
  insn = *insn_ptr;

  if (!cs_disasm_iter (self->capstone, &code, &size, &address, insn))
    return 0;

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
    case ARM_INS_MOV:
    case ARM_INS_LDR:
    case ARM_INS_SUB:
    case ARM_INS_ADD:
      self->eob = gum_arm_relocator_reg_dest_is_pc (insn);
      self->eoi = gum_arm_relocator_reg_dest_is_pc (insn);
      break;
    case ARM_INS_POP:
      self->eob = gum_arm_relocator_reg_list_contains_pc (insn, 0);
      self->eoi = gum_arm_relocator_reg_list_contains_pc (insn, 0);
      break;
    case ARM_INS_LDM:
      self->eob = gum_arm_relocator_reg_list_contains_pc (insn, 1);
      self->eoi = gum_arm_relocator_reg_list_contains_pc (insn, 1);
      break;
    default:
      self->eob = FALSE;
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
  gum_arm_relocator_peek_next_write_insn (self);
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

  g_assert (count > 0);
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

  gum_arm_relocator_clear (&rl);

  gum_arm_writer_clear (&cw);

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
    g_assert (reloc_bytes != 0);
  }
  while (reloc_bytes < min_bytes);

  gum_arm_relocator_write_all (&rl);

  gum_arm_relocator_clear (&rl);
  gum_arm_writer_clear (&cw);

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
gum_arm_relocator_reg_dest_is_pc (const cs_insn * insn)
{
  cs_arm_op * op = &insn->detail->arm.operands[0];
  g_assert (op->type == ARM_OP_REG);

  if (op->reg == ARM_REG_PC)
  {
    return TRUE;
  }

  return FALSE;
}

static gboolean
gum_arm_relocator_reg_list_contains_pc (const cs_insn * insn, guint8 start_idx)
{
  cs_arm_op * op;

  for (uint8_t idx = start_idx; idx < insn->detail->arm.op_count; idx++)
  {
    op = &insn->detail->arm.operands[idx];
    g_assert (op->type != ARM_OP_REG);
    if (op->reg == ARM_REG_PC)
    {
      return TRUE;
    }
  }
  return FALSE;
}

static gboolean
gum_arm_relocator_rewrite_ldr (GumArmRelocator * self,
                               GumCodeGenCtx * ctx)
{
  const cs_arm_op * dst = &ctx->detail->operands[0];
  const cs_arm_op * src = &ctx->detail->operands[1];

  if (src->type != ARM_OP_MEM || src->mem.base != ARM_REG_PC)
    return FALSE;

  /* Handle 'ldr Rt, [ Rn, #x ]' or  'ldr Rt, [ Rn, #-x ]'*/
  if (src->mem.index == ARM_REG_INVALID)
  {
    gint disp = src->mem.disp;

    gum_arm_writer_put_ldr_reg_address (ctx->output, dst->reg, ctx->pc);

    if (disp < 0)
    {
      gum_arm_writer_put_sub_reg_u16 (ctx->output, dst->reg, (-disp));

    }
    else
    {
      gum_arm_writer_put_add_reg_u16 (ctx->output, dst->reg, disp);
    }

    gum_arm_writer_put_ldr_reg_reg_offset (ctx->output, dst->reg, dst->reg,
        GUM_INDEX_POS, 0);

    return TRUE;
  }

  /* 'ldr Rt, [Rn, Rm, sft]' no supported */
  if (src->mem.lshift != 0)
  {
    g_error("ldr with shift not supported");
  }

  /*
  * Handle 'ldr Rt, [Rn, Rm]' or 'ldr Rt, [Rn, -Rm]'. Note that we know that Rn
  * must be PC since we otherwise would not need to relocate it (we test this
  * above). Given that this support is in aid of stalker and stalker replaces
  * all branch instructions, (those that modify PC) we also know that Rt must
  * not be PC. However, we cannot be sure that Rt and Rm are not the same
  * register. Since our target register is not PC, we can update it multiple
  * times without side-effects as we carry out the calculation.
  *
  * We start by loading +-Rm into Rt. If the instruction is to use positive Rm
  * and Rm == Rt, then the mov instruction is eventually omitted as a no-op. We
  * then add each byte of the PC to Rt (again any zero bytes are omitted as
  * being no-op). Finally, once the address of the expression [Rn, +-Rm] in Rt,
  * we dereference the address and load back into Rt. By performing the
  * operations in this order, we can avoid the need for an aditional scratch
  * register.
  */
  if (src->subtracted)
  {
    gum_arm_writer_put_rsbs_reg_reg(ctx->output, dst->reg, src->mem.index);
  }
  else
  {
    gum_arm_writer_put_mov_reg_reg(ctx->output, dst->reg, src->mem.index);
  }

  gum_arm_writer_put_add_reg_u32 (ctx->output, dst->reg, ctx->pc);
  gum_arm_writer_put_ldr_reg_reg_offset (ctx->output, dst->reg, dst->reg,
      GUM_INDEX_POS, 0);

  return TRUE;
}

static gboolean
gum_arm_relocator_rewrite_add (GumArmRelocator * self,
                               GumCodeGenCtx * ctx)
{
  const cs_arm_op * dst = &ctx->detail->operands[0];
  const cs_arm_op * left = &ctx->detail->operands[1];
  const cs_arm_op * right = &ctx->detail->operands[2];

  if (left->reg != ARM_REG_PC)
    return FALSE;

  /* Handle 'add Rd, Rn , #x' */
  if (right->type == ARM_OP_IMM)
  {
    gum_arm_writer_put_ldr_reg_address (ctx->output, dst->reg, ctx->pc);
    gum_arm_writer_put_add_reg_u32 (ctx->output, dst->reg, right->imm);
    return TRUE;
  }

  /* 'add Rd, [Rn, Rm, sft]' not supported. Generally speaking, stalker should
   * not output any add instructions where Rd == PC. The only exception is when
   * handling branches to excluded ranges where the destination cannot be
   * determined until runtime. In this case, the original instruction is emitted
   * so that it can be used to vector to the target if the target is determined
   * to be in an excluded range. These types of branch are quite uncommon, and
   * for one to target an excluded range hugely unlikely.
   *
   * Consider the following branch for example 'add pc, pc, r1, lsl #2' This
   * type of branch is complex to handle since we cannot use pc to store any
   * intermediate results (as doing so would result in an immediate branch
   * before the final result is calculated). We would therefore need to use a
   * scratch register, but we would need to restore this to its original value
   * (since the instruction only modifies Rd) prior to loading pc with the final
   * result. In short, whilst possible, this would be all kinds of ugly.
   *
   * Whilst we do encounter such branches on occasion, we need to handle this
   * scenario and generate some output. Equally, we know that the code generated
   * will never be executed unless the target ends up being an excluded range
   * (which is very unlikely). We will therefore emit a breakpoint instruction
   * so if someone does have the misfortune of encountering such an unlikely
   * scenario they at least have a chance to debug it.
   */
  if (right->shift.value != 0)
  {
    gum_arm_writer_put_breakpoint (ctx->output);
    return TRUE;
  }

  /* Handle 'add Rd, Rn, Rm' where Rd == Rm */
  if (right->reg == dst->reg)
  {
    gum_arm_writer_put_add_reg_u32 (ctx->output, dst->reg, ctx->pc);
    return TRUE;
  }

  /* Handle 'add Rd, Rn, Rm' where Rd != Rm */
  gum_arm_writer_put_ldr_reg_address (ctx->output, dst->reg, ctx->pc);
  gum_arm_writer_put_add_reg_reg_imm (ctx->output, dst->reg, right->reg, 0);

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
