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
static gboolean gum_arm_relocator_rewrite_mov (GumArmRelocator * self,
    GumCodeGenCtx * ctx);

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
    case ARM_INS_MOV:
      rewritten = gum_arm_relocator_rewrite_mov (self, &ctx);
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
  gconstpointer load_label;
  arm_reg target;

  if (src->type != ARM_OP_MEM || src->mem.base != ARM_REG_PC)
    return FALSE;

  /*
   * If the instruction has writeback, then this means it has pre or post
   * incrementing. Given that these are typically only found as return
   * instructions, and stalker will be replacing return instructions with calls
   * back into the engine, we should not need to relocate them. Note that unlike
   * for call instructions, we don't need to worry about excluded ranges as
   * these are checked on entry rather than exit from the range. In the very
   * unlikely event we do encounter such an instruction, we will instead emit a
   * breakpoint and a warning message to the user to given them a chance to
   * debug it.
   */
  if (ctx->detail->writeback == 1)
  {
    g_warning ("relocation of ldr with pre/post-index not supported");
    gum_arm_writer_put_breakpoint (ctx->output);
    return TRUE;
  }

  /*
   * If our destination register is PC, then we cannot use it to store any
   * intermediate results. Given the load store architecture of ARM, we cannot
   * perform any operations on data in memory directly and therefore we will
   * need to use another register as scratch space. We will push and pop this
   * register onto the stack.
   *
   * However, we will need to restore the value of our scratch register prior to
   * loading the correct new value into PC. The LDMDB instruction is unsuitable
   * for this since we need to push the scratch register first and then the new
   * PC, but this instruction loads the registers in the opposite order.
   *
   * To avoid clumsy asymmetric use of the stack, we instead use labels within
   * our code stream to read and write our values there. This of course will
   * only work on systems which support RWX pages, but if a system has the
   * legacy of using AARCH32 instead of AARCH64 then it likely will not have
   * these newer protections.
   */
  if (dst->reg == ARM_REG_PC)
  {
    if (gum_query_rwx_support () == GUM_RWX_NONE)
    {
      g_error ("RWX Unsupportd");
    }

    if (src->mem.index == ARM_REG_INVALID)
    {
      /* If Rm is an immediate, we choose an arbitrary register */
      target = ARM_REG_R0;
    }
    else
    {
      /*
      * When choosing a scratch register, we favour Rm since it is often this
      * value we wish to use to start our calculation and this avoids a register
      * move.
      */
      target = src->mem.index;
    }
    gum_arm_writer_put_push_registers (ctx->output, 1, target);
  }
  else
  {
    /*
     * If our target register is not PC, then we can carry out our calculations
     * using Rd to store the intermediate result as we go.
     */
    target = dst->reg;
  }

  /* Handle 'ldr Rt, [Rn, #x]' or 'ldr Rt, [Rn, #-x]' */
  if (src->mem.index == ARM_REG_INVALID)
  {
    gint disp = src->mem.disp;

    gum_arm_writer_put_ldr_reg_address (ctx->output, target, ctx->pc);

    if (disp < 0)
    {
      gum_arm_writer_put_sub_reg_u16 (ctx->output, target, (-disp));
    }
    else
    {
      gum_arm_writer_put_add_reg_u16 (ctx->output, target, disp);
    }
  }
  else
  {
    /* Reject 'ldr Rt, [Rn, -Rm, #x]' */
    if (src->subtracted)
    {
      g_warning ("relocation of ldr with subtracted register offset "
          "not supported");
      gum_arm_writer_put_breakpoint (ctx->output);
    }

    /* Handle 'ldr Rt, [Rn, Rm, lsl #x]' */
    gum_arm_writer_put_mov_reg_reg_sft (ctx->output, target, src->mem.index, \
        src->shift.type, src->shift.value);

    gum_arm_writer_put_add_reg_u32 (ctx->output, target, ctx->pc);

  }

  gum_arm_writer_put_ldr_reg_reg_offset (ctx->output, target, target,
      GUM_INDEX_POS, 0);

  if (dst->reg == ARM_REG_PC)
  {
    /*
     * If we made use of a scratch register, store the result into the code
     * stream at the given label, then pop to restore the scratch register.
     * Finally, we can load the calculated value back into the output register.
     */
    load_label = ctx->output + 1;

    gum_arm_writer_put_strcc_reg_label (ctx->output, ARM_CC_AL, target,
        load_label);

    gum_arm_writer_put_pop_registers (ctx->output, 1, target);

    gum_arm_writer_put_ldrcc_reg_label (ctx->output, ARM_CC_AL, ARM_REG_PC,
        load_label);

    /*
     * Since we only use a scratch register if our target register is PC, then
     * we know that the preceeding load should have caused a branch and we
     * therefore shouldn't reach the following. We therefore insert a break
     * instruction just in case to alert the user in the event of an error.
     */
    gum_arm_writer_put_brk_imm (ctx->output, 0x18);
    gum_arm_writer_put_label (ctx->output, load_label);
    gum_arm_writer_put_instruction (ctx->output, 0xdeadface);
  }

  return TRUE;
}

static gboolean
gum_arm_relocator_rewrite_add (GumArmRelocator * self,
                               GumCodeGenCtx * ctx)
{
  const cs_arm_op * dst = &ctx->detail->operands[0];
  const cs_arm_op * left = &ctx->detail->operands[1];
  const cs_arm_op * right = &ctx->detail->operands[2];
  gconstpointer load_label;
  arm_reg target;

  if (left->reg != ARM_REG_PC)
    return FALSE;

  /*
   * If our destination register is PC, then we cannot use it to store any
   * intermediate results. Given the load store architecture of ARM, we cannot
   * perform any operations on data in memory directly and therefore we will
   * need to use another register as scratch space. We will push and pop this
   * register onto the stack.
   *
   * However, we will need to restore the value of our scratch register prior to
   * loading the correct new value into PC. The LDMDB instruction is unsuitable
   * for this since we need to push the scratch register first and then the new
   * PC, but this instruction loads the registers in the opposite order.
   *
   * To avoid clumsy asymmetric use of the stack, we instead use labels within
   * our code stream to read and write our values there. This of course will
   * only work on systems which support RWX pages, but if a system has the
   * legacy of using AARCH32 instead of AARCH64 then it likely will not have
   * these newer protections.
   */
  if (dst->reg == ARM_REG_PC)
  {
    if (gum_query_rwx_support () == GUM_RWX_NONE)
    {
      g_error ("RWX Unsupportd");
    }

    if (right->type == ARM_OP_IMM)
    {
      /* If Rm is an immediate, we choose an arbitrary register */
      target = ARM_REG_R0;
    }
    else
    {
      /*
      * When choosing a scratch register, we favour Rm since it is often this
      * value we wish to use to start our calculation and this avoids a register
      * move.
      */
      target = right->reg;
    }
    gum_arm_writer_put_push_registers (ctx->output, 1, target);
  }
  else
  {
    /*
     * If our target register is not PC, then we can carry out our calculations
     * using Rd to store the intermediate result as we go.
     */
    target = dst->reg;
  }

  /*
   * If we have no shift to apply, then we start our calculation with the value
   * of PC since we can store this as a literal in the code stream and reduce
   * the number of instructions we need to generate.
   */
  if (right->shift.value == 0)
  {
    /* Handle 'add Rd, Rn , #x' */
    if (right->type == ARM_OP_IMM)
    {
      gum_arm_writer_put_ldr_reg_address (ctx->output, target, ctx->pc);
      gum_arm_writer_put_add_reg_u32 (ctx->output, target, right->imm);
    }
    else if (right->reg == dst->reg)
    {
      /*
       * Handle 'add Rd, Rn, Rd'. This is a special case since we cannot load PC
       * from a literal into Rd since in doing so, we lose the value of Rm which
       * we want to add on. This calculation can be simplified to just adding
       * the PC to Rd.
       */
      gum_arm_writer_put_add_reg_u32 (ctx->output, target, ctx->pc);
    }
    else
    {
      /* Handle 'add Rd, Rn, Rm' */
      gum_arm_writer_put_ldr_reg_address (ctx->output, target, ctx->pc);
      gum_arm_writer_put_add_reg_reg_imm (ctx->output, target, right->reg, 0);
    }
  }
  else
  {
    /*
     * If we have a shift operation to apply, then we must start by calculating
     * this value and adding on PC, as we would otherwise need a second scratch
     * register to calculate this. Note that in this case, we don't have to
     * worry if Rd == Rm since although we may be using Rd to hold the
     * intermediate result, we perform all necessary calculations on Rm before
     * we update Rd.
     */

    /* Handle 'add Rd, Rn, #x, lsl #n' */
    if (right->type == ARM_OP_IMM)
    {
      gum_arm_writer_put_ldr_reg_u32 (ctx->output, target, right->imm);
    }
    else
    {
      /* Handle 'add Rd, Rn, Rm, lsl #n' */
      gum_arm_writer_put_mov_reg_reg (ctx->output, target, right->reg);
    }

    gum_arm_writer_put_mov_reg_reg_sft (ctx->output, target, target,
        right->shift.type, right->shift.value);

    /*
     * Now the shifted second operand has been calculated, we can simply add the
     * PC value.
    */
    gum_arm_writer_put_add_reg_u32 (ctx->output, target, ctx->pc);
  }

  if (dst->reg == ARM_REG_PC)
  {
    /*
     * If we made use of a scratch register, store the result into the code
     * stream at the given label, then pop to restore the scratch register.
     * Finally, we can load the calculated value back into the output register.
     */
    load_label = ctx->output + 1;

    gum_arm_writer_put_strcc_reg_label (ctx->output, ARM_CC_AL, target,
        load_label);

    gum_arm_writer_put_pop_registers (ctx->output, 1, target);

    gum_arm_writer_put_ldrcc_reg_label (ctx->output, ARM_CC_AL, ARM_REG_PC,
        load_label);

    /*
     * Since we only use a scratch register if our target register is PC, then
     * we know that the preceeding load should have caused a branch and we
     * therefore shouldn't reach the following. We therefore insert a break
     * instruction just in case to alert the user in the event of an error.
     */
    gum_arm_writer_put_brk_imm (ctx->output, 0x18);
    gum_arm_writer_put_label (ctx->output, load_label);
    gum_arm_writer_put_instruction (ctx->output, 0xdeadface);
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

static gboolean
gum_arm_relocator_rewrite_mov (GumArmRelocator * self,
                               GumCodeGenCtx * ctx)
{
  const cs_arm_op * dst = &ctx->detail->operands[0];
  const cs_arm_op * src = &ctx->detail->operands[1];

  if (src->type != ARM_OP_REG)
    return FALSE;

  if (src->reg != ARM_REG_PC)
    return FALSE;

  gum_arm_writer_put_ldr_reg_address (ctx->output, dst->reg, ctx->pc);
  return TRUE;
}
