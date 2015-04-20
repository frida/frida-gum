/*
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumarmreader.h"

static cs_insn * disassemble_instruction_at (gconstpointer address);

gpointer
gum_arm_reader_try_get_relative_jump_target (gconstpointer address)
{
  gpointer result = NULL;
  cs_insn * insn;
  cs_arm_op * op;

  insn = disassemble_instruction_at (address);

  op = &insn->detail->arm.operands[0];
  if (insn->id == ARM_INS_B && op->type == ARM_OP_IMM)
    result = GSIZE_TO_POINTER (op->imm);

  cs_free (insn, 1);

  return result;
}

static cs_insn *
disassemble_instruction_at (gconstpointer address)
{
  csh capstone;
  cs_err err;
  cs_insn * insn = NULL;

  err = cs_open (CS_ARCH_ARM, CS_MODE_ARM, &capstone);
  g_assert_cmpint (err, ==, CS_ERR_OK);
  err = cs_option (capstone, CS_OPT_DETAIL, CS_OPT_ON);
  g_assert_cmpint (err, ==, CS_ERR_OK);

  cs_disasm (capstone, address, 4, GPOINTER_TO_SIZE (address), 1, &insn);
  g_assert (insn != NULL);

  cs_close (&capstone);

  return insn;
}
