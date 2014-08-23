/*
 * Copyright (C) 2009-2014 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumx86reader.h"

static gpointer try_get_relative_call_or_jump_target (gconstpointer address,
    guint call_or_jump);
static cs_insn * disassemble_instruction_at (gconstpointer address);

guint
gum_x86_reader_insn_length (guint8 * code)
{
  guint result;
  cs_insn * insn;

  insn = disassemble_instruction_at (code);
  result = insn->size;
  cs_free (insn, 1);

  return result;
}

gboolean
gum_x86_reader_insn_is_jcc (cs_insn * insn)
{
  switch (insn->id)
  {
    case X86_INS_JA:
    case X86_INS_JAE:
    case X86_INS_JB:
    case X86_INS_JBE:
    case X86_INS_JE:
    case X86_INS_JG:
    case X86_INS_JGE:
    case X86_INS_JL:
    case X86_INS_JLE:
    case X86_INS_JNE:
    case X86_INS_JNO:
    case X86_INS_JNP:
    case X86_INS_JNS:
    case X86_INS_JO:
    case X86_INS_JP:
    case X86_INS_JS:
      return TRUE;

    default:
      break;
  }

  return FALSE;
}

guint8
gum_x86_reader_jcc_insn_to_short_opcode (guint8 * code)
{
  if (*code == 0x3e || *code == 0x2e)
    code++; /* skip hint */
  if (code[0] == 0x0f)
    return code[1] - 0x10;
  else
    return code[0];
}

guint8
gum_x86_reader_jcc_opcode_negate (guint8 opcode)
{
  if (opcode % 2 == 0)
    return opcode + 1;
  else
    return opcode - 1;
}

gpointer
gum_x86_reader_try_get_relative_call_target (gconstpointer address)
{
  return try_get_relative_call_or_jump_target (address, X86_INS_CALL);
}

gpointer
gum_x86_reader_try_get_relative_jump_target (gconstpointer address)
{
  return try_get_relative_call_or_jump_target (address, X86_INS_JMP);
}

gpointer
gum_x86_reader_try_get_indirect_jump_target (gconstpointer address)
{
  gpointer result = NULL;
  cs_insn * insn;
  cs_x86_op * op;

  insn = disassemble_instruction_at (address);

  op = &insn->detail->x86.operands[0];
  if (insn->id == X86_INS_JMP && op->type == X86_OP_MEM)
  {
    if (op->mem.base == X86_REG_RIP && op->mem.index == X86_REG_INVALID)
    {
      result = *((gpointer *) ((guint8 *) address + insn->size + op->mem.disp));
    }
    else if (op->mem.base == X86_REG_INVALID &&
        op->mem.index == X86_REG_INVALID)
    {
      result = *((gpointer *) GSIZE_TO_POINTER (op->mem.disp));
    }
  }

  cs_free (insn, 1);

  return result;
}

static gpointer
try_get_relative_call_or_jump_target (gconstpointer address,
                                      guint call_or_jump)
{
  gpointer result = NULL;
  cs_insn * insn;
  cs_x86_op * op;

  insn = disassemble_instruction_at (address);

  op = &insn->detail->x86.operands[0];
  if (insn->id == call_or_jump && op->type == X86_OP_IMM)
    result = GSIZE_TO_POINTER (op->imm);

  cs_free (insn, 1);

  return result;
}

static cs_insn *
disassemble_instruction_at (gconstpointer address)
{
  csh capstone;
  cs_err err;
  cs_insn * insn;

  err = cs_open (CS_ARCH_X86, GUM_CPU_MODE, &capstone);
  g_assert_cmpint (err, ==, CS_ERR_OK);
  err = cs_option (capstone, CS_OPT_DETAIL, CS_OPT_ON);
  g_assert_cmpint (err, ==, CS_ERR_OK);

  cs_disasm_ex (capstone, address, 16, GPOINTER_TO_SIZE (address), 1, &insn);
  g_assert (insn != NULL);

  cs_close (&capstone);

  return insn;
}

