/*
 * Copyright (C) 2015-2019 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumarm64reader.h"

#include <capstone.h>

static cs_insn * disassemble_instruction_at (gconstpointer address);

gpointer
gum_arm64_reader_try_get_relative_jump_target (gconstpointer address)
{
  gpointer result = NULL;
  cs_insn * insn;
  cs_arm64_op * op;

  insn = disassemble_instruction_at (address);
  if (insn == NULL)
    return NULL;

  op = &insn->detail->arm64.operands[0];
  if (insn->id == ARM64_INS_B && op->type == ARM64_OP_IMM)
    result = GSIZE_TO_POINTER (op->imm);

  cs_free (insn, 1);

  return result;
}

static cs_insn *
disassemble_instruction_at (gconstpointer address)
{
  csh capstone;
  cs_insn * insn = NULL;

  cs_open (CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN, &capstone);
  cs_option (capstone, CS_OPT_DETAIL, CS_OPT_ON);

  cs_disasm (capstone, address, 16, GPOINTER_TO_SIZE (address), 1, &insn);

  cs_close (&capstone);

  return insn;
}
