/*
 * Copyright (C) 2009 Ole André Vadla Ravnås <ole.andre.ravnas@tandberg.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU Library General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 02111-1307, USA.
 */

#include "gumcodereader.h"

#include <udis86.h>

static gpointer try_get_relative_call_or_jump_target (gconstpointer address,
    enum ud_mnemonic_code call_or_jump);
static guint disassemble_instruction_at (gconstpointer address, ud_t * ud_obj);

gpointer
gum_code_reader_try_get_relative_call_target (gconstpointer address)
{
  return try_get_relative_call_or_jump_target (address, UD_Icall);
}

gpointer
gum_code_reader_try_get_relative_jump_target (gconstpointer address)
{
  return try_get_relative_call_or_jump_target (address, UD_Ijmp);
}

gpointer
gum_code_reader_try_get_indirect_jump_target (gconstpointer address)
{
  ud_t ud_obj;
  guint insn_size;
  ud_operand_t * op;

  insn_size = disassemble_instruction_at (address, &ud_obj);
  op = &ud_obj.operand[0];
  if (ud_obj.mnemonic != UD_Ijmp || ud_obj.operand[0].type != UD_OP_MEM)
    return NULL;

  if (op->base == UD_R_RIP && op->index == UD_NONE)
    return *((gpointer *) ((guint8 *) address + insn_size + op->lval.sdword));
  else if (op->base == UD_NONE && op->index == UD_NONE)
    return *((gpointer *) GSIZE_TO_POINTER (ud_obj.operand[0].lval.udword));
  else
    return NULL;
}

static gpointer
try_get_relative_call_or_jump_target (gconstpointer address,
                                      enum ud_mnemonic_code call_or_jump)
{
  ud_t ud_obj;
  guint insn_size;

  insn_size = disassemble_instruction_at (address, &ud_obj);
  if (ud_obj.mnemonic != call_or_jump || ud_obj.operand[0].type != UD_OP_JIMM)
    return NULL;

  return ((guint8 *) address) + insn_size + ud_obj.operand[0].lval.sdword;
}

static guint
disassemble_instruction_at (gconstpointer address,
                            ud_t * ud_obj)
{
  guint insn_size;

  ud_init (ud_obj);
  ud_set_mode (ud_obj, GUM_CPU_MODE);

  ud_set_input_buffer (ud_obj, (gpointer) address, 16);

  insn_size = ud_disassemble (ud_obj);
  g_assert (insn_size != 0);

  return insn_size;
}

