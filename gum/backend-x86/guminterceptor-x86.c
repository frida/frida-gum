/*
 * Copyright (C) 2008 Ole André Vadla Ravnås <ole.andre.ravnas@tandberg.com>
 * Copyright (C) 2008 Christian Berentsen <christian.berentsen@tandberg.com>
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

#include "guminterceptor-priv.h"

#include <udis86.h>

static gboolean is_relocatable_instruction (enum ud_mnemonic_code insn);
static guint disassemble_instruction_at (gpointer address, ud_t * ud_obj);

guint
_gum_interceptor_find_displacement_size (gpointer function_address,
                                         guint bytes_needed)
{
  guint displacement_size = 0;
  guint8 * address = function_address;

  do
  {
    ud_t ud_obj;
    guint insn_size;

    insn_size = disassemble_instruction_at (address, &ud_obj);
    if (!is_relocatable_instruction (ud_obj.mnemonic))
    {
      displacement_size = 0;
      break;
    }

    address += insn_size;
    displacement_size += insn_size;
  }
  while (displacement_size < bytes_needed);

  return displacement_size;
}

static const enum ud_mnemonic_code jump_codes[] =
{
  UD_Icall,
  UD_Ija,
  UD_Ijae,
  UD_Ijb,
  UD_Ijbe,
  UD_Ijcxz,
  UD_Ijecxz,
  UD_Ijg,
  UD_Ijge,
  UD_Ijl,
  UD_Ijle,
  UD_Ijmp,
  UD_Ijnp,
  UD_Ijns,
  UD_Ijnz,
  UD_Ijo,
  UD_Ijp,
  UD_Ijrcxz,
  UD_Ijs,
  UD_Ijz,
  UD_Iret,
  UD_Iretf
};

static gboolean
is_relocatable_instruction (enum ud_mnemonic_code insn)
{
  guint i;

  for (i = 0; i < G_N_ELEMENTS (jump_codes); i++)
  {
    if (insn == jump_codes[i])
      return FALSE;
  }

  return TRUE;
}

static guint
disassemble_instruction_at (gpointer address,
                            ud_t * ud_obj)
{
  guint insn_size;

  ud_init (ud_obj);
  ud_set_mode (ud_obj, GUM_CPU_MODE);

  ud_set_input_buffer (ud_obj, address, 16);

  insn_size = ud_disassemble (ud_obj);
  g_assert (insn_size != 0);

  return insn_size;
}
