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

#ifndef __GUM_UDIS86_H__
#define __GUM_UDIS86_H__

#include "gumdefs.h"
#include <udis86.h>

G_BEGIN_DECLS

guint gum_find_instruction_length (guint8 * code);
gboolean gum_mnemonic_is_jcc (ud_mnemonic_code_t mnemonic);
guint8 gum_jcc_insn_to_short_opcode (guint8 * code);
guint8 gum_jcc_insn_to_near_opcode (guint8 * code);
guint8 gum_jcc_opcode_negate (guint8 opcode);

G_END_DECLS

#endif
