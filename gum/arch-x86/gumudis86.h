/*
 * Copyright (C) 2009 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_UDIS86_H__
#define __GUM_UDIS86_H__

#include "gumdefs.h"
#include <udis86.h>

G_BEGIN_DECLS

guint gum_find_instruction_length (guint8 * code);
gboolean gum_mnemonic_is_jcc (ud_mnemonic_code_t mnemonic);
guint8 gum_jcc_insn_to_short_opcode (guint8 * code);
guint8 gum_jcc_opcode_negate (guint8 opcode);

G_END_DECLS

#endif
