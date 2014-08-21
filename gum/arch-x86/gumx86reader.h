/*
 * Copyright (C) 2009 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_X86_READER_H__
#define __GUM_X86_READER_H__

#include "gumdefs.h"

#include <capstone.h>

G_BEGIN_DECLS

gboolean gum_x86_reader_insn_is_jcc (cs_insn * insn);
guint8 gum_x86_reader_jcc_insn_to_short_opcode (guint8 * code);
guint8 gum_x86_reader_jcc_opcode_negate (guint8 opcode);

gpointer gum_x86_reader_try_get_relative_call_target (gconstpointer address);
gpointer gum_x86_reader_try_get_relative_jump_target (gconstpointer address);
gpointer gum_x86_reader_try_get_indirect_jump_target (gconstpointer address);

G_END_DECLS

#endif
