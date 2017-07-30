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

guint gum_x86_reader_insn_length (guint8 * code);
gboolean gum_x86_reader_insn_is_jcc (const cs_insn * insn);

gpointer gum_x86_reader_try_get_relative_call_target (gconstpointer address);
gpointer gum_x86_reader_try_get_relative_jump_target (gconstpointer address);
gpointer gum_x86_reader_try_get_indirect_jump_target (gconstpointer address);

G_END_DECLS

#endif
