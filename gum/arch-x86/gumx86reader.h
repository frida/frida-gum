/*
 * Copyright (C) 2009 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_X86_READER_H__
#define __GUM_X86_READER_H__

#include "gumdefs.h"

G_BEGIN_DECLS

gpointer gum_x86_reader_try_get_relative_call_target (gconstpointer address);
gpointer gum_x86_reader_try_get_relative_jump_target (gconstpointer address);
gpointer gum_x86_reader_try_get_indirect_jump_target (gconstpointer address);

G_END_DECLS

#endif
