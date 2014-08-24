/*
 * Copyright (C) 2010 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_WIN_EXCEPTION_HOOK_H__
#define __GUM_WIN_EXCEPTION_HOOK_H__

#include "gumwindows.h"

G_BEGIN_DECLS

typedef gboolean (* GumWinExceptionHandler) (
    EXCEPTION_RECORD * exception_record, CONTEXT * context,
    gpointer user_data);

void gum_win_exception_hook_add (GumWinExceptionHandler handler,
    gpointer user_data);
void gum_win_exception_hook_remove (GumWinExceptionHandler handler,
    gpointer user_data);

G_END_DECLS

#endif
