/*
 * Copyright (C) 2010 Ole André Vadla Ravnås <ole.andre.ravnas@tandberg.com>
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

#ifndef __GUM_WIN_EXCEPTION_HOOK_H__
#define __GUM_WIN_EXCEPTION_HOOK_H__

#include <glib.h>
#define VC_EXTRALEAN
#include <windows.h>

G_BEGIN_DECLS

typedef BOOL (WINAPI * GumWinExceptionHandler) (
    EXCEPTION_RECORD * exception_record, CONTEXT * context);

void gum_win_exception_hook_add (GumWinExceptionHandler handler);
void gum_win_exception_hook_remove (GumWinExceptionHandler handler);

G_END_DECLS

#endif
