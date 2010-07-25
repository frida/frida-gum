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

#ifndef __GUM_SYS_INTERNALS_H__
#define __GUM_SYS_INTERNALS_H__

#include <glib.h>

#ifdef G_OS_WIN32

# if GLIB_SIZEOF_VOID_P == 4
#  define GUM_TEB_OFFSET_SELF 0x0018
#  define GUM_TEB_OFFSET_TID  0x0024
#  define GUM_TEB_OFFSET_USER 0x0700
# else
#  define GUM_TEB_OFFSET_SELF 0x0030
#  define GUM_TEB_OFFSET_TID  0x0048
#  define GUM_TEB_OFFSET_USER 0x0878
# endif

# define GUM_TEB_OFFSET_INTERCEPTOR_GUARD (GUM_TEB_OFFSET_USER + 4)
# define GUM_TEB_OFFSET_TRACER_STACK      (GUM_TEB_OFFSET_USER + 8)
# define GUM_TEB_OFFSET_TRACER_DEPTH      (GUM_TEB_OFFSET_USER + 16)

#endif

#endif
