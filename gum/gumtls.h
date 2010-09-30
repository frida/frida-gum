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

#ifndef __GUM_TLS_H__
#define __GUM_TLS_H__

#include <glib.h>

#ifdef G_OS_WIN32
# define VC_EXTRALEAN
# include <windows.h>
typedef DWORD GumTlsKey;
# define GUM_TLS_KEY_INIT(k)         *(k) = TlsAlloc ()
# define GUM_TLS_KEY_FREE(k)         TlsFree (k)
# define GUM_TLS_KEY_GET_VALUE(k)    TlsGetValue (k)
# define GUM_TLS_KEY_SET_VALUE(k, v) TlsSetValue (k, v)
#else
# include <pthread.h>
typedef pthread_key_t GumTlsKey;
# define GUM_TLS_KEY_INIT(k)         pthread_key_create ((k), NULL)
# define GUM_TLS_KEY_FREE(k)         pthread_key_delete (k)
# define GUM_TLS_KEY_GET_VALUE(k)    pthread_getspecific (k)
# define GUM_TLS_KEY_SET_VALUE(k, v) pthread_setspecific (k, v)
#endif

#endif