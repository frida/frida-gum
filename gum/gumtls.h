/*
 * Copyright (C) 2010 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_TLS_H__
#define __GUM_TLS_H__

#include <glib.h>

#ifdef G_OS_WIN32
# ifndef WIN32_LEAN_AND_MEAN
#  define WIN32_LEAN_AND_MEAN
# endif
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
