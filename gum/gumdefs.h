/*
 * Copyright (C) 2008 Ole André Vadla Ravnås <ole.andre.ravnas@tandberg.com>
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

#ifndef __GUMDEFS_H__
#define __GUMDEFS_H__

#include <glib.h>

#if !defined (GUM_STATIC) && defined (G_OS_WIN32)
#  ifdef GUM_EXPORTS
#    define GUM_API __declspec(dllexport)
#  else
#    define GUM_API __declspec(dllimport)
#  endif
#else
#  define GUM_API
#endif

typedef enum _GumCpuType GumCpuType;
typedef struct _GumCpuContext GumCpuContext;

enum _GumCpuType
{
  GUM_CPU_IA32,
  GUM_CPU_AMD64
};

struct _GumCpuContext
{
#if GLIB_SIZEOF_VOID_P == 8
  guint64 rip;

  guint64 r15;
  guint64 r14;
  guint64 r13;
  guint64 r12;
  guint64 r11;
  guint64 r10;
  guint64 r9;
  guint64 r8;

  guint64 rdi;
  guint64 rsi;
  guint64 rbp;
  guint64 rsp;
  guint64 rbx;
  guint64 rdx;
  guint64 rcx;
  guint64 rax;
#else
  guint32 eip;

  guint32 edi;
  guint32 esi;
  guint32 ebp;
  guint32 esp;
  guint32 ebx;
  guint32 edx;
  guint32 ecx;
  guint32 eax;
#endif
};

#define GUM_MAX_PATH                 260
#define GUM_MAX_TYPE_NAME             16
#define GUM_MAX_SYMBOL_NAME         2000

#define GUM_MAX_THREADS              128
#define GUM_MAX_CALL_DEPTH            32
#define GUM_MAX_BACKTRACE_DEPTH       16
#define GUM_MAX_WORST_CASE_INFO_SIZE 128

#define GUM_MAX_LISTENERS_PER_FUNCTION 2

#if GLIB_SIZEOF_VOID_P == 8
#define GUM_CPU_MODE 64
#else
#define GUM_CPU_MODE 32
#endif

#ifdef _MSC_VER
#define GUM_CDECL __cdecl
#define GUM_STDCALL __stdcall
#define GUM_NOINLINE __declspec (noinline)
#else
#define GUM_CDECL __attribute__((cdecl))
#define GUM_STDCALL __attribute__((stdcall))
/* FIXME: */
#define GUM_NOINLINE
#endif

#endif
