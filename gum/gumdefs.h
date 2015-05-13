/*
 * Copyright (C) 2008-2014 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
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

#ifdef G_OS_WIN32
# define GUM_NATIVE_ABI            GUM_ABI_WINDOWS
# define GUM_NATIVE_ABI_IS_WINDOWS 1
# define GUM_NATIVE_ABI_IS_UNIX    0
#else
# define GUM_NATIVE_ABI            GUM_ABI_UNIX
# define GUM_NATIVE_ABI_IS_WINDOWS 0
# define GUM_NATIVE_ABI_IS_UNIX    1
#endif

typedef guint64 GumAddress;
#define GUM_ADDRESS(a) ((GumAddress) GPOINTER_TO_SIZE (a))
typedef guint GumOS;
typedef guint GumCallingConvention;
typedef guint GumAbiType;
typedef guint GumCpuType;
typedef guint GumArgType;
typedef guint GumBranchHint;
typedef struct _GumCpuContext GumCpuContext;

enum _GumOS
{
  GUM_OS_WINDOWS,
  GUM_OS_MAC,
  GUM_OS_LINUX,
  GUM_OS_IOS,
  GUM_OS_ANDROID,
  GUM_OS_QNX
};

enum _GumCallingConvention
{
  GUM_CALL_CAPI,
  GUM_CALL_SYSAPI
};

enum _GumAbiType
{
  GUM_ABI_UNIX,
  GUM_ABI_WINDOWS
};

enum _GumCpuType
{
  GUM_CPU_IA32,
  GUM_CPU_AMD64,
  GUM_CPU_ARM,
  GUM_CPU_ARM64
};

enum _GumArgType
{
  GUM_ARG_ADDRESS,
  GUM_ARG_REGISTER,
  GUM_ARG_POINTER /* deprecated */
};

enum _GumBranchHint
{
  GUM_NO_HINT,
  GUM_LIKELY,
  GUM_UNLIKELY
};

struct _GumCpuContext
{
#if !defined(__arm__) && !defined(__aarch64__)
# if GLIB_SIZEOF_VOID_P == 8
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
# else
  guint32 eip;

  guint32 edi;
  guint32 esi;
  guint32 ebp;
  guint32 esp;
  guint32 ebx;
  guint32 edx;
  guint32 ecx;
  guint32 eax;
# endif
#elif defined (__aarch64__)
  guint64 pc;
  guint64 sp;

  guint64 x[29];
  guint64 fp;
  guint64 lr;
#else
  guint32 pc;
  guint32 sp;

  guint32 r[8];
  guint32 lr;
#endif
};

#ifndef __arm__
# if GLIB_SIZEOF_VOID_P == 8
#  define GUM_CPU_CONTEXT_XAX(c) ((c)->rax)
#  define GUM_CPU_CONTEXT_XCX(c) ((c)->rcx)
#  define GUM_CPU_CONTEXT_XDX(c) ((c)->rdx)
#  define GUM_CPU_CONTEXT_XBX(c) ((c)->rbx)
#  define GUM_CPU_CONTEXT_XSP(c) ((c)->rsp)
#  define GUM_CPU_CONTEXT_XBP(c) ((c)->rbp)
#  define GUM_CPU_CONTEXT_XSI(c) ((c)->rsi)
#  define GUM_CPU_CONTEXT_XDI(c) ((c)->rdi)
#  define GUM_CPU_CONTEXT_XIP(c) ((c)->rip)
#  define GUM_CPU_CONTEXT_OFFSET_XAX (G_STRUCT_OFFSET (GumCpuContext, rax))
#  define GUM_CPU_CONTEXT_OFFSET_XCX (G_STRUCT_OFFSET (GumCpuContext, rcx))
#  define GUM_CPU_CONTEXT_OFFSET_XDX (G_STRUCT_OFFSET (GumCpuContext, rdx))
#  define GUM_CPU_CONTEXT_OFFSET_XBX (G_STRUCT_OFFSET (GumCpuContext, rbx))
#  define GUM_CPU_CONTEXT_OFFSET_XSP (G_STRUCT_OFFSET (GumCpuContext, rsp))
#  define GUM_CPU_CONTEXT_OFFSET_XBP (G_STRUCT_OFFSET (GumCpuContext, rbp))
#  define GUM_CPU_CONTEXT_OFFSET_XSI (G_STRUCT_OFFSET (GumCpuContext, rsi))
#  define GUM_CPU_CONTEXT_OFFSET_XDI (G_STRUCT_OFFSET (GumCpuContext, rdi))
#  define GUM_CPU_CONTEXT_OFFSET_XIP (G_STRUCT_OFFSET (GumCpuContext, rip))
# else
#  define GUM_CPU_CONTEXT_XAX(c) ((c)->eax)
#  define GUM_CPU_CONTEXT_XCX(c) ((c)->ecx)
#  define GUM_CPU_CONTEXT_XDX(c) ((c)->edx)
#  define GUM_CPU_CONTEXT_XBX(c) ((c)->ebx)
#  define GUM_CPU_CONTEXT_XSP(c) ((c)->esp)
#  define GUM_CPU_CONTEXT_XBP(c) ((c)->ebp)
#  define GUM_CPU_CONTEXT_XSI(c) ((c)->esi)
#  define GUM_CPU_CONTEXT_XDI(c) ((c)->edi)
#  define GUM_CPU_CONTEXT_XIP(c) ((c)->eip)
#  define GUM_CPU_CONTEXT_OFFSET_XAX (G_STRUCT_OFFSET (GumCpuContext, eax))
#  define GUM_CPU_CONTEXT_OFFSET_XCX (G_STRUCT_OFFSET (GumCpuContext, ecx))
#  define GUM_CPU_CONTEXT_OFFSET_XDX (G_STRUCT_OFFSET (GumCpuContext, edx))
#  define GUM_CPU_CONTEXT_OFFSET_XBX (G_STRUCT_OFFSET (GumCpuContext, ebx))
#  define GUM_CPU_CONTEXT_OFFSET_XSP (G_STRUCT_OFFSET (GumCpuContext, esp))
#  define GUM_CPU_CONTEXT_OFFSET_XBP (G_STRUCT_OFFSET (GumCpuContext, ebp))
#  define GUM_CPU_CONTEXT_OFFSET_XSI (G_STRUCT_OFFSET (GumCpuContext, esi))
#  define GUM_CPU_CONTEXT_OFFSET_XDI (G_STRUCT_OFFSET (GumCpuContext, edi))
#  define GUM_CPU_CONTEXT_OFFSET_XIP (G_STRUCT_OFFSET (GumCpuContext, eip))
# endif
#endif

#define GUM_MAX_PATH                 260
#define GUM_MAX_TYPE_NAME             16
#define GUM_MAX_SYMBOL_NAME         2000

#define GUM_MAX_THREADS              768
#define GUM_MAX_CALL_DEPTH            32
#define GUM_MAX_BACKTRACE_DEPTH       16
#define GUM_MAX_WORST_CASE_INFO_SIZE 128

#define GUM_MAX_LISTENERS_PER_FUNCTION 2
#define GUM_MAX_LISTENER_DATA        512

#if GLIB_SIZEOF_VOID_P == 8
#define GUM_CPU_MODE CS_MODE_64
#define GUM_THUNK
#else
#define GUM_CPU_MODE CS_MODE_32
#define GUM_THUNK GUM_FASTCALL
#endif
#if !defined (G_OS_WIN32) && GLIB_SIZEOF_VOID_P == 8
# define GUM_THUNK_REG_ARG0 GUM_REG_XDI
# define GUM_THUNK_REG_ARG1 GUM_REG_XSI
#else
# define GUM_THUNK_REG_ARG0 GUM_REG_XCX
# define GUM_THUNK_REG_ARG1 GUM_REG_XDX
#endif

#ifdef _MSC_VER
# define GUM_CDECL __cdecl
# define GUM_STDCALL __stdcall
# define GUM_FASTCALL __fastcall
# define GUM_NOINLINE __declspec (noinline)
#else
# ifndef __arm__
#  if GLIB_SIZEOF_VOID_P == 4
#   define GUM_CDECL __attribute__((cdecl))
#   define GUM_STDCALL __attribute__((stdcall))
#  else
#   define GUM_CDECL
#   define GUM_STDCALL
#  endif
#  define GUM_FASTCALL __attribute__((fastcall))
# else
#  define GUM_CDECL
#  define GUM_STDCALL
#  define GUM_FASTCALL
# endif
# define GUM_NOINLINE __attribute__((noinline))
#endif

#define GUM_FUNCPTR_TO_POINTER(f) (GSIZE_TO_POINTER (f))
#define GUM_POINTER_TO_FUNCPTR(t, p) ((t) GPOINTER_TO_SIZE (p))

#endif
