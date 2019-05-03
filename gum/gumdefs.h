/*
 * Copyright (C) 2008-2018 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUMDEFS_H__
#define __GUMDEFS_H__

#include <glib-object.h>

#if !defined (GUM_STATIC) && defined (G_OS_WIN32)
#  ifdef GUM_EXPORTS
#    define GUM_API __declspec(dllexport)
#  else
#    define GUM_API __declspec(dllimport)
#  endif
#else
#  define GUM_API
#endif

#if !defined (__arm__) && !defined (__aarch64__)
# if GLIB_SIZEOF_VOID_P == 4
#  define GUM_NATIVE_CPU GUM_CPU_IA32
# else
#  define GUM_NATIVE_CPU GUM_CPU_AMD64
# endif
#elif defined (__arm__) || defined (__aarch64__)
# if GLIB_SIZEOF_VOID_P == 4
#  define GUM_NATIVE_CPU GUM_CPU_ARM
# else
#  define GUM_NATIVE_CPU GUM_CPU_ARM64
# endif
#elif defined (__mips__)
# define GUM_NATIVE_CPU GUM_CPU_MIPS
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

G_BEGIN_DECLS

typedef guint64 GumAddress;
#define GUM_ADDRESS(a) ((GumAddress) (guintptr) (a))
#define GUM_TYPE_ADDRESS (gum_address_get_type ())
typedef guint GumOS;
typedef guint GumCallingConvention;
typedef guint GumAbiType;
typedef guint GumCpuType;
#define GUM_TYPE_CPU_TYPE (gum_cpu_type_get_type ())
typedef guint GumArgType;
typedef struct _GumArgument GumArgument;
typedef guint GumBranchHint;
typedef struct _GumIA32CpuContext GumIA32CpuContext;
typedef struct _GumX64CpuContext GumX64CpuContext;
typedef struct _GumArmCpuContext GumArmCpuContext;
typedef struct _GumArm64CpuContext GumArm64CpuContext;
typedef struct _GumMipsCpuContext GumMipsCpuContext;
#if !defined (__arm__) && !defined (__aarch64__) && !defined (__mips__)
# define GUM_DEFAULT_CS_ARCH CS_ARCH_X86
# if GLIB_SIZEOF_VOID_P == 4
#  define GUM_DEFAULT_CS_MODE CS_MODE_32
typedef GumIA32CpuContext GumCpuContext;
# else
#  define GUM_DEFAULT_CS_MODE CS_MODE_64
typedef GumX64CpuContext GumCpuContext;
# endif
#elif defined (__arm__) && !defined (__aarch64__)
# define GUM_DEFAULT_CS_ARCH CS_ARCH_ARM
# define GUM_DEFAULT_CS_MODE CS_MODE_ARM
typedef GumArmCpuContext GumCpuContext;
#elif defined (__aarch64__)
# define GUM_DEFAULT_CS_ARCH CS_ARCH_ARM64
# define GUM_DEFAULT_CS_MODE CS_MODE_ARM
typedef GumArm64CpuContext GumCpuContext;
#elif defined (__mips__)
# define GUM_DEFAULT_CS_ARCH CS_ARCH_MIPS
# if G_BYTE_ORDER == G_LITTLE_ENDIAN
#  define GUM_DEFAULT_CS_MODE (CS_MODE_MIPS32 | CS_MODE_LITTLE_ENDIAN)
# else
#  define GUM_DEFAULT_CS_MODE (CS_MODE_MIPS32 | CS_MODE_BIG_ENDIAN)
# endif
typedef GumMipsCpuContext GumCpuContext;
#endif
typedef guint GumRelocationScenario;

enum _GumOS
{
  GUM_OS_WINDOWS,
  GUM_OS_MACOS,
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
  GUM_CPU_INVALID,
  GUM_CPU_IA32,
  GUM_CPU_AMD64,
  GUM_CPU_ARM,
  GUM_CPU_ARM64,
  GUM_CPU_MIPS
};

enum _GumArgType
{
  GUM_ARG_ADDRESS,
  GUM_ARG_REGISTER
};

struct _GumArgument
{
  GumArgType type;

  union
  {
    GumAddress address;
    gint reg;
  } value;
};

enum _GumBranchHint
{
  GUM_NO_HINT,
  GUM_LIKELY,
  GUM_UNLIKELY
};

struct _GumIA32CpuContext
{
  guint32 eip;

  guint32 edi;
  guint32 esi;
  guint32 ebp;
  guint32 esp;
  guint32 ebx;
  guint32 edx;
  guint32 ecx;
  guint32 eax;
};

struct _GumX64CpuContext
{
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
};

struct _GumArmCpuContext
{
  guint32 cpsr;
  guint32 pc;
  guint32 sp;

  guint32 r8;
  guint32 r9;
  guint32 r10;
  guint32 r11;
  guint32 r12;

  guint32 r[8];
  guint32 lr;
};

struct _GumArm64CpuContext
{
  guint64 pc;
  guint64 sp;

  guint64 x[29];
  guint64 fp;
  guint64 lr;
  guint8 q[128];
};

struct _GumMipsCpuContext
{
  guint32 pc;

  guint32 gp;
  guint32 sp;
  guint32 fp;
  guint32 ra;

  guint32 hi;
  guint32 lo;

  guint32 at;

  guint32 v0;
  guint32 v1;

  guint32 a0;
  guint32 a1;
  guint32 a2;
  guint32 a3;

  guint32 t0;
  guint32 t1;
  guint32 t2;
  guint32 t3;
  guint32 t4;
  guint32 t5;
  guint32 t6;
  guint32 t7;
  guint32 t8;
  guint32 t9;

  guint32 s0;
  guint32 s1;
  guint32 s2;
  guint32 s3;
  guint32 s4;
  guint32 s5;
  guint32 s6;
  guint32 s7;

  guint32 k0;
  guint32 k1;
};

enum _GumRelocationScenario
{
  GUM_SCENARIO_OFFLINE,
  GUM_SCENARIO_ONLINE
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

#define GUM_MAX_THREAD_RANGES 2

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
#define GUM_RED_ZONE_SIZE 128

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

#define GUM_ALIGN_POINTER(t, p, b) \
    ((t) GSIZE_TO_POINTER (((GPOINTER_TO_SIZE (p) + ((gsize) (b - 1))) & \
        ~((gsize) (b - 1)))))
#define GUM_ALIGN_SIZE(s, b) \
    ((((gsize) s) + ((gsize) (b - 1))) & ~((gsize) (b - 1)))

#define GUM_FUNCPTR_TO_POINTER(f) (GSIZE_TO_POINTER (f))
#define GUM_POINTER_TO_FUNCPTR(t, p) ((t) GPOINTER_TO_SIZE (p))

#define GUM_INT5_MASK  0x0000001f
#define GUM_INT6_MASK  0x0000003f
#define GUM_INT8_MASK  0x000000ff
#define GUM_INT10_MASK 0x000003ff
#define GUM_INT11_MASK 0x000007ff
#define GUM_INT12_MASK 0x00000fff
#define GUM_INT14_MASK 0x00003fff
#define GUM_INT16_MASK 0x0000ffff
#define GUM_INT18_MASK 0x0003ffff
#define GUM_INT19_MASK 0x0007ffff
#define GUM_INT24_MASK 0x00ffffff
#define GUM_INT26_MASK 0x03ffffff
#define GUM_INT28_MASK 0x0fffffff

#define GUM_IS_WITHIN_UINT7_RANGE(i) \
    (((gint64) (i)) >= G_GINT64_CONSTANT (0) && \
     ((gint64) (i)) <= G_GINT64_CONSTANT (127))
#define GUM_IS_WITHIN_INT8_RANGE(i) \
    (((gint64) (i)) >= G_GINT64_CONSTANT (-128) && \
     ((gint64) (i)) <= G_GINT64_CONSTANT (127))
#define GUM_IS_WITHIN_INT11_RANGE(i) \
    (((gint64) (i)) >= G_GINT64_CONSTANT (-1024) && \
     ((gint64) (i)) <= G_GINT64_CONSTANT (1023))
#define GUM_IS_WITHIN_INT14_RANGE(i) \
    (((gint64) (i)) >= G_GINT64_CONSTANT (-8192) && \
     ((gint64) (i)) <= G_GINT64_CONSTANT (8191))
#define GUM_IS_WITHIN_INT16_RANGE(i) \
    (((gint64) (i)) >= G_GINT64_CONSTANT (-32768) && \
     ((gint64) (i)) <= G_GINT64_CONSTANT (32767))
#define GUM_IS_WITHIN_INT18_RANGE(i) \
    (((gint64) (i)) >= G_GINT64_CONSTANT (-131072) && \
     ((gint64) (i)) <= G_GINT64_CONSTANT (131071))
#define GUM_IS_WITHIN_INT19_RANGE(i) \
    (((gint64) (i)) >= G_GINT64_CONSTANT (-262144) && \
     ((gint64) (i)) <= G_GINT64_CONSTANT (262143))
#define GUM_IS_WITHIN_INT20_RANGE(i) \
    (((gint64) (i)) >= G_GINT64_CONSTANT (-524288) && \
     ((gint64) (i)) <= G_GINT64_CONSTANT (524287))
#define GUM_IS_WITHIN_INT21_RANGE(i) \
    (((gint64) (i)) >= G_GINT64_CONSTANT (-1048576) && \
     ((gint64) (i)) <= G_GINT64_CONSTANT (1048575))
#define GUM_IS_WITHIN_INT24_RANGE(i) \
    (((gint64) (i)) >= G_GINT64_CONSTANT (-8388608) && \
     ((gint64) (i)) <= G_GINT64_CONSTANT (8388607))
#define GUM_IS_WITHIN_INT26_RANGE(i) \
    (((gint64) (i)) >= G_GINT64_CONSTANT (-33554432) && \
     ((gint64) (i)) <= G_GINT64_CONSTANT (33554431))
#define GUM_IS_WITHIN_INT28_RANGE(i) \
    (((gint64) (i)) >= G_GINT64_CONSTANT (-134217728) && \
     ((gint64) (i)) <= G_GINT64_CONSTANT (134217727))
#define GUM_IS_WITHIN_INT32_RANGE(i) \
    (((gint64) (i)) >= (gint64) G_MININT32 && \
     ((gint64) (i)) <= (gint64) G_MAXINT32)

GUM_API gpointer gum_cpu_context_get_nth_argument (GumCpuContext * self,
    guint n);
GUM_API void gum_cpu_context_replace_nth_argument (GumCpuContext * self,
    guint n, gpointer value);
GUM_API gpointer gum_cpu_context_get_return_value (GumCpuContext * self);
GUM_API void gum_cpu_context_replace_return_value (GumCpuContext * self,
    gpointer value);

GUM_API GType gum_address_get_type (void) G_GNUC_CONST;
GUM_API GType gum_cpu_type_get_type (void) G_GNUC_CONST;

G_END_DECLS

#endif
