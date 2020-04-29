/*
 * Copyright (C) 2015-2018 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_EXCEPTOR_H__
#define __GUM_EXCEPTOR_H__

#include <glib-object.h>
#include <gum/gummemory.h>
#include <gum/gumprocess.h>
#include <setjmp.h>

G_BEGIN_DECLS

#define GUM_TYPE_EXCEPTOR (gum_exceptor_get_type ())
G_DECLARE_FINAL_TYPE (GumExceptor, gum_exceptor, GUM, EXCEPTOR, GObject)

#if defined (G_OS_WIN32) || defined (__APPLE__)
# define GUM_NATIVE_SETJMP(env) setjmp (env)
# define GUM_NATIVE_LONGJMP longjmp
  typedef jmp_buf GumExceptorNativeJmpBuf;
#else
# define GUM_NATIVE_SETJMP(env) sigsetjmp (env, TRUE)
# define GUM_NATIVE_LONGJMP siglongjmp
  typedef sigjmp_buf GumExceptorNativeJmpBuf;
#endif

typedef struct _GumExceptionDetails GumExceptionDetails;
typedef guint GumExceptionType;
typedef struct _GumExceptionMemoryDetails GumExceptionMemoryDetails;
typedef gboolean (* GumExceptionHandler) (GumExceptionDetails * details,
    gpointer user_data);

typedef struct _GumExceptorScope GumExceptorScope;

enum _GumExceptionType
{
  GUM_EXCEPTION_ABORT = 1,
  GUM_EXCEPTION_ACCESS_VIOLATION,
  GUM_EXCEPTION_GUARD_PAGE,
  GUM_EXCEPTION_ILLEGAL_INSTRUCTION,
  GUM_EXCEPTION_STACK_OVERFLOW,
  GUM_EXCEPTION_ARITHMETIC,
  GUM_EXCEPTION_BREAKPOINT,
  GUM_EXCEPTION_SINGLE_STEP,
  GUM_EXCEPTION_SYSTEM
};

struct _GumExceptionMemoryDetails
{
  GumMemoryOperation operation;
  gpointer address;
};

struct _GumExceptionDetails
{
  GumThreadId thread_id;
  GumExceptionType type;
  gpointer address;
  GumExceptionMemoryDetails memory;
  GumCpuContext context;
  gpointer native_context;
};

struct _GumExceptorScope
{
  GumExceptionDetails exception;

  /*< private */
  gboolean exception_occurred;
  gpointer padding[2];
  jmp_buf env;
#ifdef __ANDROID__
  sigset_t mask;
#endif

  GumExceptorScope * next;
};

GUM_API GumExceptor * gum_exceptor_obtain (void);

GUM_API void gum_exceptor_add (GumExceptor * self, GumExceptionHandler func,
    gpointer user_data);
GUM_API void gum_exceptor_remove (GumExceptor * self, GumExceptionHandler func,
    gpointer user_data);

#if defined (_MSC_VER) && GLIB_SIZEOF_VOID_P == 8
/*
 * On MSVC/64-bit setjmp() is actually an intrinsic that calls _setjmp() with a
 * a hidden second argument specifying the frame pointer. This makes sense when
 * the longjmp() is guaranteed to happen from code we control, but is not
 * reliable otherwise.
 */
# define gum_exceptor_try(self, scope) ( \
    _gum_exceptor_prepare_try (self, scope), \
    ((int (*) (jmp_buf env, void * frame_pointer)) _setjmp) ( \
        (scope)->env, NULL) == 0)
#else
# define gum_exceptor_try(self, scope) ( \
    _gum_exceptor_prepare_try (self, scope), \
    GUM_NATIVE_SETJMP ((scope)->env) == 0)
#endif
GUM_API gboolean gum_exceptor_catch (GumExceptor * self,
    GumExceptorScope * scope);

GUM_API gchar * gum_exception_details_to_string (
    const GumExceptionDetails * details);

GUM_API void _gum_exceptor_prepare_try (GumExceptor * self,
    GumExceptorScope * scope);

G_END_DECLS

#endif
