/*
 * Copyright (C) 2015 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_EXCEPTOR_H__
#define __GUM_EXCEPTOR_H__

#include <glib-object.h>
#include <gum/gummemory.h>

#define GUM_TYPE_EXCEPTOR (gum_exceptor_get_type ())
#define GUM_EXCEPTOR(obj) (G_TYPE_CHECK_INSTANCE_CAST ((obj),\
    GUM_TYPE_EXCEPTOR, GumExceptor))
#define GUM_EXCEPTOR_CAST(obj) ((GumExceptor *) (obj))
#define GUM_EXCEPTOR_CLASS(klass) (G_TYPE_CHECK_CLASS_CAST ((klass),\
    GUM_TYPE_EXCEPTOR, GumExceptorClass))
#define GUM_IS_EXCEPTOR(obj) (G_TYPE_CHECK_INSTANCE_TYPE ((obj),\
    GUM_TYPE_EXCEPTOR))
#define GUM_IS_EXCEPTOR_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE (\
    (klass), GUM_TYPE_EXCEPTOR))
#define GUM_EXCEPTOR_GET_CLASS(obj) (G_TYPE_INSTANCE_GET_CLASS (\
    (obj), GUM_TYPE_EXCEPTOR, GumExceptorClass))

G_BEGIN_DECLS

typedef struct _GumExceptor GumExceptor;
typedef struct _GumExceptorClass GumExceptorClass;
typedef struct _GumExceptorPrivate GumExceptorPrivate;

typedef struct _GumExceptionDetails GumExceptionDetails;
typedef guint GumExceptionType;
typedef struct _GumExceptionMemoryDetails GumExceptionMemoryDetails;
typedef gboolean (* GumExceptionHandler) (GumExceptionDetails * details,
    gpointer user_data);

typedef struct _GumExceptorScope GumExceptorScope;
typedef struct _GumExceptorScopeImpl GumExceptorScopeImpl;
typedef gpointer GumExceptorJmpBuf;
typedef gint (* GumExceptorSetJmp) (GumExceptorJmpBuf buf, gboolean save_mask);

struct _GumExceptor
{
  GObject parent;

  GumExceptorPrivate * priv;
};

struct _GumExceptorClass
{
  GObjectClass parent_class;
};

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
  GumExceptionType type;
  gpointer address;
  GumExceptionMemoryDetails memory;
  GumCpuContext context;
  gpointer native_context;
};

struct _GumExceptorScope
{
  GumExceptionDetails exception;

  GumExceptorScopeImpl * impl;
};

GUM_API GType gum_exceptor_get_type (void) G_GNUC_CONST;

GUM_API GumExceptor * gum_exceptor_obtain (void);

GUM_API void gum_exceptor_add (GumExceptor * self, GumExceptionHandler func,
    gpointer user_data);
GUM_API void gum_exceptor_remove (GumExceptor * self, GumExceptionHandler func,
    gpointer user_data);

#if defined (HAVE_QNX) && defined (HAVE_ARM) && defined (sigsetjmp)
/*
 * On qnx-arm, the sigsetjmp _function_ is BROKEN. See
 * http://community.qnx.com/sf/discussion/do/listPosts/projects.core_os/discussion.newcode.topc26577
 * for details. We need to use the sigsetjmp _macro_ instead.
 * The macro evaluates the 'env' argument twice, so we need to make sure that
 * the _gum_exceptor_prepare_try is safe to run twice.
 */
#define gum_exceptor_try(self, scope) \
    (scope)->impl = NULL, \
    sigsetjmp (_gum_exceptor_prepare_try (self, scope), TRUE) == 0
#else
/*
 * The setjmp() API does not allow longjmp() to be called after the function
 * that called setjmp() returns. That's why we cannot hide all the gory details
 * behind our API and need this hack...
 */
#define gum_exceptor_try(self, scope) \
    (scope)->impl = NULL, \
    _gum_exceptor_get_setjmp () ( \
        _gum_exceptor_prepare_try (self, scope), TRUE) == 0
#endif

GUM_API gboolean gum_exceptor_catch (GumExceptor * self,
    GumExceptorScope * scope);

GUM_API gchar * gum_exception_details_to_string (
    const GumExceptionDetails * details);

GUM_API GumExceptorSetJmp _gum_exceptor_get_setjmp (void);
GUM_API GumExceptorJmpBuf _gum_exceptor_prepare_try (GumExceptor * self,
    GumExceptorScope * scope);

G_END_DECLS

#endif
