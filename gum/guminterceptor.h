/*
 * Copyright (C) 2008-2010 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
 * Copyright (C) 2008 Christian Berentsen <jc.berentsen@gmail.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_INTERCEPTOR_H__
#define __GUM_INTERCEPTOR_H__

#include <glib-object.h>
#include <gum/gumdefs.h>
#include <gum/guminvocationlistener.h>

#define GUM_TYPE_INTERCEPTOR (gum_interceptor_get_type ())
#define GUM_INTERCEPTOR(obj) (G_TYPE_CHECK_INSTANCE_CAST ((obj),\
    GUM_TYPE_INTERCEPTOR, GumInterceptor))
#define GUM_INTERCEPTOR_CAST(obj) ((GumInterceptor *) (obj))
#define GUM_INTERCEPTOR_CLASS(klass) (G_TYPE_CHECK_CLASS_CAST ((klass),\
    GUM_TYPE_INTERCEPTOR, GumInterceptorClass))
#define GUM_IS_INTERCEPTOR(obj) (G_TYPE_CHECK_INSTANCE_TYPE ((obj),\
    GUM_TYPE_INTERCEPTOR))
#define GUM_IS_INTERCEPTOR_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE (\
    (klass), GUM_TYPE_INTERCEPTOR))
#define GUM_INTERCEPTOR_GET_CLASS(obj) (G_TYPE_INSTANCE_GET_CLASS (\
    (obj), GUM_TYPE_INTERCEPTOR, GumInterceptorClass))

typedef struct _GumInterceptor GumInterceptor;
typedef struct _GumInterceptorClass GumInterceptorClass;
typedef GArray GumInvocationStack;

typedef struct _GumInterceptorPrivate GumInterceptorPrivate;

typedef enum
{
  GUM_ATTACH_OK               =  0,
  GUM_ATTACH_WRONG_SIGNATURE  = -1,
  GUM_ATTACH_ALREADY_ATTACHED = -2
} GumAttachReturn;

typedef enum
{
  GUM_REPLACE_OK               =  0,
  GUM_REPLACE_WRONG_SIGNATURE  = -1,
  GUM_REPLACE_ALREADY_REPLACED = -2
} GumReplaceReturn;

struct _GumInterceptor
{
  GObject parent;

  GumInterceptorPrivate * priv;
};

struct _GumInterceptorClass
{
  GObjectClass parent_class;
};

G_BEGIN_DECLS

GUM_API GType gum_interceptor_get_type (void) G_GNUC_CONST;

GUM_API GumInterceptor * gum_interceptor_obtain (void);

GUM_API GumAttachReturn gum_interceptor_attach_listener (GumInterceptor * self,
    gpointer function_address, GumInvocationListener * listener,
    gpointer listener_function_data);
GUM_API void gum_interceptor_detach_listener (GumInterceptor * self,
    GumInvocationListener * listener);

GUM_API GumReplaceReturn gum_interceptor_replace_function (
    GumInterceptor * self, gpointer function_address,
    gpointer replacement_function, gpointer replacement_function_data);
GUM_API void gum_interceptor_revert_function (GumInterceptor * self,
    gpointer function_address);

GUM_API void gum_interceptor_begin_transaction (GumInterceptor * self);
GUM_API void gum_interceptor_end_transaction (GumInterceptor * self);
GUM_API gboolean gum_interceptor_flush (GumInterceptor * self);

GUM_API GumInvocationContext * gum_interceptor_get_current_invocation (void);
GUM_API GumInvocationStack * gum_interceptor_get_current_stack (void);

GUM_API void gum_interceptor_ignore_current_thread (GumInterceptor * self);
GUM_API void gum_interceptor_unignore_current_thread (GumInterceptor * self);

GUM_API void gum_interceptor_ignore_other_threads (GumInterceptor * self);
GUM_API void gum_interceptor_unignore_other_threads (GumInterceptor * self);

GUM_API gpointer gum_invocation_stack_translate (GumInvocationStack * self,
    gpointer return_address);

G_END_DECLS

#endif
