/*
 * Copyright (C) 2008-2018 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 * Copyright (C) 2008 Christian Berentsen <jc.berentsen@gmail.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_INTERCEPTOR_H__
#define __GUM_INTERCEPTOR_H__

#include <glib-object.h>
#include <gum/gumdefs.h>
#include <gum/guminvocationlistener.h>

G_BEGIN_DECLS

#define GUM_TYPE_INTERCEPTOR (gum_interceptor_get_type ())
G_DECLARE_FINAL_TYPE (GumInterceptor, gum_interceptor, GUM, INTERCEPTOR,
    GObject)

typedef GArray GumInvocationStack;

typedef enum
{
  GUM_ATTACH_OK               =  0,
  GUM_ATTACH_WRONG_SIGNATURE  = -1,
  GUM_ATTACH_ALREADY_ATTACHED = -2,
  GUM_ATTACH_POLICY_VIOLATION = -3
} GumAttachReturn;

typedef enum
{
  GUM_REPLACE_OK               =  0,
  GUM_REPLACE_WRONG_SIGNATURE  = -1,
  GUM_REPLACE_ALREADY_REPLACED = -2,
  GUM_REPLACE_POLICY_VIOLATION = -3
} GumReplaceReturn;

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
