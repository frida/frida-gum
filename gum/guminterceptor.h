/*
 * Copyright (C) 2008-2025 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 * Copyright (C) 2008 Christian Berentsen <jc.berentsen@gmail.com>
 * Copyright (C) 2024 Francesco Tamagni <mrmacete@protonmail.ch>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_INTERCEPTOR_H__
#define __GUM_INTERCEPTOR_H__

#include <gum/gumdefs.h>
#include <gum/guminvocationlistener.h>

#include <capstone.h>

G_BEGIN_DECLS

#define GUM_TYPE_INTERCEPTOR (gum_interceptor_get_type ())
G_DECLARE_FINAL_TYPE (GumInterceptor, gum_interceptor, GUM, INTERCEPTOR,
                      GObject)

typedef GArray GumInvocationStack;
typedef guint GumInvocationState;
typedef void (* GumInterceptorLockedFunc) (gpointer user_data);

typedef enum
{
  GUM_ATTACH_FLAGS_NONE        = 0,
  GUM_ATTACH_FLAGS_UNIGNORABLE = (1 << 0),
} GumAttachFlags;

typedef enum
{
  GUM_ATTACH_OK               =  0,
  GUM_ATTACH_WRONG_SIGNATURE  = -1,
  GUM_ATTACH_ALREADY_ATTACHED = -2,
  GUM_ATTACH_POLICY_VIOLATION = -3,
  GUM_ATTACH_WRONG_TYPE       = -4,
} GumAttachReturn;

typedef enum
{
  GUM_REPLACE_OK               =  0,
  GUM_REPLACE_WRONG_SIGNATURE  = -1,
  GUM_REPLACE_ALREADY_REPLACED = -2,
  GUM_REPLACE_POLICY_VIOLATION = -3,
  GUM_REPLACE_WRONG_TYPE       = -4,
} GumReplaceReturn;

GUM_API GumInterceptor * gum_interceptor_obtain (void);

GUM_API GumAttachReturn gum_interceptor_attach (GumInterceptor * self,
    gpointer function_address, GumInvocationListener * listener,
    gpointer listener_function_data, GumAttachFlags flags);
GUM_API void gum_interceptor_detach (GumInterceptor * self,
    GumInvocationListener * listener);

GUM_API GumReplaceReturn gum_interceptor_replace (GumInterceptor * self,
    gpointer function_address, gpointer replacement_function,
    gpointer replacement_data, gpointer * original_function);
GumReplaceReturn gum_interceptor_replace_fast (GumInterceptor * self,
    gpointer function_address, gpointer replacement_function,
    gpointer * original_function);
GUM_API void gum_interceptor_revert (GumInterceptor * self,
    gpointer function_address);

GUM_API void gum_interceptor_begin_transaction (GumInterceptor * self);
GUM_API void gum_interceptor_end_transaction (GumInterceptor * self);
GUM_API gboolean gum_interceptor_flush (GumInterceptor * self);

GUM_API GumInvocationContext * gum_interceptor_get_current_invocation (void);
GUM_API GumInvocationContext * gum_interceptor_get_live_replacement_invocation (
    gpointer replacement_function);
GUM_API GumInvocationStack * gum_interceptor_get_current_stack (void);

GUM_API void gum_interceptor_ignore_current_thread (GumInterceptor * self);
GUM_API void gum_interceptor_unignore_current_thread (GumInterceptor * self);
GUM_API gboolean gum_interceptor_maybe_unignore_current_thread (
    GumInterceptor * self);

GUM_API void gum_interceptor_ignore_other_threads (GumInterceptor * self);
GUM_API void gum_interceptor_unignore_other_threads (GumInterceptor * self);

GUM_API gpointer gum_invocation_stack_translate (GumInvocationStack * self,
    gpointer return_address);

GUM_API void gum_interceptor_save (GumInvocationState * state);
GUM_API void gum_interceptor_restore (GumInvocationState * state);

GUM_API void gum_interceptor_with_lock_held (GumInterceptor * self,
    GumInterceptorLockedFunc func, gpointer user_data);
GUM_API gboolean gum_interceptor_is_locked (GumInterceptor * self);

// Configure the alternate stack for the interceptor. The alternate stack is
// used by the interceptor to run the intercepted code on a separate stack to
// avoid overflowing the current execution stack. The configuration applied when
// constructing new threads contexts, so it generally must be called before
// attaching the interceptor in order to apply.
GUM_API void gum_interceptor_configure_alternate_stack (gint stack_size);

// Configure the alternate stack for the interceptor. The alternate stack is
// used by the interceptor to run the intercepted code on a separate stack to
// avoid overflowing the current execution stack. The configuration applied when
// constructing new threads contexts, so it generally must be called before
// attaching the interceptor in order to apply.
GUM_API void gum_interceptor_configure_alternate_stack (gint stack_size);

GUM_API gsize gum_interceptor_detect_hook_size (gconstpointer code,
    csh capstone, cs_insn * insn);

G_END_DECLS

#endif
