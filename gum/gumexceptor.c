/*
 * Copyright (C) 2015 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumexceptor.h"

#ifdef G_OS_WIN32
# include "backend-windows/gumwinexceptionhook.h"
#endif
#include "gumtls.h"

#ifdef HAVE_DARWIN
# include "backend-darwin/gumdarwin.h"
#endif

#include <setjmp.h>
#ifndef G_OS_WIN32
# include <signal.h>
#endif
#include <stdlib.h>

typedef struct _GumExceptionHandlerEntry GumExceptionHandlerEntry;
#if defined (G_OS_WIN32) || defined (HAVE_DARWIN)
# define GUM_NATIVE_SETJMP setjmp
# define GUM_NATIVE_LONGJMP longjmp
  typedef jmp_buf GumExceptorNativeJmpBuf;
#else
# define GUM_NATIVE_SETJMP sigsetjmp
# define GUM_NATIVE_LONGJMP siglongjmp
  typedef sigjmp_buf GumExceptorNativeJmpBuf;
#endif

#define GUM_EXCEPTOR_LOCK()   (g_mutex_lock (&priv->mutex))
#define GUM_EXCEPTOR_UNLOCK() (g_mutex_unlock (&priv->mutex))

struct _GumExceptorPrivate
{
  GMutex mutex;

  GSList * handlers;
  GumTlsKey scope_tls;

#ifndef G_OS_WIN32
  struct sigaction old_sigsegv;
  struct sigaction old_sigbus;
#endif
};

struct _GumExceptionHandlerEntry
{
  GumExceptionHandler func;
  gpointer user_data;
};

struct _GumExceptorScopeImpl
{
  gboolean exception_occurred;
  GumExceptorNativeJmpBuf env;
#ifdef HAVE_ANDROID
  sigset_t mask;
#endif
};

static void gum_exceptor_finalize (GObject * object);
static void the_exceptor_weak_notify (gpointer data,
    GObject * where_the_object_was);

static gboolean gum_exceptor_handle_scope_exception (
    GumExceptionDetails * details, gpointer user_data);

#ifdef G_OS_WIN32
static gboolean gum_exceptor_on_exception (
    EXCEPTION_RECORD * exception_record, CONTEXT * context,
    gpointer user_data);
#else
static void gum_exceptor_on_signal (int sig, siginfo_t * siginfo,
    void * context);
static void gum_exceptor_parse_context (gconstpointer context,
    GumCpuContext * ctx);
static void gum_exceptor_unparse_context (const GumCpuContext * ctx,
    gpointer context);
#endif

static void gum_exceptor_scope_impl_perform_longjmp (
    GumExceptorScopeImpl * impl);

G_DEFINE_TYPE (GumExceptor, gum_exceptor, G_TYPE_OBJECT);

G_LOCK_DEFINE_STATIC (the_exceptor);
static GumExceptor * the_exceptor = NULL;

static void
gum_exceptor_class_init (GumExceptorClass * klass)
{
  GObjectClass * object_class = G_OBJECT_CLASS (klass);

  g_type_class_add_private (klass, sizeof (GumExceptorPrivate));

  object_class->finalize = gum_exceptor_finalize;
}

static void
gum_exceptor_init (GumExceptor * self)
{
  GumExceptorPrivate * priv;

  self->priv = priv = G_TYPE_INSTANCE_GET_PRIVATE (self, GUM_TYPE_EXCEPTOR,
      GumExceptorPrivate);

  g_mutex_init (&priv->mutex);

  GUM_TLS_KEY_INIT (&priv->scope_tls);

#ifdef G_OS_WIN32
  gum_win_exception_hook_add (gum_exceptor_on_exception, self);
#else
  struct sigaction action;
  action.sa_sigaction = gum_exceptor_on_signal;
  sigemptyset (&action.sa_mask);
  action.sa_flags = SA_SIGINFO;
  sigaction (SIGSEGV, &action, &priv->old_sigsegv);
  sigaction (SIGBUS, &action, &priv->old_sigbus);
#endif

  gum_exceptor_add (self, gum_exceptor_handle_scope_exception, self);
}

static void
gum_exceptor_finalize (GObject * object)
{
  GumExceptor * self = GUM_EXCEPTOR (object);
  GumExceptorPrivate * priv = self->priv;

  gum_exceptor_remove (self, gum_exceptor_handle_scope_exception, self);

#ifdef G_OS_WIN32
  gum_win_exception_hook_remove (gum_exceptor_on_exception, self);
#else
  sigaction (SIGSEGV, &priv->old_sigsegv, NULL);
  sigaction (SIGBUS, &priv->old_sigbus, NULL);
#endif

  GUM_TLS_KEY_FREE (priv->scope_tls);

  g_mutex_clear (&priv->mutex);

  G_OBJECT_CLASS (gum_exceptor_parent_class)->finalize (object);
}

GumExceptor *
gum_exceptor_obtain (void)
{
  GumExceptor * exceptor;

  G_LOCK (the_exceptor);

  if (the_exceptor != NULL)
  {
    exceptor = GUM_EXCEPTOR_CAST (g_object_ref (the_exceptor));
  }
  else
  {
    the_exceptor = GUM_EXCEPTOR_CAST (g_object_new (GUM_TYPE_EXCEPTOR, NULL));
    g_object_weak_ref (G_OBJECT (the_exceptor), the_exceptor_weak_notify, NULL);

    exceptor = the_exceptor;
  }

  G_UNLOCK (the_exceptor);

  return exceptor;
}

static void
the_exceptor_weak_notify (gpointer data,
                          GObject * where_the_object_was)
{
  (void) data;

  G_LOCK (the_exceptor);

  g_assert (the_exceptor == (GumExceptor *) where_the_object_was);
  the_exceptor = NULL;

  G_UNLOCK (the_exceptor);
}

void
gum_exceptor_add (GumExceptor * self,
                  GumExceptionHandler func,
                  gpointer user_data)
{
  GumExceptorPrivate * priv = self->priv;
  GumExceptionHandlerEntry * entry;

  entry = g_slice_new (GumExceptionHandlerEntry);
  entry->func = func;
  entry->user_data = user_data;

  GUM_EXCEPTOR_LOCK ();
  priv->handlers = g_slist_append (priv->handlers, entry);
  GUM_EXCEPTOR_UNLOCK ();
}

void
gum_exceptor_remove (GumExceptor * self,
                     GumExceptionHandler func,
                     gpointer user_data)
{
  GumExceptorPrivate * priv = self->priv;
  GumExceptionHandlerEntry * matching_entry;
  GSList * cur;

  GUM_EXCEPTOR_LOCK ();

  for (matching_entry = NULL, cur = priv->handlers;
      matching_entry == NULL && cur != NULL;
      cur = cur->next)
  {
    GumExceptionHandlerEntry * entry = (GumExceptionHandlerEntry *) cur->data;

    if (entry->func == func && entry->user_data == user_data)
      matching_entry = entry;
  }

  g_assert (matching_entry != NULL);

  priv->handlers = g_slist_remove (priv->handlers, matching_entry);

  GUM_EXCEPTOR_UNLOCK ();

  g_slice_free (GumExceptionHandlerEntry, matching_entry);
}

static gboolean
gum_exceptor_handle (GumExceptor * self,
                     GumExceptionDetails * details)
{
  GumExceptorPrivate * priv = self->priv;
  gboolean handled = FALSE;
  GSList * invoked = NULL;
  GumExceptionHandlerEntry e;

  do
  {
    GSList * cur;

    e.func = NULL;
    e.user_data = NULL;

    GUM_EXCEPTOR_LOCK ();
    for (cur = priv->handlers; e.func == NULL && cur != NULL; cur = cur->next)
    {
      GumExceptionHandlerEntry * entry = (GumExceptionHandlerEntry *) cur->data;

      if (g_slist_find (invoked, entry) == NULL)
      {
        invoked = g_slist_prepend (invoked, entry);
        e = *entry;
      }
    }
    GUM_EXCEPTOR_UNLOCK ();

    if (e.func != NULL)
      handled = e.func (details, e.user_data);
  }
  while (!handled && e.func != NULL);

  g_slist_free (invoked);

  return handled;
}

GumExceptorSetJmp
_gum_exceptor_get_setjmp (void)
{
  return GUM_POINTER_TO_FUNCPTR (GumExceptorSetJmp,
      GUM_FUNCPTR_TO_POINTER (GUM_NATIVE_SETJMP));
}

GumExceptorJmpBuf
_gum_exceptor_prepare_try (GumExceptor * self,
                           GumExceptorScope * scope)
{
  GumExceptorScopeImpl * impl;

  impl = g_slice_new (GumExceptorScopeImpl);
  impl->exception_occurred = FALSE;
#ifdef HAVE_ANDROID
  /* Workaround for Bionic bug up to and including Android L */
  sigprocmask (SIG_SETMASK, NULL, &impl->mask);
#endif

  scope->impl = impl;

  GUM_TLS_KEY_SET_VALUE (self->priv->scope_tls, scope);

  return impl->env;
}

gboolean
gum_exceptor_catch (GumExceptor * self,
                    GumExceptorScope * scope)
{
  GumExceptorScopeImpl * impl = scope->impl;
  gboolean exception_occurred;

  GUM_TLS_KEY_SET_VALUE (self->priv->scope_tls, NULL);

  exception_occurred = impl->exception_occurred;
  g_slice_free (GumExceptorScopeImpl, impl);
  scope->impl = NULL;

  return exception_occurred;
}

static gboolean
gum_exceptor_handle_scope_exception (GumExceptionDetails * details,
                                     gpointer user_data)
{
  GumExceptor * self = GUM_EXCEPTOR_CAST (user_data);
  GumExceptorScope * scope;
  GumExceptorScopeImpl * impl;
  GumCpuContext * cpu_context = &details->cpu_context;

  scope = (GumExceptorScope *) GUM_TLS_KEY_GET_VALUE (self->priv->scope_tls);
  if (scope == NULL)
    return FALSE;

  impl = scope->impl;
  if (impl->exception_occurred)
    return FALSE;

  impl->exception_occurred = TRUE;
  memcpy (&scope->exception, details, sizeof (GumExceptionDetails));

  /*
   * Place IP at the start of the function as if the call already happened,
   * and set up stack and registers accordingly.
   */
#if defined (HAVE_I386)
  GUM_CPU_CONTEXT_XIP (cpu_context) = GPOINTER_TO_SIZE (
      GUM_FUNCPTR_TO_POINTER (gum_exceptor_scope_impl_perform_longjmp));

  /* Align to 16 byte boundary (Mac ABI) */
  GUM_CPU_CONTEXT_XSP (cpu_context) &= ~(gsize) (16 - 1);
  /* Avoid the red zone (when applicable) */
  GUM_CPU_CONTEXT_XSP (cpu_context) -= GUM_RED_ZONE_SIZE;
  /* Reserve spill space for first four arguments (Win64 ABI) */
  GUM_CPU_CONTEXT_XSP (cpu_context) -= 4 * 8;

# if GLIB_SIZEOF_VOID_P == 4
  /* 32-bit: First argument goes on the stack (cdecl) */
  *((GumExceptorScopeImpl **) cpu_context->esp) = impl;
# else
  /* 64-bit: First argument goes in a register */
#  if GUM_NATIVE_ABI_IS_WINDOWS
  cpu_context->rcx = GPOINTER_TO_SIZE (impl);
#  else
  cpu_context->rdi = GPOINTER_TO_SIZE (impl);
#  endif
# endif

  /* Dummy return address (we won't return) */
  GUM_CPU_CONTEXT_XSP (cpu_context) -= sizeof (gpointer);
  *((gsize *) GUM_CPU_CONTEXT_XSP (cpu_context)) = 1337;
#elif defined (HAVE_ARM) || defined (HAVE_ARM64)
  cpu_context->pc = GPOINTER_TO_SIZE (
      GUM_FUNCPTR_TO_POINTER (gum_exceptor_scope_impl_perform_longjmp));

  /* Align to 16 byte boundary */
  cpu_context->sp &= ~(gsize) (16 - 1);
  /* Avoid the red zone (when applicable) */
  cpu_context->sp -= GUM_RED_ZONE_SIZE;

# if GLIB_SIZEOF_VOID_P == 4
  cpu_context->r[0] = GPOINTER_TO_SIZE (impl);
# else
  cpu_context->x[0] = GPOINTER_TO_SIZE (impl);
# endif

  /* Dummy return address (we won't return) */
  cpu_context->lr = 1337;
#endif

  return TRUE;
}

#ifdef G_OS_WIN32

static gboolean
gum_exceptor_on_exception (EXCEPTION_RECORD * exception_record,
                           CONTEXT * context,
                           gpointer user_data)
{
  GumExceptor * self = GUM_EXCEPTOR_CAST (user_data);

  (void) user_data;
  /* address = (gpointer) exception_record->ExceptionInformation[1]; */

  return FALSE;
}

#else

static void
gum_exceptor_on_signal (int sig,
                        siginfo_t * siginfo,
                        void * context)
{
  GumExceptor * self = the_exceptor;
  GumExceptorPrivate * priv = self->priv;
  GumExceptionDetails ed;
  GumExceptionMemoryAccessDetails * mad = &ed.memory_access;
  GumCpuContext * cpu_context = &ed.cpu_context;
  struct sigaction * action;

  gum_exceptor_parse_context (context, cpu_context);

#if defined (HAVE_I386)
  ed.address = GUM_CPU_CONTEXT_XIP (cpu_context);
#elif defined (HAVE_ARM) || defined (HAVE_ARM64)
  ed.address = cpu_context->pc;
#else
# error Unsupported architecture
#endif

  switch (sig)
  {
    case SIGSEGV:
    case SIGBUS:
      ed.type = GUM_EXCEPTION_ACCESS_VIOLATION;

      /* TODO: can we determine this without disassembling PC? */
      mad->operation = GUM_MEMOP_READ;
      mad->address = siginfo->si_addr;
      break;
    default:
      g_assert_not_reached ();
  }

  if (gum_exceptor_handle (self, &ed))
  {
    gum_exceptor_unparse_context (cpu_context, context);
    return;
  }

  action = (sig == SIGSEGV) ? &priv->old_sigsegv : &priv->old_sigbus;
  if ((action->sa_flags & SA_SIGINFO) != 0)
  {
    if (action->sa_sigaction != NULL)
      action->sa_sigaction (sig, siginfo, context);
    else
      abort ();
  }
  else
  {
    if (action->sa_handler != NULL)
      action->sa_handler (sig);
    else
      abort ();
  }
}

#ifdef HAVE_DARWIN

static void
gum_exceptor_parse_context (gconstpointer context,
                            GumCpuContext * ctx)
{
  const ucontext_t * uc = context;

  gum_darwin_parse_native_thread_state (&uc->uc_mcontext->__ss, ctx);
}

static void
gum_exceptor_unparse_context (const GumCpuContext * ctx,
                              gpointer context)
{
  ucontext_t * uc = context;

  gum_darwin_unparse_native_thread_state (ctx, &uc->uc_mcontext->__ss);
}

#endif

#endif

static void
gum_exceptor_scope_impl_perform_longjmp (GumExceptorScopeImpl * impl)
{
#ifdef HAVE_ANDROID
  sigprocmask (SIG_SETMASK, &impl->mask, NULL);
#endif
  GUM_NATIVE_LONGJMP (impl->env, 1);
}
