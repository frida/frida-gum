/*
 * Copyright (C) 2015 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumexceptor.h"

#include "guminterceptor.h"
#include "gumtls.h"
#ifdef G_OS_WIN32
# include "backend-windows/gumwindows.h"
# include "arch-x86/gumx86writer.h"
#endif
#ifdef HAVE_DARWIN
# include "backend-darwin/gumdarwin.h"
#endif
#ifdef HAVE_LINUX
# include "backend-linux/gumlinux.h"
#endif
#ifdef HAVE_QNX
# include "backend-qnx/gumqnx.h"
#endif

#include <setjmp.h>
#include <stdlib.h>
#include <string.h>
#ifdef G_OS_WIN32
# include <capstone.h>
# include <tchar.h>
#else
# include <signal.h>
#endif
#ifdef HAVE_QNX
# include <sys/debug.h>
# include <unix.h>
#endif

typedef struct _GumExceptionHandlerEntry GumExceptionHandlerEntry;
#if defined (G_OS_WIN32) || defined (HAVE_DARWIN)
# define GUM_NATIVE_SETJMP setjmp
# define GUM_NATIVE_LONGJMP longjmp
  typedef jmp_buf GumExceptorNativeJmpBuf;
#else
# if defined (sigsetjmp) && !defined (HAVE_QNX)
#   define GUM_NATIVE_SETJMP __sigsetjmp
# else
#   define GUM_NATIVE_SETJMP sigsetjmp
# endif
# define GUM_NATIVE_LONGJMP siglongjmp
  typedef sigjmp_buf GumExceptorNativeJmpBuf;
#endif
#ifdef G_OS_WIN32
typedef BOOL (WINAPI * GumWindowsExceptionHandler) (
    EXCEPTION_RECORD * exception_record, CONTEXT * context);
#endif

#define GUM_EXCEPTOR_LOCK()   (g_mutex_lock (&priv->mutex))
#define GUM_EXCEPTOR_UNLOCK() (g_mutex_unlock (&priv->mutex))

struct _GumExceptorPrivate
{
  GMutex mutex;

  GumInterceptor * interceptor;
  GSList * handlers;
  GumTlsKey scope_tls;

#ifdef G_OS_WIN32
  GumWindowsExceptionHandler system_handler;

  gpointer dispatcher_impl;
  gint32 * dispatcher_impl_call_immediate;
  DWORD previous_page_protection;

  gpointer trampoline;
#else
  struct sigaction ** old_handlers;
  gint num_old_handlers;
#endif
};

struct _GumExceptionHandlerEntry
{
  GumExceptionHandler func;
  gpointer user_data;
};

struct _GumExceptorScopeImpl
{
  GumExceptorNativeJmpBuf env;
  gboolean exception_occurred;
#ifdef HAVE_ANDROID
  sigset_t mask;
#endif
};

static void gum_exceptor_dispose (GObject * object);
static void gum_exceptor_finalize (GObject * object);
static void the_exceptor_weak_notify (gpointer data,
    GObject * where_the_object_was);

static gboolean gum_exceptor_handle_scope_exception (
    GumExceptionDetails * details, gpointer user_data);

static void gum_exceptor_attach (GumExceptor * self);
static void gum_exceptor_detach (GumExceptor * self);

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

  object_class->dispose = gum_exceptor_dispose;
  object_class->finalize = gum_exceptor_finalize;
}

static void
gum_exceptor_init (GumExceptor * self)
{
  GumExceptorPrivate * priv;

  self->priv = priv = G_TYPE_INSTANCE_GET_PRIVATE (self, GUM_TYPE_EXCEPTOR,
      GumExceptorPrivate);

  g_mutex_init (&priv->mutex);

  priv->interceptor = gum_interceptor_obtain ();

  priv->scope_tls = gum_tls_key_new ();

  gum_exceptor_add (self, gum_exceptor_handle_scope_exception, self);
}

static void
gum_exceptor_dispose (GObject * object)
{
  GumExceptor * self = GUM_EXCEPTOR (object);
  GumExceptorPrivate * priv = self->priv;

  if (priv->interceptor != NULL)
  {
    gum_exceptor_detach (self);

    g_object_unref (priv->interceptor);
    priv->interceptor = NULL;
  }

  G_OBJECT_CLASS (gum_exceptor_parent_class)->dispose (object);
}

static void
gum_exceptor_finalize (GObject * object)
{
  GumExceptor * self = GUM_EXCEPTOR (object);
  GumExceptorPrivate * priv = self->priv;

  gum_exceptor_remove (self, gum_exceptor_handle_scope_exception, self);

  gum_tls_key_free (priv->scope_tls);

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

    gum_exceptor_attach (the_exceptor);

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

#ifndef G_OS_WIN32

static void
gum_exceptor_abort (GumExceptor * self,
                    GumExceptionDetails * details)
{
  /* TODO: should we create a backtrace and log it? */
  abort ();
}

#endif

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

  if (scope->impl != NULL)
    return scope->impl->env;

  impl = g_slice_new (GumExceptorScopeImpl);
  impl->exception_occurred = FALSE;
#ifdef HAVE_ANDROID
  /* Workaround for Bionic bug up to and including Android L */
  sigprocmask (SIG_SETMASK, NULL, &impl->mask);
#endif

  scope->impl = impl;
  scope->next = gum_tls_key_get_value (self->priv->scope_tls);

  gum_tls_key_set_value (self->priv->scope_tls, scope);

  return impl->env;
}

gboolean
gum_exceptor_catch (GumExceptor * self,
                    GumExceptorScope * scope)
{
  GumExceptorScopeImpl * impl = scope->impl;
  gboolean exception_occurred;

  gum_tls_key_set_value (self->priv->scope_tls, scope->next);

  exception_occurred = impl->exception_occurred;
  g_slice_free (GumExceptorScopeImpl, impl);
  scope->impl = NULL;

  return exception_occurred;
}

gchar *
gum_exception_details_to_string (const GumExceptionDetails * details)
{
  GString * message;

  message = g_string_new ("");

  switch (details->type)
  {
    case GUM_EXCEPTION_ABORT:
      g_string_append (message, "abort was called");
      break;
    case GUM_EXCEPTION_ACCESS_VIOLATION:
      g_string_append (message, "access violation");
      break;
    case GUM_EXCEPTION_GUARD_PAGE:
      g_string_append (message, "guard page was hit");
      break;
    case GUM_EXCEPTION_ILLEGAL_INSTRUCTION:
      g_string_append (message, "illegal instruction");
      break;
    case GUM_EXCEPTION_STACK_OVERFLOW:
      g_string_append (message, "stack overflow");
      break;
    case GUM_EXCEPTION_ARITHMETIC:
      g_string_append (message, "arithmetic error");
      break;
    case GUM_EXCEPTION_BREAKPOINT:
      g_string_append (message, "breakpoint triggered");
      break;
    case GUM_EXCEPTION_SINGLE_STEP:
      g_string_append (message, "single-step triggered");
      break;
    case GUM_EXCEPTION_SYSTEM:
      g_string_append (message, "system error");
      break;
    default:
      break;
  }

  if (details->memory.operation != GUM_MEMOP_INVALID)
  {
    g_string_append_printf (message, " accessing 0x%" G_GSIZE_MODIFIER "x",
        GPOINTER_TO_SIZE (details->memory.address));
  }

  return g_string_free (message, FALSE);
}

static gboolean
gum_exceptor_handle_scope_exception (GumExceptionDetails * details,
                                     gpointer user_data)
{
  GumExceptor * self = GUM_EXCEPTOR_CAST (user_data);
  GumExceptorScope * scope;
  GumExceptorScopeImpl * impl;
  GumCpuContext * context = &details->context;

  scope = (GumExceptorScope *) gum_tls_key_get_value (self->priv->scope_tls);
  if (scope == NULL)
    return FALSE;

  impl = scope->impl;
  if (impl->exception_occurred)
    return FALSE;

  impl->exception_occurred = TRUE;
  memcpy (&scope->exception, details, sizeof (GumExceptionDetails));
  scope->exception.native_context = NULL;

  /*
   * Place IP at the start of the function as if the call already happened,
   * and set up stack and registers accordingly.
   */
#if defined (HAVE_I386)
  GUM_CPU_CONTEXT_XIP (context) = GPOINTER_TO_SIZE (
      GUM_FUNCPTR_TO_POINTER (gum_exceptor_scope_impl_perform_longjmp));

  /* Align to 16 byte boundary (Mac ABI) */
  GUM_CPU_CONTEXT_XSP (context) &= ~(gsize) (16 - 1);
  /* Avoid the red zone (when applicable) */
  GUM_CPU_CONTEXT_XSP (context) -= GUM_RED_ZONE_SIZE;
  /* Reserve spill space for first four arguments (Win64 ABI) */
  GUM_CPU_CONTEXT_XSP (context) -= 4 * 8;

# if GLIB_SIZEOF_VOID_P == 4
  /* 32-bit: First argument goes on the stack (cdecl) */
  *((GumExceptorScopeImpl **) context->esp) = impl;
# else
  /* 64-bit: First argument goes in a register */
#  if GUM_NATIVE_ABI_IS_WINDOWS
  context->rcx = GPOINTER_TO_SIZE (impl);
#  else
  context->rdi = GPOINTER_TO_SIZE (impl);
#  endif
# endif

  /* Dummy return address (we won't return) */
  GUM_CPU_CONTEXT_XSP (context) -= sizeof (gpointer);
  *((gsize *) GUM_CPU_CONTEXT_XSP (context)) = 1337;
#elif defined (HAVE_ARM) || defined (HAVE_ARM64)
  context->pc = GPOINTER_TO_SIZE (
      GUM_FUNCPTR_TO_POINTER (gum_exceptor_scope_impl_perform_longjmp));

  /* Align to 16 byte boundary */
  context->sp &= ~(gsize) (16 - 1);
  /* Avoid the red zone (when applicable) */
  context->sp -= GUM_RED_ZONE_SIZE;

# if GLIB_SIZEOF_VOID_P == 4
  context->r[0] = GPOINTER_TO_SIZE (impl);
# else
  context->x[0] = GPOINTER_TO_SIZE (impl);
# endif

  /* Dummy return address (we won't return) */
  context->lr = 1337;
#elif defined (HAVE_MIPS)
  context->pc = GPOINTER_TO_SIZE (
      GUM_FUNCPTR_TO_POINTER (gum_exceptor_scope_impl_perform_longjmp));

  /* set t9 to gum_exceptor_scope_impl_perform_longjmp, as it is PIC and needs
   * t9 for the gp calculation.
   */
  context->t9 = context->pc;

  /* Align to 16 byte boundary */
  context->sp &= ~(gsize) (16 - 1);
  /* Avoid the red zone (when applicable) */
  context->sp -= GUM_RED_ZONE_SIZE;

  context->a0 = GPOINTER_TO_SIZE (impl);

  /* Dummy return address (we won't return) */
  context->ra = 1337;
#else
# error Unsupported architecture
#endif

  return TRUE;
}

#ifdef G_OS_WIN32

static BOOL gum_exceptor_dispatch (EXCEPTION_RECORD * exception_record,
    CONTEXT * context);

static void
gum_exceptor_attach (GumExceptor * self)
{
  GumExceptorPrivate * priv = self->priv;
  HMODULE ntdll_mod;
  csh capstone;
  cs_err err;
  guint offset;

  ntdll_mod = GetModuleHandle (_T ("ntdll.dll"));
  g_assert (ntdll_mod != NULL);

  priv->dispatcher_impl = GUM_FUNCPTR_TO_POINTER (
      GetProcAddress (ntdll_mod, "KiUserExceptionDispatcher"));
  g_assert (priv->dispatcher_impl != NULL);

  err = cs_open (CS_ARCH_X86, GUM_CPU_MODE, &capstone);
  g_assert_cmpint (err, == , CS_ERR_OK);
  err = cs_option (capstone, CS_OPT_DETAIL, CS_OPT_ON);
  g_assert_cmpint (err, == , CS_ERR_OK);

  offset = 0;
  while (priv->system_handler == NULL)
  {
    cs_insn * insn = NULL;

    cs_disasm (capstone,
        (guint8 *) priv->dispatcher_impl + offset, 16,
        GPOINTER_TO_SIZE (priv->dispatcher_impl) + offset,
        1, &insn);
    g_assert (insn != NULL);

    offset += insn->size;

    if (insn->id == X86_INS_CALL)
    {
      cs_x86_op * op = &insn->detail->x86.operands[0];
      if (op->type == X86_OP_IMM)
      {
        guint8 * call_begin, * call_end;
        gssize distance;

        call_begin = (guint8 *) insn->address;
        call_end = call_begin + insn->size;

        priv->system_handler = GUM_POINTER_TO_FUNCPTR (
            GumWindowsExceptionHandler, op->imm);

        VirtualProtect (priv->dispatcher_impl, 4096,
            PAGE_EXECUTE_READWRITE, &priv->previous_page_protection);
        priv->dispatcher_impl_call_immediate = (gint32 *) (call_begin + 1);

        distance = (gssize) gum_exceptor_dispatch - (gssize) call_end;
        if (!GUM_IS_WITHIN_INT32_RANGE (distance))
        {
          GumAddressSpec as;
          GumX86Writer cw;

          as.near_address = priv->dispatcher_impl;
          as.max_distance = (G_MAXINT32 - 16384);
          priv->trampoline = gum_alloc_n_pages_near (1, GUM_PAGE_RWX, &as);

          gum_x86_writer_init (&cw, priv->trampoline);
          gum_x86_writer_put_jmp (&cw,
              GUM_FUNCPTR_TO_POINTER (gum_exceptor_dispatch));
          gum_x86_writer_free (&cw);

          distance = (gssize) priv->trampoline - (gssize) call_end;
        }

        *priv->dispatcher_impl_call_immediate = distance;
      }
    }

    cs_free (insn, 1);
  }
}

static void
gum_exceptor_detach (GumExceptor * self)
{
  GumExceptorPrivate * priv = self->priv;
  DWORD page_prot;

  *priv->dispatcher_impl_call_immediate =
      (gssize) priv->system_handler -
      (gssize) (priv->dispatcher_impl_call_immediate + 1);

  VirtualProtect (priv->dispatcher_impl, 4096,
      priv->previous_page_protection, &page_prot);

  priv->system_handler = NULL;

  priv->dispatcher_impl = NULL;
  priv->dispatcher_impl_call_immediate = NULL;
  priv->previous_page_protection = 0;

  if (priv->trampoline != NULL)
  {
    gum_free_pages (priv->trampoline);
    priv->trampoline = NULL;
  }
}

static BOOL
gum_exceptor_dispatch (EXCEPTION_RECORD * exception_record,
                       CONTEXT * context)
{
  GumExceptor * self = the_exceptor;
  GumExceptorPrivate * priv = self->priv;
  GumExceptionDetails ed;
  GumExceptionMemoryDetails * md = &ed.memory;
  GumCpuContext * cpu_context = &ed.context;

  switch (exception_record->ExceptionCode)
  {
    case EXCEPTION_ACCESS_VIOLATION:
    case EXCEPTION_DATATYPE_MISALIGNMENT:
    case EXCEPTION_ARRAY_BOUNDS_EXCEEDED:
      ed.type = GUM_EXCEPTION_ACCESS_VIOLATION;
      break;
    case EXCEPTION_GUARD_PAGE:
      ed.type = GUM_EXCEPTION_GUARD_PAGE;
      break;
    case EXCEPTION_ILLEGAL_INSTRUCTION:
    case EXCEPTION_PRIV_INSTRUCTION:
      ed.type = GUM_EXCEPTION_ILLEGAL_INSTRUCTION;
      break;
    case EXCEPTION_STACK_OVERFLOW:
      ed.type = GUM_EXCEPTION_STACK_OVERFLOW;
      break;
    case EXCEPTION_FLT_DENORMAL_OPERAND:
    case EXCEPTION_FLT_DIVIDE_BY_ZERO:
    case EXCEPTION_FLT_INEXACT_RESULT:
    case EXCEPTION_FLT_INVALID_OPERATION:
    case EXCEPTION_FLT_OVERFLOW:
    case EXCEPTION_FLT_STACK_CHECK:
    case EXCEPTION_FLT_UNDERFLOW:
    case EXCEPTION_INT_DIVIDE_BY_ZERO:
    case EXCEPTION_INT_OVERFLOW:
      ed.type = GUM_EXCEPTION_ARITHMETIC;
      break;
    case EXCEPTION_BREAKPOINT:
      ed.type = GUM_EXCEPTION_BREAKPOINT;
      break;
    case EXCEPTION_SINGLE_STEP:
      ed.type = GUM_EXCEPTION_SINGLE_STEP;
      break;
    default:
      ed.type = GUM_EXCEPTION_SYSTEM;
      break;
  }

  ed.address = exception_record->ExceptionAddress;

  switch (exception_record->ExceptionCode)
  {
    case EXCEPTION_ACCESS_VIOLATION:
    case EXCEPTION_GUARD_PAGE:
    case EXCEPTION_IN_PAGE_ERROR:
      switch (exception_record->ExceptionInformation[0])
      {
        case 0:
          md->operation = GUM_MEMOP_READ;
          break;
        case 1:
          md->operation = GUM_MEMOP_WRITE;
          break;
        case 8:
          md->operation = GUM_MEMOP_EXECUTE;
          break;
        default:
          md->operation = GUM_MEMOP_INVALID;
          break;
      }
      md->address =
          GSIZE_TO_POINTER (exception_record->ExceptionInformation[1]);
      break;
    default:
      md->operation = GUM_MEMOP_INVALID;
      md->address = 0;
      break;
  }

  gum_windows_parse_context (context, cpu_context);
  ed.native_context = context;

  if (gum_exceptor_handle (self, &ed))
  {
    gum_windows_unparse_context (cpu_context, context);
    return TRUE;
  }

  return priv->system_handler (exception_record, context);
}

#else

static void gum_exceptor_detach_handler (GumExceptor * self, int sig);
static sig_t gum_exceptor_replacement_signal (int sig, sig_t handler);
static int gum_exceptor_replacement_sigaction (int sig,
    const struct sigaction * act, struct sigaction * oact);
static void gum_exceptor_on_signal (int sig, siginfo_t * siginfo,
    void * context);
static gboolean gum_is_signal_handler_chainable (sig_t handler);
static void gum_exceptor_parse_context (gconstpointer context,
    GumCpuContext * ctx);
static void gum_exceptor_unparse_context (const GumCpuContext * ctx,
    gpointer context);

static void
gum_exceptor_attach (GumExceptor * self)
{
  GumExceptorPrivate * priv = self->priv;
  const gint handled_signals[] = {
    SIGABRT,
    SIGSEGV,
    SIGBUS,
    SIGILL,
    SIGFPE,
    SIGTRAP,
    SIGSYS,
  };
  gint highest, i;
  struct sigaction action;

  highest = handled_signals[0];
  for (i = 0; i != G_N_ELEMENTS (handled_signals); i++)
    highest = MAX (handled_signals[i], highest);
  g_assert_cmpint (highest, >, 0);
  priv->num_old_handlers = highest + 1;
  priv->old_handlers = g_new0 (struct sigaction *, priv->num_old_handlers);

  action.sa_sigaction = gum_exceptor_on_signal;
  sigemptyset (&action.sa_mask);
  action.sa_flags = SA_SIGINFO;
  for (i = 0; i != G_N_ELEMENTS (handled_signals); i++)
  {
    gint sig = handled_signals[i];
    struct sigaction * old_handler;

    old_handler = g_slice_new0 (struct sigaction);
    priv->old_handlers[sig] = old_handler;
    sigaction (sig, &action, old_handler);
  }

  gum_interceptor_begin_transaction (priv->interceptor);

  gum_interceptor_replace_function (priv->interceptor, signal,
      gum_exceptor_replacement_signal, self);
  gum_interceptor_replace_function (priv->interceptor, sigaction,
      gum_exceptor_replacement_sigaction, self);

  gum_interceptor_end_transaction (priv->interceptor);
}

static void
gum_exceptor_detach (GumExceptor * self)
{
  GumExceptorPrivate * priv = self->priv;
  gint i;

  gum_interceptor_begin_transaction (priv->interceptor);

  gum_interceptor_revert_function (priv->interceptor, signal);
  gum_interceptor_revert_function (priv->interceptor, sigaction);

  gum_interceptor_end_transaction (priv->interceptor);

  for (i = 0; i != priv->num_old_handlers; i++)
    gum_exceptor_detach_handler (self, i);
  g_free (priv->old_handlers);
  priv->old_handlers = NULL;
  priv->num_old_handlers = 0;
}

static void
gum_exceptor_detach_handler (GumExceptor * self,
                             int sig)
{
  GumExceptorPrivate * priv = self->priv;
  struct sigaction * old_handler;

  old_handler = priv->old_handlers[sig];
  if (old_handler != NULL)
  {
    priv->old_handlers[sig] = NULL;
    sigaction (sig, old_handler, NULL);
    g_slice_free (struct sigaction, old_handler);
  }
}

static struct sigaction *
gum_exceptor_get_old_handler (GumExceptor * self,
                              gint sig)
{
  GumExceptorPrivate * priv = self->priv;

  if (sig < 0 || sig >= priv->num_old_handlers)
    return NULL;

  return priv->old_handlers[sig];
}

static sig_t
gum_exceptor_replacement_signal (int sig,
                                 sig_t handler)
{
  GumExceptor * self;
  GumInvocationContext * ctx;
  struct sigaction * old_handler;
  sig_t result;

  ctx = gum_interceptor_get_current_invocation ();
  g_assert (ctx != NULL);

  self = GUM_EXCEPTOR_CAST (
      gum_invocation_context_get_replacement_function_data (ctx));

  old_handler = gum_exceptor_get_old_handler (self, sig);
  if (old_handler == NULL)
    goto passthrough;

  result = ((old_handler->sa_flags & SA_SIGINFO) != 0)
      ? old_handler->sa_handler
      : SIG_DFL;

  old_handler->sa_handler = handler;
  old_handler->sa_flags &= ~SA_SIGINFO;

  return result;

passthrough:
  return signal (sig, handler);
}

static int
gum_exceptor_replacement_sigaction (int sig,
                                    const struct sigaction * act,
                                    struct sigaction * oact)
{
  GumExceptor * self;
  GumInvocationContext * ctx;
  struct sigaction * old_handler;

  ctx = gum_interceptor_get_current_invocation ();
  g_assert (ctx != NULL);

  self = GUM_EXCEPTOR_CAST (
      gum_invocation_context_get_replacement_function_data (ctx));

  old_handler = gum_exceptor_get_old_handler (self, sig);
  if (old_handler == NULL)
    goto passthrough;

  if (oact != NULL)
    *oact = *old_handler;
  if (act != NULL)
    *old_handler = *act;

  return 0;

passthrough:
  return sigaction (sig, act, oact);
}

static void
gum_exceptor_on_signal (int sig,
                        siginfo_t * siginfo,
                        void * context)
{
  GumExceptor * self = the_exceptor;
  GumExceptorPrivate * priv = self->priv;
  GumExceptionDetails ed;
  GumExceptionMemoryDetails * md = &ed.memory;
  GumCpuContext * cpu_context = &ed.context;
  struct sigaction * action = priv->old_handlers[sig];

  switch (sig)
  {
    case SIGABRT:
      ed.type = GUM_EXCEPTION_ABORT;
      break;
    case SIGSEGV:
    case SIGBUS:
      ed.type = GUM_EXCEPTION_ACCESS_VIOLATION;
      break;
    case SIGILL:
      ed.type = GUM_EXCEPTION_ILLEGAL_INSTRUCTION;
      break;
    case SIGFPE:
      ed.type = GUM_EXCEPTION_ARITHMETIC;
      break;
    case SIGTRAP:
      ed.type = GUM_EXCEPTION_BREAKPOINT;
      break;
    default:
      ed.type = GUM_EXCEPTION_SYSTEM;
      break;
  }

  gum_exceptor_parse_context (context, cpu_context);
  ed.native_context = context;

#if defined (HAVE_I386)
  ed.address = GSIZE_TO_POINTER (GUM_CPU_CONTEXT_XIP (cpu_context));
#elif defined (HAVE_ARM) || defined (HAVE_ARM64)
  ed.address = GSIZE_TO_POINTER (cpu_context->pc);
#elif defined (HAVE_MIPS)
  ed.address = GSIZE_TO_POINTER (cpu_context->pc);
#else
# error Unsupported architecture
#endif

  switch (sig)
  {
    case SIGSEGV:
    case SIGBUS:
      if (siginfo->si_addr == ed.address)
        md->operation = GUM_MEMOP_EXECUTE;
      else
        md->operation = GUM_MEMOP_READ; /* FIXME */
      md->address = siginfo->si_addr;
      break;
    default:
      md->operation = GUM_MEMOP_INVALID;
      md->address = NULL;
      break;
  }

  if (action == NULL)
    gum_exceptor_abort (self, &ed);

  if (gum_exceptor_handle (self, &ed))
  {
    gum_exceptor_unparse_context (cpu_context, context);
    return;
  }

  if ((action->sa_flags & SA_SIGINFO) != 0)
  {
    if (action->sa_sigaction != NULL)
      action->sa_sigaction (sig, siginfo, context);
    else
      goto panic;
  }
  else
  {
    if (gum_is_signal_handler_chainable (action->sa_handler))
      action->sa_handler (sig);
    else if (action->sa_handler == SIG_IGN)
      return;
    else
      goto panic;
  }

  return;

panic:
  gum_exceptor_detach_handler (self, sig);
}

static gboolean
gum_is_signal_handler_chainable (sig_t handler)
{
  return handler != SIG_DFL && handler != SIG_IGN && handler != SIG_ERR;
}

#if defined (HAVE_DARWIN)

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

#elif defined (HAVE_LINUX)

static void
gum_exceptor_parse_context (gconstpointer context,
                            GumCpuContext * ctx)
{
  const ucontext_t * uc = context;

  gum_linux_parse_ucontext (uc, ctx);
}

static void
gum_exceptor_unparse_context (const GumCpuContext * ctx,
                              gpointer context)
{
  ucontext_t * uc = context;

  gum_linux_unparse_ucontext (ctx, uc);
}

#elif defined (HAVE_QNX)

static void
gum_exceptor_parse_context (gconstpointer context,
                            GumCpuContext * ctx)
{
  const ucontext_t * uc = context;

  gum_qnx_parse_ucontext (uc, ctx);
}

static void
gum_exceptor_unparse_context (const GumCpuContext * ctx,
                              gpointer context)
{
  ucontext_t * uc = context;

  gum_qnx_unparse_ucontext (ctx, uc);
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
