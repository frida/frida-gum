/*
 * Copyright (C) 2015-2026 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 * Copyright (C) 2020 Francesco Tamagni <mrmacete@protonmail.ch>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumexceptor.h"

#include "gumexceptorbackend.h"

#include <string.h>
#if defined (G_OS_WIN32) && defined (HAVE_ARM64)
# include <windows.h>
#endif

typedef struct _GumExceptionHandlerEntry GumExceptionHandlerEntry;

#define GUM_EXCEPTOR_LOCK()   (g_mutex_lock (&self->mutex))
#define GUM_EXCEPTOR_UNLOCK() (g_mutex_unlock (&self->mutex))

#define GUM_LONGJMP_VALUE 1

struct _GumExceptor
{
  GObject parent;

  GMutex mutex;

  GSList * handlers;
  GHashTable * scopes;

  GumExceptorBackend * backend;
};

struct _GumExceptionHandlerEntry
{
  GumExceptionHandler func;
  gpointer user_data;
};

static void gum_exceptor_dispose (GObject * object);
static void gum_exceptor_finalize (GObject * object);
static void the_exceptor_weak_notify (gpointer data,
    GObject * where_the_object_was);

static gboolean gum_exceptor_handle_exception (GumExceptionDetails * details,
    GumExceptor * self);
static gboolean gum_exceptor_handle_scope_exception (
    GumExceptionDetails * details, gpointer user_data);

static void gum_exceptor_scope_perform_longjmp (GumExceptorScope * scope);
#if defined (G_OS_WIN32) && defined (HAVE_ARM64)
static void gum_exceptor_scope_restore_context (GumExceptorScope * scope);
#endif

G_DEFINE_TYPE (GumExceptor, gum_exceptor, G_TYPE_OBJECT)

G_LOCK_DEFINE_STATIC (the_exceptor);
static GumExceptor * the_exceptor = NULL;
static GumExceptorMode gum_exceptor_mode = GUM_EXCEPTOR_MODE_FULL;

static void
gum_exceptor_class_init (GumExceptorClass * klass)
{
  GObjectClass * object_class = G_OBJECT_CLASS (klass);

  object_class->dispose = gum_exceptor_dispose;
  object_class->finalize = gum_exceptor_finalize;
}

static void
gum_exceptor_init (GumExceptor * self)
{
  g_mutex_init (&self->mutex);

  self->scopes = g_hash_table_new (NULL, NULL);

  gum_exceptor_add (self, gum_exceptor_handle_scope_exception, self);

  gum_exceptor_reset (self);
}

static void
gum_exceptor_dispose (GObject * object)
{
  GumExceptor * self = GUM_EXCEPTOR (object);

  g_clear_object (&self->backend);

  G_OBJECT_CLASS (gum_exceptor_parent_class)->dispose (object);
}

static void
gum_exceptor_finalize (GObject * object)
{
  GumExceptor * self = GUM_EXCEPTOR (object);

  gum_exceptor_remove (self, gum_exceptor_handle_scope_exception, self);

  g_hash_table_unref (self->scopes);

  g_mutex_clear (&self->mutex);

  G_OBJECT_CLASS (gum_exceptor_parent_class)->finalize (object);
}

/**
 * gum_exceptor_set_mode:
 * @mode: the desired exceptor mode
 *
 * Configures how the exceptor handles exceptions:
 *
 * - %GUM_EXCEPTOR_MODE_FULL: install signal handlers and hook
 *   signal()/sigaction() so the target cannot override them (default).
 * - %GUM_EXCEPTOR_MODE_HANDLER_ONLY: install signal handlers but leave
 *   signal()/sigaction() alone, so the target is free to replace them.
 * - %GUM_EXCEPTOR_MODE_OFF: don't install anything.
 *
 * The signal()/sigaction() distinction is only meaningful on POSIX backends.
 * Must be called before the first gum_exceptor_obtain(), as the backend is
 * created on first obtain.
 */
void
gum_exceptor_set_mode (GumExceptorMode mode)
{
  g_assert (the_exceptor == NULL);

  gum_exceptor_mode = mode;
}

GumExceptorMode
_gum_exceptor_get_mode (void)
{
  return gum_exceptor_mode;
}

/**
 * gum_exceptor_obtain:
 *
 * Obtains the exceptor singleton.
 *
 * Returns: (transfer full): the exceptor
 */
GumExceptor *
gum_exceptor_obtain (void)
{
  GumExceptor * exceptor;

  G_LOCK (the_exceptor);

  if (the_exceptor != NULL)
  {
    exceptor = g_object_ref (the_exceptor);
  }
  else
  {
    the_exceptor = g_object_new (GUM_TYPE_EXCEPTOR, NULL);
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
  G_LOCK (the_exceptor);

  g_assert (the_exceptor == (GumExceptor *) where_the_object_was);
  the_exceptor = NULL;

  G_UNLOCK (the_exceptor);
}

void
gum_exceptor_reset (GumExceptor * self)
{
  g_clear_object (&self->backend);

  if (gum_exceptor_mode != GUM_EXCEPTOR_MODE_OFF)
  {
    self->backend = gum_exceptor_backend_new (
        (GumExceptionHandler) gum_exceptor_handle_exception, self);
  }
}

/**
 * gum_exceptor_add:
 * @self: the exceptor
 * @func: (scope forever): handler to add
 * @user_data: data to pass to @func
 *
 * Adds an exception handler.
 */
void
gum_exceptor_add (GumExceptor * self,
                  GumExceptionHandler func,
                  gpointer user_data)
{
  GumExceptionHandlerEntry * entry;

  entry = g_slice_new (GumExceptionHandlerEntry);
  entry->func = func;
  entry->user_data = user_data;

  GUM_EXCEPTOR_LOCK ();
  self->handlers = g_slist_append (self->handlers, entry);
  GUM_EXCEPTOR_UNLOCK ();
}

/**
 * gum_exceptor_remove:
 * @self: the exceptor
 * @func: (scope forever): handler to remove
 * @user_data: data that was passed to gum_exceptor_add()
 *
 * Removes a previously added exception handler.
 */
void
gum_exceptor_remove (GumExceptor * self,
                     GumExceptionHandler func,
                     gpointer user_data)
{
  GumExceptionHandlerEntry * matching_entry;
  GSList * cur;

  GUM_EXCEPTOR_LOCK ();

  for (matching_entry = NULL, cur = self->handlers;
      matching_entry == NULL && cur != NULL;
      cur = cur->next)
  {
    GumExceptionHandlerEntry * entry = (GumExceptionHandlerEntry *) cur->data;

    if (entry->func == func && entry->user_data == user_data)
      matching_entry = entry;
  }

  g_assert (matching_entry != NULL);

  self->handlers = g_slist_remove (self->handlers, matching_entry);

  GUM_EXCEPTOR_UNLOCK ();

  g_slice_free (GumExceptionHandlerEntry, matching_entry);
}

static gboolean
gum_exceptor_handle_exception (GumExceptionDetails * details,
                               GumExceptor * self)
{
  gboolean handled = FALSE;
  GSList * invoked = NULL;
  GumExceptionHandlerEntry e;

  do
  {
    GSList * cur;

    e.func = NULL;
    e.user_data = NULL;

    GUM_EXCEPTOR_LOCK ();
    for (cur = self->handlers; e.func == NULL && cur != NULL; cur = cur->next)
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

void
_gum_exceptor_prepare_try (GumExceptor * self,
                           GumExceptorScope * scope)
{
  gpointer thread_id_key;

  thread_id_key = GSIZE_TO_POINTER (gum_process_get_current_thread_id ());

  scope->exception_occurred = FALSE;
#ifdef HAVE_ANDROID
  /* Workaround for Bionic bug up to and including Android L */
  sigprocmask (SIG_SETMASK, NULL, &scope->mask);
#endif

  GUM_EXCEPTOR_LOCK ();
  scope->next = g_hash_table_lookup (self->scopes, thread_id_key);
  g_hash_table_insert (self->scopes, thread_id_key, scope);
  GUM_EXCEPTOR_UNLOCK ();
}

gboolean
gum_exceptor_catch (GumExceptor * self,
                    GumExceptorScope * scope)
{
  gpointer thread_id_key;

  thread_id_key = GSIZE_TO_POINTER (gum_process_get_current_thread_id ());

  GUM_EXCEPTOR_LOCK ();
  g_hash_table_insert (self->scopes, thread_id_key, scope->next);
  GUM_EXCEPTOR_UNLOCK ();

  return scope->exception_occurred;
}

gboolean
gum_exceptor_has_scope (GumExceptor * self, GumThreadId thread_id)
{
  GumExceptorScope * scope;

  GUM_EXCEPTOR_LOCK ();
  scope = g_hash_table_lookup (self->scopes, GSIZE_TO_POINTER (thread_id));
  GUM_EXCEPTOR_UNLOCK ();

  return scope != NULL;
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
  GumExceptor * self = GUM_EXCEPTOR (user_data);
  GumExceptorScope * scope;
  G_GNUC_UNUSED GumCpuContext * context = &details->context;

  GUM_EXCEPTOR_LOCK ();
  scope = g_hash_table_lookup (self->scopes,
      GSIZE_TO_POINTER (details->thread_id));
  GUM_EXCEPTOR_UNLOCK ();
  if (scope == NULL)
    return FALSE;

  if (scope->exception_occurred)
    return FALSE;

  scope->exception_occurred = TRUE;
  memcpy (&scope->exception, details, sizeof (GumExceptionDetails));
  scope->exception.native_context = NULL;

  /*
   * Place IP at the start of the function as if the call already happened,
   * and set up stack and registers accordingly.
   */
#if defined (HAVE_I386)
  GUM_CPU_CONTEXT_XIP (context) = GPOINTER_TO_SIZE (
      GUM_FUNCPTR_TO_POINTER (gum_exceptor_scope_perform_longjmp));

  /* Align to 16 byte boundary (macOS ABI) */
  GUM_CPU_CONTEXT_XSP (context) &= ~(gsize) (16 - 1);
  /* Avoid the red zone (when applicable) */
  GUM_CPU_CONTEXT_XSP (context) -= GUM_RED_ZONE_SIZE;
  /* Reserve spill space for first four arguments (Win64 ABI) */
  GUM_CPU_CONTEXT_XSP (context) -= 4 * 8;

# if GLIB_SIZEOF_VOID_P == 4
  /* 32-bit: First argument goes on the stack (cdecl) */
  *((GumExceptorScope **) context->esp) = scope;
# else
  /* 64-bit: First argument goes in a register */
#  if GUM_NATIVE_ABI_IS_WINDOWS
  context->rcx = GPOINTER_TO_SIZE (scope);
#  else
  context->rdi = GPOINTER_TO_SIZE (scope);
#  endif
# endif

  /* Dummy return address (we won't return) */
  GUM_CPU_CONTEXT_XSP (context) -= sizeof (gpointer);
  *((gsize *) GUM_CPU_CONTEXT_XSP (context)) = 1337;
#elif defined (HAVE_ARM)
  context->pc = GPOINTER_TO_SIZE (
      GUM_FUNCPTR_TO_POINTER (gum_exceptor_scope_perform_longjmp));
  if ((context->pc & 1) != 0)
    context->cpsr |= GUM_PSR_T_BIT;
  else
    context->cpsr &= ~GUM_PSR_T_BIT;
  context->pc &= ~1;

  /* Align to 16 byte boundary */
  context->sp &= ~(gsize) (16 - 1);
  /* Avoid the red zone (when applicable) */
  context->sp -= GUM_RED_ZONE_SIZE;

  context->r[0] = GPOINTER_TO_SIZE (scope);

  /* Dummy return address (we won't return) */
  context->lr = 1337;
#elif defined (HAVE_ARM64)
# ifdef HAVE_PTRAUTH
  /*
   * arm64e XNU rejects sigreturn with a modified PC: it validates against a
   * per-signal kernel-private token that we cannot reproduce. Long-jump
   * straight from the signal handler instead.
   */
  gum_exceptor_scope_perform_longjmp (scope);
  g_assert_not_reached ();
# else
  {
    gsize pc, sp, lr;

    pc = GPOINTER_TO_SIZE (
        GUM_FUNCPTR_TO_POINTER (gum_exceptor_scope_perform_longjmp));
    sp = context->sp;

    /* Align to 16 byte boundary */
    sp &= ~(gsize) (16 - 1);
    /* Avoid the red zone (when applicable) */
    sp -= GUM_RED_ZONE_SIZE;

    /* Dummy return address (we won't return) */
    lr = 1337;

    context->pc = pc;
    context->sp = sp;
    context->lr = lr;

    context->x[0] = GPOINTER_TO_SIZE (scope);
  }
# endif
#elif defined (HAVE_MIPS)
  context->pc = GPOINTER_TO_SIZE (
      GUM_FUNCPTR_TO_POINTER (gum_exceptor_scope_perform_longjmp));

  /*
   * Set t9 to gum_exceptor_scope_perform_longjmp, as it is PIC and needs
   * t9 for the gp calculation.
   */
  context->t9 = context->pc;

  /* Align to 16 byte boundary */
  context->sp &= ~(gsize) (16 - 1);
  /* Avoid the red zone (when applicable) */
  context->sp -= GUM_RED_ZONE_SIZE;

  context->a0 = GPOINTER_TO_SIZE (scope);

  /* Dummy return address (we won't return) */
  context->ra = 1337;
#else
# error Unsupported architecture
#endif

  return TRUE;
}

static void
gum_exceptor_scope_perform_longjmp (GumExceptorScope * self)
{
#ifdef G_OS_NONE
  g_assert_not_reached ();
#else
# ifdef HAVE_ANDROID
  sigprocmask (SIG_SETMASK, &self->mask, NULL);
# endif
# if defined (G_OS_WIN32) && defined (HAVE_ARM64)
  gum_exceptor_scope_restore_context (self);
# else
  GUM_NATIVE_LONGJMP (self->env, GUM_LONGJMP_VALUE);
# endif
#endif
}

#if defined (G_OS_WIN32) && defined (HAVE_ARM64)

/*
 * Windows longjmp() unwinds the stack with RtlUnwindEx(), but recovery resumes
 * into a synthetic frame whose return address is a sentinel (see
 * gum_exceptor_handle_scope_exception()), so unwinding through it makes the
 * arm64 unwinder abort with STATUS_BAD_FUNCTION_TABLE. The x86_64 path dodges
 * this with a non-unwinding _setjmp(env, NULL); arm64 has no equivalent, so
 * restore the registers saved by setjmp() ourselves.
 */
static void
gum_exceptor_scope_restore_context (GumExceptorScope * self)
{
  const _JUMP_BUFFER * jb = (const _JUMP_BUFFER *) (gconstpointer) self->env;
  CONTEXT ctx;
  guint i;

  RtlCaptureContext (&ctx);

  ctx.X19 = jb->X19;
  ctx.X20 = jb->X20;
  ctx.X21 = jb->X21;
  ctx.X22 = jb->X22;
  ctx.X23 = jb->X23;
  ctx.X24 = jb->X24;
  ctx.X25 = jb->X25;
  ctx.X26 = jb->X26;
  ctx.X27 = jb->X27;
  ctx.X28 = jb->X28;
  ctx.Fp = jb->Fp;
  ctx.Lr = jb->Lr;
  ctx.Sp = jb->Sp;
  ctx.Pc = jb->Lr;
  ctx.Fpcr = jb->Fpcr;
  ctx.Fpsr = jb->Fpsr;
  for (i = 0; i != G_N_ELEMENTS (jb->D); i++)
    ctx.V[8 + i].D[0] = jb->D[i];

  ctx.X0 = GUM_LONGJMP_VALUE;

  RtlRestoreContext (&ctx, NULL);
}

#endif
