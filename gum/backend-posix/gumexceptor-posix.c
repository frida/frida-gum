/*
 * Copyright (C) 2015-2026 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumexceptorbackend.h"

#include "guminterceptor.h"
#include "gumtls.h"
#ifdef HAVE_DARWIN
# include "gum/gumdarwin.h"
#endif
#ifdef HAVE_LINUX
# include "gum/gumlinux.h"
#endif
#ifdef HAVE_FREEBSD
# include "gum/gumfreebsd.h"
#endif
#ifdef HAVE_QNX
# include "gum/gumqnx.h"
/* Work around conflict between QNX headers and Capstone. */
# undef ARM_REG_R0
# undef ARM_REG_R1
# undef ARM_REG_R2
# undef ARM_REG_R3
# undef ARM_REG_R4
# undef ARM_REG_R5
# undef ARM_REG_R6
# undef ARM_REG_R7
# undef ARM_REG_R8
# undef ARM_REG_R9
# undef ARM_REG_R10
# undef ARM_REG_R11
# undef ARM_REG_R12
# undef ARM_REG_R13
# undef ARM_REG_R14
# undef ARM_REG_R15
# undef ARM_REG_SPSR
# undef ARM_REG_FP
# undef ARM_REG_IP
# undef ARM_REG_SP
# undef ARM_REG_LR
# undef ARM_REG_PC
#endif

#include <capstone.h>
#include <setjmp.h>
#include <signal.h>
#include <stdlib.h>
#ifdef HAVE_PTRAUTH
# include <ptrauth.h>
#endif
#ifdef HAVE_QNX
# include <sys/debug.h>
# include <unix.h>
#endif

#if (defined (HAVE_MACOS) || defined (HAVE_IOS)) && defined (HAVE_ARM64)
# define GUM_HAVE_THREAD_EXCEPTION_PORTS 1
#endif

#ifdef GUM_HAVE_THREAD_EXCEPTION_PORTS
# define GUM_THREAD_EXCEPTION_MASK \
    (EXC_MASK_BAD_ACCESS | EXC_MASK_BAD_INSTRUCTION | EXC_MASK_ARITHMETIC)
# define GUM_THREAD_PORT_INSTALLED GSIZE_TO_POINTER (1)
# define GUM_THREAD_PORT_DECLINED GSIZE_TO_POINTER (2)
# define GUM_EXCEPTION_SERVER_STOP 1
# define GUM_ESR_EC_MASK 0xfc000000
# define GUM_ESR_EC_INSTRUCTION_ABORT 0x80000000
# define GUM_ESR_WNR (1 << 6)
#endif

#if defined (HAVE_DARWIN) || defined (HAVE_FREEBSD) || defined (HAVE_QNX)
typedef sig_t GumSignalHandler;
#else
typedef sighandler_t GumSignalHandler;
#endif

#ifdef GUM_HAVE_THREAD_EXCEPTION_PORTS
typedef struct _GumExceptionRequest GumExceptionRequest;
typedef struct _GumExceptionReply GumExceptionReply;
#endif

struct _GumExceptorBackend
{
  GObject parent;

  gboolean disposed;

  GumExceptionHandler handler;
  gpointer handler_data;

  struct sigaction ** old_handlers;
  gint num_old_handlers;

  GumInterceptor * interceptor;

#ifdef GUM_HAVE_THREAD_EXCEPTION_PORTS
  GumTlsKey thread_port_key;
  mach_port_t port_set;
  mach_port_t control_port;
  GThread * server_thread;
#endif
};

#ifdef GUM_HAVE_THREAD_EXCEPTION_PORTS

#pragma pack (push, 4)

struct _GumExceptionRequest
{
  mach_msg_header_t header;
  NDR_record_t ndr;
  exception_type_t exception;
  mach_msg_type_number_t code_count;
  gint64 code[EXCEPTION_CODE_MAX];
  int flavor;
  mach_msg_type_number_t old_state_count;
  GumDarwinUnifiedThreadState old_state;
  mach_msg_max_trailer_t trailer;
};

struct _GumExceptionReply
{
  mach_msg_header_t header;
  NDR_record_t ndr;
  kern_return_t result;
  int flavor;
  mach_msg_type_number_t new_state_count;
  GumDarwinUnifiedThreadState new_state;
};

#pragma pack (pop)

#endif

static void gum_exceptor_backend_dispose (GObject * object);

#ifdef GUM_HAVE_THREAD_EXCEPTION_PORTS
static gboolean gum_exceptor_backend_install_thread_port (
    GumExceptorBackend * self);
static gboolean gum_swap_in_thread_exception_port (GumThreadId thread,
    mach_port_t port);
static mach_port_t gum_exceptor_backend_ensure_server (
    GumExceptorBackend * self);
static void gum_exceptor_backend_stop_server (GumExceptorBackend * self);
static gpointer gum_exceptor_backend_serve (GumExceptorBackend * self);
static void gum_exceptor_backend_reply_to_exception (GumExceptorBackend * self,
    GumExceptionRequest * request, GumExceptionReply * reply);
static gboolean gum_exceptor_backend_handle_thread_exception (
    GumExceptorBackend * self, GumExceptionRequest * request,
    GumDarwinUnifiedThreadState * new_state);
static GumMemoryOperation gum_query_memory_operation (GumThreadId thread);
static void gum_parse_exception_state (
    const GumDarwinUnifiedThreadState * state, GumCpuContext * ctx);
static void gum_unparse_exception_state (const GumCpuContext * ctx,
    GumDarwinUnifiedThreadState * state);
#endif

static void gum_exceptor_backend_attach (GumExceptorBackend * self);
static void gum_exceptor_backend_detach (GumExceptorBackend * self);
static void gum_exceptor_backend_detach_handler (GumExceptorBackend * self,
    int sig);
static sig_t gum_exceptor_backend_replacement_signal (int sig, sig_t handler);
static int gum_exceptor_backend_replacement_sigaction (int sig,
    const struct sigaction * act, struct sigaction * oact);
static void gum_exceptor_backend_on_signal (int sig, siginfo_t * siginfo,
    void * context);
#ifdef HAVE_PTRAUTH
G_GNUC_INTERNAL void _gum_exceptor_perform_divert (GumCpuContext * ctx);
static void gum_exceptor_stage_divert (volatile GumCpuContext * dst,
    const GumCpuContext * src);
#endif
static void gum_exceptor_backend_abort (GumExceptorBackend * self,
    GumExceptionDetails * details);

static gboolean gum_is_signal_handler_chainable (sig_t handler);

static gpointer gum_resolve_symbol (const gchar * symbol_name,
    GPtrArray * module_candidates);
static gpointer gum_try_resolve_symbol (const gchar * symbol_name,
    GPtrArray * module_candidates);

static void gum_parse_context (gconstpointer context,
    GumCpuContext * ctx);
G_GNUC_UNUSED static void gum_unparse_context (const GumCpuContext * ctx,
    gpointer context);

static GumMemoryOperation gum_infer_memory_operation (gconstpointer address,
    GumCpuContext * context);
static cs_insn * gum_disassemble_instruction_at (gconstpointer address,
    GumCpuContext * context);
#if defined (HAVE_I386)
static GumMemoryOperation gum_infer_x86_memory_operation (cs_insn * insn);
#elif defined (HAVE_ARM)
static GumMemoryOperation gum_infer_arm_memory_operation (cs_insn * insn);
#elif defined (HAVE_ARM64)
static GumMemoryOperation gum_infer_arm64_memory_operation (
    cs_insn * insn);
#elif defined (HAVE_MIPS)
static GumMemoryOperation gum_infer_mips_memory_operation (cs_insn * insn);
#endif

G_DEFINE_TYPE (GumExceptorBackend, gum_exceptor_backend, G_TYPE_OBJECT)

static GumExceptorBackend * the_backend = NULL;
#ifdef GUM_HAVE_THREAD_EXCEPTION_PORTS
G_LOCK_DEFINE_STATIC (gum_exception_server);
#endif

static GumSignalHandler (* gum_original_signal) (int signum,
    GumSignalHandler handler);
static int (* gum_original_sigaction) (int signum, const struct sigaction * act,
    struct sigaction * oldact);

void
_gum_exceptor_backend_prepare_to_fork (void)
{
}

void
_gum_exceptor_backend_recover_from_fork_in_parent (void)
{
}

void
_gum_exceptor_backend_recover_from_fork_in_child (void)
{
#ifdef GUM_HAVE_THREAD_EXCEPTION_PORTS
  if (the_backend == NULL)
    return;

  the_backend->port_set = MACH_PORT_NULL;
  the_backend->control_port = MACH_PORT_NULL;
  the_backend->server_thread = NULL;
  gum_tls_key_set_value (the_backend->thread_port_key, NULL);
#endif
}

static void
gum_exceptor_backend_class_init (GumExceptorBackendClass * klass)
{
  GObjectClass * object_class = G_OBJECT_CLASS (klass);
  GPtrArray * module_candidates;
  GumModule * libc;

  object_class->dispose = gum_exceptor_backend_dispose;

  module_candidates = g_ptr_array_new_full (3, g_object_unref);

  libc = gum_process_get_libc_module ();
  g_ptr_array_add (module_candidates, g_object_ref (libc));

#if defined (HAVE_DARWIN)
  gum_original_signal = gum_resolve_symbol ("signal", module_candidates);
#elif defined (HAVE_ANDROID)
  gum_original_signal = gum_try_resolve_symbol ("signal", module_candidates);
  if (gum_original_signal == NULL)
    gum_original_signal = gum_resolve_symbol ("bsd_signal", module_candidates);
#elif defined (HAVE_QNX)
  gum_original_signal = gum_resolve_symbol ("signal", module_candidates);
#elif defined (HAVE_PROSPERO)
  {
    GumModule * libkernel;

    libkernel = gum_process_find_module_by_address (
        gum_module_find_global_export_by_name ("signal"));
    if (libkernel != NULL)
      g_ptr_array_insert (module_candidates, 0, libkernel);
  }

  gum_original_signal = gum_resolve_symbol ("signal", module_candidates);
#else
  {
    gchar * libdir, * pthread_name;
    GumModule * pthread;

    libdir = g_path_get_dirname (gum_module_get_path (libc));
    pthread_name = g_build_filename (libdir, "libpthread.so.0", NULL);

    pthread = gum_process_find_module_by_name (pthread_name);
    if (pthread != NULL)
      g_ptr_array_insert (module_candidates, 0, pthread);

    g_free (pthread_name);
    g_free (libdir);
  }

  gum_original_signal = gum_resolve_symbol ("signal", module_candidates);
#endif

  gum_original_sigaction = gum_resolve_symbol ("sigaction", module_candidates);

  g_ptr_array_unref (module_candidates);
}

static void
gum_exceptor_backend_init (GumExceptorBackend * self)
{
  self->interceptor = gum_interceptor_obtain ();

#ifdef GUM_HAVE_THREAD_EXCEPTION_PORTS
  self->thread_port_key = gum_tls_key_new ();
#endif

  the_backend = self;
}

static void
gum_exceptor_backend_dispose (GObject * object)
{
  GumExceptorBackend * self = GUM_EXCEPTOR_BACKEND (object);

  if (!self->disposed)
  {
    self->disposed = TRUE;

    gum_exceptor_backend_detach (self);

#ifdef GUM_HAVE_THREAD_EXCEPTION_PORTS
    gum_exceptor_backend_stop_server (self);
    gum_tls_key_free (self->thread_port_key);
#endif

    g_object_unref (self->interceptor);
    self->interceptor = NULL;

    the_backend = NULL;
  }

  G_OBJECT_CLASS (gum_exceptor_backend_parent_class)->dispose (object);
}

GumExceptorBackend *
gum_exceptor_backend_new (GumExceptionHandler handler,
                          gpointer user_data)
{
  GumExceptorBackend * backend;

  backend = g_object_new (GUM_TYPE_EXCEPTOR_BACKEND, NULL);
  backend->handler = handler;
  backend->handler_data = user_data;

  gum_exceptor_backend_attach (backend);

  return backend;
}

#ifdef HAVE_DARWIN

void
_gum_exceptor_backend_prepare_try (GumExceptorBackend * self)
{
#ifdef GUM_HAVE_THREAD_EXCEPTION_PORTS
  if (gum_tls_key_get_value (self->thread_port_key) != NULL)
    return;

  gum_tls_key_set_value (self->thread_port_key,
      gum_exceptor_backend_install_thread_port (self)
          ? GUM_THREAD_PORT_INSTALLED
          : GUM_THREAD_PORT_DECLINED);
#endif
}

gboolean
_gum_exceptor_backend_supports_thread_ports (void)
{
#ifdef GUM_HAVE_THREAD_EXCEPTION_PORTS
  return !gum_darwin_query_hardened () && !gum_process_is_debugger_attached ();
#else
  return FALSE;
#endif
}

#endif

#ifdef GUM_HAVE_THREAD_EXCEPTION_PORTS

static gboolean
gum_exceptor_backend_install_thread_port (GumExceptorBackend * self)
{
  gboolean installed;
  mach_port_t port_set, self_task, port, previous;
  GumThreadId thread;

  if (!_gum_exceptor_backend_supports_thread_ports ())
    return FALSE;

  port_set = gum_exceptor_backend_ensure_server (self);

  self_task = mach_task_self ();
  thread = gum_process_get_current_thread_id ();

  mach_port_allocate (self_task, MACH_PORT_RIGHT_RECEIVE, &port);
  mach_port_insert_right (self_task, port, port, MACH_MSG_TYPE_MAKE_SEND);
  mach_port_set_context (self_task, port, thread);
  mach_port_insert_member (self_task, port, port_set);

  installed = gum_swap_in_thread_exception_port (thread, port);
  if (installed)
  {
    mach_port_request_notification (self_task, port, MACH_NOTIFY_NO_SENDERS,
        0, port, MACH_MSG_TYPE_MAKE_SEND_ONCE, &previous);
    mach_port_mod_refs (self_task, port, MACH_PORT_RIGHT_SEND, -1);
  }
  else
  {
    mach_port_destruct (self_task, port, -1, 0);
  }

  return installed;
}

static gboolean
gum_swap_in_thread_exception_port (GumThreadId thread,
                                   mach_port_t port)
{
  gboolean has_own_port;
  mach_port_t self_task;
  mach_msg_type_number_t count, i;
  exception_mask_t masks[EXC_TYPES_COUNT];
  mach_port_t handlers[EXC_TYPES_COUNT];
  exception_behavior_t behaviors[EXC_TYPES_COUNT];
  thread_state_flavor_t flavors[EXC_TYPES_COUNT];
  kern_return_t kr;

  self_task = mach_task_self ();

  count = EXC_TYPES_COUNT;
  kr = thread_swap_exception_ports (thread, GUM_THREAD_EXCEPTION_MASK, port,
      EXCEPTION_STATE | MACH_EXCEPTION_CODES, GUM_DARWIN_THREAD_STATE_FLAVOR,
      masks, &count, handlers, behaviors, flavors);
  if (kr != KERN_SUCCESS)
    return FALSE;

  has_own_port = FALSE;
  for (i = 0; i != count; i++)
  {
    if (MACH_PORT_VALID (handlers[i]))
      has_own_port = TRUE;
  }

  for (i = 0; i != count; i++)
  {
    if (has_own_port)
    {
      thread_set_exception_ports (thread, masks[i], handlers[i], behaviors[i],
          flavors[i]);
    }

    if (MACH_PORT_VALID (handlers[i]))
      mach_port_deallocate (self_task, handlers[i]);
  }

  return !has_own_port;
}

static mach_port_t
gum_exceptor_backend_ensure_server (GumExceptorBackend * self)
{
  mach_port_t port_set, self_task;

  G_LOCK (gum_exception_server);

  if (self->port_set == MACH_PORT_NULL)
  {
    self_task = mach_task_self ();

    mach_port_allocate (self_task, MACH_PORT_RIGHT_PORT_SET, &self->port_set);
    mach_port_allocate (self_task, MACH_PORT_RIGHT_RECEIVE,
        &self->control_port);
    mach_port_insert_right (self_task, self->control_port, self->control_port,
        MACH_MSG_TYPE_MAKE_SEND);
    mach_port_insert_member (self_task, self->control_port, self->port_set);

    self->server_thread = g_thread_new ("gum-exception-server",
        (GThreadFunc) gum_exceptor_backend_serve, self);
  }

  port_set = self->port_set;

  G_UNLOCK (gum_exception_server);

  return port_set;
}

static void
gum_exceptor_backend_stop_server (GumExceptorBackend * self)
{
  mach_port_t self_task;
  mach_msg_header_t stop;
  mach_port_name_array_t members;
  mach_msg_type_number_t count, i;

  if (self->server_thread == NULL)
    return;

  self_task = mach_task_self ();

  stop.msgh_bits = MACH_MSGH_BITS (MACH_MSG_TYPE_COPY_SEND, 0);
  stop.msgh_size = sizeof (stop);
  stop.msgh_remote_port = self->control_port;
  stop.msgh_local_port = MACH_PORT_NULL;
  stop.msgh_voucher_port = MACH_PORT_NULL;
  stop.msgh_id = GUM_EXCEPTION_SERVER_STOP;
  mach_msg_send (&stop);

  g_thread_join (g_steal_pointer (&self->server_thread));

  mach_port_mod_refs (self_task, self->control_port, MACH_PORT_RIGHT_SEND, -1);
  self->control_port = MACH_PORT_NULL;

  mach_port_get_set_status (self_task, self->port_set, &members, &count);
  for (i = 0; i != count; i++)
    mach_port_mod_refs (self_task, members[i], MACH_PORT_RIGHT_RECEIVE, -1);
  vm_deallocate (self_task, (vm_address_t) members,
      count * sizeof (mach_port_name_t));

  mach_port_mod_refs (self_task, self->port_set, MACH_PORT_RIGHT_PORT_SET, -1);
  self->port_set = MACH_PORT_NULL;
}

static gpointer
gum_exceptor_backend_serve (GumExceptorBackend * self)
{
  mach_port_t self_task;
  GumExceptionRequest request;
  GumExceptionReply reply;
  G_GNUC_UNUSED kern_return_t kr;

  self_task = mach_task_self ();

  while (TRUE)
  {
    kr = mach_msg (&request.header, MACH_RCV_MSG, 0, sizeof (request),
        self->port_set, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
    g_assert (kr == KERN_SUCCESS);

    if (request.header.msgh_id == GUM_EXCEPTION_SERVER_STOP)
      break;

    if (request.header.msgh_id == MACH_NOTIFY_NO_SENDERS)
    {
      mach_port_mod_refs (self_task, request.header.msgh_local_port,
          MACH_PORT_RIGHT_RECEIVE, -1);
      continue;
    }

    gum_exceptor_backend_reply_to_exception (self, &request, &reply);

    mach_msg (&reply.header, MACH_SEND_MSG, reply.header.msgh_size, 0,
        MACH_PORT_NULL, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
  }

  return NULL;
}

static void
gum_exceptor_backend_reply_to_exception (GumExceptorBackend * self,
                                         GumExceptionRequest * request,
                                         GumExceptionReply * reply)
{
  reply->header.msgh_bits =
      MACH_MSGH_BITS (MACH_MSGH_BITS_REMOTE (request->header.msgh_bits), 0);
  reply->header.msgh_remote_port = request->header.msgh_remote_port;
  reply->header.msgh_local_port = MACH_PORT_NULL;
  reply->header.msgh_voucher_port = MACH_PORT_NULL;
  reply->header.msgh_id = request->header.msgh_id + 100;
  reply->ndr = NDR_record;

  if (gum_exceptor_backend_handle_thread_exception (self, request,
      &reply->new_state))
  {
    reply->header.msgh_size = sizeof (GumExceptionReply);
    reply->result = KERN_SUCCESS;
    reply->flavor = request->flavor;
    reply->new_state_count = request->old_state_count;
  }
  else
  {
    reply->header.msgh_size = sizeof (mig_reply_error_t);
    reply->result = KERN_FAILURE;
  }
}

static gboolean
gum_exceptor_backend_handle_thread_exception (
    GumExceptorBackend * self,
    GumExceptionRequest * request,
    GumDarwinUnifiedThreadState * new_state)
{
  GumExceptionDetails ed;
  GumExceptionMemoryDetails * md = &ed.memory;
  GumCpuContext * cpu_context = &ed.context;
  mach_port_context_t thread_id;

  mach_port_get_context (mach_task_self (), request->header.msgh_local_port,
      &thread_id);
  if (!gum_exceptor_has_scope (self->handler_data, thread_id))
    return FALSE;

  ed.thread_id = thread_id;

  switch (request->exception)
  {
    case EXC_BAD_ACCESS:
      ed.type = GUM_EXCEPTION_ACCESS_VIOLATION;
      break;
    case EXC_BAD_INSTRUCTION:
      ed.type = GUM_EXCEPTION_ILLEGAL_INSTRUCTION;
      break;
    case EXC_ARITHMETIC:
      ed.type = GUM_EXCEPTION_ARITHMETIC;
      break;
    default:
      g_assert_not_reached ();
  }

  gum_parse_exception_state (&request->old_state, cpu_context);
  ed.native_context = new_state;

  ed.address = GSIZE_TO_POINTER (cpu_context->pc);

  if (request->exception == EXC_BAD_ACCESS)
  {
    md->operation = gum_query_memory_operation (thread_id);
    md->address = GSIZE_TO_POINTER (request->code[1]);
  }
  else
  {
    md->operation = GUM_MEMOP_INVALID;
    md->address = NULL;
  }

  if (!_gum_exceptor_handle_scope_exception (&ed, self->handler_data))
    return FALSE;

  *new_state = request->old_state;
  gum_unparse_exception_state (cpu_context, new_state);

  return TRUE;
}

static GumMemoryOperation
gum_query_memory_operation (GumThreadId thread)
{
  arm_exception_state64_t es;
  mach_msg_type_number_t count;

  count = ARM_EXCEPTION_STATE64_COUNT;
  if (thread_get_state (thread, ARM_EXCEPTION_STATE64, (thread_state_t) &es,
      &count) != KERN_SUCCESS)
  {
    return GUM_MEMOP_READ;
  }

  if ((es.__esr & GUM_ESR_EC_MASK) == GUM_ESR_EC_INSTRUCTION_ABORT)
    return GUM_MEMOP_EXECUTE;

  if ((es.__esr & GUM_ESR_WNR) != 0)
    return GUM_MEMOP_WRITE;

  return GUM_MEMOP_READ;
}

static void
gum_parse_exception_state (const GumDarwinUnifiedThreadState * state,
                           GumCpuContext * ctx)
{
  gum_darwin_parse_unified_thread_state (state, ctx);

#ifdef HAVE_PTRAUTH
  ctx->pc = GPOINTER_TO_SIZE (ptrauth_strip (GSIZE_TO_POINTER (ctx->pc),
      ptrauth_key_process_independent_code));
  ctx->lr = GPOINTER_TO_SIZE (ptrauth_strip (GSIZE_TO_POINTER (ctx->lr),
      ptrauth_key_process_independent_code));
  ctx->sp = GPOINTER_TO_SIZE (ptrauth_strip (GSIZE_TO_POINTER (ctx->sp),
      ptrauth_key_process_independent_data));
  ctx->fp = GPOINTER_TO_SIZE (ptrauth_strip (GSIZE_TO_POINTER (ctx->fp),
      ptrauth_key_process_independent_data));
#endif
}

static void
gum_unparse_exception_state (const GumCpuContext * ctx,
                             GumDarwinUnifiedThreadState * state)
{
  gum_darwin_unparse_unified_thread_state (ctx, state);

#ifdef HAVE_PTRAUTH
  __darwin_arm_thread_state64_set_pc_fptr (state->ts_64,
      gum_sign_code_pointer (GSIZE_TO_POINTER (ctx->pc)));
  __darwin_arm_thread_state64_set_lr_fptr (state->ts_64,
      gum_sign_code_pointer (GSIZE_TO_POINTER (ctx->lr)));
  __darwin_arm_thread_state64_set_sp (state->ts_64, ctx->sp);
  __darwin_arm_thread_state64_set_fp (state->ts_64, ctx->fp);
#endif
}

#endif

static void
gum_exceptor_backend_attach (GumExceptorBackend * self)
{
  GumInterceptor * interceptor = self->interceptor;
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
  GumReplaceOptions options = { 0, };

  options.replacement_data = self;

  highest = 0;
  for (i = 0; i != G_N_ELEMENTS (handled_signals); i++)
    highest = MAX (handled_signals[i], highest);
  g_assert (highest > 0);
  self->num_old_handlers = highest + 1;
  self->old_handlers = g_new0 (struct sigaction *, self->num_old_handlers);

  action.sa_sigaction = gum_exceptor_backend_on_signal;
  sigemptyset (&action.sa_mask);
  action.sa_flags = SA_SIGINFO | SA_NODEFER;
#ifdef SA_ONSTACK
  action.sa_flags |= SA_ONSTACK;
#endif
  for (i = 0; i != G_N_ELEMENTS (handled_signals); i++)
  {
    gint sig = handled_signals[i];
    struct sigaction * old_handler;

    old_handler = g_slice_new0 (struct sigaction);
    self->old_handlers[sig] = old_handler;
    gum_original_sigaction (sig, &action, old_handler);
  }

  if (_gum_exceptor_get_mode () == GUM_EXCEPTOR_MODE_FULL)
  {
    gum_interceptor_begin_transaction (interceptor);

    gum_interceptor_replace (interceptor, gum_original_signal,
        gum_exceptor_backend_replacement_signal, NULL, &options);
    gum_interceptor_replace (interceptor, gum_original_sigaction,
        gum_exceptor_backend_replacement_sigaction, NULL, &options);

    gum_interceptor_end_transaction (interceptor);
  }
}

static void
gum_exceptor_backend_detach (GumExceptorBackend * self)
{
  GumInterceptor * interceptor = self->interceptor;
  gint i;

  if (_gum_exceptor_get_mode () == GUM_EXCEPTOR_MODE_FULL)
  {
    gum_interceptor_begin_transaction (interceptor);

    gum_interceptor_revert (interceptor, gum_original_signal);
    gum_interceptor_revert (interceptor, gum_original_sigaction);

    gum_interceptor_end_transaction (interceptor);
  }

  for (i = 0; i != self->num_old_handlers; i++)
    gum_exceptor_backend_detach_handler (self, i);
  g_free (self->old_handlers);
  self->old_handlers = NULL;
  self->num_old_handlers = 0;
}

static void
gum_exceptor_backend_detach_handler (GumExceptorBackend * self,
                                     int sig)
{
  struct sigaction * old_handler;

  old_handler = self->old_handlers[sig];
  if (old_handler == NULL)
    return;

  self->old_handlers[sig] = NULL;
  gum_original_sigaction (sig, old_handler, NULL);
  g_slice_free (struct sigaction, old_handler);
}

static struct sigaction *
gum_exceptor_backend_get_old_handler (GumExceptorBackend * self,
                                      gint sig)
{
  if (sig < 0 || sig >= self->num_old_handlers)
    return NULL;

  return self->old_handlers[sig];
}

static sig_t
gum_exceptor_backend_replacement_signal (int sig,
                                         sig_t handler)
{
  GumExceptorBackend * self;
  GumInvocationContext * ctx;
  struct sigaction * old_handler;
  sig_t result;

  ctx = gum_interceptor_get_current_invocation ();
  g_assert (ctx != NULL);

  self = GUM_EXCEPTOR_BACKEND (
      gum_invocation_context_get_replacement_data (ctx));

  old_handler = gum_exceptor_backend_get_old_handler (self, sig);
  if (old_handler == NULL)
    return gum_original_signal (sig, handler);

  result = ((old_handler->sa_flags & SA_SIGINFO) == 0)
      ? old_handler->sa_handler
      : SIG_DFL;

  old_handler->sa_handler = handler;
  old_handler->sa_flags &= ~SA_SIGINFO;

  return result;
}

static int
gum_exceptor_backend_replacement_sigaction (int sig,
                                            const struct sigaction * act,
                                            struct sigaction * oact)
{
  GumExceptorBackend * self;
  GumInvocationContext * ctx;
  struct sigaction * old_handler;
  struct sigaction previous_old_handler;

  ctx = gum_interceptor_get_current_invocation ();
  g_assert (ctx != NULL);

  self = GUM_EXCEPTOR_BACKEND (
      gum_invocation_context_get_replacement_data (ctx));

  old_handler = gum_exceptor_backend_get_old_handler (self, sig);
  if (old_handler == NULL)
    return gum_original_sigaction (sig, act, oact);

  previous_old_handler = *old_handler;
  if (act != NULL)
    *old_handler = *act;
  if (oact != NULL)
    *oact = previous_old_handler;

  return 0;
}

static void
gum_exceptor_backend_on_signal (int sig,
                                siginfo_t * siginfo,
                                void * context)
{
  GumExceptorBackend * self = the_backend;
  GumExceptionDetails ed;
  GumExceptionMemoryDetails * md = &ed.memory;
  GumCpuContext * cpu_context = &ed.context;
  struct sigaction * action;
#ifdef HAVE_PTRAUTH
  volatile GumCpuContext divert_ctx;
  sigjmp_buf divert_env;
#endif

  action = self->old_handlers[sig];

#ifdef HAVE_PTRAUTH
  if (sigsetjmp (divert_env, 1) != 0)
    _gum_exceptor_perform_divert ((GumCpuContext *) &divert_ctx);
#endif

  ed.thread_id = gum_process_get_current_thread_id ();

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

  gum_parse_context (context, cpu_context);
  ed.native_context = context;

#if defined (HAVE_I386)
  ed.address = GSIZE_TO_POINTER (GUM_CPU_CONTEXT_XIP (cpu_context));
#elif defined (HAVE_ARM) || defined (HAVE_ARM64)
  ed.address = gum_strip_code_pointer (GSIZE_TO_POINTER (cpu_context->pc));
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
        md->operation = gum_infer_memory_operation (ed.address, cpu_context);
      md->address = siginfo->si_addr;
      break;
    default:
      md->operation = GUM_MEMOP_INVALID;
      md->address = NULL;
      break;
  }

  if (action == NULL)
    gum_exceptor_backend_abort (self, &ed);

  if (self->handler (&ed, self->handler_data))
  {
#ifdef HAVE_PTRAUTH
    gum_exceptor_stage_divert (&divert_ctx, cpu_context);
    siglongjmp (divert_env, 1);
#else
    gum_unparse_context (cpu_context, context);
    return;
#endif
  }

  if ((action->sa_flags & SA_SIGINFO) != 0)
  {
    void (* old_sigaction) (int, siginfo_t *, void *) = action->sa_sigaction;

    if (old_sigaction != NULL)
      old_sigaction (sig, siginfo, context);
    else
      goto panic;
  }
  else
  {
    void (* old_handler) (int) = action->sa_handler;

    if (gum_is_signal_handler_chainable (old_handler))
      old_handler (sig);
    else if (action->sa_handler != SIG_IGN)
      goto panic;
  }

  if (sig == SIGABRT)
    goto panic;

  return;

panic:
  gum_exceptor_backend_detach_handler (self, sig);
}

#ifdef HAVE_PTRAUTH

static void
gum_exceptor_stage_divert (volatile GumCpuContext * dst,
                           const GumCpuContext * src)
{
  *((GumCpuContext *) dst) = *src;
  dst->pc = GPOINTER_TO_SIZE (ptrauth_strip (GSIZE_TO_POINTER (dst->pc),
      ptrauth_key_process_independent_code));
  dst->lr = GPOINTER_TO_SIZE (ptrauth_strip (GSIZE_TO_POINTER (dst->lr),
      ptrauth_key_process_independent_code));
  dst->sp = GPOINTER_TO_SIZE (ptrauth_strip (GSIZE_TO_POINTER (dst->sp),
      ptrauth_key_process_independent_data));
  dst->fp = GPOINTER_TO_SIZE (ptrauth_strip (GSIZE_TO_POINTER (dst->fp),
      ptrauth_key_process_independent_data));
}

#endif

static void
gum_exceptor_backend_abort (GumExceptorBackend * self,
                            GumExceptionDetails * details)
{
  /* TODO: should we create a backtrace and log it? */
  abort ();
}

static gboolean
gum_is_signal_handler_chainable (sig_t handler)
{
  return handler != SIG_DFL && handler != SIG_IGN && handler != SIG_ERR;
}

static gpointer
gum_resolve_symbol (const gchar * symbol_name,
                    GPtrArray * module_candidates)
{
  gpointer result;

  result = gum_try_resolve_symbol (symbol_name, module_candidates);
  if (result == NULL)
    gum_panic ("Unable to locate %s(); please file a bug", symbol_name);

  return result;
}

static gpointer
gum_try_resolve_symbol (const gchar * symbol_name,
                        GPtrArray * module_candidates)
{
  guint i;

  for (i = 0; i != module_candidates->len; i++)
  {
    GumModule * module;
    GumAddress address;

    module = g_ptr_array_index (module_candidates, i);

    address = gum_module_find_export_by_name (module, symbol_name);
    if (address != 0)
      return GSIZE_TO_POINTER (address);
  }

  return NULL;
}

#if defined (HAVE_DARWIN)

static void
gum_parse_context (gconstpointer context,
                   GumCpuContext * ctx)
{
  const ucontext_t * uc = context;

  gum_darwin_parse_native_thread_state (&uc->uc_mcontext->__ss, ctx);
#if defined (HAVE_I386) && GLIB_SIZEOF_VOID_P == 8
  ctx->xmm = (GumX86VectorReg *) &uc->uc_mcontext->__fs.__fpu_xmm0;
#endif
}

static void
gum_unparse_context (const GumCpuContext * ctx,
                     gpointer context)
{
  ucontext_t * uc = context;

  gum_darwin_unparse_native_thread_state (ctx, &uc->uc_mcontext->__ss);
}

#elif defined (HAVE_LINUX)

static void
gum_parse_context (gconstpointer context,
                   GumCpuContext * ctx)
{
  const ucontext_t * uc = context;

  gum_linux_parse_ucontext (uc, ctx);
}

static void
gum_unparse_context (const GumCpuContext * ctx,
                     gpointer context)
{
  ucontext_t * uc = context;

  gum_linux_unparse_ucontext (ctx, uc);
}

#elif defined (HAVE_FREEBSD)

static void
gum_parse_context (gconstpointer context,
                   GumCpuContext * ctx)
{
  const ucontext_t * uc = context;

  gum_freebsd_parse_ucontext (uc, ctx);
}

static void
gum_unparse_context (const GumCpuContext * ctx,
                     gpointer context)
{
  ucontext_t * uc = context;

  gum_freebsd_unparse_ucontext (ctx, uc);
}

#elif defined (HAVE_QNX)

static void
gum_parse_context (gconstpointer context,
                   GumCpuContext * ctx)
{
  const ucontext_t * uc = context;

  gum_qnx_parse_ucontext (uc, ctx);
}

static void
gum_unparse_context (const GumCpuContext * ctx,
                     gpointer context)
{
  ucontext_t * uc = context;

  gum_qnx_unparse_ucontext (ctx, uc);
}

#endif

static GumMemoryOperation
gum_infer_memory_operation (gconstpointer address,
                            GumCpuContext * context)
{
  GumMemoryOperation op;
  cs_insn * insn;

  insn = gum_disassemble_instruction_at (address, context);
  if (insn == NULL)
    return GUM_MEMOP_READ;

#if defined (HAVE_I386)
  op = gum_infer_x86_memory_operation (insn);
#elif defined (HAVE_ARM)
  op = gum_infer_arm_memory_operation (insn);
#elif defined (HAVE_ARM64)
  op = gum_infer_arm64_memory_operation (insn);
#elif defined (HAVE_MIPS)
  op = gum_infer_mips_memory_operation (insn);
#else
  op = GUM_MEMOP_READ;
#endif

  cs_free (insn, 1);

  return op;
}

static cs_insn *
gum_disassemble_instruction_at (gconstpointer address,
                                GumCpuContext * context)
{
  cs_insn * insn = NULL;
  csh capstone;
  cs_err err;

  gum_cs_arch_register_native ();
#if defined (HAVE_I386)
  err = cs_open (CS_ARCH_X86, GUM_CPU_MODE, &capstone);
#elif defined (HAVE_ARM)
  err = cs_open (CS_ARCH_ARM,
      (((context->cpsr & GUM_PSR_T_BIT) != 0) ? CS_MODE_THUMB : CS_MODE_ARM) |
      CS_MODE_V8 | GUM_DEFAULT_CS_ENDIAN, &capstone);
#elif defined (HAVE_ARM64)
  err = cs_open (CS_ARCH_ARM64, GUM_DEFAULT_CS_ENDIAN, &capstone);
#elif defined (HAVE_MIPS)
  err = cs_open (CS_ARCH_MIPS, GUM_DEFAULT_CS_MODE, &capstone);
#else
  return NULL;
#endif

  if (err != CS_ERR_OK)
    return NULL;

  cs_option (capstone, CS_OPT_DETAIL, CS_OPT_ON);
  cs_disasm (capstone, address, 16, GPOINTER_TO_SIZE (address), 1, &insn);
  cs_close (&capstone);

  return insn;
}

#if defined (HAVE_I386)

static GumMemoryOperation
gum_infer_x86_memory_operation (cs_insn * insn)
{
  switch (insn->id)
  {
    case X86_INS_CLI:
    case X86_INS_STI:
    case X86_INS_CLC:
    case X86_INS_STC:
    case X86_INS_CLAC:
    case X86_INS_CLGI:
    case X86_INS_CLTS:
    case X86_INS_CLWB:
    case X86_INS_STAC:
    case X86_INS_STGI:
    case X86_INS_CPUID:
    case X86_INS_MOVNTQ:
    case X86_INS_MOVNTDQA:
    case X86_INS_MOVNTDQ:
    case X86_INS_MOVNTI:
    case X86_INS_MOVNTPD:
    case X86_INS_MOVNTPS:
    case X86_INS_MOVNTSD:
    case X86_INS_MOVNTSS:
    case X86_INS_VMOVNTDQA:
    case X86_INS_VMOVNTDQ:
    case X86_INS_VMOVNTPD:
    case X86_INS_VMOVNTPS:
    case X86_INS_MOVSS:
    case X86_INS_MOV:
    case X86_INS_MOVAPS:
    case X86_INS_MOVAPD:
    case X86_INS_MOVZX:
    case X86_INS_MOVUPS:
    case X86_INS_MOVABS:
    case X86_INS_MOVHPD:
    case X86_INS_MOVHPS:
    case X86_INS_MOVLPD:
    case X86_INS_MOVLPS:
    case X86_INS_MOVBE:
    case X86_INS_MOVSB:
    case X86_INS_MOVSD:
    case X86_INS_MOVSQ:
    case X86_INS_MOVSX:
    case X86_INS_MOVSXD:
    case X86_INS_MOVSW:
    case X86_INS_MOVD:
    case X86_INS_MOVQ:
    case X86_INS_MOVDQ2Q:
    case X86_INS_RDRAND:
    case X86_INS_RDSEED:
    case X86_INS_RDMSR:
    case X86_INS_RDPMC:
    case X86_INS_RDTSC:
    case X86_INS_RDTSCP:
    case X86_INS_CRC32:
    case X86_INS_SHA1MSG1:
    case X86_INS_SHA1MSG2:
    case X86_INS_SHA1NEXTE:
    case X86_INS_SHA1RNDS4:
    case X86_INS_SHA256MSG1:
    case X86_INS_SHA256MSG2:
    case X86_INS_SHA256RNDS2:
    case X86_INS_AESDECLAST:
    case X86_INS_AESDEC:
    case X86_INS_AESENCLAST:
    case X86_INS_AESENC:
    case X86_INS_AESIMC:
    case X86_INS_AESKEYGENASSIST:
    case X86_INS_PACKSSDW:
    case X86_INS_PACKSSWB:
    case X86_INS_PACKUSWB:
    case X86_INS_XCHG:
    case X86_INS_CLD:
    case X86_INS_STD:
      switch (insn->detail->x86.operands[0].type)
      {
        case X86_OP_MEM:
          return GUM_MEMOP_WRITE;
        case X86_OP_REG:
          if (insn->detail->x86.operands[1].type == X86_OP_MEM)
            return GUM_MEMOP_READ;
        default:
          return GUM_MEMOP_READ;
      }
    default:
      return GUM_MEMOP_READ;
  }
}

#elif defined (HAVE_ARM)

static GumMemoryOperation
gum_infer_arm_memory_operation (cs_insn * insn)
{
  switch (insn->id)
  {
    case ARM_INS_STREX:
    case ARM_INS_STREXB:
    case ARM_INS_STREXD:
    case ARM_INS_STREXH:
    case ARM_INS_STR:
    case ARM_INS_STRB:
    case ARM_INS_STRD:
    case ARM_INS_STRBT:
    case ARM_INS_STRH:
    case ARM_INS_STRHT:
    case ARM_INS_STRT:
      return GUM_MEMOP_WRITE;
    default:
      return GUM_MEMOP_READ;
  }
}

#elif defined (HAVE_ARM64)

static GumMemoryOperation
gum_infer_arm64_memory_operation (cs_insn * insn)
{
  switch (insn->id)
  {
    case ARM64_INS_STRB:
    case ARM64_INS_STURB:
    case ARM64_INS_STUR:
    case ARM64_INS_STR:
    case ARM64_INS_STP:
    case ARM64_INS_STNP:
    case ARM64_INS_STXR:
    case ARM64_INS_STXRH:
    case ARM64_INS_STLXRH:
    case ARM64_INS_STXRB:
      return GUM_MEMOP_WRITE;
    default:
      return GUM_MEMOP_READ;
  }
}

#elif defined (HAVE_MIPS)

static GumMemoryOperation
gum_infer_mips_memory_operation (cs_insn * insn)
{
  switch (insn->id)
  {
    case MIPS_INS_SB:
    case MIPS_INS_SH:
    case MIPS_INS_SW:
    case MIPS_INS_SWL:
    case MIPS_INS_SWR:
    case MIPS_INS_SD:
    case MIPS_INS_SDL:
    case MIPS_INS_SDR:
    case MIPS_INS_SC:
    case MIPS_INS_SCD:
    case MIPS_INS_SWC1:
    case MIPS_INS_SDC1:
      return GUM_MEMOP_WRITE;
    default:
      return GUM_MEMOP_READ;
  }
}

#endif
