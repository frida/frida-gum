/*
 * Copyright (C) 2016 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumexceptorbackend.h"

#include "gumdarwin.h"
#include "guminterceptor.h"

/*
 * Regenerate with:
 *
 * $(xcrun --sdk macosx -f mig) \
 *     -header exc.h \
 *     -user excclient.c \
 *     -server excserver.c \
 *     $(xcrun --sdk macosx --show-sdk-path)/usr/include/mach/exc.defs
 * $(xcrun --sdk macosx -f mig) \
 *     -header machexc.h \
 *     -user machexcclient.c \
 *     -server machexcserver.c \
 *     $(xcrun --sdk macosx --show-sdk-path)/usr/include/mach/mach_exc.defs
 */
#include "exc.h"
#include "excclient.c"
#include "machexc.h"
#include "machexcclient.c"
#undef msgh_request_port
#undef msgh_reply_port
#include "machexcserver.c"

#include <dispatch/dispatch.h>
#include <mach/mach.h>

#define GUM_EXCEPTOR_BACKEND_MESSAGE_STOP 1

typedef struct _GumExceptionPortSet GumExceptionPortSet;

struct _GumExceptionPortSet
{
  mach_msg_type_number_t count;
  exception_mask_t masks[EXC_TYPES_COUNT];
  mach_port_t handlers[EXC_TYPES_COUNT];
  exception_behavior_t behaviors[EXC_TYPES_COUNT];
  thread_state_flavor_t flavors[EXC_TYPES_COUNT];
};

struct _GumExceptorBackend
{
  GObject parent;

  gboolean attached;
  gboolean disposed;

  GumExceptionHandler handler;
  gpointer handler_data;

  mach_port_t server_port;
  exception_mask_t exception_mask;
  GumExceptionPortSet old_ports;
  gboolean old_abort_handler_present;
  struct sigaction old_abort_handler;
  GThread * worker;

  GumInterceptor * interceptor;
};

static void gum_exceptor_backend_dispose (GObject * object);

static void gum_exceptor_backend_attach (GumExceptorBackend * self);
static void gum_exceptor_backend_detach (GumExceptorBackend * self);
static void gum_exceptor_backend_send_stop_request (GumExceptorBackend * self);
static gpointer gum_exceptor_backend_process_messages (
    GumExceptorBackend * self);
static void gum_exceptor_backend_on_signal (int sig, siginfo_t * siginfo,
    void * context);

static kern_return_t gum_exceptor_backend_replacement_task_get_exception_ports (
    task_t task, exception_mask_t exception_mask, exception_mask_array_t masks,
    mach_msg_type_number_t * masks_count,
    exception_handler_array_t old_handlers,
    exception_behavior_array_t old_behaviors,
    exception_flavor_array_t old_flavors);
static kern_return_t gum_exceptor_backend_replacement_task_set_exception_ports (
    task_t task, exception_mask_t exception_mask, mach_port_t new_port,
    exception_behavior_t behavior, thread_state_flavor_t new_flavor);
static kern_return_t gum_exceptor_backend_replacement_task_swap_exception_ports
    (task_t task, exception_mask_t exception_mask, mach_port_t new_port,
    exception_behavior_t behavior, thread_state_flavor_t new_flavor,
    exception_mask_array_t masks, mach_msg_type_number_t * masks_count,
    exception_handler_array_t old_handlers,
    exception_behavior_array_t old_behaviors,
    exception_flavor_array_t old_flavors);

static sig_t gum_exceptor_backend_replacement_signal (int sig, sig_t handler);
static int gum_exceptor_backend_replacement_sigaction (int sig,
    const struct sigaction * act, struct sigaction * oact);

static gboolean gum_is_signal_handler_chainable (sig_t handler);

static gboolean gum_exception_memory_details_from_thread (
    mach_port_t thread, GumExceptionMemoryDetails * md);

static void gum_exception_port_set_clear (GumExceptionPortSet * self);
static void gum_exception_port_set_copy (GumExceptionPortSet * self,
    GumExceptionPortSet * target);
static void gum_exception_port_set_copy_with_filter (GumExceptionPortSet * self,
    GumExceptionPortSet * target, exception_mask_t mask);
static void gum_exception_port_set_extract (GumExceptionPortSet * self,
    exception_mask_array_t masks, mach_msg_type_number_t * masks_count,
    exception_handler_array_t old_handlers,
    exception_behavior_array_t old_behaviors,
    exception_flavor_array_t old_flavors);
static void gum_exception_port_set_explode (GumExceptionPortSet * self,
    GumExceptionPortSet * target);
static void gum_exception_port_set_implode (GumExceptionPortSet * self,
    GumExceptionPortSet * target);
static void gum_exception_port_set_mod_refs (GumExceptionPortSet * self,
    mach_port_delta_t delta);

G_DEFINE_TYPE (GumExceptorBackend, gum_exceptor_backend, G_TYPE_OBJECT)

static GumExceptorBackend * the_backend = NULL;

static void
gum_exceptor_backend_class_init (GumExceptorBackendClass * klass)
{
  GObjectClass * object_class = G_OBJECT_CLASS (klass);

  object_class->dispose = gum_exceptor_backend_dispose;
}

static void
gum_exceptor_backend_init (GumExceptorBackend * self)
{
  self->interceptor = gum_interceptor_obtain ();

  the_backend = self;
}

static void
gum_exceptor_backend_dispose (GObject * object)
{
  GumExceptorBackend * self = GUM_EXCEPTOR_BACKEND (object);

  if (!self->disposed)
  {
    self->disposed = TRUE;

    if (self->attached)
      gum_exceptor_backend_detach (self);

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

  if (!gum_process_is_debugger_attached ())
    gum_exceptor_backend_attach (backend);

  return backend;
}

static void
gum_exceptor_backend_attach (GumExceptorBackend * self)
{
  GumInterceptor * interceptor = self->interceptor;
  mach_port_t self_task;
  kern_return_t kr;
  GumExceptionPortSet * old_ports;
  struct sigaction action;

  g_assert (!self->attached);

  self_task = mach_task_self ();

  kr = mach_port_allocate (self_task, MACH_PORT_RIGHT_RECEIVE,
      &self->server_port);
  g_assert_cmpint (kr, ==, KERN_SUCCESS);

  kr = mach_port_insert_right (self_task, self->server_port, self->server_port,
      MACH_MSG_TYPE_MAKE_SEND);
  g_assert_cmpint (kr, ==, KERN_SUCCESS);

  self->exception_mask = EXC_MASK_ARITHMETIC |
      EXC_MASK_BAD_ACCESS |
      EXC_MASK_BAD_INSTRUCTION |
      EXC_MASK_BREAKPOINT |
      EXC_MASK_GUARD |
      EXC_MASK_SOFTWARE;

  old_ports = &self->old_ports;
  kr = task_swap_exception_ports (self_task,
      self->exception_mask,
      self->server_port,
      EXCEPTION_STATE_IDENTITY | MACH_EXCEPTION_CODES,
      GUM_DARWIN_THREAD_STATE_FLAVOR,
      old_ports->masks,
      &old_ports->count,
      old_ports->handlers,
      old_ports->behaviors,
      old_ports->flavors);
  g_assert_cmpint (kr, ==, KERN_SUCCESS);

  self->old_abort_handler_present = TRUE;
  action.sa_sigaction = gum_exceptor_backend_on_signal;
  sigemptyset (&action.sa_mask);
  action.sa_flags = SA_SIGINFO;
  sigaction (SIGABRT, &action, &self->old_abort_handler);

  gum_interceptor_begin_transaction (interceptor);

  gum_interceptor_replace_function (interceptor, task_get_exception_ports,
      gum_exceptor_backend_replacement_task_get_exception_ports, self);
  gum_interceptor_replace_function (interceptor, task_set_exception_ports,
      gum_exceptor_backend_replacement_task_set_exception_ports, self);
  gum_interceptor_replace_function (interceptor, task_swap_exception_ports,
      gum_exceptor_backend_replacement_task_swap_exception_ports, self);

  gum_interceptor_replace_function (interceptor, signal,
      gum_exceptor_backend_replacement_signal, self);
  gum_interceptor_replace_function (interceptor, sigaction,
      gum_exceptor_backend_replacement_sigaction, self);

  gum_interceptor_end_transaction (interceptor);

  self->worker = g_thread_new ("gum-exceptor-worker",
      (GThreadFunc) gum_exceptor_backend_process_messages, self);

  self->attached = TRUE;
}

static void
gum_exceptor_backend_detach (GumExceptorBackend * self)
{
  GumInterceptor * interceptor = self->interceptor;
  mach_port_t self_task;
  GumExceptionPortSet * old_ports;
  mach_msg_type_number_t port_index;

  g_assert (self->attached);

  gum_interceptor_begin_transaction (interceptor);

  gum_interceptor_revert_function (interceptor, task_get_exception_ports);
  gum_interceptor_revert_function (interceptor, task_set_exception_ports);
  gum_interceptor_revert_function (interceptor, task_swap_exception_ports);

  gum_interceptor_revert_function (interceptor, signal);
  gum_interceptor_revert_function (interceptor, sigaction);

  gum_interceptor_end_transaction (interceptor);

  self_task = mach_task_self ();

  old_ports = &self->old_ports;
  for (port_index = 0; port_index != old_ports->count; port_index++)
  {
    kern_return_t kr;

    kr = task_set_exception_ports (self_task,
        old_ports->masks[port_index],
        old_ports->handlers[port_index],
        old_ports->behaviors[port_index],
        old_ports->flavors[port_index]);
    g_assert_cmpint (kr, ==, KERN_SUCCESS);
  }
  gum_exception_port_set_mod_refs (old_ports, -1);
  old_ports->count = 0;

  gum_exceptor_backend_send_stop_request (self);
  g_thread_join (self->worker);
  self->worker = NULL;

  mach_port_mod_refs (self_task, self->server_port, MACH_PORT_RIGHT_SEND, -1);
  mach_port_mod_refs (self_task, self->server_port, MACH_PORT_RIGHT_RECEIVE,
      -1);
  self->server_port = MACH_PORT_NULL;

  self->attached = FALSE;
}

static void
gum_exceptor_backend_send_stop_request (GumExceptorBackend * self)
{
  mach_msg_header_t header;
  kern_return_t kr;

  header.msgh_bits = MACH_MSGH_BITS (MACH_MSG_TYPE_MAKE_SEND_ONCE, 0);
  header.msgh_size = sizeof (header);
  header.msgh_remote_port = self->server_port;
  header.msgh_local_port = MACH_PORT_NULL;
  header.msgh_reserved = 0;
  header.msgh_id = GUM_EXCEPTOR_BACKEND_MESSAGE_STOP;
  kr = mach_msg_send (&header);
  g_assert_cmpint (kr, ==, KERN_SUCCESS);
}

static gpointer
gum_exceptor_backend_process_messages (GumExceptorBackend * self)
{
  union __RequestUnion__mach_exc_subsystem request;
  union __ReplyUnion__mach_exc_subsystem reply;
  mach_msg_header_t * header_in, * header_out;
  kern_return_t kr;
  boolean_t handled;

  while (TRUE)
  {
    bzero (&request, sizeof (request));
    header_in = (mach_msg_header_t *) &request;
    header_in->msgh_size = sizeof (request);
    header_in->msgh_local_port = self->server_port;
    kr = mach_msg_receive (header_in);
    g_assert_cmpint (kr, ==, KERN_SUCCESS);

    if (header_in->msgh_id == GUM_EXCEPTOR_BACKEND_MESSAGE_STOP)
      break;

    header_out = (mach_msg_header_t *) &reply;

    handled = mach_exc_server (header_in, header_out);
    if (!handled)
      continue;

    mach_msg_send (header_out);
  }

  return NULL;
}

kern_return_t
catch_mach_exception_raise (mach_port_t exception_port,
                            mach_port_t thread,
                            mach_port_t task,
                            exception_type_t exception,
                            mach_exception_data_t code,
                            mach_msg_type_number_t code_count)
{
  g_assert_not_reached ();

  return KERN_INVALID_ARGUMENT;
}

kern_return_t
catch_mach_exception_raise_state (mach_port_t exception_port,
                                  exception_type_t exception,
                                  const mach_exception_data_t code,
                                  mach_msg_type_number_t code_count,
                                  int * flavor,
                                  const thread_state_t old_state,
                                  mach_msg_type_number_t old_state_count,
                                  thread_state_t new_state,
                                  mach_msg_type_number_t *new_state_count)
{
  g_assert_not_reached ();

  return KERN_INVALID_ARGUMENT;
}

kern_return_t
catch_mach_exception_raise_state_identity (
    mach_port_t exception_port,
    mach_port_t thread,
    mach_port_t task,
    exception_type_t exception,
    mach_exception_data_t code,
    mach_msg_type_number_t code_count,
    int * flavor,
    thread_state_t old_state,
    mach_msg_type_number_t old_state_count,
    thread_state_t new_state,
    mach_msg_type_number_t * new_state_count)
{
  GumExceptorBackend * self = the_backend;
  mach_port_t self_task;
  GumExceptionDetails ed;
  GumExceptionMemoryDetails * md = &ed.memory;
  GumCpuContext * cpu_context = &ed.context;
  kern_return_t kr;

  self_task = mach_task_self ();

  ed.thread_id = thread;

  switch (exception)
  {
    case EXC_ARITHMETIC:
      ed.type = GUM_EXCEPTION_ARITHMETIC;
      break;
    case EXC_BAD_ACCESS:
      ed.type = GUM_EXCEPTION_ACCESS_VIOLATION;
      break;
    case EXC_BAD_INSTRUCTION:
      ed.type = GUM_EXCEPTION_ILLEGAL_INSTRUCTION;
      break;
    case EXC_BREAKPOINT:
      ed.type = GUM_EXCEPTION_BREAKPOINT;
      break;
    case EXC_GUARD:
      ed.type = GUM_EXCEPTION_GUARD_PAGE;
      break;
    case EXC_SOFTWARE:
      ed.type = GUM_EXCEPTION_SYSTEM;
      break;
    default:
      g_assert_not_reached ();
  }

  gum_darwin_parse_unified_thread_state (
      (const GumDarwinUnifiedThreadState *) old_state, cpu_context);
  ed.native_context = old_state;

#if defined (HAVE_I386)
  ed.address = GSIZE_TO_POINTER (GUM_CPU_CONTEXT_XIP (cpu_context));
#elif defined (HAVE_ARM) || defined (HAVE_ARM64)
  ed.address = GSIZE_TO_POINTER (cpu_context->pc);
#else
# error Unsupported architecture
#endif

  switch (exception)
  {
    case EXC_BAD_ACCESS:
    case EXC_GUARD:
      if (gum_exception_memory_details_from_thread (thread, md))
        break;
    default:
      md->operation = GUM_MEMOP_INVALID;
      md->address = NULL;
      break;
  }

  if (self->handler (&ed, self->handler_data))
  {
    gum_darwin_unparse_unified_thread_state (cpu_context,
        (GumDarwinUnifiedThreadState *) new_state);
    *new_state_count = old_state_count;

    kr = KERN_SUCCESS;
  }
  else
  {
    GumExceptionPortSet * old_ports = &self->old_ports;
    mach_msg_type_number_t port_index;
    exception_data_t small_code;
    mach_msg_type_number_t code_index;

    small_code = g_alloca (code_count * sizeof (exception_data_type_t));
    for (code_index = 0; code_index != code_count; code_index++)
    {
      small_code[code_index] = code[code_index];
    }

    kr = KERN_FAILURE;

    for (port_index = 0; port_index != old_ports->count; port_index++)
    {
      exception_mask_t mask = old_ports->masks[port_index];
      mach_port_t port = old_ports->handlers[port_index];
      exception_behavior_t behavior = old_ports->behaviors[port_index];
      gboolean is_modern;

      if (port == MACH_PORT_NULL)
        continue;

      if ((mask & (1 << exception)) == 0)
        continue;

      is_modern = behavior & MACH_EXCEPTION_CODES;

      switch (behavior & ~MACH_EXCEPTION_CODES)
      {
        case EXCEPTION_DEFAULT:
        {
          if (is_modern)
          {
            kr = mach_exception_raise (port, thread, task, exception, code,
                code_count);
          }
          else
          {
            kr = exception_raise (port, thread, task, exception, small_code,
                code_count);
          }

          if (kr == KERN_SUCCESS)
          {
            *new_state_count = old_state_count;
            kr = thread_get_state (thread, GUM_DARWIN_THREAD_STATE_FLAVOR,
                new_state, new_state_count);
          }

          break;
        }
        case EXCEPTION_STATE:
        {
          if (is_modern)
          {
            kr = mach_exception_raise_state (port, exception, code, code_count,
                flavor, old_state, old_state_count, new_state, new_state_count);
          }
          else
          {
            kr = exception_raise_state (port, exception, small_code, code_count,
                flavor, old_state, old_state_count, new_state, new_state_count);
          }

          break;
        }
        case EXCEPTION_STATE_IDENTITY:
        {
          if (is_modern)
          {
            kr = mach_exception_raise_state_identity (port, thread, task,
                exception, code, code_count, flavor, old_state,
                old_state_count, new_state, new_state_count);
          }
          else
          {
            kr = exception_raise_state_identity (port, thread, task, exception,
                small_code, code_count, flavor, old_state, old_state_count,
                new_state, new_state_count);
          }

          break;
        }
        default:
        {
          g_assert_not_reached ();
          break;
        }
      }

      if (kr == KERN_SUCCESS)
        break;
    }
  }

  mach_port_deallocate (self_task, thread);
  mach_port_deallocate (self_task, task);

  return kr;
}

static void
gum_exceptor_backend_on_signal (int sig,
                                siginfo_t * siginfo,
                                void * context)
{
  GumExceptorBackend * self = the_backend;
  ucontext_t * uc = context;
  GumExceptionDetails ed;
  GumExceptionMemoryDetails * md = &ed.memory;
  GumCpuContext * cpu_context = &ed.context;
  struct sigaction * action;

  g_assert_cmpint (sig, ==, SIGABRT);

  action = &self->old_abort_handler;

  ed.thread_id = gum_process_get_current_thread_id ();
  ed.type = GUM_EXCEPTION_ABORT;

  gum_darwin_parse_native_thread_state (&uc->uc_mcontext->__ss, cpu_context);
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

  md->operation = GUM_MEMOP_INVALID;
  md->address = NULL;

  if (self->handler (&ed, self->handler_data))
  {
    gum_darwin_unparse_native_thread_state (cpu_context,
        &uc->uc_mcontext->__ss);
    return;
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

  return;

panic:
  self->old_abort_handler_present = FALSE;
  signal (SIGABRT, SIG_DFL);
}

static kern_return_t
gum_exceptor_backend_replacement_task_get_exception_ports (
    task_t task,
    exception_mask_t exception_mask,
    exception_mask_array_t masks,
    mach_msg_type_number_t * masks_count,
    exception_handler_array_t old_handlers,
    exception_behavior_array_t old_behaviors,
    exception_flavor_array_t old_flavors)
{
  mach_port_t self_task;
  GumExceptorBackend * self;
  GumInvocationContext * ctx;
  GumExceptionPortSet all_ports, filtered_ports;
  kern_return_t kr;
  gboolean found_server_port;
  mach_msg_type_number_t src_index, dst_index;

  self_task = mach_task_self ();

  if (task != self_task)
    goto passthrough;

  ctx = gum_interceptor_get_current_invocation ();
  g_assert (ctx != NULL);

  self = GUM_EXCEPTOR_BACKEND (
      gum_invocation_context_get_replacement_function_data (ctx));

  kr = task_get_exception_ports (task, exception_mask, all_ports.masks,
      &all_ports.count, all_ports.handlers, all_ports.behaviors,
      all_ports.flavors);
  if (kr != KERN_SUCCESS)
    return kr;

  found_server_port = FALSE;

  dst_index = 0;
  for (src_index = 0; src_index != all_ports.count; src_index++)
  {
    mach_port_t handler = all_ports.handlers[src_index];

    if (handler == self->server_port)
    {
      found_server_port = TRUE;
      continue;
    }

    filtered_ports.masks[dst_index] = all_ports.masks[src_index];
    filtered_ports.handlers[dst_index] = handler;
    filtered_ports.behaviors[dst_index] = all_ports.behaviors[src_index];
    filtered_ports.flavors[dst_index] = all_ports.flavors[src_index];
    dst_index++;
  }
  filtered_ports.count = dst_index;

  if (found_server_port)
  {
    GumExceptionPortSet merged_ports;

    gum_exception_port_set_clear (&merged_ports);
    gum_exception_port_set_explode (&self->old_ports, &merged_ports);
    gum_exception_port_set_explode (&filtered_ports, &merged_ports);
    gum_exception_port_set_implode (&merged_ports, &filtered_ports);
  }

  gum_exception_port_set_mod_refs (&filtered_ports, 1);
  gum_exception_port_set_mod_refs (&all_ports, -1);

  gum_exception_port_set_extract (&filtered_ports, masks, masks_count,
      old_handlers, old_behaviors, old_flavors);

  return KERN_SUCCESS;

passthrough:
  return task_get_exception_ports (task, exception_mask, masks, masks_count,
      old_handlers, old_behaviors, old_flavors);
}

static kern_return_t
gum_exceptor_backend_replacement_task_set_exception_ports (
    task_t task,
    exception_mask_t exception_mask,
    mach_port_t new_port,
    exception_behavior_t behavior,
    thread_state_flavor_t new_flavor)
{
  mach_port_t self_task;
  GumExceptorBackend * self;
  GumInvocationContext * ctx;
  exception_mask_t inside_mask, outside_mask;
  GumExceptionPortSet in_ports, next_ports, imploded_next_ports;

  self_task = mach_task_self ();

  if (task != self_task)
    goto passthrough;

  ctx = gum_interceptor_get_current_invocation ();
  g_assert (ctx != NULL);

  self = GUM_EXCEPTOR_BACKEND (
      gum_invocation_context_get_replacement_function_data (ctx));

  inside_mask = self->exception_mask & exception_mask;
  if (inside_mask == 0)
    goto passthrough;

  outside_mask = exception_mask & ~self->exception_mask;

  if (outside_mask != 0)
  {
    kern_return_t kr;

    kr = task_set_exception_ports (task, outside_mask, new_port, behavior,
        new_flavor);
    if (kr != KERN_SUCCESS)
      return kr;
  }

  in_ports.count = 1;
  in_ports.masks[0] = inside_mask;
  in_ports.handlers[0] = new_port;
  in_ports.behaviors[0] = behavior;
  in_ports.flavors[0] = new_flavor;

  gum_exception_port_set_clear (&next_ports);
  gum_exception_port_set_explode (&self->old_ports, &next_ports);
  gum_exception_port_set_explode (&in_ports, &next_ports);

  gum_exception_port_set_implode (&next_ports, &imploded_next_ports);
  gum_exception_port_set_mod_refs (&imploded_next_ports, 1);
  gum_exception_port_set_mod_refs (&self->old_ports, -1);
  gum_exception_port_set_copy (&imploded_next_ports, &self->old_ports);

  return KERN_SUCCESS;

passthrough:
  return task_set_exception_ports (task, exception_mask, new_port, behavior,
      new_flavor);
}

static kern_return_t
gum_exceptor_backend_replacement_task_swap_exception_ports (
    task_t task,
    exception_mask_t exception_mask,
    mach_port_t new_port,
    exception_behavior_t behavior,
    thread_state_flavor_t new_flavor,
    exception_mask_array_t masks,
    mach_msg_type_number_t * masks_count,
    exception_handler_array_t old_handlers,
    exception_behavior_array_t old_behaviors,
    exception_flavor_array_t old_flavors)
{
  mach_port_t self_task;
  GumExceptorBackend * self;
  GumInvocationContext * ctx;
  exception_mask_t inside_mask, outside_mask;
  GumExceptionPortSet in_ports, out_ports, imploded_out_ports;
  GumExceptionPortSet prev_ports, next_ports, imploded_next_ports;
  GumExceptionPortSet prev_outside_ports;

  self_task = mach_task_self ();

  if (task != self_task)
    goto passthrough;

  ctx = gum_interceptor_get_current_invocation ();
  g_assert (ctx != NULL);

  self = GUM_EXCEPTOR_BACKEND (
      gum_invocation_context_get_replacement_function_data (ctx));

  inside_mask = self->exception_mask & exception_mask;
  if (inside_mask == 0)
    goto passthrough;

  outside_mask = exception_mask & ~self->exception_mask;

  in_ports.count = 1;
  in_ports.masks[0] = inside_mask;
  in_ports.handlers[0] = new_port;
  in_ports.behaviors[0] = behavior;
  in_ports.flavors[0] = new_flavor;

  gum_exception_port_set_clear (&prev_ports);
  gum_exception_port_set_explode (&self->old_ports, &prev_ports);

  gum_exception_port_set_copy (&prev_ports, &next_ports);
  gum_exception_port_set_explode (&in_ports, &next_ports);

  gum_exception_port_set_copy_with_filter (&prev_ports, &out_ports,
      inside_mask);

  if (outside_mask != 0)
  {
    kern_return_t kr;

    kr = task_swap_exception_ports (task, outside_mask, new_port, behavior,
        new_flavor, prev_outside_ports.masks, &prev_outside_ports.count,
        prev_outside_ports.handlers, prev_outside_ports.behaviors,
        prev_outside_ports.flavors);
    if (kr != KERN_SUCCESS)
      return kr;

    gum_exception_port_set_explode (&prev_outside_ports, &out_ports);
  }
  else
  {
    prev_outside_ports.count = 0;
  }

  gum_exception_port_set_implode (&out_ports, &imploded_out_ports);
  gum_exception_port_set_mod_refs (&imploded_out_ports, 1);
  gum_exception_port_set_mod_refs (&prev_outside_ports, -1);
  gum_exception_port_set_extract (&imploded_out_ports, masks, masks_count,
      old_handlers, old_behaviors, old_flavors);

  gum_exception_port_set_implode (&next_ports, &imploded_next_ports);
  gum_exception_port_set_mod_refs (&imploded_next_ports, 1);
  gum_exception_port_set_mod_refs (&self->old_ports, -1);
  gum_exception_port_set_copy (&imploded_next_ports, &self->old_ports);

  return KERN_SUCCESS;

passthrough:
  return task_swap_exception_ports (task, exception_mask, new_port, behavior,
      new_flavor, masks, masks_count, old_handlers, old_behaviors, old_flavors);
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
      gum_invocation_context_get_replacement_function_data (ctx));

  if (sig != SIGABRT || !self->old_abort_handler_present)
    return signal (sig, handler);

  old_handler = &self->old_abort_handler;

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

  ctx = gum_interceptor_get_current_invocation ();
  g_assert (ctx != NULL);

  self = GUM_EXCEPTOR_BACKEND (
      gum_invocation_context_get_replacement_function_data (ctx));

  if (sig != SIGABRT || !self->old_abort_handler_present)
    return sigaction (sig, act, oact);

  old_handler = &self->old_abort_handler;

  if (oact != NULL)
    *oact = *old_handler;
  if (act != NULL)
    *old_handler = *act;

  return 0;
}

static gboolean
gum_is_signal_handler_chainable (sig_t handler)
{
  return handler != SIG_DFL && handler != SIG_IGN && handler != SIG_ERR;
}

static gboolean
gum_exception_memory_details_from_thread (mach_port_t thread,
                                          GumExceptionMemoryDetails * md)
{
  mach_msg_type_number_t state_count;

#if defined (HAVE_I386)
# if GLIB_SIZEOF_VOID_P == 4
  x86_exception_state32_t es;

  state_count = x86_EXCEPTION_STATE32_COUNT;
  if (thread_get_state (thread, x86_EXCEPTION_STATE32,
      (thread_state_t) &es, &state_count) != KERN_SUCCESS)
    return FALSE;
# else
  x86_exception_state64_t es;

  state_count = x86_EXCEPTION_STATE64_COUNT;
  if (thread_get_state (thread, x86_EXCEPTION_STATE64,
      (thread_state_t) &es, &state_count) != KERN_SUCCESS)
    return FALSE;
# endif

  /*
   * Constants from osfmk/i386/trap.h
   */
# define GUM_TRAP_PAGE_FAULT_WRITE 0x02
# define GUM_TRAP_PAGE_FAULT_EXECUTE 0x10

  if ((es.__err & GUM_TRAP_PAGE_FAULT_EXECUTE) != 0)
    md->operation = GUM_MEMOP_EXECUTE;
  else if ((es.__err & GUM_TRAP_PAGE_FAULT_WRITE) != 0)
    md->operation = GUM_MEMOP_WRITE;
  else
    md->operation = GUM_MEMOP_READ;

  md->address = GSIZE_TO_POINTER (es.__faultvaddr);
#elif defined (HAVE_ARM) || defined (HAVE_ARM64)
# if GLIB_SIZEOF_VOID_P == 4
  arm_exception_state32_t es;

  state_count = ARM_EXCEPTION_STATE_COUNT;
  if (thread_get_state (thread, ARM_EXCEPTION_STATE,
      (thread_state_t) &es, &state_count) != KERN_SUCCESS)
    return FALSE;

  /*
   * FSR aka Fault Status Register
   *
   * execute: 1000 001000000000000000000 0 000111
   *
   *    read: 1001 001000000000000000000 0 000111
   *   write: 1001 001000000000000000000 1 000111
   */
  if ((es.__fsr & 0xf0000000) == 0x80000000)
    md->operation = GUM_MEMOP_EXECUTE;
  else if ((es.__fsr & 0x40) != 0)
    md->operation = GUM_MEMOP_WRITE;
  else
    md->operation = GUM_MEMOP_READ;
# else
  arm_exception_state64_t es;

  state_count = ARM_EXCEPTION_STATE64_COUNT;
  if (thread_get_state (thread, ARM_EXCEPTION_STATE64,
      (thread_state_t) &es, &state_count) != KERN_SUCCESS)
    return FALSE;

  /*
   * ESR aka Exception Syndrome Register:
   *
   * Instruction Abort from a lower Exception level
   *            ||
   *            ||             Translation fault, third level
   *            ||                           ||
   *          __vv__                       __vv__
   * execute: 100000 1 0000000000000000000 000111
   *                 |
   *     4 byte instruction length
   *
   * Data Abort from a lower Exception level
   *            ||
   *            ||             Translation fault, first level
   *            ||                            ||
   *          __vv__                        __vv__
   *    read: 100100 1 000000000000000000 0 000101
   *   write: 100100 1 000000000000000000 1 000101
   *                 |                    |
   *     4 byte instruction length        |
   *                                      |
   *                      Abort caused by a write instruction
   */
  if ((es.__esr & 0xfc000000) == 0x80000000)
    md->operation = GUM_MEMOP_EXECUTE;
  else if ((es.__esr & 0x40) != 0)
    md->operation = GUM_MEMOP_WRITE;
  else
    md->operation = GUM_MEMOP_READ;
# endif

  md->address = GSIZE_TO_POINTER (es.__far);
#else
# error Unsupported architecture
#endif

  return TRUE;
}

static void
gum_exception_port_set_clear (GumExceptionPortSet * self)
{
  bzero (self, sizeof (GumExceptionPortSet));
}

static void
gum_exception_port_set_copy (GumExceptionPortSet * self,
                             GumExceptionPortSet * dst)
{
  memcpy (dst, self, sizeof (GumExceptionPortSet));
}

static void
gum_exception_port_set_copy_with_filter (GumExceptionPortSet * self,
                                         GumExceptionPortSet * dst,
                                         exception_mask_t mask)
{
  mach_msg_type_number_t port_index;

  for (port_index = 0; port_index != self->count; port_index++)
  {
    if ((self->masks[port_index] & mask) != 0)
    {
      dst->masks[port_index] = self->masks[port_index];
      dst->handlers[port_index] = self->handlers[port_index];
      dst->behaviors[port_index] = self->behaviors[port_index];
      dst->flavors[port_index] = self->flavors[port_index];
    }
    else
    {
      dst->masks[port_index] = 0;
      dst->handlers[port_index] = MACH_PORT_NULL;
      dst->behaviors[port_index] = 0;
      dst->flavors[port_index] = 0;
    }
  }
  dst->count = self->count;
}

static void
gum_exception_port_set_extract (GumExceptionPortSet * self,
                                exception_mask_array_t masks,
                                mach_msg_type_number_t * masks_count,
                                exception_handler_array_t old_handlers,
                                exception_behavior_array_t old_behaviors,
                                exception_flavor_array_t old_flavors)
{
  memcpy (masks, self->masks, sizeof (self->masks));
  *masks_count = self->count;
  memcpy (old_handlers, self->handlers, sizeof (self->handlers));
  memcpy (old_behaviors, self->behaviors, sizeof (self->behaviors));
  memcpy (old_flavors, self->flavors, sizeof (self->flavors));
}

static void
gum_exception_port_set_explode (GumExceptionPortSet * self,
                                GumExceptionPortSet * dst)
{
  mach_msg_type_number_t port_index;
  guint bit_index;

  for (port_index = 0; port_index != self->count; port_index++)
  {
    for (bit_index = FIRST_EXCEPTION; bit_index != EXC_TYPES_COUNT; bit_index++)
    {
      exception_mask_t flag = 1 << bit_index;

      if ((self->masks[port_index] & flag) == 0)
        continue;

      dst->masks[bit_index] = flag;
      dst->handlers[bit_index] = self->handlers[port_index];
      dst->behaviors[bit_index] = self->behaviors[port_index];
      dst->flavors[bit_index] = self->flavors[port_index];
    }
  }
  dst->count = EXC_TYPES_COUNT;
}

static void
gum_exception_port_set_implode (GumExceptionPortSet * self,
                                GumExceptionPortSet * dst)
{
  mach_msg_type_number_t bit_index, dst_index;

  dst_index = 0;
  for (bit_index = FIRST_EXCEPTION; bit_index != EXC_TYPES_COUNT; bit_index++)
  {
    exception_mask_t flag = 1 << bit_index;
    mach_port_t handler = self->handlers[bit_index];
    exception_behavior_t behavior = self->behaviors[bit_index];
    thread_state_flavor_t flavor = self->flavors[bit_index];
    mach_msg_type_number_t existing_index;

    if (self->masks[bit_index] == 0)
      continue;

    for (existing_index = 0; existing_index != dst_index; existing_index++)
    {
      if (dst->handlers[existing_index] == handler &&
          dst->behaviors[existing_index] == behavior &&
          dst->flavors[existing_index] == flavor)
      {
        dst->masks[existing_index] |= flag;
        break;
      }
    }

    if (existing_index == dst_index)
    {
      dst->masks[dst_index] = flag;
      dst->handlers[dst_index] = handler;
      dst->behaviors[dst_index] = behavior;
      dst->flavors[dst_index] = flavor;
      dst_index++;
    }
  }
  dst->count = dst_index;
}

static void
gum_exception_port_set_mod_refs (GumExceptionPortSet * self,
                                 mach_port_delta_t delta)
{
  mach_port_t self_task;
  mach_msg_type_number_t i;

  self_task = mach_task_self ();

  for (i = 0; i != self->count; i++)
  {
    mach_port_t handler;

    handler = self->handlers[i];
    if (handler == MACH_PORT_NULL)
      continue;

    mach_port_mod_refs (self_task, handler, MACH_PORT_RIGHT_SEND, delta);
  }
}
