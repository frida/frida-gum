/*
 * Copyright (C) 2016 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumexceptorbackend.h"

#include "gumdarwin.h"
#include "guminterceptor.h"
#include "machexc.h"
#include "machexcserver.c"

#include <dispatch/dispatch.h>
#include <mach/mach.h>

/*
 * Regenerate with:
 *
 * $(xcrun --sdk macosx -f mig) \
 *     -header machexc.h \
 *     -user machexcclient.c \
 *     -server machexcserver.c \
 *     $(xcrun --sdk macosx --show-sdk-path)/usr/include/mach/mach_exc.defs
 */

typedef struct _GumExceptionPortSet GumExceptionPortSet;

struct _GumExceptionPortSet
{
  mach_msg_type_number_t count;
  exception_mask_t masks[EXC_TYPES_COUNT];
  mach_port_t ports[EXC_TYPES_COUNT];
  exception_behavior_t behaviors[EXC_TYPES_COUNT];
  thread_state_flavor_t flavors[EXC_TYPES_COUNT];
};

struct _GumExceptorBackend
{
  GObject parent;

  gboolean disposed;

  GumExceptionHandler handler;
  gpointer handler_data;

  dispatch_queue_t dispatch_queue;
  mach_port_name_t server_port;
  dispatch_source_t server_recv_source;
  GumExceptionPortSet previous_ports;

  GumInterceptor * interceptor;
};

static void gum_exceptor_backend_dispose (GObject * object);

static void gum_exceptor_backend_attach (GumExceptorBackend * self);
static void gum_exceptor_backend_detach (GumExceptorBackend * self);
static void gum_exceptor_backend_on_server_recv (void * context);

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

    gum_exceptor_backend_detach (self);

    g_object_unref (self->interceptor);
    self->interceptor = NULL;
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

static void
gum_exceptor_backend_attach (GumExceptorBackend * self)
{
  mach_port_name_t self_task;
  kern_return_t ret;
  GumExceptionPortSet * previous_ports;
  dispatch_source_t source;

  self_task = mach_task_self ();

  self->dispatch_queue = dispatch_queue_create ("re.frida.gum.exceptor.queue",
      DISPATCH_QUEUE_SERIAL);

  ret = mach_port_allocate (self_task, MACH_PORT_RIGHT_RECEIVE,
      &self->server_port);
  g_assert_cmpint (ret, ==, KERN_SUCCESS);

  ret = mach_port_insert_right (self_task, self->server_port, self->server_port,
      MACH_MSG_TYPE_MAKE_SEND);
  g_assert_cmpint (ret, ==, KERN_SUCCESS);

  previous_ports = &self->previous_ports;
  ret = task_swap_exception_ports (self_task,
      EXC_MASK_ARITHMETIC |
      EXC_MASK_BAD_ACCESS |
      EXC_MASK_BAD_INSTRUCTION |
      EXC_MASK_BREAKPOINT |
      EXC_MASK_GUARD |
      EXC_MASK_SOFTWARE,
      self->server_port,
      EXCEPTION_STATE_IDENTITY | MACH_EXCEPTION_CODES,
      GUM_DARWIN_THREAD_STATE_FLAVOR,
      previous_ports->masks,
      &previous_ports->count,
      previous_ports->ports,
      previous_ports->behaviors,
      previous_ports->flavors);
  g_assert_cmpint (ret, ==, KERN_SUCCESS);

  /* TODO: SIGABRT */

  source = dispatch_source_create (DISPATCH_SOURCE_TYPE_MACH_RECV,
      self->server_port, 0, self->dispatch_queue);
  self->server_recv_source = source;
  dispatch_set_context (source, self);
  dispatch_source_set_event_handler_f (source,
      gum_exceptor_backend_on_server_recv);
  dispatch_resume (source);
}

static void
gum_exceptor_backend_detach (GumExceptorBackend * self)
{
  mach_port_name_t self_task;
  GumExceptionPortSet * previous_ports;
  mach_msg_type_number_t port_index;

  self_task = mach_task_self ();

  previous_ports = &self->previous_ports;
  for (port_index = 0; port_index != previous_ports->count; port_index++)
  {
    kern_return_t ret;

    ret = task_set_exception_ports (self_task,
        previous_ports->masks[port_index],
        previous_ports->ports[port_index],
        previous_ports->behaviors[port_index],
        previous_ports->flavors[port_index]);
    g_assert_cmpint (ret, ==, KERN_SUCCESS);
  }
  previous_ports->count = 0;

  dispatch_release (self->server_recv_source);
  self->server_recv_source = NULL;

  mach_port_mod_refs (self_task, self->server_port, MACH_PORT_RIGHT_SEND, -1);
  mach_port_mod_refs (self_task, self->server_port, MACH_PORT_RIGHT_RECEIVE,
      -1);
  self->server_port = MACH_PORT_NULL;

  dispatch_release (self->dispatch_queue);
  self->dispatch_queue = NULL;
}

static void
gum_exceptor_backend_on_server_recv (void * context)
{
  GumExceptorBackend * self = context;
  union __RequestUnion__mach_exc_subsystem request;
  union __ReplyUnion__mach_exc_subsystem reply;
  mach_msg_header_t * header_in, * header_out;
  kern_return_t ret;
  boolean_t handled;

  bzero (&request, sizeof (request));
  header_in = (mach_msg_header_t *) &request;
  header_in->msgh_size = sizeof (request);
  header_in->msgh_local_port = self->server_port;
  ret = mach_msg_receive (header_in);
  g_assert_cmpint (ret, ==, 0);

  header_out = (mach_msg_header_t *) &reply;

  handled = mach_exc_server (header_in, header_out);
  g_assert (handled);

  ret = mach_msg_send (header_out);
  g_assert_cmpint (ret, ==, 0);
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
  GumExceptionDetails ed;
  GumExceptionMemoryDetails * md = &ed.memory;
  GumCpuContext * cpu_context = &ed.context;

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

  /* FIXME: */
  md->operation = GUM_MEMOP_INVALID;
  md->address = NULL;

  if (self->handler (&ed, self->handler_data))
  {
    gum_darwin_unparse_unified_thread_state (cpu_context,
        (GumDarwinUnifiedThreadState *) new_state);
    *new_state_count = old_state_count;

    return KERN_SUCCESS;
  }
  else
  {
    /* FIXME: forward to old handler */
  }

  /* FIXME: deallocate ports */

  return KERN_INVALID_ARGUMENT;
}
