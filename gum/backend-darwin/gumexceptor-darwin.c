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

static gboolean gum_exception_memory_details_from_thread (
    mach_port_t thread, GumExceptionMemoryDetails * md);

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

static void
gum_exceptor_backend_attach (GumExceptorBackend * self)
{
  mach_port_name_t self_task;
  kern_return_t kr;
  GumExceptionPortSet * previous_ports;
  dispatch_source_t source;

  self_task = mach_task_self ();

  self->dispatch_queue = dispatch_queue_create ("re.frida.gum.exceptor.queue",
      DISPATCH_QUEUE_SERIAL);

  kr = mach_port_allocate (self_task, MACH_PORT_RIGHT_RECEIVE,
      &self->server_port);
  g_assert_cmpint (kr, ==, KERN_SUCCESS);

  kr = mach_port_insert_right (self_task, self->server_port, self->server_port,
      MACH_MSG_TYPE_MAKE_SEND);
  g_assert_cmpint (kr, ==, KERN_SUCCESS);

  previous_ports = &self->previous_ports;
  kr = task_swap_exception_ports (self_task,
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
  g_assert_cmpint (kr, ==, KERN_SUCCESS);

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
    kern_return_t kr;

    kr = task_set_exception_ports (self_task,
        previous_ports->masks[port_index],
        previous_ports->ports[port_index],
        previous_ports->behaviors[port_index],
        previous_ports->flavors[port_index]);
    g_assert_cmpint (kr, ==, KERN_SUCCESS);
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
  kern_return_t kr;
  boolean_t handled;

  bzero (&request, sizeof (request));
  header_in = (mach_msg_header_t *) &request;
  header_in->msgh_size = sizeof (request);
  header_in->msgh_local_port = self->server_port;
  kr = mach_msg_receive (header_in);
  g_assert_cmpint (kr, ==, KERN_SUCCESS);

  header_out = (mach_msg_header_t *) &reply;

  handled = mach_exc_server (header_in, header_out);
  if (!handled)
    return;

  mach_msg_send (header_out);
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
  mach_port_name_t self_task;
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
    GumExceptionPortSet * previous_ports = &self->previous_ports;
    mach_msg_type_number_t port_index;
    exception_data_t small_code;
    mach_msg_type_number_t code_index;

    small_code = g_alloca (code_count * sizeof (exception_data_type_t));
    for (code_index = 0; code_index != code_count; code_index++)
    {
      small_code[code_index] = code[code_index];
    }

    kr = KERN_FAILURE;

    for (port_index = 0; port_index != previous_ports->count; port_index++)
    {
      exception_mask_t mask = previous_ports->masks[port_index];
      mach_port_t port = previous_ports->ports[port_index];
      exception_behavior_t behavior = previous_ports->behaviors[port_index];
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
