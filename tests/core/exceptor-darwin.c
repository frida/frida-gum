/*
 * Copyright (C) 2026 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumexceptor.h"
#include "gumexceptorbackend.h"
#include "testutil.h"

#include "gum/gumdarwin.h"

#define TESTCASE(NAME) \
    void test_exceptor_darwin_ ## NAME (void)
#define TESTENTRY(NAME) \
    TESTENTRY_SIMPLE ("Core/Exceptor/Darwin", test_exceptor_darwin, NAME)

#define TEST_EXCEPTION_MASK \
    (EXC_MASK_BAD_ACCESS | EXC_MASK_BAD_INSTRUCTION | EXC_MASK_ARITHMETIC)
#define TEST_EXCEPTION_PORT_STOP 1

TESTLIST_BEGIN (exceptor_darwin)
  TESTENTRY (fault_in_scope_should_not_reach_task_exception_port)
#ifdef HAVE_ARM64
  TESTENTRY (execution_fault_at_odd_address_in_scope_should_be_caught)
#endif
  TESTENTRY (fault_outside_scope_should_still_reach_task_exception_port)
  TESTENTRY (thread_exception_port_should_be_left_in_place)
TESTLIST_END ()

typedef struct _TestExceptionPort TestExceptionPort;
typedef struct _TestOwnPortContext TestOwnPortContext;

struct _TestExceptionPort
{
  mach_port_t port;
  GThread * server;
  volatile guint exceptions_seen;

  mach_msg_type_number_t previous_count;
  exception_mask_t previous_masks[EXC_TYPES_COUNT];
  mach_port_t previous_handlers[EXC_TYPES_COUNT];
  exception_behavior_t previous_behaviors[EXC_TYPES_COUNT];
  thread_state_flavor_t previous_flavors[EXC_TYPES_COUNT];
};

struct _TestOwnPortContext
{
  GumExceptor * exceptor;
  TestExceptionPort * port;

  gboolean caught;
  gboolean port_left_in_place;
};

static gpointer fault_with_own_thread_port (gpointer data);
static gboolean is_thread_exception_port (mach_port_t port);
static gboolean recover_by_long_jump (GumExceptionDetails * details,
    gpointer user_data);
static void read_invalid_address (void);
#ifdef HAVE_ARM64
static void call_non_canonical_address (void);
#endif

static void test_exception_port_init (TestExceptionPort * self);
static void test_exception_port_deinit (TestExceptionPort * self);
static void test_exception_port_attach_to_task (TestExceptionPort * self);
static void test_exception_port_detach_from_task (TestExceptionPort * self);
static gpointer test_exception_port_serve (TestExceptionPort * self);

static GumExceptorNativeJmpBuf recovery_env;

TESTCASE (fault_in_scope_should_not_reach_task_exception_port)
{
  GumExceptor * exceptor;
  TestExceptionPort reporter;
  GumExceptorScope scope;
  gboolean caught;
  gchar * message;

  if (!_gum_exceptor_backend_supports_thread_ports ())
  {
    g_print ("<skipping, not supported on this platform> ");
    return;
  }

  exceptor = gum_exceptor_obtain ();

  test_exception_port_init (&reporter);
  test_exception_port_attach_to_task (&reporter);

  if (gum_exceptor_try (exceptor, &scope))
  {
    read_invalid_address ();
  }

  caught = gum_exceptor_catch (exceptor, &scope);

  test_exception_port_detach_from_task (&reporter);
  test_exception_port_deinit (&reporter);

  g_assert_true (caught);
  message = gum_exception_details_to_string (&scope.exception);
  g_assert_cmpstr (message, ==, "access violation accessing 0x8");
  g_free (message);
  g_assert_cmpuint (reporter.exceptions_seen, ==, 0);

  g_object_unref (exceptor);
}

#ifdef HAVE_ARM64

TESTCASE (execution_fault_at_odd_address_in_scope_should_be_caught)
{
  GumExceptor * exceptor;
  TestExceptionPort reporter;
  GumExceptorScope scope;
  gboolean caught;

  if (!_gum_exceptor_backend_supports_thread_ports ())
  {
    g_print ("<skipping, not supported on this platform> ");
    return;
  }

  exceptor = gum_exceptor_obtain ();

  test_exception_port_init (&reporter);
  test_exception_port_attach_to_task (&reporter);

  if (gum_exceptor_try (exceptor, &scope))
  {
    call_non_canonical_address ();
  }

  caught = gum_exceptor_catch (exceptor, &scope);

  test_exception_port_detach_from_task (&reporter);
  test_exception_port_deinit (&reporter);

  g_assert_true (caught);
  g_assert_cmpuint (scope.exception.type, ==, GUM_EXCEPTION_ACCESS_VIOLATION);
  g_assert_cmpuint (scope.exception.memory.operation, ==, GUM_MEMOP_EXECUTE);
  g_assert_cmpuint (reporter.exceptions_seen, ==, 0);

  g_object_unref (exceptor);
}

#endif

TESTCASE (fault_outside_scope_should_still_reach_task_exception_port)
{
  GumExceptor * exceptor;
  TestExceptionPort reporter;
  GumExceptorScope scope;
  gboolean caught;

  exceptor = gum_exceptor_obtain ();

  if (gum_exceptor_try (exceptor, &scope))
  {
    read_invalid_address ();
  }

  caught = gum_exceptor_catch (exceptor, &scope);
  g_assert_true (caught);

  test_exception_port_init (&reporter);
  test_exception_port_attach_to_task (&reporter);
  gum_exceptor_add (exceptor, recover_by_long_jump, NULL);

  if (GUM_NATIVE_SETJMP (recovery_env) == 0)
    read_invalid_address ();

  gum_exceptor_remove (exceptor, recover_by_long_jump, NULL);
  test_exception_port_detach_from_task (&reporter);
  test_exception_port_deinit (&reporter);

  g_assert_cmpuint (reporter.exceptions_seen, ==, 1);

  g_object_unref (exceptor);
}

TESTCASE (thread_exception_port_should_be_left_in_place)
{
  TestExceptionPort runtime;
  TestOwnPortContext ctx;

  ctx.exceptor = gum_exceptor_obtain ();
  ctx.port = &runtime;
  ctx.caught = FALSE;
  ctx.port_left_in_place = FALSE;

  test_exception_port_init (&runtime);

  g_thread_join (g_thread_new ("exceptor-own-port", fault_with_own_thread_port,
      &ctx));

  test_exception_port_deinit (&runtime);

  g_assert_true (ctx.caught);
  g_assert_true (ctx.port_left_in_place);
  g_assert_cmpuint (runtime.exceptions_seen, ==, 1);

  g_object_unref (ctx.exceptor);
}

static gpointer
fault_with_own_thread_port (gpointer data)
{
  TestOwnPortContext * ctx = data;
  GumExceptorScope scope;
  G_GNUC_UNUSED kern_return_t kr;

  kr = thread_set_exception_ports (gum_process_get_current_thread_id (),
      TEST_EXCEPTION_MASK, ctx->port->port,
      EXCEPTION_STATE | MACH_EXCEPTION_CODES, GUM_DARWIN_THREAD_STATE_FLAVOR);
  g_assert_cmpint (kr, ==, KERN_SUCCESS);

  if (gum_exceptor_try (ctx->exceptor, &scope))
  {
    read_invalid_address ();
  }

  ctx->caught = gum_exceptor_catch (ctx->exceptor, &scope);
  ctx->port_left_in_place = is_thread_exception_port (ctx->port->port);

  return NULL;
}

static gboolean
is_thread_exception_port (mach_port_t port)
{
  gboolean result = TRUE;
  mach_port_t self_task;
  mach_msg_type_number_t count, i;
  exception_mask_t masks[EXC_TYPES_COUNT];
  mach_port_t handlers[EXC_TYPES_COUNT];
  exception_behavior_t behaviors[EXC_TYPES_COUNT];
  thread_state_flavor_t flavors[EXC_TYPES_COUNT];
  G_GNUC_UNUSED kern_return_t kr;

  self_task = mach_task_self ();

  count = EXC_TYPES_COUNT;
  kr = thread_get_exception_ports (gum_process_get_current_thread_id (),
      TEST_EXCEPTION_MASK, masks, &count, handlers, behaviors, flavors);
  g_assert_cmpint (kr, ==, KERN_SUCCESS);

  for (i = 0; i != count; i++)
  {
    if (handlers[i] != port)
      result = FALSE;

    if (MACH_PORT_VALID (handlers[i]))
      mach_port_deallocate (self_task, handlers[i]);
  }

  return result;
}

static gboolean
recover_by_long_jump (GumExceptionDetails * details,
                      gpointer user_data)
{
  GUM_NATIVE_LONGJMP (recovery_env, 1);

  return TRUE;
}

static void
read_invalid_address (void)
{
  G_GNUC_UNUSED volatile gint value;

  value = *((volatile gint *) GSIZE_TO_POINTER (8));
}

#ifdef HAVE_ARM64

static void
call_non_canonical_address (void)
{
  asm volatile (
      "mov x16, #0x1000\n\t"
      "movk x16, #0x20, lsl #48\n\t"
      "blr x16\n\t"
      :
      :
      : "x16", "x30", "memory");
}

#endif

static void
test_exception_port_init (TestExceptionPort * self)
{
  mach_port_t self_task;
  G_GNUC_UNUSED kern_return_t kr;

  self_task = mach_task_self ();

  kr = mach_port_allocate (self_task, MACH_PORT_RIGHT_RECEIVE, &self->port);
  g_assert_cmpint (kr, ==, KERN_SUCCESS);

  kr = mach_port_insert_right (self_task, self->port, self->port,
      MACH_MSG_TYPE_MAKE_SEND);
  g_assert_cmpint (kr, ==, KERN_SUCCESS);

  self->exceptions_seen = 0;
  self->server = g_thread_new ("exceptor-test-port",
      (GThreadFunc) test_exception_port_serve, self);
}

static void
test_exception_port_deinit (TestExceptionPort * self)
{
  mach_port_t self_task;
  mach_msg_header_t stop;
  G_GNUC_UNUSED kern_return_t kr;

  self_task = mach_task_self ();

  stop.msgh_bits = MACH_MSGH_BITS (MACH_MSG_TYPE_COPY_SEND, 0);
  stop.msgh_size = sizeof (stop);
  stop.msgh_remote_port = self->port;
  stop.msgh_local_port = MACH_PORT_NULL;
  stop.msgh_voucher_port = MACH_PORT_NULL;
  stop.msgh_id = TEST_EXCEPTION_PORT_STOP;
  kr = mach_msg_send (&stop);
  g_assert_cmpint (kr, ==, KERN_SUCCESS);

  g_thread_join (self->server);

  mach_port_mod_refs (self_task, self->port, MACH_PORT_RIGHT_SEND, -1);
  mach_port_mod_refs (self_task, self->port, MACH_PORT_RIGHT_RECEIVE, -1);
}

static void
test_exception_port_attach_to_task (TestExceptionPort * self)
{
  G_GNUC_UNUSED kern_return_t kr;

  self->previous_count = EXC_TYPES_COUNT;
  kr = task_swap_exception_ports (mach_task_self (), TEST_EXCEPTION_MASK,
      self->port, EXCEPTION_STATE | MACH_EXCEPTION_CODES,
      GUM_DARWIN_THREAD_STATE_FLAVOR, self->previous_masks,
      &self->previous_count, self->previous_handlers,
      self->previous_behaviors, self->previous_flavors);
  g_assert_cmpint (kr, ==, KERN_SUCCESS);
}

static void
test_exception_port_detach_from_task (TestExceptionPort * self)
{
  mach_port_t self_task;
  mach_msg_type_number_t i;

  self_task = mach_task_self ();

  for (i = 0; i != self->previous_count; i++)
  {
    mach_port_t handler = self->previous_handlers[i];

    task_set_exception_ports (self_task, self->previous_masks[i], handler,
        self->previous_behaviors[i], self->previous_flavors[i]);

    if (MACH_PORT_VALID (handler))
      mach_port_deallocate (self_task, handler);
  }
}

static gpointer
test_exception_port_serve (TestExceptionPort * self)
{
  union
  {
    mach_msg_header_t header;
    guint8 storage[4096];
  } request;
  mig_reply_error_t reply;
  G_GNUC_UNUSED kern_return_t kr;

  while (TRUE)
  {
    kr = mach_msg (&request.header, MACH_RCV_MSG, 0, sizeof (request),
        self->port, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
    g_assert_cmpint (kr, ==, KERN_SUCCESS);

    if (request.header.msgh_id == TEST_EXCEPTION_PORT_STOP)
      break;

    self->exceptions_seen++;

    reply.Head.msgh_bits =
        MACH_MSGH_BITS (MACH_MSGH_BITS_REMOTE (request.header.msgh_bits), 0);
    reply.Head.msgh_size = sizeof (reply);
    reply.Head.msgh_remote_port = request.header.msgh_remote_port;
    reply.Head.msgh_local_port = MACH_PORT_NULL;
    reply.Head.msgh_voucher_port = MACH_PORT_NULL;
    reply.Head.msgh_id = request.header.msgh_id + 100;
    reply.NDR = NDR_record;
    reply.RetCode = KERN_FAILURE;

    mach_msg_send (&reply.Head);
  }

  return NULL;
}
