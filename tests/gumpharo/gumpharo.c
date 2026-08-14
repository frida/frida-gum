/*
 * Copyright (C) 2026 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumpharo-fixture.c"

TESTLIST_BEGIN (gumpharo)
  TESTENTRY (module_should_be_named_after_the_plugin)
  TESTENTRY (every_export_should_belong_to_the_plugin)
  TESTENTRY (every_primitive_should_declare_an_accessor_depth)
  TESTENTRY (interpreter_should_be_rejected_when_too_old)
  TESTENTRY (pointer_result_should_round_trip)
  TESTENTRY (boolean_result_should_round_trip)
  TESTENTRY (void_result_should_answer_the_receiver)
  TESTENTRY (arguments_should_be_read_in_declaration_order)
  TESTENTRY (listener_should_observe_enter_and_leave)
  TESTENTRY (outgoing_message_should_reach_the_handler)
  TESTENTRY (outgoing_message_should_carry_binary_data)
  TESTENTRY (incoming_message_should_be_queued_in_order)
  TESTENTRY (incoming_message_should_signal_the_semaphore)
  TESTENTRY (taking_from_an_empty_queue_should_answer_zero)
  TESTENTRY (null_handle_should_fail_the_primitive)
TESTLIST_END ()

static void on_message (const gchar * payload, GBytes * data,
    gpointer user_data);
static gint target_function (gint n);
static void on_enter (GumInvocationContext * context);
static void on_leave (GumInvocationContext * context);

static GString * listener_events;
static GString * delivered_payloads;
static GBytes * delivered_data;

TESTCASE (module_should_be_named_after_the_plugin)
{
  const char * (* get_module_name) (void);

  get_module_name = (const char * (*) (void)) find_primitive ("getModuleName");
  g_assert_nonnull (get_module_name);

  g_assert_cmpstr (get_module_name (), ==, "GumPlugin");
}

TESTCASE (every_export_should_belong_to_the_plugin)
{
  guint i;

  for (i = 0; GumPlugin_exports[i][0] != NULL; i++)
  {
    g_assert_cmpstr (GumPlugin_exports[i][0], ==, "GumPlugin");
    g_assert_nonnull (GumPlugin_exports[i][2]);
  }

  g_assert_cmpuint (i, >, 300);
}

TESTCASE (every_primitive_should_declare_an_accessor_depth)
{
  guint i;

  for (i = 0; GumPlugin_exports[i][0] != NULL; i++)
  {
    const gchar * name = GumPlugin_exports[i][1];
    gsize length;

    if (!g_str_has_prefix (name, "prim"))
      continue;

    length = strlen (name);
    g_assert_cmpint (((const gint8 *) name)[length + 1], ==, 0);
  }
}

TESTCASE (interpreter_should_be_rejected_when_too_old)
{
  struct VirtualMachine ancient = test_interpreter;

  ancient.majorVersion = test_ancient_major_version;

  g_assert_false (gum_pharo_set_interpreter (&ancient));

  gum_pharo_set_interpreter (&test_interpreter);
}

TESTCASE (pointer_result_should_round_trip)
{
  sqInt result;

  result = invoke_primitive ("primGumInterceptorObtain", 0);

  g_assert_cmphex (result, ==, (sqInt) gum_interceptor_obtain ());
}

TESTCASE (boolean_result_should_round_trip)
{
  gsize page_size;
  guint8 * code;
  sqInt result;

  page_size = gum_query_page_size ();
  code = gum_memory_allocate (NULL, page_size, page_size, GUM_PAGE_RW);

  result = invoke_primitive ("primGumMemoryIsReadable", 2, (sqInt) code,
      (sqInt) 1);
  g_assert_cmpint (result, ==, TRUE);

  gum_memory_free (code, page_size);
}

TESTCASE (void_result_should_answer_the_receiver)
{
  invoke_primitive ("primGumInterceptorBeginTransaction", 1,
      (sqInt) gum_interceptor_obtain ());

  g_assert_true (fixture->returned_receiver);

  invoke_primitive ("primGumInterceptorEndTransaction", 1,
      (sqInt) gum_interceptor_obtain ());
}

TESTCASE (arguments_should_be_read_in_declaration_order)
{
  guint8 * pages;
  gsize page_size;
  sqInt result;

  page_size = gum_query_page_size ();
  pages = gum_memory_allocate (NULL, 2 * page_size, page_size, GUM_PAGE_RW);
  gum_mprotect (pages + page_size, page_size, GUM_PAGE_NO_ACCESS);

  result = invoke_primitive ("primGumMemoryIsReadable", 2, (sqInt) pages,
      (sqInt) page_size);
  g_assert_cmpint (result, ==, TRUE);

  result = invoke_primitive ("primGumMemoryIsReadable", 2, (sqInt) pages,
      (sqInt) (page_size * 2));
  g_assert_cmpint (result, ==, FALSE);

  gum_mprotect (pages + page_size, page_size, GUM_PAGE_RW);
  gum_memory_free (pages, 2 * page_size);
}

TESTCASE (listener_should_observe_enter_and_leave)
{
  sqInt listener;
  GumInterceptor * interceptor;

  listener_events = g_string_new ("");

  listener = invoke_primitive ("primGumPharoListenerNew", 2,
      (sqInt) on_enter, (sqInt) on_leave);
  g_assert_cmphex (listener, !=, 0);

  interceptor = gum_interceptor_obtain ();
  g_assert_cmpint (invoke_primitive ("primGumInterceptorAttach", 4,
      (sqInt) interceptor, (sqInt) target_function, listener, (sqInt) NULL),
      ==, GUM_ATTACH_OK);

  target_function (42);

  g_assert_cmpstr (listener_events->str, ==, "enter,leave,");

  gum_interceptor_detach (interceptor, (GumInvocationListener *) listener);
  g_object_unref ((gpointer) listener);
  g_string_free (listener_events, TRUE);
}

static gint
target_function (gint n)
{
  return n * 2;
}

static void
on_enter (GumInvocationContext * context)
{
  g_string_append (listener_events, "enter,");
}

static void
on_leave (GumInvocationContext * context)
{
  g_string_append (listener_events, "leave,");
}

TESTCASE (outgoing_message_should_reach_the_handler)
{
  delivered_payloads = g_string_new ("");
  gum_pharo_set_message_handler (on_message, NULL);

  invoke_primitive ("primGumPharoPost", 2,
      string_oop ("{\"type\":\"log\"}"), nil_oop ());

  g_assert_cmpstr (delivered_payloads->str, ==, "{\"type\":\"log\"}");

  gum_pharo_set_message_handler (NULL, NULL);
  g_string_free (delivered_payloads, TRUE);
}

TESTCASE (outgoing_message_should_carry_binary_data)
{
  gsize size;
  gconstpointer bytes;

  delivered_payloads = g_string_new ("");
  delivered_data = NULL;
  gum_pharo_set_message_handler (on_message, NULL);

  invoke_primitive ("primGumPharoPost", 2, string_oop ("{}"),
      byte_array_oop ("\x01\x02\x03", 3));

  g_assert_nonnull (delivered_data);
  bytes = g_bytes_get_data (delivered_data, &size);
  g_assert_cmpuint (size, ==, 3);
  g_assert_cmpint (((const guint8 *) bytes)[1], ==, 2);

  g_bytes_unref (delivered_data);
  delivered_data = NULL;
  gum_pharo_set_message_handler (NULL, NULL);
  g_string_free (delivered_payloads, TRUE);
}

TESTCASE (incoming_message_should_be_queued_in_order)
{
  sqInt first, second;

  gum_pharo_post ("first", NULL);
  gum_pharo_post ("second", NULL);

  first = invoke_primitive ("primGumPharoTakeMessage", 0);
  second = invoke_primitive ("primGumPharoTakeMessage", 0);
  g_assert_cmphex (first, !=, 0);
  g_assert_cmphex (second, !=, 0);

  g_assert_cmpstr (payload_of (first), ==, "first");
  g_assert_cmpstr (payload_of (second), ==, "second");

  invoke_primitive ("primGumPharoReleaseMessage", 1, first);
  invoke_primitive ("primGumPharoReleaseMessage", 1, second);
}

TESTCASE (incoming_message_should_signal_the_semaphore)
{
  sqInt message;

  invoke_primitive ("primGumPharoSetMessageSemaphore", 1, (sqInt) 42);
  fixture->signalled_semaphore = -1;

  gum_pharo_post ("ping", NULL);

  g_assert_cmpint (fixture->signalled_semaphore, ==, 42);

  message = invoke_primitive ("primGumPharoTakeMessage", 0);
  invoke_primitive ("primGumPharoReleaseMessage", 1, message);
  invoke_primitive ("primGumPharoSetMessageSemaphore", 1, (sqInt) -1);
}

TESTCASE (taking_from_an_empty_queue_should_answer_zero)
{
  sqInt message;

  while ((message = invoke_primitive ("primGumPharoTakeMessage", 0)) != 0)
    invoke_primitive ("primGumPharoReleaseMessage", 1, message);

  g_assert_cmphex (invoke_primitive ("primGumPharoTakeMessage", 0), ==, 0);
}

static void
on_message (const gchar * payload,
            GBytes * data,
            gpointer user_data)
{
  g_string_append (delivered_payloads, payload);
  if (data != NULL)
    delivered_data = g_bytes_ref (data);
}

TESTCASE (null_handle_should_fail_the_primitive)
{
  fixture->failure = 0;

  invoke_primitive ("primGumModuleGetName", 1, (sqInt) NULL);

  g_assert_cmpint (fixture->failure, ==, PrimErrBadArgument);
}
