/*
 * Copyright (C) 2010-2015 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
 * Copyright (C) 2015 Marc Hartmayer <hello@hartmayer.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "script-fixture.c"

TEST_LIST_BEGIN (script)
  SCRIPT_TESTENTRY (invalid_script_should_return_null)
  SCRIPT_TESTENTRY (array_buffer_can_be_created)
  SCRIPT_TESTENTRY (message_can_be_sent)
  SCRIPT_TESTENTRY (message_can_be_sent_with_data)
  SCRIPT_TESTENTRY (message_can_be_received)
  SCRIPT_TESTENTRY (recv_may_specify_desired_message_type)
  SCRIPT_TESTENTRY (recv_can_be_waited_for)
  SCRIPT_TESTENTRY (thread_can_be_forced_to_sleep)
  SCRIPT_TESTENTRY (timeout_can_be_scheduled)
  SCRIPT_TESTENTRY (timeout_can_be_cancelled)
  SCRIPT_TESTENTRY (interval_can_be_scheduled)
  SCRIPT_TESTENTRY (interval_can_be_cancelled)
  SCRIPT_TESTENTRY (argument_can_be_read)
  SCRIPT_TESTENTRY (argument_can_be_replaced)
  SCRIPT_TESTENTRY (return_value_can_be_read)
  SCRIPT_TESTENTRY (return_value_can_be_replaced)
  SCRIPT_TESTENTRY (return_address_can_be_read)
  SCRIPT_TESTENTRY (register_can_be_read)
  SCRIPT_TESTENTRY (system_error_can_be_read)
  SCRIPT_TESTENTRY (system_error_can_be_replaced)
  SCRIPT_TESTENTRY (invocations_are_bound_on_tls_object)
  SCRIPT_TESTENTRY (invocations_provide_call_depth)
  SCRIPT_TESTENTRY (invocations_provide_context_for_backtrace)
  SCRIPT_TESTENTRY (callbacks_can_be_detached)
  SCRIPT_TESTENTRY (function_can_be_replaced)
  SCRIPT_TESTENTRY (function_can_be_reverted)
  SCRIPT_TESTENTRY (interceptor_handles_invalid_arguments)
  SCRIPT_TESTENTRY (interceptor_performance)
  SCRIPT_TESTENTRY (pointer_can_be_read)
  SCRIPT_TESTENTRY (pointer_can_be_written)
  SCRIPT_TESTENTRY (memory_can_be_allocated)
  SCRIPT_TESTENTRY (memory_can_be_copied)
  SCRIPT_TESTENTRY (memory_can_be_duped)
  SCRIPT_TESTENTRY (memory_can_be_protected)
  SCRIPT_TESTENTRY (s8_can_be_read)
  SCRIPT_TESTENTRY (s8_can_be_written)
  SCRIPT_TESTENTRY (u8_can_be_read)
  SCRIPT_TESTENTRY (u8_can_be_written)
  SCRIPT_TESTENTRY (s16_can_be_read)
  SCRIPT_TESTENTRY (s16_can_be_written)
  SCRIPT_TESTENTRY (u16_can_be_read)
  SCRIPT_TESTENTRY (u16_can_be_written)
  SCRIPT_TESTENTRY (s32_can_be_read)
  SCRIPT_TESTENTRY (s32_can_be_written)
  SCRIPT_TESTENTRY (u32_can_be_read)
  SCRIPT_TESTENTRY (u32_can_be_written)
  SCRIPT_TESTENTRY (s64_can_be_read)
  SCRIPT_TESTENTRY (s64_can_be_written)
  SCRIPT_TESTENTRY (u64_can_be_read)
  SCRIPT_TESTENTRY (u64_can_be_written)
  SCRIPT_TESTENTRY (short_can_be_read)
  SCRIPT_TESTENTRY (short_can_be_written)
  SCRIPT_TESTENTRY (ushort_can_be_read)
  SCRIPT_TESTENTRY (ushort_can_be_written)
  SCRIPT_TESTENTRY (int_can_be_read)
  SCRIPT_TESTENTRY (int_can_be_written)
  SCRIPT_TESTENTRY (uint_can_be_read)
  SCRIPT_TESTENTRY (uint_can_be_written)
  SCRIPT_TESTENTRY (long_can_be_read)
  SCRIPT_TESTENTRY (long_can_be_written)
  SCRIPT_TESTENTRY (ulong_can_be_read)
  SCRIPT_TESTENTRY (ulong_can_be_written)
  SCRIPT_TESTENTRY (byte_array_can_be_read)
  SCRIPT_TESTENTRY (byte_array_can_be_written)
  SCRIPT_TESTENTRY (c_string_can_be_read)
  SCRIPT_TESTENTRY (utf8_string_can_be_read)
  SCRIPT_TESTENTRY (utf8_string_can_be_written)
  SCRIPT_TESTENTRY (utf8_string_can_be_allocated)
  SCRIPT_TESTENTRY (utf16_string_can_be_read)
  SCRIPT_TESTENTRY (utf16_string_can_be_written)
  SCRIPT_TESTENTRY (utf16_string_can_be_allocated)
#ifdef G_OS_WIN32
  SCRIPT_TESTENTRY (ansi_string_can_be_read)
  SCRIPT_TESTENTRY (ansi_string_can_be_written)
  SCRIPT_TESTENTRY (ansi_string_can_be_allocated)
#endif
  SCRIPT_TESTENTRY (invalid_read_results_in_exception)
  SCRIPT_TESTENTRY (invalid_write_results_in_exception)
  SCRIPT_TESTENTRY (memory_can_be_scanned)
  SCRIPT_TESTENTRY (memory_scan_should_be_interruptible)
  SCRIPT_TESTENTRY (memory_scan_handles_unreadable_memory)
#ifdef G_OS_WIN32
  SCRIPT_TESTENTRY (memory_access_can_be_monitored)
#endif
  SCRIPT_TESTENTRY (frida_version_is_available)
  SCRIPT_TESTENTRY (process_arch_is_available)
  SCRIPT_TESTENTRY (process_get_module_by_name)
  SCRIPT_TESTENTRY (process_platform_is_available)
  SCRIPT_TESTENTRY (process_pointer_size_is_available)
  SCRIPT_TESTENTRY (process_debugger_status_is_available)
#ifndef HAVE_ANDROID
  SCRIPT_TESTENTRY (process_threads_can_be_enumerated)
  SCRIPT_TESTENTRY (process_threads_can_be_enumerated_synchronously)
#endif
  SCRIPT_TESTENTRY (process_modules_can_be_enumerated)
  SCRIPT_TESTENTRY (process_modules_can_be_enumerated_synchronously)
  SCRIPT_TESTENTRY (process_ranges_can_be_enumerated)
  SCRIPT_TESTENTRY (process_ranges_can_be_enumerated_synchronously)
#ifdef HAVE_DARWIN
  SCRIPT_TESTENTRY (process_malloc_ranges_can_be_enumerated)
  SCRIPT_TESTENTRY (process_malloc_ranges_can_be_enumerated_synchronously)
#endif
  SCRIPT_TESTENTRY (module_exports_can_be_enumerated)
  SCRIPT_TESTENTRY (module_exports_can_be_enumerated_synchronously)
  SCRIPT_TESTENTRY (module_exports_enumeration_performance)
  SCRIPT_TESTENTRY (module_ranges_can_be_enumerated)
  SCRIPT_TESTENTRY (module_ranges_can_be_enumerated_synchronously)
  SCRIPT_TESTENTRY (module_base_address_can_be_found)
  SCRIPT_TESTENTRY (module_export_can_be_found_by_name)
  SCRIPT_TESTENTRY (socket_type_can_be_inspected)
#ifndef HAVE_ANDROID
  SCRIPT_TESTENTRY (socket_endpoints_can_be_inspected)
#endif
  SCRIPT_TESTENTRY (native_pointer_provides_is_null)
  SCRIPT_TESTENTRY (native_pointer_to_match_pattern)
  SCRIPT_TESTENTRY (native_function_can_be_invoked)
  SCRIPT_TESTENTRY (variadic_native_function_can_be_invoked)
  SCRIPT_TESTENTRY (native_function_is_a_native_pointer)
  SCRIPT_TESTENTRY (native_callback_can_be_invoked)
  SCRIPT_TESTENTRY (native_callback_is_a_native_pointer)
  SCRIPT_TESTENTRY (address_can_be_resolved_to_symbol)
  SCRIPT_TESTENTRY (name_can_be_resolved_to_symbol)
  SCRIPT_TESTENTRY (function_can_be_found_by_name)
  SCRIPT_TESTENTRY (functions_can_be_found_by_name)
  SCRIPT_TESTENTRY (functions_can_be_found_by_matching)
  SCRIPT_TESTENTRY (instruction_can_be_parsed)
  SCRIPT_TESTENTRY (file_can_be_written_to)
#ifdef HAVE_I386
  SCRIPT_TESTENTRY (execution_can_be_traced)
  SCRIPT_TESTENTRY (call_can_be_probed)
#endif
  SCRIPT_TESTENTRY (script_can_be_reloaded)
  SCRIPT_TESTENTRY (types_handle_invalid_construction)
  SCRIPT_TESTENTRY (weak_callback_is_triggered_on_gc)
  SCRIPT_TESTENTRY (weak_callback_is_triggered_on_unload)
  SCRIPT_TESTENTRY (weak_callback_is_triggered_on_unbind)
  SCRIPT_TESTENTRY (debugger_can_be_enabled)
TEST_LIST_END ()

static gint gum_toupper (gchar * str, gint limit);
static gint gum_sum (gint count, ...);

#ifndef HAVE_ANDROID
static gboolean on_incoming_connection (GSocketService * service,
    GSocketConnection * connection, GObject * source_object,
    gpointer user_data);
static void on_read_ready (GObject * source_object, GAsyncResult * res,
    gpointer user_data);
#endif

static gpointer invoke_target_function_int_worker (gpointer data);

static void on_message (GumScript * script, const gchar * message,
    const guint8 * data, gint data_length, gpointer user_data);

static int target_function_int (int arg);
static const gchar * target_function_string (const gchar * arg);
static int target_function_nested_a (int arg);
static int target_function_nested_b (int arg);
static int target_function_nested_c (int arg);

gint gum_script_dummy_global_to_trick_optimizer = 0;

SCRIPT_TESTCASE (instruction_can_be_parsed)
{
  COMPILE_AND_LOAD_SCRIPT (
      "var first = Instruction.parse(" GUM_PTR_CONST ");"
      "var second = Instruction.parse(first.next);"
      "send(typeof first.toString());"
      "send(typeof second.toString());"
      "send(first.address.toInt32() !== 0);"
      "send(first.size > 0);"
      "send(typeof first.mnemonic);"
      "send(typeof first.opStr);",
      target_function_int);
  EXPECT_SEND_MESSAGE_WITH ("\"string\"");
  EXPECT_SEND_MESSAGE_WITH ("\"string\"");
  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_SEND_MESSAGE_WITH ("\"string\"");
  EXPECT_SEND_MESSAGE_WITH ("\"string\"");
  EXPECT_NO_MESSAGES ();

  COMPILE_AND_LOAD_SCRIPT ("Instruction.parse(ptr(\"0x1\"));");
  EXPECT_ERROR_MESSAGE_WITH (ANY_LINE_NUMBER,
      "Error: access violation reading 0x1");
}

SCRIPT_TESTCASE (address_can_be_resolved_to_symbol)
{
  COMPILE_AND_LOAD_SCRIPT (
      "send(DebugSymbol.fromAddress(" GUM_PTR_CONST ").name);",
      target_function_int);
  EXPECT_SEND_MESSAGE_WITH ("\"target_function_int\"");
  EXPECT_NO_MESSAGES ();
}

SCRIPT_TESTCASE (name_can_be_resolved_to_symbol)
{
  gchar * expected;

  COMPILE_AND_LOAD_SCRIPT (
      "send(DebugSymbol.fromName(\"target_function_int\").address);");
  expected = g_strdup_printf ("\"0x%" G_GINT64_MODIFIER "x\"",
      GUM_ADDRESS (target_function_int));
  EXPECT_SEND_MESSAGE_WITH (expected);
  g_free (expected);
  EXPECT_NO_MESSAGES ();
}

SCRIPT_TESTCASE (function_can_be_found_by_name)
{
  COMPILE_AND_LOAD_SCRIPT ("send("
      "!DebugSymbol.getFunctionByName(\"g_thread_new\").isNull()"
  ");"
  "send("
      "DebugSymbol.getFunctionByName(\"g_thread_!@#$\")"
  ");");
  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_ERROR_MESSAGE_WITH (ANY_LINE_NUMBER,
      "Error: unable to find function with name 'g_thread_!@#$'");
  EXPECT_NO_MESSAGES ();
}

SCRIPT_TESTCASE (functions_can_be_found_by_name)
{
  COMPILE_AND_LOAD_SCRIPT ("send("
      "DebugSymbol.findFunctionsNamed(\"g_thread_new\").length >= 1"
  ");");
  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_NO_MESSAGES ();
}

SCRIPT_TESTCASE (functions_can_be_found_by_matching)
{
  COMPILE_AND_LOAD_SCRIPT ("send("
      "DebugSymbol.findFunctionsMatching(\"gum_dummy_function_*\").length"
  ");");
  EXPECT_SEND_MESSAGE_WITH ("2");
  EXPECT_NO_MESSAGES ();
}

SCRIPT_TESTCASE (native_function_can_be_invoked)
{
  gchar str[7];

  strcpy (str, "badger");
  COMPILE_AND_LOAD_SCRIPT (
      "var toupper = new NativeFunction(" GUM_PTR_CONST ", "
          "'int', ['pointer', 'int']);"
      "send(toupper(" GUM_PTR_CONST ", 3));"
      "send(toupper(" GUM_PTR_CONST ", -1));",
      gum_toupper, str, str);
  EXPECT_SEND_MESSAGE_WITH ("3");
  EXPECT_SEND_MESSAGE_WITH ("-6");
  EXPECT_NO_MESSAGES ();
  g_assert_cmpstr (str, ==, "BADGER");
}

SCRIPT_TESTCASE (variadic_native_function_can_be_invoked)
{
  COMPILE_AND_LOAD_SCRIPT (
      "var sum = new NativeFunction(" GUM_PTR_CONST ", "
          "'int', ['int', '...', 'int', 'int', 'int']);"
      "send(sum(3, 1, 2, 3));",
      gum_sum);
  EXPECT_SEND_MESSAGE_WITH ("6");
  EXPECT_NO_MESSAGES ();
}

SCRIPT_TESTCASE (native_function_is_a_native_pointer)
{
  COMPILE_AND_LOAD_SCRIPT (
      "var toupper = new NativeFunction(" GUM_PTR_CONST ", "
          "'int', ['pointer', 'int']);"
      "send(toupper instanceof NativePointer);"
      "send(toupper.toString() === " GUM_PTR_CONST ".toString());",
      gum_toupper, gum_toupper);
  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_SEND_MESSAGE_WITH ("true");
}

SCRIPT_TESTCASE (native_callback_can_be_invoked)
{
  TestScriptMessageItem * item;
  gint (* toupper_impl) (gchar * str, gint limit);
  gchar str[7];

  COMPILE_AND_LOAD_SCRIPT (
      "toupper = new NativeCallback(function (str, limit) {"
      "  var count = 0;"
      "  while (count < limit || limit === -1) {"
      "    var p = str.add(count);"
      "    var b = Memory.readU8(p);"
      "    if (b === 0)"
      "      break;"
      "    Memory.writeU8(p, String.fromCharCode(b).toUpperCase().charCodeAt(0));"
      "    count++;"
      "  }"
      "  return (limit === -1) ? -count : count;"
      "}, 'int', ['pointer', 'int']);"
      "send(toupper);");

  item = test_script_fixture_pop_message (fixture);
  sscanf (item->message, "{\"type\":\"send\",\"payload\":"
      "\"0x%" G_GSIZE_MODIFIER "x\"}", (gsize *) &toupper_impl);
  g_assert (toupper_impl != NULL);
  test_script_message_item_free (item);

  strcpy (str, "badger");
  g_assert_cmpint (toupper_impl (str, 3), ==, 3);
  g_assert_cmpstr (str, ==, "BADger");
  g_assert_cmpint (toupper_impl (str, -1), ==, -6);
  g_assert_cmpstr (str, ==, "BADGER");
}

SCRIPT_TESTCASE (native_callback_is_a_native_pointer)
{
  COMPILE_AND_LOAD_SCRIPT (
      "var cb = new NativeCallback(function () {}, 'void', []);"
      "send(cb instanceof NativePointer);");
  EXPECT_SEND_MESSAGE_WITH ("true");
}

SCRIPT_TESTCASE (native_pointer_provides_is_null)
{
  COMPILE_AND_LOAD_SCRIPT (
      "send(ptr(\"0\").isNull());"
      "send(ptr(\"1337\").isNull());");
  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_SEND_MESSAGE_WITH ("false");
}

SCRIPT_TESTCASE (native_pointer_to_match_pattern)
{
  const gchar * extra_checks;

#if GLIB_SIZEOF_VOID_P == 4
  extra_checks = "";
#else
  extra_checks = "send(ptr(\"0xa1b2c3d4e5f6a7b8\").toMatchPattern());";
#endif

  COMPILE_AND_LOAD_SCRIPT (
      "send(ptr(\"0x0\").toMatchPattern());"
      "send(ptr(\"0xa\").toMatchPattern());"
      "send(ptr(\"0xa1b\").toMatchPattern());"
      "send(ptr(\"0xa1b2\").toMatchPattern());"
      "send(ptr(\"0xa1b2c3\").toMatchPattern());"
      "send(ptr(\"0xa1b2c3d4\").toMatchPattern());"
      "%s",
      extra_checks);

#if GLIB_SIZEOF_VOID_P == 4
# if G_BYTE_ORDER == G_LITTLE_ENDIAN
  EXPECT_SEND_MESSAGE_WITH ("\"00000000\"");
  EXPECT_SEND_MESSAGE_WITH ("\"0a000000\"");
  EXPECT_SEND_MESSAGE_WITH ("\"1b0a0000\"");
  EXPECT_SEND_MESSAGE_WITH ("\"b2a10000\"");
  EXPECT_SEND_MESSAGE_WITH ("\"c3b2a100\"");
  EXPECT_SEND_MESSAGE_WITH ("\"d4c3b2a1\"");
# else
  EXPECT_SEND_MESSAGE_WITH ("\"00000000\"");
  EXPECT_SEND_MESSAGE_WITH ("\"0000000a\"");
  EXPECT_SEND_MESSAGE_WITH ("\"00000a1b\"");
  EXPECT_SEND_MESSAGE_WITH ("\"0000a1b2\"");
  EXPECT_SEND_MESSAGE_WITH ("\"00a1b2c3\"");
  EXPECT_SEND_MESSAGE_WITH ("\"a1b2c3d4\"");
# endif
#else
# if G_BYTE_ORDER == G_LITTLE_ENDIAN
  EXPECT_SEND_MESSAGE_WITH ("\"0000000000000000\"");
  EXPECT_SEND_MESSAGE_WITH ("\"0a00000000000000\"");
  EXPECT_SEND_MESSAGE_WITH ("\"1b0a000000000000\"");
  EXPECT_SEND_MESSAGE_WITH ("\"b2a1000000000000\"");
  EXPECT_SEND_MESSAGE_WITH ("\"c3b2a10000000000\"");
  EXPECT_SEND_MESSAGE_WITH ("\"d4c3b2a100000000\"");
  EXPECT_SEND_MESSAGE_WITH ("\"b8a7f6e5d4c3b2a1\"");
# else
  EXPECT_SEND_MESSAGE_WITH ("\"0000000000000000\"");
  EXPECT_SEND_MESSAGE_WITH ("\"000000000000000a\"");
  EXPECT_SEND_MESSAGE_WITH ("\"0000000000000a1b\"");
  EXPECT_SEND_MESSAGE_WITH ("\"000000000000a1b2\"");
  EXPECT_SEND_MESSAGE_WITH ("\"0000000000a1b2c3\"");
  EXPECT_SEND_MESSAGE_WITH ("\"00000000a1b2c3d4\"");
  EXPECT_SEND_MESSAGE_WITH ("\"a1b2c3d4e5f6a7b8\"");
# endif
#endif
}

static gint
gum_toupper (gchar * str,
             gint limit)
{
  gint count = 0;
  gchar * c;

  for (c = str; *c != '\0' && (count < limit || limit == -1); c++, count++)
  {
    *c = g_ascii_toupper (*c);
  }

  return (limit == -1) ? -count : count;
}

static gint
gum_sum (gint count,
         ...)
{
  gint total = 0;
  va_list vl;
  gint i;

  va_start (vl, count);
  for (i = 0; i != count; i++)
    total += va_arg (vl, gint);
  va_end (vl);

  return total;
}

SCRIPT_TESTCASE (file_can_be_written_to)
{
  gchar d00d[4] = { 0x64, 0x30, 0x30, 0x64 };

  if (!g_test_slow ())
  {
    g_print ("<skipping, run in slow mode> ");
    return;
  }

  COMPILE_AND_LOAD_SCRIPT (
      "var log = new File(\"/tmp/script-test.log\", 'a');"
      "log.write(\"Hello \");"
      "log.write(Memory.readByteArray(" GUM_PTR_CONST ", 4));"
      "log.write(\"!\\n\");"
      "log.close();",
      d00d);
  EXPECT_NO_MESSAGES ();
}

SCRIPT_TESTCASE (socket_type_can_be_inspected)
{
  int fd;
  struct sockaddr_in addr = { 0, };

  fd = socket (AF_INET, SOCK_STREAM, 0);
  COMPILE_AND_LOAD_SCRIPT ("send(Socket.type(%d));", fd);
  EXPECT_SEND_MESSAGE_WITH ("\"tcp\"");
  addr.sin_family = AF_INET;
  addr.sin_port = htons (39876);
  addr.sin_addr.s_addr = INADDR_ANY;
  bind (fd, (struct sockaddr *) &addr, sizeof (addr));
  COMPILE_AND_LOAD_SCRIPT ("send(Socket.type(%d));", fd);
  EXPECT_SEND_MESSAGE_WITH ("\"tcp\"");
  GUM_CLOSE_SOCKET (fd);

  fd = socket (AF_INET, SOCK_DGRAM, 0);
  COMPILE_AND_LOAD_SCRIPT ("send(Socket.type(%d));", fd);
  EXPECT_SEND_MESSAGE_WITH ("\"udp\"");
  GUM_CLOSE_SOCKET (fd);

  fd = socket (AF_INET6, SOCK_STREAM, 0);
  if (fd != -1)
  {
    COMPILE_AND_LOAD_SCRIPT ("send(Socket.type(%d));", fd);
    EXPECT_SEND_MESSAGE_WITH ("\"tcp6\"");
    GUM_CLOSE_SOCKET (fd);
  }

  fd = socket (AF_INET6, SOCK_DGRAM, 0);
  if (fd != -1)
  {
    COMPILE_AND_LOAD_SCRIPT ("send(Socket.type(%d));", fd);
    EXPECT_SEND_MESSAGE_WITH ("\"udp6\"");
    GUM_CLOSE_SOCKET (fd);
  }

  COMPILE_AND_LOAD_SCRIPT ("send(Socket.type(-1));");
  EXPECT_SEND_MESSAGE_WITH ("null");

#ifndef G_OS_WIN32
  fd = socket (AF_UNIX, SOCK_STREAM, 0);
  COMPILE_AND_LOAD_SCRIPT ("send(Socket.type(%d));", fd);
  EXPECT_SEND_MESSAGE_WITH ("\"unix:stream\"");
  close (fd);

  fd = socket (AF_UNIX, SOCK_DGRAM, 0);
  COMPILE_AND_LOAD_SCRIPT ("send(Socket.type(%d));", fd);
  EXPECT_SEND_MESSAGE_WITH ("\"unix:dgram\"");
  close (fd);

  fd = open ("/etc/hosts", O_RDONLY);
  g_assert (fd >= 0);
  COMPILE_AND_LOAD_SCRIPT ("send(Socket.type(%d));", fd);
  EXPECT_SEND_MESSAGE_WITH ("null");
  close (fd);
#endif
}

#ifndef HAVE_ANDROID

SCRIPT_TESTCASE (socket_endpoints_can_be_inspected)
{
  GSocketFamily family[] = { G_SOCKET_FAMILY_IPV4, G_SOCKET_FAMILY_IPV6 };
  guint i;
  GMainContext * context;
  int fd;

  context = g_main_context_get_thread_default ();

  for (i = 0; i != G_N_ELEMENTS (family); i++)
  {
    GSocket * socket;
    GSocketService * service;
    guint16 client_port, server_port;
    GSocketAddress * client_address, * server_address;
    GInetAddress * loopback;

    socket = g_socket_new (family[i], G_SOCKET_TYPE_STREAM,
        G_SOCKET_PROTOCOL_TCP, NULL);
    if (socket == NULL)
      continue;
    fd = g_socket_get_fd (socket);

    service = g_socket_service_new ();
    g_signal_connect (service, "incoming", G_CALLBACK (on_incoming_connection),
        NULL);
    server_port = g_socket_listener_add_any_inet_port (
        G_SOCKET_LISTENER (service), NULL, NULL);
    g_socket_service_start (service);
    loopback = g_inet_address_new_loopback (family[i]);
    server_address = g_inet_socket_address_new (loopback, server_port);
    g_object_unref (loopback);

    COMPILE_AND_LOAD_SCRIPT ("send(Socket.peerAddress(%d));", fd);
    EXPECT_SEND_MESSAGE_WITH ("null");

    while (g_main_context_pending (context))
      g_main_context_iteration (context, FALSE);

    g_assert (g_socket_connect (socket, server_address, NULL, NULL));

    g_object_get (socket, "local-address", &client_address, NULL);
    client_port =
        g_inet_socket_address_get_port (G_INET_SOCKET_ADDRESS (client_address));

    while (g_main_context_pending (context))
      g_main_context_iteration (context, FALSE);

    COMPILE_AND_LOAD_SCRIPT (
        "var addr = Socket.localAddress(%d);"
        "send([typeof addr.ip, addr.port]);", fd);
    EXPECT_SEND_MESSAGE_WITH ("[\"string\",%u]", client_port);

    COMPILE_AND_LOAD_SCRIPT (
        "var addr = Socket.peerAddress(%d);"
        "send([typeof addr.ip, addr.port]);", fd);
    EXPECT_SEND_MESSAGE_WITH ("[\"string\",%u]", server_port);

    g_socket_close (socket, NULL);
    g_socket_service_stop (service);
    while (g_main_context_pending (context))
      g_main_context_iteration (context, FALSE);

    g_object_unref (socket);

    g_object_unref (client_address);
    g_object_unref (server_address);
    g_object_unref (service);
  }

#ifdef HAVE_DARWIN
  {
    struct sockaddr_un address;
    socklen_t len;

    fd = socket (AF_UNIX, SOCK_STREAM, 0);

    address.sun_family = AF_UNIX;
    strcpy (address.sun_path, "/tmp/gum-script-test");
    unlink (address.sun_path);
    address.sun_len = sizeof (address) - sizeof (address.sun_path) +
        strlen (address.sun_path) + 1;
    len = address.sun_len;
    bind (fd, (struct sockaddr *) &address, len);

    COMPILE_AND_LOAD_SCRIPT ("send(Socket.localAddress(%d));", fd);
    EXPECT_SEND_MESSAGE_WITH ("{\"path\":\"\"}");
    close (fd);

    unlink (address.sun_path);
  }
#endif
}

static gboolean
on_incoming_connection (GSocketService * service,
                        GSocketConnection * connection,
                        GObject * source_object,
                        gpointer user_data)
{
  GInputStream * input;
  void * buf;

  input = g_io_stream_get_input_stream (G_IO_STREAM (connection));
  buf = g_malloc (1);
  g_input_stream_read_async (input, buf, 1, G_PRIORITY_DEFAULT, NULL,
      on_read_ready, g_object_ref (connection));

  return TRUE;
}

static void
on_read_ready (GObject * source_object,
               GAsyncResult * res,
               gpointer user_data)
{
  GSocketConnection * connection = user_data;

  GError * error = NULL;
  g_input_stream_read_finish (G_INPUT_STREAM (source_object), res, &error);
  g_clear_error (&error);

  g_io_stream_close_async (G_IO_STREAM (connection), G_PRIORITY_LOW, NULL,
      NULL, NULL);
  g_object_unref (connection);
}

#endif /* !HAVE_ANDROID */

#ifdef HAVE_I386

SCRIPT_TESTCASE (execution_can_be_traced)
{
  if (!g_test_slow ())
  {
    g_print ("<skipping, run in slow mode> ");
    return;
  }

  COMPILE_AND_LOAD_SCRIPT (
    "var me = Process.getCurrentThreadId();"
    "Stalker.follow(me, {"
    "  events: {"
    "    call: true,"
    "    ret: false,"
    "    exec: false"
    "  },"
    "  onReceive: function (events) {"
    "    send(events.length > 0);"
    "  },"
    "  onCallSummary: function (summary) {"
    "    send(Object.keys(summary).length > 0);"
    "  }"
    "});"
    "recv('stop', function (message) {"
    "  Stalker.unfollow();"
    "});");
  g_usleep (1);
  EXPECT_NO_MESSAGES ();
  POST_MESSAGE ("{\"type\":\"stop\"}");
  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_SEND_MESSAGE_WITH ("true");
}

SCRIPT_TESTCASE (call_can_be_probed)
{
  if (!g_test_slow ())
  {
    g_print ("<skipping, run in slow mode> ");
    return;
  }

  COMPILE_AND_LOAD_SCRIPT ("Stalker.follow();"
    "Stalker.addCallProbe(" GUM_PTR_CONST ", function (args) {"
    "  send(args[0].toInt32());"
    "});"
    "recv('stop', function (message) {"
    "  Stalker.unfollow();"
    "});", target_function_int);
  EXPECT_NO_MESSAGES ();
  target_function_int (1337);
  EXPECT_SEND_MESSAGE_WITH ("1337");
  POST_MESSAGE ("{\"type\":\"stop\"}");
}

#endif /* HAVE_I386 */

SCRIPT_TESTCASE (frida_version_is_available)
{
  COMPILE_AND_LOAD_SCRIPT ("send(typeof Frida.version);");
  EXPECT_SEND_MESSAGE_WITH ("\"string\"");
}

SCRIPT_TESTCASE (process_arch_is_available)
{
  COMPILE_AND_LOAD_SCRIPT ("send(Process.arch);");
#if defined (HAVE_I386)
# if GLIB_SIZEOF_VOID_P == 4
  EXPECT_SEND_MESSAGE_WITH ("\"ia32\"");
# else
  EXPECT_SEND_MESSAGE_WITH ("\"x64\"");
# endif
#elif defined (HAVE_ARM)
  EXPECT_SEND_MESSAGE_WITH ("\"arm\"");
#elif defined (HAVE_ARM64)
  EXPECT_SEND_MESSAGE_WITH ("\"arm64\"");
#endif
}

SCRIPT_TESTCASE (process_get_module_by_name)
{
  COMPILE_AND_LOAD_SCRIPT (
      "send(Process.getModuleByName('%s') !== null);", SYSTEM_MODULE_NAME);
  EXPECT_SEND_MESSAGE_WITH ("true");
}

SCRIPT_TESTCASE (process_platform_is_available)
{
  COMPILE_AND_LOAD_SCRIPT ("send(Process.platform);");
#if defined (HAVE_LINUX)
  EXPECT_SEND_MESSAGE_WITH ("\"linux\"");
#elif defined (HAVE_DARWIN)
  EXPECT_SEND_MESSAGE_WITH ("\"darwin\"");
#elif defined (G_OS_WIN32)
  EXPECT_SEND_MESSAGE_WITH ("\"windows\"");
#endif
}

SCRIPT_TESTCASE (process_pointer_size_is_available)
{
  COMPILE_AND_LOAD_SCRIPT ("send(Process.pointerSize);");
  EXPECT_SEND_MESSAGE_WITH (G_STRINGIFY (GLIB_SIZEOF_VOID_P));
}

SCRIPT_TESTCASE (process_debugger_status_is_available)
{
  COMPILE_AND_LOAD_SCRIPT ("send(Process.isDebuggerAttached());");
  if (gum_process_is_debugger_attached ())
    EXPECT_SEND_MESSAGE_WITH ("true");
  else
    EXPECT_SEND_MESSAGE_WITH ("false");
}

#ifndef HAVE_ANDROID

SCRIPT_TESTCASE (process_threads_can_be_enumerated)
{
  COMPILE_AND_LOAD_SCRIPT (
      "Process.enumerateThreads({"
        "onMatch: function (thread) {"
        "  send('onMatch');"
        "  return 'stop';"
        "},"
        "onComplete: function () {"
        "  send('onComplete');"
        "}"
      "});");
  EXPECT_SEND_MESSAGE_WITH ("\"onMatch\"");
  EXPECT_SEND_MESSAGE_WITH ("\"onComplete\"");
}

SCRIPT_TESTCASE (process_threads_can_be_enumerated_synchronously)
{
  COMPILE_AND_LOAD_SCRIPT ("send(Process.enumerateThreadsSync().length > 1);");
  EXPECT_SEND_MESSAGE_WITH ("true");
}

#endif

SCRIPT_TESTCASE (process_modules_can_be_enumerated)
{
  COMPILE_AND_LOAD_SCRIPT (
      "Process.enumerateModules({"
        "onMatch: function (module) {"
        "  send('onMatch');"
        "  return 'stop';"
        "},"
        "onComplete: function () {"
        "  send('onComplete');"
        "}"
      "});");
  EXPECT_SEND_MESSAGE_WITH ("\"onMatch\"");
  EXPECT_SEND_MESSAGE_WITH ("\"onComplete\"");
}

SCRIPT_TESTCASE (process_modules_can_be_enumerated_synchronously)
{
  COMPILE_AND_LOAD_SCRIPT ("send(Process.enumerateModulesSync().length > 1);");
  EXPECT_SEND_MESSAGE_WITH ("true");
}

SCRIPT_TESTCASE (process_ranges_can_be_enumerated)
{
  COMPILE_AND_LOAD_SCRIPT (
      "Process.enumerateRanges('--x', {"
        "onMatch: function (range) {"
        "  send('onMatch');"
        "  return 'stop';"
        "},"
        "onComplete: function () {"
        "  send('onComplete');"
        "}"
      "});");
  EXPECT_SEND_MESSAGE_WITH ("\"onMatch\"");
  EXPECT_SEND_MESSAGE_WITH ("\"onComplete\"");
}

SCRIPT_TESTCASE (process_ranges_can_be_enumerated_synchronously)
{
  COMPILE_AND_LOAD_SCRIPT (
      "send(Process.enumerateRangesSync('--x').length > 1);");
  EXPECT_SEND_MESSAGE_WITH ("true");
}

#ifdef HAVE_DARWIN
SCRIPT_TESTCASE (process_malloc_ranges_can_be_enumerated)
{
  COMPILE_AND_LOAD_SCRIPT (
      "Process.enumerateMallocRanges({"
        "onMatch: function (range) {"
        "  send('onMatch');"
        "  return 'stop';"
        "},"
        "onComplete: function () {"
        "  send('onComplete');"
        "}"
      "});");
  EXPECT_SEND_MESSAGE_WITH ("\"onMatch\"");
  EXPECT_SEND_MESSAGE_WITH ("\"onComplete\"");
}

SCRIPT_TESTCASE (process_malloc_ranges_can_be_enumerated_synchronously)
{
  COMPILE_AND_LOAD_SCRIPT (
      "send(Process.enumerateMallocRangesSync().length > 1);");
  EXPECT_SEND_MESSAGE_WITH ("true");
}
#endif

SCRIPT_TESTCASE (module_exports_can_be_enumerated)
{
  COMPILE_AND_LOAD_SCRIPT (
      "Module.enumerateExports(\"%s\", {"
        "onMatch: function (exp) {"
        "  send('onMatch');"
        "  return 'stop';"
        "},"
        "onComplete: function () {"
        "  send('onComplete');"
        "}"
      "});", SYSTEM_MODULE_NAME);
  EXPECT_SEND_MESSAGE_WITH ("\"onMatch\"");
  EXPECT_SEND_MESSAGE_WITH ("\"onComplete\"");
}

SCRIPT_TESTCASE (module_exports_can_be_enumerated_synchronously)
{
  COMPILE_AND_LOAD_SCRIPT (
      "send(Module.enumerateExportsSync(\"%s\").length > 1);",
      SYSTEM_MODULE_NAME);
  EXPECT_SEND_MESSAGE_WITH ("true");
}

SCRIPT_TESTCASE (module_exports_enumeration_performance)
{
  TestScriptMessageItem * item;
  gint duration;

  COMPILE_AND_LOAD_SCRIPT (
      "var start = new Date();"
      "Module.enumerateExports(\"%s\", {"
        "onMatch: function (exp) {"
        "},"
        "onComplete: function () {"
        "}"
      "});"
      "send((new Date()).getTime() - start.getTime());",
      SYSTEM_MODULE_NAME);
  item = test_script_fixture_pop_message (fixture);
  sscanf (item->message, "{\"type\":\"send\",\"payload\":%d}", &duration);
  g_print ("<%d ms> ", duration);
  test_script_message_item_free (item);
}

SCRIPT_TESTCASE (module_ranges_can_be_enumerated)
{
  COMPILE_AND_LOAD_SCRIPT (
      "Module.enumerateRanges(\"%s\", '--x', {"
        "onMatch: function (range) {"
        "  send('onMatch');"
        "  return 'stop';"
        "},"
        "onComplete: function () {"
        "  send('onComplete');"
        "}"
      "});", SYSTEM_MODULE_NAME);
  EXPECT_SEND_MESSAGE_WITH ("\"onMatch\"");
  EXPECT_SEND_MESSAGE_WITH ("\"onComplete\"");
}

SCRIPT_TESTCASE (module_ranges_can_be_enumerated_synchronously)
{
  COMPILE_AND_LOAD_SCRIPT (
      "send(Module.enumerateRangesSync(\"%s\", '--x').length > 0);",
      SYSTEM_MODULE_NAME);
  EXPECT_SEND_MESSAGE_WITH ("true");
}

SCRIPT_TESTCASE (module_base_address_can_be_found)
{
  COMPILE_AND_LOAD_SCRIPT (
      "send(Module.findBaseAddress('%s') !== null);", SYSTEM_MODULE_NAME);
  EXPECT_SEND_MESSAGE_WITH ("true");
}

SCRIPT_TESTCASE (module_export_can_be_found_by_name)
{
#ifdef G_OS_WIN32
  HMODULE mod;
  gpointer actual_address;
  char actual_address_str[32];

  mod = GetModuleHandle (_T ("kernel32.dll"));
  g_assert (mod != NULL);
  actual_address = GetProcAddress (mod, "Sleep");
  g_assert (actual_address != NULL);
  sprintf_s (actual_address_str, sizeof (actual_address_str),
      "\"%" G_GSIZE_MODIFIER "x\"", GPOINTER_TO_SIZE (actual_address));

  COMPILE_AND_LOAD_SCRIPT (
      "send(Module.findExportByName('kernel32.dll', 'Sleep').toString(16));");
  EXPECT_SEND_MESSAGE_WITH (actual_address_str);
#else
  COMPILE_AND_LOAD_SCRIPT (
      "send(Module.findExportByName('%s', '%s') !== null);",
      SYSTEM_MODULE_NAME, SYSTEM_MODULE_EXPORT);
  EXPECT_SEND_MESSAGE_WITH ("true");
#endif
}

SCRIPT_TESTCASE (invalid_script_should_return_null)
{
  GError * err = NULL;

  g_assert (gum_script_from_string_sync ("testcase", "'", NULL, NULL) == NULL);

  g_assert (gum_script_from_string_sync ("testcase", "'", NULL, &err) == NULL);
  g_assert (err != NULL);
  g_assert_cmpstr (err->message, ==,
      "Script(line 1): SyntaxError: Unexpected token ILLEGAL");
}

SCRIPT_TESTCASE (array_buffer_can_be_created)
{
  COMPILE_AND_LOAD_SCRIPT ("new ArrayBuffer(16);");
  EXPECT_NO_MESSAGES ();
}

SCRIPT_TESTCASE (message_can_be_sent)
{
  COMPILE_AND_LOAD_SCRIPT ("send(1234);");
  EXPECT_SEND_MESSAGE_WITH ("1234");
}

SCRIPT_TESTCASE (message_can_be_sent_with_data)
{
  COMPILE_AND_LOAD_SCRIPT ("send(1234, [0x13, 0x37]);");
  EXPECT_SEND_MESSAGE_WITH_PAYLOAD_AND_DATA ("1234", "13 37");
}

SCRIPT_TESTCASE (message_can_be_received)
{
  COMPILE_AND_LOAD_SCRIPT (
      "recv(function (message) {"
      "  if (message.type === 'ping')"
      "    send('pong');"
      "});");
  EXPECT_NO_MESSAGES ();
  POST_MESSAGE ("{\"type\":\"ping\"}");
  EXPECT_SEND_MESSAGE_WITH ("\"pong\"");
}

SCRIPT_TESTCASE (recv_may_specify_desired_message_type)
{
  COMPILE_AND_LOAD_SCRIPT (
      "recv('wobble', function (message) {"
      "  send('wibble');"
      "});"
      "recv('ping', function (message) {"
      "  send('pong');"
      "});");
  EXPECT_NO_MESSAGES ();
  POST_MESSAGE ("{\"type\":\"ping\"}");
  EXPECT_SEND_MESSAGE_WITH ("\"pong\"");
}

typedef struct _GumInvokeTargetContext GumInvokeTargetContext;

struct _GumInvokeTargetContext
{
  GumScript * script;
  volatile gboolean started;
  volatile gboolean finished;
};

SCRIPT_TESTCASE (recv_can_be_waited_for)
{
  GThread * worker_thread;
  GumInvokeTargetContext ctx;

  COMPILE_AND_LOAD_SCRIPT (
      "Interceptor.attach(" GUM_PTR_CONST ", {"
      "  onEnter: function (args) {"
      "    op = recv('poke', function (pokeMessage) {"
      "      send('pokeBack');"
      "    });"
      "    op.wait();"
      "    send('pokeReceived');"
      "  }"
      "});", target_function_int);
  EXPECT_NO_MESSAGES ();

  ctx.script = fixture->script;
  ctx.started = FALSE;
  ctx.finished = FALSE;
  worker_thread = g_thread_new ("script-test-worker-thread",
      invoke_target_function_int_worker, &ctx);
  while (!ctx.started)
    g_usleep (G_USEC_PER_SEC / 200);

  g_usleep (G_USEC_PER_SEC / 25);
  EXPECT_NO_MESSAGES ();
  g_assert (!ctx.finished);

  POST_MESSAGE ("{\"type\":\"poke\"}");
  g_thread_join (worker_thread);
  g_assert (ctx.finished);
  EXPECT_SEND_MESSAGE_WITH ("\"pokeBack\"");
  EXPECT_SEND_MESSAGE_WITH ("\"pokeReceived\"");
  EXPECT_NO_MESSAGES ();
}

static gpointer
invoke_target_function_int_worker (gpointer data)
{
  GumInvokeTargetContext * ctx = (GumInvokeTargetContext *) data;

  ctx->started = TRUE;
  target_function_int (42);
  ctx->finished = TRUE;

  return NULL;
}

SCRIPT_TESTCASE (thread_can_be_forced_to_sleep)
{
  GTimer * timer = g_timer_new ();
  COMPILE_AND_LOAD_SCRIPT ("Thread.sleep(0.25);");
  g_assert_cmpfloat (g_timer_elapsed (timer, NULL), >=, 0.2f);
  EXPECT_NO_MESSAGES ();
  g_timer_destroy (timer);
}

SCRIPT_TESTCASE (timeout_can_be_scheduled)
{
  COMPILE_AND_LOAD_SCRIPT (
      "setTimeout(function () {"
      "  send(1337);"
      "}, 20);");
  EXPECT_NO_MESSAGES ();

  g_usleep (25000);
  EXPECT_SEND_MESSAGE_WITH ("1337");

  g_usleep (25000);
  EXPECT_NO_MESSAGES ();
}

SCRIPT_TESTCASE (timeout_can_be_cancelled)
{
  COMPILE_AND_LOAD_SCRIPT (
      "var timeout = setTimeout(function () {"
      "  send(1337);"
      "}, 20);"
      "clearTimeout(timeout);");
  g_usleep (25000);
  EXPECT_NO_MESSAGES ();
}

SCRIPT_TESTCASE (interval_can_be_scheduled)
{
  COMPILE_AND_LOAD_SCRIPT (
      "setInterval(function () {"
      "  send(1337);"
      "}, 20);");
  EXPECT_NO_MESSAGES ();

  g_usleep (25000);
  EXPECT_SEND_MESSAGE_WITH ("1337");

  g_usleep (25000);
  EXPECT_SEND_MESSAGE_WITH ("1337");
}

SCRIPT_TESTCASE (interval_can_be_cancelled)
{
  COMPILE_AND_LOAD_SCRIPT (
      "var count = 1;"
      "var interval = setInterval(function () {"
      "  send(count++);"
      "  if (count === 3)"
      "    clearInterval(interval);"
      "}, 20);");

  g_usleep (25000);
  EXPECT_SEND_MESSAGE_WITH ("1");

  g_usleep (25000);
  EXPECT_SEND_MESSAGE_WITH ("2");

  g_usleep (25000);
  EXPECT_NO_MESSAGES ();
}

SCRIPT_TESTCASE (argument_can_be_read)
{
  COMPILE_AND_LOAD_SCRIPT (
      "Interceptor.attach(" GUM_PTR_CONST ", {"
      "  onEnter: function (args) {"
      "    send(args[0].toInt32());"
      "  }"
      "});", target_function_int);

  EXPECT_NO_MESSAGES ();

  target_function_int (42);
  EXPECT_SEND_MESSAGE_WITH ("42");

  target_function_int (-42);
  EXPECT_SEND_MESSAGE_WITH ("-42");
}

SCRIPT_TESTCASE (argument_can_be_replaced)
{
  COMPILE_AND_LOAD_SCRIPT (
      "var replacementString = Memory.allocUtf8String('Hei');"
      "Interceptor.attach(" GUM_PTR_CONST ", {"
      "  onEnter: function (args) {"
      "    args[0] = replacementString;"
      "  }"
      "});", target_function_string);

  EXPECT_NO_MESSAGES ();
  g_assert_cmpstr (target_function_string ("Hello"), ==, "Hei");
  EXPECT_NO_MESSAGES ();
}

SCRIPT_TESTCASE (return_value_can_be_read)
{
  COMPILE_AND_LOAD_SCRIPT (
      "Interceptor.attach(" GUM_PTR_CONST ", {"
      "  onLeave: function (retval) {"
      "    send(retval.toInt32());"
      "  }"
      "});", target_function_int);

  EXPECT_NO_MESSAGES ();
  target_function_int (7);
  EXPECT_SEND_MESSAGE_WITH ("315");
}

SCRIPT_TESTCASE (return_value_can_be_replaced)
{
  COMPILE_AND_LOAD_SCRIPT (
      "Interceptor.attach(" GUM_PTR_CONST ", {"
      "  onLeave: function (retval) {"
      "    retval.replace(1337);"
      "  }"
      "});", target_function_int);

  EXPECT_NO_MESSAGES ();
  g_assert_cmpint (target_function_int (7), ==, 1337);
  EXPECT_NO_MESSAGES ();
}

SCRIPT_TESTCASE (return_address_can_be_read)
{
  COMPILE_AND_LOAD_SCRIPT (
      "Interceptor.attach(" GUM_PTR_CONST ", {"
      "  onEnter: function () {"
      "    send(this.returnAddress instanceof NativePointer);"
      "    this.onEnterReturnAddress = this.returnAddress;"
      "  },"
      "  onLeave: function () {"
      "    send(this.returnAddress.equals(this.onEnterReturnAddress));"
      "  }"
      "});", target_function_int);

  EXPECT_NO_MESSAGES ();
  target_function_int (7);
  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_NO_MESSAGES ();
}

SCRIPT_TESTCASE (register_can_be_read)
{
  const gchar * register_name;

#if defined (HAVE_I386) && GLIB_SIZEOF_VOID_P == 4
  register_name = "eax";
#elif defined (HAVE_I386) && GLIB_SIZEOF_VOID_P == 8
  register_name = "rax";
#elif defined (HAVE_ARM)
  register_name = "r0";
#elif defined (HAVE_ARM64)
  register_name = "x0";
#else
# error Unsupported architecture
#endif

  COMPILE_AND_LOAD_SCRIPT (
      "Interceptor.attach(" GUM_PTR_CONST ", {"
      "  onLeave: function () {"
      "    send(this.context.%s.toInt32());"
      "  }"
      "});", target_function_int, register_name);

  EXPECT_NO_MESSAGES ();
  target_function_int (42);
  EXPECT_SEND_MESSAGE_WITH ("1890");
}

SCRIPT_TESTCASE (system_error_can_be_read)
{
#ifdef G_OS_WIN32
  COMPILE_AND_LOAD_SCRIPT (
      "Interceptor.attach(" GUM_PTR_CONST ", {"
      "  onEnter: function (retval) {"
      "    send(this.lastError);"
      "  }"
      "});", target_function_int);

  SetLastError (13);
  target_function_int (7);
  SetLastError (37);
  target_function_int (7);
#else
  COMPILE_AND_LOAD_SCRIPT (
      "Interceptor.attach(" GUM_PTR_CONST ", {"
      "  onEnter: function (retval) {"
      "    send(this.errno);"
      "  }"
      "});", target_function_int);

  errno = 13;
  target_function_int (7);
  errno = 37;
  target_function_int (7);
#endif
  EXPECT_SEND_MESSAGE_WITH ("13");
  EXPECT_SEND_MESSAGE_WITH ("37");
}

SCRIPT_TESTCASE (system_error_can_be_replaced)
{
#ifdef G_OS_WIN32
  COMPILE_AND_LOAD_SCRIPT (
      "Interceptor.attach(" GUM_PTR_CONST ", {"
      "  onEnter: function (retval) {"
      "    this.lastError = 1337;"
      "  }"
      "});", target_function_int);

  SetLastError (42);
  target_function_int (7);
  g_assert_cmpint (GetLastError (), ==, 1337);
#else
  COMPILE_AND_LOAD_SCRIPT (
      "Interceptor.attach(" GUM_PTR_CONST ", {"
      "  onEnter: function (retval) {"
      "    this.errno = 1337;"
      "  }"
      "});", target_function_int);

  errno = 42;
  target_function_int (7);
  g_assert_cmpint (errno, ==, 1337);
#endif
}

SCRIPT_TESTCASE (invocations_are_bound_on_tls_object)
{
  COMPILE_AND_LOAD_SCRIPT (
      "Interceptor.attach(" GUM_PTR_CONST ", {"
      "  onEnter: function (args) {"
      "    send(this.value || null);"
      "    this.value = args[0].toInt32();"
      "  },"
      "  onLeave: function (retval) {"
      "    send(this.value || null);"
      "  }"
      "});", target_function_int);

  EXPECT_NO_MESSAGES ();
  target_function_int (7);
  EXPECT_SEND_MESSAGE_WITH ("null");
  EXPECT_SEND_MESSAGE_WITH ("7");
  target_function_int (11);
  EXPECT_SEND_MESSAGE_WITH ("null");
  EXPECT_SEND_MESSAGE_WITH ("11");
}

SCRIPT_TESTCASE (invocations_provide_call_depth)
{
  COMPILE_AND_LOAD_SCRIPT (
      "Interceptor.attach(" GUM_PTR_CONST ", {"
      "  onEnter: function (args) {"
      "    send('>a' + this.depth);"
      "  },"
      "  onLeave: function (retval) {"
      "    send('<a' + this.depth);"
      "  }"
      "});"
      "Interceptor.attach(" GUM_PTR_CONST ", {"
      "  onEnter: function (args) {"
      "    send('>b' + this.depth);"
      "  },"
      "  onLeave: function (retval) {"
      "    send('<b' + this.depth);"
      "  }"
      "});"
      "Interceptor.attach(" GUM_PTR_CONST ", {"
      "  onEnter: function (args) {"
      "    send('>c' + this.depth);"
      "  },"
      "  onLeave: function (retval) {"
      "    send('<c' + this.depth);"
      "  }"
      "});",
      target_function_nested_a,
      target_function_nested_b,
      target_function_nested_c);

  EXPECT_NO_MESSAGES ();
  target_function_nested_a (7);
  EXPECT_SEND_MESSAGE_WITH ("\">a0\"");
  EXPECT_SEND_MESSAGE_WITH ("\">b1\"");
  EXPECT_SEND_MESSAGE_WITH ("\">c2\"");
  EXPECT_SEND_MESSAGE_WITH ("\"<c2\"");
  EXPECT_SEND_MESSAGE_WITH ("\"<b1\"");
  EXPECT_SEND_MESSAGE_WITH ("\"<a0\"");
  EXPECT_NO_MESSAGES ();
}

SCRIPT_TESTCASE (invocations_provide_context_for_backtrace)
{
  COMPILE_AND_LOAD_SCRIPT (
      "Interceptor.attach(" GUM_PTR_CONST ", {"
      "  onEnter: function (args) {"
      "    send(Thread.backtrace(this.context, Backtracer.ACCURATE)"
      "        .length > 0);"
      "  },"
      "  onLeave: function (retval) {"
      "    try {"
      "      send(Thread.backtrace(this.context, Backtracer.FUZZY).length > 0);"
      "    } catch (e) {"
      "    }"
      "  }"
      "});",
      target_function_int);

  EXPECT_NO_MESSAGES ();
  target_function_int (7);
  EXPECT_SEND_MESSAGE_WITH ("true");
#if !(defined (HAVE_IOS) && defined (HAVE_ARM64))
  EXPECT_SEND_MESSAGE_WITH ("true");
#endif
  EXPECT_NO_MESSAGES ();
}

SCRIPT_TESTCASE (callbacks_can_be_detached)
{
  COMPILE_AND_LOAD_SCRIPT (
      "Interceptor.attach(" GUM_PTR_CONST ", {"
      "  onEnter: function (args) {"
      "    send(args[0].toInt32());"
      "  }"
      "});"
      "Interceptor.detachAll();",
      target_function_int);

  EXPECT_NO_MESSAGES ();
  target_function_int (42);
  EXPECT_NO_MESSAGES ();
}

SCRIPT_TESTCASE (function_can_be_replaced)
{
  COMPILE_AND_LOAD_SCRIPT (
      "Interceptor.replace(" GUM_PTR_CONST ", new NativeCallback(function (arg) {"
      "  send(arg);"
      "  return 1337;"
      "}, 'int', ['int']));",
      target_function_int);

  EXPECT_NO_MESSAGES ();
  g_assert_cmpint (target_function_int (7), ==, 1337);
  EXPECT_SEND_MESSAGE_WITH ("7");
  EXPECT_NO_MESSAGES ();

  gum_script_unload_sync (fixture->script, NULL);
  target_function_int (1);
  EXPECT_NO_MESSAGES ();
}

SCRIPT_TESTCASE (function_can_be_reverted)
{
  COMPILE_AND_LOAD_SCRIPT (
      "Interceptor.replace(" GUM_PTR_CONST ", new NativeCallback(function (arg) {"
      "  send(arg);"
      "  return 1337;"
      "}, 'int', ['int']));"
      "Interceptor.revert(" GUM_PTR_CONST ");",
      target_function_int, target_function_int);

  EXPECT_NO_MESSAGES ();
  target_function_int (7);
  EXPECT_NO_MESSAGES ();
}

SCRIPT_TESTCASE (interceptor_handles_invalid_arguments)
{
  COMPILE_AND_LOAD_SCRIPT (
      "Interceptor.attach(ptr(\"0x1\"), {"
      "  onEnter: function (args) {"
      "  }"
      "});");
  EXPECT_ERROR_MESSAGE_WITH (ANY_LINE_NUMBER,
      "Error: access violation reading 0x1");

  COMPILE_AND_LOAD_SCRIPT (
      "Interceptor.replace(ptr(\"0x1\"), new NativeCallback(function (arg) {"
      "}, 'void', []));");
  EXPECT_ERROR_MESSAGE_WITH (ANY_LINE_NUMBER,
      "Error: access violation reading 0x1");
}

SCRIPT_TESTCASE (interceptor_performance)
{
  COMPILE_AND_LOAD_SCRIPT (
      "Interceptor.attach(" GUM_PTR_CONST ", {"
      "  onEnter: function (args) {"
      "  },"
      "  onLeave: function (retval) {"
      "  }"
      "});", target_function_int);
  /* while (TRUE) */
    target_function_int (7);
}

SCRIPT_TESTCASE (memory_can_be_scanned)
{
  guint8 haystack[] = { 0x01, 0x02, 0x13, 0x37, 0x03, 0x13, 0x37 };
  COMPILE_AND_LOAD_SCRIPT (
      "Memory.scan(" GUM_PTR_CONST ", 7, '13 37', {"
        "onMatch: function (address, size) {"
        "  send('onMatch offset=' + address.sub(" GUM_PTR_CONST
             ").toInt32() + ' size=' + size);"
        "},"
        "onComplete: function () {"
        "  send('onComplete');"
        "}"
      "});", haystack, haystack);
  EXPECT_SEND_MESSAGE_WITH ("\"onMatch offset=2 size=2\"");
  EXPECT_SEND_MESSAGE_WITH ("\"onMatch offset=5 size=2\"");
  EXPECT_SEND_MESSAGE_WITH ("\"onComplete\"");
}

SCRIPT_TESTCASE (memory_scan_should_be_interruptible)
{
  guint8 haystack[] = { 0x01, 0x02, 0x13, 0x37, 0x03, 0x13, 0x37 };
  COMPILE_AND_LOAD_SCRIPT (
      "Memory.scan(" GUM_PTR_CONST ", 7, '13 37', {"
        "onMatch: function (address, size) {"
        "  send('onMatch offset=' + address.sub(" GUM_PTR_CONST
             ").toInt32() + ' size=' + size);"
        "  return 'stop';"
        "},"
        "onComplete: function () {"
        "  send('onComplete');"
        "}"
      "});", haystack, haystack);
  EXPECT_SEND_MESSAGE_WITH ("\"onMatch offset=2 size=2\"");
  EXPECT_SEND_MESSAGE_WITH ("\"onComplete\"");
}

SCRIPT_TESTCASE (memory_scan_handles_unreadable_memory)
{
  COMPILE_AND_LOAD_SCRIPT (
      "Memory.scan(ptr(\"1328\"), 7, '13 37', {"
        "onMatch: function (address, size) {"
        "  send('onMatch');"
        "},"
        "onError: function (message) {"
        "  send('onError: ' + message);"
        "},"
        "onComplete: function () {"
        "  send('onComplete');"
        "}"
      "});");
  EXPECT_SEND_MESSAGE_WITH ("\"onError: access violation reading 0x530\"");
  EXPECT_SEND_MESSAGE_WITH ("\"onComplete\"");
}

#ifdef G_OS_WIN32

SCRIPT_TESTCASE (memory_access_can_be_monitored)
{
  volatile guint8 * a, * b;
  guint page_size;

  a = gum_alloc_n_pages (2, GUM_PAGE_RW);
  b = gum_alloc_n_pages (1, GUM_PAGE_RW);
  page_size = gum_query_page_size ();

  COMPILE_AND_LOAD_SCRIPT (
      "MemoryAccessMonitor.enable([{ base: " GUM_PTR_CONST ", size: %u },"
        "{ base: " GUM_PTR_CONST ", size: %u }], {"
        "onAccess: function (details) {"
          "send([details.operation, !!details.from, details.address,"
            "details.rangeIndex, details.pageIndex, details.pagesCompleted,"
            "details.pagesTotal]);"
        "}"
      "});",
      a + page_size, page_size, b, page_size);
  EXPECT_NO_MESSAGES ();

  a[0] = 1;
  a[page_size - 1] = 2;
  EXPECT_NO_MESSAGES ();

  a[page_size] = 3;
  EXPECT_SEND_MESSAGE_WITH ("[\"write\",true,\"0x%" G_GSIZE_MODIFIER "x\","
      "0,0,1,2]", GPOINTER_TO_SIZE (a + page_size));

  a[0] = b[page_size - 1];
  EXPECT_SEND_MESSAGE_WITH ("[\"read\",true,\"0x%" G_GSIZE_MODIFIER "x\","
      "1,0,2,2]", GPOINTER_TO_SIZE (b + page_size - 1));

  gum_free_pages ((gpointer) b);
  gum_free_pages ((gpointer) a);
}

#endif

SCRIPT_TESTCASE (pointer_can_be_read)
{
  gpointer val = GSIZE_TO_POINTER (0x1337000);
  COMPILE_AND_LOAD_SCRIPT (
      "send(Memory.readPointer(" GUM_PTR_CONST ").toString());", &val);
  EXPECT_SEND_MESSAGE_WITH ("\"0x1337000\"");
}

SCRIPT_TESTCASE (pointer_can_be_written)
{
  gpointer val = NULL;
  COMPILE_AND_LOAD_SCRIPT (
      "Memory.writePointer(" GUM_PTR_CONST ", ptr(\"0x1337000\"));", &val);
  g_assert_cmphex (GPOINTER_TO_SIZE (val), ==, 0x1337000);
}

SCRIPT_TESTCASE (memory_can_be_allocated)
{
  COMPILE_AND_LOAD_SCRIPT (
      "var p = Memory.alloc(8);"
      "Memory.writePointer(p, ptr(\"1337\"));"
      "send(Memory.readPointer(p).toInt32() === 1337);");
  EXPECT_SEND_MESSAGE_WITH ("true");
}

SCRIPT_TESTCASE (memory_can_be_copied)
{
  const gchar * from = "Hei";
  gchar to[5] = { 0x01, 0x02, 0x03, 0x04, 0x05 };

  COMPILE_AND_LOAD_SCRIPT (
      "Memory.copy(" GUM_PTR_CONST ", " GUM_PTR_CONST ", 3);", to, from);
  g_assert_cmphex (to[0], ==, 'H');
  g_assert_cmphex (to[1], ==, 'e');
  g_assert_cmphex (to[2], ==, 'i');
  g_assert_cmphex (to[3], ==, 0x04);
  g_assert_cmphex (to[4], ==, 0x05);

  COMPILE_AND_LOAD_SCRIPT (
      "Memory.copy(" GUM_PTR_CONST ", ptr(\"1337\"), 1);", to);
  EXPECT_ERROR_MESSAGE_WITH (1, "Error: access violation accessing 0x539");
}

SCRIPT_TESTCASE (memory_can_be_duped)
{
  guint8 buf[3] = { 0x13, 0x37, 0x42 };

  COMPILE_AND_LOAD_SCRIPT (
      "var p = Memory.dup(" GUM_PTR_CONST ", 3);"
      "Memory.writeU8(p, 0x12);"
      "send('p', Memory.readByteArray(p, 3));"
      "send('buf', Memory.readByteArray(" GUM_PTR_CONST ", 3));",
      buf, buf);
  EXPECT_SEND_MESSAGE_WITH_PAYLOAD_AND_DATA ("\"p\"", "12 37 42");
  EXPECT_SEND_MESSAGE_WITH_PAYLOAD_AND_DATA ("\"buf\"", "13 37 42");
}

SCRIPT_TESTCASE (memory_can_be_protected)
{
  gpointer buf;
  gboolean exception_on_read, exception_on_write;

  buf = gum_alloc_n_pages (1, GUM_PAGE_RW);

  COMPILE_AND_LOAD_SCRIPT (
      "send(Memory.protect(" GUM_PTR_CONST ", 1, 'r--'));",
      buf, gum_query_page_size ());
  EXPECT_SEND_MESSAGE_WITH ("true");

  /* avoid overlapping signal handlers */
  gum_script_unload_sync (fixture->script, NULL);
  g_object_unref (fixture->script);
  fixture->script = NULL;

  gum_try_read_and_write_at (buf, 0, &exception_on_read, &exception_on_write);
  g_assert (!exception_on_read);
  g_assert (exception_on_write);

  gum_free_pages (buf);
}

SCRIPT_TESTCASE (s8_can_be_read)
{
  gint8 val = -42;
  COMPILE_AND_LOAD_SCRIPT ("send(Memory.readS8(" GUM_PTR_CONST "));", &val);
  EXPECT_SEND_MESSAGE_WITH ("-42");
}

SCRIPT_TESTCASE (s8_can_be_written)
{
  gint8 val = 0;
  COMPILE_AND_LOAD_SCRIPT ("Memory.writeS8(" GUM_PTR_CONST ", -42);", &val);
  g_assert_cmpint (val, ==, -42);
}

SCRIPT_TESTCASE (u8_can_be_read)
{
  guint8 val = 42;
  COMPILE_AND_LOAD_SCRIPT ("send(Memory.readU8(" GUM_PTR_CONST "));", &val);
  EXPECT_SEND_MESSAGE_WITH ("42");
}

SCRIPT_TESTCASE (u8_can_be_written)
{
  guint8 val = 0;
  COMPILE_AND_LOAD_SCRIPT ("Memory.writeU8(" GUM_PTR_CONST ", 42);", &val);
  g_assert_cmpint (val, ==, 42);
}

SCRIPT_TESTCASE (s16_can_be_read)
{
  gint16 val = -12123;
  COMPILE_AND_LOAD_SCRIPT ("send(Memory.readS16(" GUM_PTR_CONST "));", &val);
  EXPECT_SEND_MESSAGE_WITH ("-12123");
}

SCRIPT_TESTCASE (s16_can_be_written)
{
  gint16 val = 0;
  COMPILE_AND_LOAD_SCRIPT ("Memory.writeS16(" GUM_PTR_CONST ", -12123);", &val);
  g_assert_cmpint (val, ==, -12123);
}

SCRIPT_TESTCASE (u16_can_be_read)
{
  guint16 val = 12123;
  COMPILE_AND_LOAD_SCRIPT ("send(Memory.readU16(" GUM_PTR_CONST "));", &val);
  EXPECT_SEND_MESSAGE_WITH ("12123");
}

SCRIPT_TESTCASE (u16_can_be_written)
{
  guint16 val = 0;
  COMPILE_AND_LOAD_SCRIPT ("Memory.writeU16(" GUM_PTR_CONST ", 12123);", &val);
  g_assert_cmpint (val, ==, 12123);
}

SCRIPT_TESTCASE (s32_can_be_read)
{
  gint32 val = -120123;
  COMPILE_AND_LOAD_SCRIPT ("send(Memory.readS32(" GUM_PTR_CONST "));", &val);
  EXPECT_SEND_MESSAGE_WITH ("-120123");
}

SCRIPT_TESTCASE (s32_can_be_written)
{
  gint32 val = 0;
  COMPILE_AND_LOAD_SCRIPT ("Memory.writeS32(" GUM_PTR_CONST ", -120123);", &val);
  g_assert_cmpint (val, ==, -120123);
}

SCRIPT_TESTCASE (u32_can_be_read)
{
  guint32 val = 120123;
  COMPILE_AND_LOAD_SCRIPT ("send(Memory.readU32(" GUM_PTR_CONST "));", &val);
  EXPECT_SEND_MESSAGE_WITH ("120123");
}

SCRIPT_TESTCASE (u32_can_be_written)
{
  guint32 val = 0;
  COMPILE_AND_LOAD_SCRIPT ("Memory.writeU32(" GUM_PTR_CONST ", 120123);", &val);
  g_assert_cmpint (val, ==, 120123);
}

SCRIPT_TESTCASE (s64_can_be_read)
{
  gint64 val = G_GINT64_CONSTANT (-1201239876783);
  COMPILE_AND_LOAD_SCRIPT ("send(Memory.readS64(" GUM_PTR_CONST "));", &val);
  EXPECT_SEND_MESSAGE_WITH ("-1201239876783");
}

SCRIPT_TESTCASE (s64_can_be_written)
{
  gint64 val = 0;
  COMPILE_AND_LOAD_SCRIPT ("Memory.writeS64(" GUM_PTR_CONST
      ", -1201239876783);", &val);
  g_assert_cmpint (val, ==, G_GINT64_CONSTANT (-1201239876783));
}

SCRIPT_TESTCASE (u64_can_be_read)
{
  guint64 val = G_GUINT64_CONSTANT (1201239876783);
  COMPILE_AND_LOAD_SCRIPT ("send(Memory.readU64(" GUM_PTR_CONST "));", &val);
  EXPECT_SEND_MESSAGE_WITH ("1201239876783");
}

SCRIPT_TESTCASE (u64_can_be_written)
{
  gint64 val = 0;
  COMPILE_AND_LOAD_SCRIPT ("Memory.writeU64(" GUM_PTR_CONST
      ", 1201239876783);", &val);
  g_assert_cmpint (val, ==, G_GUINT64_CONSTANT (1201239876783));
}

SCRIPT_TESTCASE (short_can_be_read)
{
  short val = -12123;
  COMPILE_AND_LOAD_SCRIPT ("send(Memory.readShort(" GUM_PTR_CONST "));", &val);
  EXPECT_SEND_MESSAGE_WITH ("-12123");
}

SCRIPT_TESTCASE (short_can_be_written)
{
  short val = 0;
  COMPILE_AND_LOAD_SCRIPT ("Memory.writeShort(" GUM_PTR_CONST ", -12123);",
    &val);
  g_assert_cmpint (val, ==, -12123);
}

SCRIPT_TESTCASE (ushort_can_be_read)
{
  unsigned short val = 12123;
  COMPILE_AND_LOAD_SCRIPT ("send(Memory.readUShort(" GUM_PTR_CONST "));", &val);
  EXPECT_SEND_MESSAGE_WITH ("12123");
}

SCRIPT_TESTCASE (ushort_can_be_written)
{
  unsigned short val = 0;
  COMPILE_AND_LOAD_SCRIPT ("Memory.writeUShort(" GUM_PTR_CONST ", 12123);",
    &val);
  g_assert_cmpint (val, ==, 12123);
}

SCRIPT_TESTCASE (int_can_be_read)
{
  int val = -120123;
  COMPILE_AND_LOAD_SCRIPT ("send(Memory.readInt(" GUM_PTR_CONST "));", &val);
  EXPECT_SEND_MESSAGE_WITH ("-120123");
}

SCRIPT_TESTCASE (int_can_be_written)
{
  int val = 0;
  COMPILE_AND_LOAD_SCRIPT ("Memory.writeInt(" GUM_PTR_CONST ", -120123);",
    &val);
  g_assert_cmpint (val, ==, -120123);
}

SCRIPT_TESTCASE (uint_can_be_read)
{
  unsigned int val = 120123;
  COMPILE_AND_LOAD_SCRIPT ("send(Memory.readUInt(" GUM_PTR_CONST "));", &val);
  EXPECT_SEND_MESSAGE_WITH ("120123");
}

SCRIPT_TESTCASE (uint_can_be_written)
{
  unsigned int val = 0;
  COMPILE_AND_LOAD_SCRIPT ("Memory.writeUInt(" GUM_PTR_CONST ", 120123);",
    &val);
  g_assert_cmpint (val, ==, 120123);
}

SCRIPT_TESTCASE (long_can_be_read)
{
  long val = -123;
  COMPILE_AND_LOAD_SCRIPT ("send(Memory.readLong(" GUM_PTR_CONST "));", &val);
  EXPECT_SEND_MESSAGE_WITH ("-123");
}

SCRIPT_TESTCASE (long_can_be_written)
{
  long val = 0;
  COMPILE_AND_LOAD_SCRIPT ("Memory.writeLong(" GUM_PTR_CONST ", 1350966097);",
    &val);
  g_assert_cmpint (val, ==, 1350966097);
}

SCRIPT_TESTCASE (ulong_can_be_read)
{
  unsigned long val = 4294967295;
  COMPILE_AND_LOAD_SCRIPT ("send(Memory.readULong(" GUM_PTR_CONST "));", &val);
  EXPECT_SEND_MESSAGE_WITH ("4294967295");
}

SCRIPT_TESTCASE (ulong_can_be_written)
{
  unsigned long val = 0;
  COMPILE_AND_LOAD_SCRIPT ("Memory.writeULong(" GUM_PTR_CONST ", 4294967295);",
    &val);
  g_assert_cmpint (val, ==, 4294967295);
}

SCRIPT_TESTCASE (byte_array_can_be_read)
{
  guint8 buf[3] = { 0x13, 0x37, 0x42 };
  COMPILE_AND_LOAD_SCRIPT (
      "send('badger', Memory.readByteArray(" GUM_PTR_CONST ", 3));"
      "send('snake', Memory.readByteArray(" GUM_PTR_CONST ", 0));"
      "send('mushroom', Memory.readByteArray(" GUM_PTR_CONST ", -1));",
      buf);
  EXPECT_SEND_MESSAGE_WITH_PAYLOAD_AND_DATA ("\"badger\"", "13 37 42");
  EXPECT_SEND_MESSAGE_WITH_PAYLOAD_AND_DATA ("\"snake\"", NULL);
  EXPECT_SEND_MESSAGE_WITH_PAYLOAD_AND_DATA ("\"mushroom\"", NULL);
}

SCRIPT_TESTCASE (byte_array_can_be_written)
{
  guint8 val[4] = { 0x00, 0x00, 0x00, 0xff };
  const guint8 other[3] = { 0x01, 0x02, 0x03 };

  COMPILE_AND_LOAD_SCRIPT ("Memory.writeByteArray(" GUM_PTR_CONST
      ", [0x13, 0x37, 0x42]);", val);
  EXPECT_NO_MESSAGES ();
  g_assert_cmpint (val[0], ==, 0x13);
  g_assert_cmpint (val[1], ==, 0x37);
  g_assert_cmpint (val[2], ==, 0x42);
  g_assert_cmpint (val[3], ==, 0xff);

  COMPILE_AND_LOAD_SCRIPT ("Memory.writeByteArray(" GUM_PTR_CONST
      ", Memory.readByteArray(" GUM_PTR_CONST ", 3));", val, other);
  EXPECT_NO_MESSAGES ();
  g_assert_cmpint (val[0], ==, 0x01);
  g_assert_cmpint (val[1], ==, 0x02);
  g_assert_cmpint (val[2], ==, 0x03);
  g_assert_cmpint (val[3], ==, 0xff);
}

SCRIPT_TESTCASE (c_string_can_be_read)
{
  const gchar * str = "Hello";

  COMPILE_AND_LOAD_SCRIPT ("send(Memory.readCString(" GUM_PTR_CONST "));",
      str);
  EXPECT_SEND_MESSAGE_WITH ("\"Hello\"");

  COMPILE_AND_LOAD_SCRIPT ("send(Memory.readCString(" GUM_PTR_CONST ", 3));",
      str);
  EXPECT_SEND_MESSAGE_WITH ("\"Hel\"");

  COMPILE_AND_LOAD_SCRIPT ("send(Memory.readCString(" GUM_PTR_CONST ", 0));",
      str);
  EXPECT_SEND_MESSAGE_WITH ("\"\"");

  COMPILE_AND_LOAD_SCRIPT ("send(Memory.readCString(" GUM_PTR_CONST ", -1));",
      str);
  EXPECT_SEND_MESSAGE_WITH ("\"Hello\"");

  COMPILE_AND_LOAD_SCRIPT ("send(Memory.readCString(ptr(\"0\")));", str);
  EXPECT_SEND_MESSAGE_WITH ("null");
}

SCRIPT_TESTCASE (utf8_string_can_be_read)
{
  const gchar * str = "Bjøærheimsbygd";

  COMPILE_AND_LOAD_SCRIPT ("send(Memory.readUtf8String(" GUM_PTR_CONST "));",
      str);
  EXPECT_SEND_MESSAGE_WITH ("\"Bjøærheimsbygd\"");

  COMPILE_AND_LOAD_SCRIPT ("send(Memory.readUtf8String(" GUM_PTR_CONST
      ", 3));", str);
  EXPECT_SEND_MESSAGE_WITH ("\"Bjø\"");

  COMPILE_AND_LOAD_SCRIPT ("send(Memory.readUtf8String(" GUM_PTR_CONST
      ", 0));", str);
  EXPECT_SEND_MESSAGE_WITH ("\"\"");

  COMPILE_AND_LOAD_SCRIPT ("send(Memory.readUtf8String(" GUM_PTR_CONST
      ", -1));", str);
  EXPECT_SEND_MESSAGE_WITH ("\"Bjøærheimsbygd\"");

  COMPILE_AND_LOAD_SCRIPT ("send(Memory.readUtf8String(ptr(\"0\")));", str);
  EXPECT_SEND_MESSAGE_WITH ("null");
}

SCRIPT_TESTCASE (utf8_string_can_be_written)
{
  gchar str[6];

  strcpy (str, "Hello");
  COMPILE_AND_LOAD_SCRIPT ("Memory.writeUtf8String(" GUM_PTR_CONST ", 'Bye');",
      str);
  g_assert_cmpstr (str, ==, "Bye");
  g_assert_cmphex (str[4], ==, 'o');
  g_assert_cmphex (str[5], ==, '\0');
}

SCRIPT_TESTCASE (utf8_string_can_be_allocated)
{
  COMPILE_AND_LOAD_SCRIPT (
      "send(Memory.readUtf8String(Memory.allocUtf8String('Bjørheimsbygd')));");
  EXPECT_SEND_MESSAGE_WITH ("\"Bjørheimsbygd\"");
}

SCRIPT_TESTCASE (utf16_string_can_be_read)
{
  const gchar * str_utf8 = "Bjørheimsbygd";
  gunichar2 * str = g_utf8_to_utf16 (str_utf8, -1, NULL, NULL, NULL);

  COMPILE_AND_LOAD_SCRIPT ("send(Memory.readUtf16String(" GUM_PTR_CONST "));",
      str);
  EXPECT_SEND_MESSAGE_WITH ("\"Bjørheimsbygd\"");

  COMPILE_AND_LOAD_SCRIPT ("send(Memory.readUtf16String(" GUM_PTR_CONST
      ", 3));", str);
  EXPECT_SEND_MESSAGE_WITH ("\"Bjø\"");

  COMPILE_AND_LOAD_SCRIPT ("send(Memory.readUtf16String(" GUM_PTR_CONST
      ", 0));", str);
  EXPECT_SEND_MESSAGE_WITH ("\"\"");

  COMPILE_AND_LOAD_SCRIPT ("send(Memory.readUtf16String(" GUM_PTR_CONST
      ", -1));", str);
  EXPECT_SEND_MESSAGE_WITH ("\"Bjørheimsbygd\"");

  COMPILE_AND_LOAD_SCRIPT ("send(Memory.readUtf16String(ptr(\"0\")));", str);
  EXPECT_SEND_MESSAGE_WITH ("null");

  g_free (str);
}

SCRIPT_TESTCASE (utf16_string_can_be_written)
{
  gunichar2 * str = g_utf8_to_utf16 ("Hello", -1, NULL, NULL, NULL);

  COMPILE_AND_LOAD_SCRIPT ("Memory.writeUtf16String(" GUM_PTR_CONST ", 'Bye');",
      str);
  g_assert_cmphex (str[0], ==, 'B');
  g_assert_cmphex (str[1], ==, 'y');
  g_assert_cmphex (str[2], ==, 'e');
  g_assert_cmphex (str[3], ==, '\0');
  g_assert_cmphex (str[4], ==, 'o');
  g_assert_cmphex (str[5], ==, '\0');

  g_free (str);
}

SCRIPT_TESTCASE (utf16_string_can_be_allocated)
{
  COMPILE_AND_LOAD_SCRIPT ("send(Memory.readUtf16String("
      "Memory.allocUtf16String('Bjørheimsbygd')));");
  EXPECT_SEND_MESSAGE_WITH ("\"Bjørheimsbygd\"");
}

#ifdef G_OS_WIN32

SCRIPT_TESTCASE (ansi_string_can_be_read)
{
  const gchar * str_utf8 = "Bjørheimsbygd";
  gunichar2 * str_utf16 = g_utf8_to_utf16 (str_utf8, -1, NULL, NULL, NULL);
  gchar str[64];
  WideCharToMultiByte (CP_THREAD_ACP, 0, (LPCWSTR) str_utf16, -1,
      (LPSTR) str, sizeof (str), NULL, NULL);

  COMPILE_AND_LOAD_SCRIPT ("send(Memory.readAnsiString(" GUM_PTR_CONST "));",
      str);
  EXPECT_SEND_MESSAGE_WITH ("\"Bjørheimsbygd\"");

  COMPILE_AND_LOAD_SCRIPT ("send(Memory.readAnsiString(" GUM_PTR_CONST
      ", 3));", str);
  EXPECT_SEND_MESSAGE_WITH ("\"Bjø\"");

  COMPILE_AND_LOAD_SCRIPT ("send(Memory.readAnsiString(" GUM_PTR_CONST
      ", 0));", str);
  EXPECT_SEND_MESSAGE_WITH ("\"\"");

  COMPILE_AND_LOAD_SCRIPT ("send(Memory.readAnsiString(" GUM_PTR_CONST
      ", -1));", str);
  EXPECT_SEND_MESSAGE_WITH ("\"Bjørheimsbygd\"");

  COMPILE_AND_LOAD_SCRIPT ("send(Memory.readAnsiString(ptr(\"0\")));", str);
  EXPECT_SEND_MESSAGE_WITH ("null");

  g_free (str_utf16);
}

SCRIPT_TESTCASE (ansi_string_can_be_written)
{
  gchar str_ansi[17];
  gunichar2 str_utf16[17];
  gchar * str_utf8;

  strcpy (str_ansi, "Kjempeforhaustar");
  COMPILE_AND_LOAD_SCRIPT ("Memory.writeAnsiString(" GUM_PTR_CONST
      ", 'Bjørheimsbygd');", str_ansi);
  MultiByteToWideChar (CP_ACP, 0, str_ansi, -1, str_utf16, sizeof (str_utf16));
  str_utf8 = g_utf16_to_utf8 (str_utf16, -1, NULL, NULL, NULL);
  g_assert_cmpstr (str_utf8, == , "Bjørheimsbygd");
  g_free (str_utf8);
  g_assert_cmphex (str_ansi[13], == , '\0');
  g_assert_cmphex (str_ansi[14], == , 'a');
  g_assert_cmphex (str_ansi[15], == , 'r');
  g_assert_cmphex (str_ansi[16], == , '\0');
}

SCRIPT_TESTCASE (ansi_string_can_be_allocated)
{
  COMPILE_AND_LOAD_SCRIPT (
      "send(Memory.readAnsiString(Memory.allocAnsiString('Bjørheimsbygd')));");
  EXPECT_SEND_MESSAGE_WITH ("\"Bjørheimsbygd\"");
}

#endif

SCRIPT_TESTCASE (invalid_read_results_in_exception)
{
  const gchar * type_name[] = {
      "Pointer",
      "S8",
      "U8",
      "S16",
      "U16",
      "S32",
      "U32",
      /*
       * We don't know if the compiler will decide to access the lower or higher
       * part first, so we can't know the exact error message for these two.
       * Hence we limit this part of the test to 64 bit builds...
       */
#if GLIB_SIZEOF_VOID_P == 8
      "S64",
      "U64",
#endif
      "Utf8String",
      "Utf16String",
#ifdef G_OS_WIN32
      "AnsiString"
#endif
  };
  guint i;

  for (i = 0; i != G_N_ELEMENTS (type_name); i++)
  {
    gchar * source;

    source = g_strconcat ("Memory.read", type_name[i], "(ptr(\"1328\"));",
        NULL);
    COMPILE_AND_LOAD_SCRIPT (source);
    EXPECT_ERROR_MESSAGE_WITH (1, "Error: access violation reading 0x530");
    g_free (source);
  }
}

SCRIPT_TESTCASE (invalid_write_results_in_exception)
{
  const gchar * primitive_type_name[] = {
      "S8",
      "U8",
      "S16",
      "U16",
      "S32",
      "U32",
#if GLIB_SIZEOF_VOID_P == 8
      "S64",
      "U64"
#endif
  };
  const gchar * string_type_name[] = {
      "Utf8String",
      "Utf16String"
  };
  guint i;

  for (i = 0; i != G_N_ELEMENTS (primitive_type_name); i++)
  {
    gchar * source;

    source = g_strconcat ("Memory.write", primitive_type_name[i],
        "(ptr(\"1328\"), 13);", NULL);
    COMPILE_AND_LOAD_SCRIPT (source);
    EXPECT_ERROR_MESSAGE_WITH (1, "Error: access violation writing to 0x530");
    g_free (source);
  }

  for (i = 0; i != G_N_ELEMENTS (string_type_name); i++)
  {
    gchar * source;

    source = g_strconcat ("Memory.write", string_type_name[i],
        "(ptr(\"1328\"), 'Hey');", NULL);
    COMPILE_AND_LOAD_SCRIPT (source);
    EXPECT_ERROR_MESSAGE_WITH (1, "Error: access violation writing to 0x530");
    g_free (source);
  }
}

SCRIPT_TESTCASE (script_can_be_reloaded)
{
  COMPILE_AND_LOAD_SCRIPT (
      "send(typeof badger);"
      "badger = 42;");
  EXPECT_SEND_MESSAGE_WITH ("\"undefined\"");
  gum_script_load_sync (fixture->script, NULL);
  EXPECT_NO_MESSAGES ();
  gum_script_unload_sync (fixture->script, NULL);
  gum_script_unload_sync (fixture->script, NULL);
  EXPECT_NO_MESSAGES ();
  gum_script_load_sync (fixture->script, NULL);
  EXPECT_SEND_MESSAGE_WITH ("\"undefined\"");
}

SCRIPT_TESTCASE (types_handle_invalid_construction)
{
  COMPILE_AND_LOAD_SCRIPT (
      "try {"
      "  NativePointer(\"0x1234\")"
      "} catch (e) {"
      "  send(e.message);"
      "}");
  EXPECT_SEND_MESSAGE_WITH ("\"Use `new NativePointer()` to create a new "
      "instance, or use one of the two shorthands: `ptr()` and `NULL`\"");

  COMPILE_AND_LOAD_SCRIPT (
      "try {"
      "  NativeFunction(" GUM_PTR_CONST ", 'void', []);"
      "} catch (e) {"
      "  send(e.message);"
      "}");
  EXPECT_SEND_MESSAGE_WITH ("\"Use `new NativeFunction()` to create a new "
      "instance\"");

  COMPILE_AND_LOAD_SCRIPT (
      "try {"
      "  NativeCallback(function () {}, 'void', []);"
      "} catch (e) {"
      "  send(e.message);"
      "}");
  EXPECT_SEND_MESSAGE_WITH ("\"Use `new NativeCallback()` to create a new "
      "instance\"");

  COMPILE_AND_LOAD_SCRIPT (
      "try {"
      "  File(\"/foo\", \"r\");"
      "} catch (e) {"
      "  send(e.message);"
      "}");
  EXPECT_SEND_MESSAGE_WITH ("\"Use `new File()` to create a new instance\"");
}

SCRIPT_TESTCASE (weak_callback_is_triggered_on_gc)
{
  COMPILE_AND_LOAD_SCRIPT (
      "var val = {};"
      "WeakRef.bind(val, function () {"
      "  send(\"weak notify\");"
      "});"
      "val = null;"
      "gc();");
  EXPECT_SEND_MESSAGE_WITH ("\"weak notify\"");
  EXPECT_NO_MESSAGES ();
}

SCRIPT_TESTCASE (weak_callback_is_triggered_on_unload)
{
  COMPILE_AND_LOAD_SCRIPT (
      "var val = {};"
      "WeakRef.bind(val, function () {"
      "  send(\"weak notify\");"
      "});");
  EXPECT_NO_MESSAGES ();
  gum_script_unload_sync (fixture->script, NULL);
  EXPECT_SEND_MESSAGE_WITH ("\"weak notify\"");
  EXPECT_NO_MESSAGES ();
}

SCRIPT_TESTCASE (weak_callback_is_triggered_on_unbind)
{
  COMPILE_AND_LOAD_SCRIPT (
      "var val = {};"
      "var id = WeakRef.bind(val, function () {"
      "  send(\"weak notify\");"
      "});"
      "WeakRef.unbind(id);");
  EXPECT_SEND_MESSAGE_WITH ("\"weak notify\"");
}

#include "script-debugserver.c"

SCRIPT_TESTCASE (debugger_can_be_enabled)
{
  GumScript * badger, * snake;
  GMainLoop * loop;
  const guint16 port = 5858;
  GumDebugServer * server;

  if (!g_test_slow ())
  {
    g_print ("<skipping, run in slow mode> ");
    return;
  }

  badger = gum_script_from_string_sync ("badger",
      "setInterval(function () {\n"
      "  send('badger');\n"
      "}, 1000);", NULL, NULL);
  gum_script_set_message_handler (badger, on_message, "badger", NULL);
  gum_script_load_sync (badger, NULL);

  snake = gum_script_from_string_sync ("snake",
      "setInterval(function () {\n"
      "  send('snake');\n"
      "}, 1000);", NULL, NULL);
  gum_script_set_message_handler (snake, on_message, "snake", NULL);
  gum_script_load_sync (snake, NULL);

  loop = g_main_loop_new (g_main_context_get_thread_default (), FALSE);

  server = gum_debug_server_new (port);

  g_print ("Debugger enabled. You may now connect to port %u.\n", port);
  g_main_loop_run (loop);

  gum_debug_server_free (server);

  g_main_loop_unref (loop);
}

static void
on_message (GumScript * script,
            const gchar * message,
            const guint8 * data,
            gint data_length,
            gpointer user_data)
{
  gchar * sender = user_data;
  g_print ("Message from %s: %s\n", sender, message);
}

GUM_NOINLINE static int
target_function_int (int arg)
{
  int result = 0;
  int i;

  for (i = 0; i != 10; i++)
    result += i * arg;

  gum_script_dummy_global_to_trick_optimizer += result;

  return result;
}

GUM_NOINLINE static const gchar *
target_function_string (const gchar * arg)
{
  int i;

  for (i = 0; i != 10; i++)
    gum_script_dummy_global_to_trick_optimizer += i * arg[0];

  return arg;
}

GUM_NOINLINE static int
target_function_nested_a (int arg)
{
  int result = 0;
  int i;

  for (i = 0; i != 7; i++)
    result += i * arg;

  gum_script_dummy_global_to_trick_optimizer += result;

  return target_function_nested_b (result);
}

GUM_NOINLINE static int
target_function_nested_b (int arg)
{
  int result = 0;
  int i;

  for (i = 0; i != 14; i++)
    result += i * arg;

  gum_script_dummy_global_to_trick_optimizer += result;

  return target_function_nested_c (result);
}

GUM_NOINLINE static int
target_function_nested_c (int arg)
{
  int result = 0;
  int i;

  for (i = 0; i != 21; i++)
    result += i * arg;

  gum_script_dummy_global_to_trick_optimizer += result;

  return result;
}
