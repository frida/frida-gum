/*
 * Copyright (C) 2010-2012 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU Library General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 02111-1307, USA.
 */

#include "script-fixture.c"

TEST_LIST_BEGIN (script)
  SCRIPT_TESTENTRY (invalid_script_should_return_null)
  SCRIPT_TESTENTRY (message_can_be_sent)
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
  SCRIPT_TESTENTRY (invocations_are_bound_on_tls_object)
  SCRIPT_TESTENTRY (sword_can_be_read)
  SCRIPT_TESTENTRY (uword_can_be_read)
  SCRIPT_TESTENTRY (s8_can_be_read)
  SCRIPT_TESTENTRY (u8_can_be_read)
  SCRIPT_TESTENTRY (u8_can_be_written)
  SCRIPT_TESTENTRY (s16_can_be_read)
  SCRIPT_TESTENTRY (u16_can_be_read)
  SCRIPT_TESTENTRY (s32_can_be_read)
  SCRIPT_TESTENTRY (u32_can_be_read)
  SCRIPT_TESTENTRY (s64_can_be_read)
  SCRIPT_TESTENTRY (u64_can_be_read)
  SCRIPT_TESTENTRY (byte_array_can_be_read)
  SCRIPT_TESTENTRY (utf8_string_can_be_read)
  SCRIPT_TESTENTRY (utf8_string_can_be_written)
  SCRIPT_TESTENTRY (utf8_string_can_be_allocated)
  SCRIPT_TESTENTRY (utf16_string_can_be_read)
  SCRIPT_TESTENTRY (utf16_string_can_be_allocated)
#ifdef G_OS_WIN32
  SCRIPT_TESTENTRY (ansi_string_can_be_read)
  SCRIPT_TESTENTRY (ansi_string_can_be_allocated)
#endif
  SCRIPT_TESTENTRY (invalid_read_results_in_exception)
  SCRIPT_TESTENTRY (invalid_write_results_in_exception)
  SCRIPT_TESTENTRY (memory_can_be_scanned)
  SCRIPT_TESTENTRY (memory_scan_should_be_interruptible)
  SCRIPT_TESTENTRY (memory_scan_handles_unreadable_memory)
  SCRIPT_TESTENTRY (process_arch_is_available)
  SCRIPT_TESTENTRY (process_platform_is_available)
  SCRIPT_TESTENTRY (process_modules_can_be_enumerated)
  SCRIPT_TESTENTRY (process_ranges_can_be_enumerated)
  SCRIPT_TESTENTRY (module_exports_can_be_enumerated)
  SCRIPT_TESTENTRY (module_ranges_can_be_enumerated)
  SCRIPT_TESTENTRY (module_base_address_can_be_found)
  SCRIPT_TESTENTRY (module_export_can_be_found_by_name)
  SCRIPT_TESTENTRY (socket_type_can_be_inspected)
  SCRIPT_TESTENTRY (socket_endpoints_can_be_inspected)
  SCRIPT_TESTENTRY (execution_can_be_traced)
TEST_LIST_END ()

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
  COMPILE_AND_LOAD_SCRIPT ("send(Socket.type(%d));", fd);
  EXPECT_SEND_MESSAGE_WITH ("\"tcp6\"");
  GUM_CLOSE_SOCKET (fd);

  fd = socket (AF_INET6, SOCK_DGRAM, 0);
  COMPILE_AND_LOAD_SCRIPT ("send(Socket.type(%d));", fd);
  EXPECT_SEND_MESSAGE_WITH ("\"udp6\"");
  GUM_CLOSE_SOCKET (fd);

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

SCRIPT_TESTCASE (socket_endpoints_can_be_inspected)
{
  GSocketFamily family[] = { G_SOCKET_FAMILY_IPV4, G_SOCKET_FAMILY_IPV6 };
  guint i;
  GMainContext * context;
  int fd;

  context = g_main_context_get_thread_default ();

  for (i = 0; i != G_N_ELEMENTS (family); i++)
  {
    GSocketService * service;
    guint16 client_port, server_port;
    GSocketAddress * client_address, * server_address;
    GInetAddress * loopback;
    GSocket * socket;

    service = g_socket_service_new ();
    g_signal_connect (service, "incoming", G_CALLBACK (on_incoming_connection),
        NULL);
    server_port = g_socket_listener_add_any_inet_port (
        G_SOCKET_LISTENER (service), NULL, NULL);
    g_socket_service_start (service);
    loopback = g_inet_address_new_loopback (family[i]);
    server_address = g_inet_socket_address_new (loopback, server_port);
    g_object_unref (loopback);

    socket = g_socket_new (family[i], G_SOCKET_TYPE_STREAM,
        G_SOCKET_PROTOCOL_TCP, NULL);
    fd = g_socket_get_fd (socket);

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
      on_read_ready, NULL);

  return TRUE;
}

static void
on_read_ready (GObject * source_object,
               GAsyncResult * res,
               gpointer user_data)
{
  GError * error = NULL;
  g_input_stream_read_finish (G_INPUT_STREAM (source_object), res, &error);
  g_clear_error (&error);
}

SCRIPT_TESTCASE (execution_can_be_traced)
{
  GMainContext * context;

  context = g_main_context_get_thread_default ();

  COMPILE_AND_LOAD_SCRIPT ("Stalker.follow({"
    "  onReceive: function(events) {"
    "    send(events.length > 0);"
    "  }"
    "});"
    "Thread.sleep(0.01);"
    "Stalker.unfollow();");
  EXPECT_NO_MESSAGES ();
  while (g_main_context_pending (context))
    g_main_context_iteration (context, FALSE);
  EXPECT_SEND_MESSAGE_WITH ("true");
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
#endif
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

SCRIPT_TESTCASE (process_modules_can_be_enumerated)
{
  COMPILE_AND_LOAD_SCRIPT (
      "Process.enumerateModules({"
        "onMatch: function(name, address, path) {"
        "  send('onMatch');"
        "  return 'stop';"
        "},"
        "onComplete: function() {"
        "  send('onComplete');"
        "}"
      "});");
  EXPECT_SEND_MESSAGE_WITH ("\"onMatch\"");
  EXPECT_SEND_MESSAGE_WITH ("\"onComplete\"");
}

SCRIPT_TESTCASE (process_ranges_can_be_enumerated)
{
  COMPILE_AND_LOAD_SCRIPT (
      "Process.enumerateRanges('--x', {"
        "onMatch: function(address, size, prot) {"
        "  send('onMatch');"
        "  return 'stop';"
        "},"
        "onComplete: function() {"
        "  send('onComplete');"
        "}"
      "});");
  EXPECT_SEND_MESSAGE_WITH ("\"onMatch\"");
  EXPECT_SEND_MESSAGE_WITH ("\"onComplete\"");
}

SCRIPT_TESTCASE (module_exports_can_be_enumerated)
{
  COMPILE_AND_LOAD_SCRIPT (
      "Module.enumerateExports(\"%s\", {"
        "onMatch: function(name, address) {"
        "  send('onMatch');"
        "  return 'stop';"
        "},"
        "onComplete: function() {"
        "  send('onComplete');"
        "}"
      "});", SYSTEM_MODULE_NAME);
  EXPECT_SEND_MESSAGE_WITH ("\"onMatch\"");
  EXPECT_SEND_MESSAGE_WITH ("\"onComplete\"");
}

SCRIPT_TESTCASE (module_ranges_can_be_enumerated)
{
  COMPILE_AND_LOAD_SCRIPT (
      "Module.enumerateRanges(\"%s\", '--x', {"
        "onMatch: function(address, size, prot) {"
        "  send('onMatch');"
        "  return 'stop';"
        "},"
        "onComplete: function() {"
        "  send('onComplete');"
        "}"
      "});", SYSTEM_MODULE_NAME);
  EXPECT_SEND_MESSAGE_WITH ("\"onMatch\"");
  EXPECT_SEND_MESSAGE_WITH ("\"onComplete\"");
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
  char actual_address_str[64];

  mod = GetModuleHandle (_T ("kernel32.dll"));
  g_assert (mod != NULL);
  actual_address = GetProcAddress (mod, "Sleep");
  g_assert (actual_address != NULL);
  sprintf_s (actual_address_str, sizeof (actual_address_str),
      "%" G_GSIZE_MODIFIER "d", GPOINTER_TO_SIZE (actual_address));

  COMPILE_AND_LOAD_SCRIPT (
      "send(Module.findExportByName('kernel32.dll', 'Sleep'));");
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

  g_assert (gum_script_from_string ("'", NULL) == NULL);

  g_assert (gum_script_from_string ("'", &err) == NULL);
  g_assert (err != NULL);
  g_assert_cmpstr (err->message, ==,
      "Script(line 1): SyntaxError: Unexpected token ILLEGAL");
}

SCRIPT_TESTCASE (message_can_be_sent)
{
  COMPILE_AND_LOAD_SCRIPT ("send(1234);");
  EXPECT_SEND_MESSAGE_WITH ("1234");
}

SCRIPT_TESTCASE (message_can_be_received)
{
  COMPILE_AND_LOAD_SCRIPT (
      "recv(function(message) {"
      "  if (message.type == 'ping')"
      "    send('pong');"
      "});");
  EXPECT_NO_MESSAGES ();
  POST_MESSAGE ("{\"type\":\"ping\"}");
  EXPECT_SEND_MESSAGE_WITH ("\"pong\"");
}

SCRIPT_TESTCASE (recv_may_specify_desired_message_type)
{
  COMPILE_AND_LOAD_SCRIPT (
      "recv('wobble', function(message) {"
      "  send('wibble');"
      "});"
      "recv('ping', function(message) {"
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

  target_function_int (0);

  COMPILE_AND_LOAD_SCRIPT (
      "Interceptor.attach(" GUM_PTR_FORMAT ", {"
      "  onEnter: function(args) {"
      "    op = recv('poke', function(pokeMessage) {"
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
  worker_thread = g_thread_create (invoke_target_function_int_worker,
      &ctx, TRUE, NULL);
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
  GMainContext * context;

  context = g_main_context_get_thread_default ();

  COMPILE_AND_LOAD_SCRIPT (
      "setTimeout(function() {"
      "  send(1337);"
      "}, 20);");
  EXPECT_NO_MESSAGES ();
  while (g_main_context_pending (context))
    g_main_context_iteration (context, FALSE);
  EXPECT_NO_MESSAGES ();

  g_usleep (25000);
  while (g_main_context_pending (context))
    g_main_context_iteration (context, FALSE);
  EXPECT_SEND_MESSAGE_WITH ("1337");

  g_usleep (25000);
  while (g_main_context_pending (context))
    g_main_context_iteration (context, FALSE);
  EXPECT_NO_MESSAGES ();
}

SCRIPT_TESTCASE (timeout_can_be_cancelled)
{
  GMainContext * context;

  context = g_main_context_get_thread_default ();

  COMPILE_AND_LOAD_SCRIPT (
      "var timeout = setTimeout(function() {"
      "  send(1337);"
      "}, 20);"
      "clearTimeout(timeout);");
  while (g_main_context_pending (context))
    g_main_context_iteration (context, FALSE);
  g_usleep (25000);
  while (g_main_context_pending (context))
    g_main_context_iteration (context, FALSE);
  EXPECT_NO_MESSAGES ();
}

SCRIPT_TESTCASE (interval_can_be_scheduled)
{
  GMainContext * context;

  context = g_main_context_get_thread_default ();

  COMPILE_AND_LOAD_SCRIPT (
      "setInterval(function() {"
      "  send(1337);"
      "}, 20);");
  EXPECT_NO_MESSAGES ();
  while (g_main_context_pending (context))
    g_main_context_iteration (context, FALSE);
  EXPECT_NO_MESSAGES ();

  g_usleep (25000);
  while (g_main_context_pending (context))
    g_main_context_iteration (context, FALSE);
  EXPECT_SEND_MESSAGE_WITH ("1337");

  g_usleep (25000);
  while (g_main_context_pending (context))
    g_main_context_iteration (context, FALSE);
  EXPECT_SEND_MESSAGE_WITH ("1337");
}

SCRIPT_TESTCASE (interval_can_be_cancelled)
{
  GMainContext * context;

  context = g_main_context_get_thread_default ();

  COMPILE_AND_LOAD_SCRIPT (
      "var count = 1;"
      "var interval = setInterval(function() {"
      "  send(count++);"
      "  if (count == 3)"
      "    clearInterval(interval);"
      "}, 20);");
  while (g_main_context_pending (context))
    g_main_context_iteration (context, FALSE);

  g_usleep (25000);
  while (g_main_context_pending (context))
    g_main_context_iteration (context, FALSE);
  EXPECT_SEND_MESSAGE_WITH ("1");

  g_usleep (25000);
  while (g_main_context_pending (context))
    g_main_context_iteration (context, FALSE);
  EXPECT_SEND_MESSAGE_WITH ("2");

  g_usleep (25000);
  while (g_main_context_pending (context))
    g_main_context_iteration (context, FALSE);
  EXPECT_NO_MESSAGES ();
}

SCRIPT_TESTCASE (argument_can_be_read)
{
  COMPILE_AND_LOAD_SCRIPT (
      "Interceptor.attach(" GUM_PTR_FORMAT ", {"
      "  onEnter: function(args) {"
      "    send(Int32(args[0]));"
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
      "Interceptor.attach(" GUM_PTR_FORMAT ", {"
      "  onEnter: function(args) {"
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
      "Interceptor.attach(" GUM_PTR_FORMAT ", {"
      "  onLeave: function(retval) {"
      "    send(retval);"
      "  }"
      "});", target_function_int);

  EXPECT_NO_MESSAGES ();
  target_function_int (7);
  EXPECT_SEND_MESSAGE_WITH ("315");
}

SCRIPT_TESTCASE (invocations_are_bound_on_tls_object)
{
  COMPILE_AND_LOAD_SCRIPT (
      "Interceptor.attach(" GUM_PTR_FORMAT ", {"
      "  onEnter: function(args) {"
      "    send(this.value || null);"
      "    this.value = args[0];"
      "  },"
      "  onLeave: function(retval) {"
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

SCRIPT_TESTCASE (memory_can_be_scanned)
{
  guint8 haystack[] = { 0x01, 0x02, 0x13, 0x37, 0x03, 0x13, 0x37 };
  COMPILE_AND_LOAD_SCRIPT (
      "Memory.scan(" GUM_PTR_FORMAT ", 7, '13 37', {"
        "onMatch: function(address, size) {"
        "  send('onMatch offset=' + (address - " GUM_PTR_FORMAT
             ") + ' size=' + size);"
        "},"
        "onComplete: function() {"
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
      "Memory.scan(" GUM_PTR_FORMAT ", 7, '13 37', {"
        "onMatch: function(address, size) {"
        "  send('onMatch offset=' + (address - " GUM_PTR_FORMAT
             ") + ' size=' + size);"
        "  return 'stop';"
        "},"
        "onComplete: function() {"
        "  send('onComplete');"
        "}"
      "});", haystack, haystack);
  EXPECT_SEND_MESSAGE_WITH ("\"onMatch offset=2 size=2\"");
  EXPECT_SEND_MESSAGE_WITH ("\"onComplete\"");
}

SCRIPT_TESTCASE (memory_scan_handles_unreadable_memory)
{
  COMPILE_AND_LOAD_SCRIPT (
      "Memory.scan(1328, 7, '13 37', {"
        "onMatch: function(address, size) {"
        "  send('onMatch');"
        "},"
        "onError: function(message) {"
        "  send('onError: ' + message);"
        "},"
        "onComplete: function() {"
        "  send('onComplete');"
        "}"
      "});");
  EXPECT_SEND_MESSAGE_WITH ("\"onError: access violation reading 0x530\"");
  EXPECT_SEND_MESSAGE_WITH ("\"onComplete\"");
}

SCRIPT_TESTCASE (sword_can_be_read)
{
  int val = -1337000;
  COMPILE_AND_LOAD_SCRIPT ("send(Memory.readSWord(" GUM_PTR_FORMAT "));", &val);
  EXPECT_SEND_MESSAGE_WITH ("-1337000");
}

SCRIPT_TESTCASE (uword_can_be_read)
{
  unsigned int val = 1337000;
  COMPILE_AND_LOAD_SCRIPT ("send(Memory.readUWord(" GUM_PTR_FORMAT "));", &val);
  EXPECT_SEND_MESSAGE_WITH ("1337000");
}

SCRIPT_TESTCASE (s8_can_be_read)
{
  gint8 val = -42;
  COMPILE_AND_LOAD_SCRIPT ("send(Memory.readS8(" GUM_PTR_FORMAT "));", &val);
  EXPECT_SEND_MESSAGE_WITH ("-42");
}

SCRIPT_TESTCASE (u8_can_be_read)
{
  guint8 val = 42;
  COMPILE_AND_LOAD_SCRIPT ("send(Memory.readU8(" GUM_PTR_FORMAT "));", &val);
  EXPECT_SEND_MESSAGE_WITH ("42");
}

SCRIPT_TESTCASE (u8_can_be_written)
{
  guint8 val = 42;
  COMPILE_AND_LOAD_SCRIPT ("Memory.writeU8(37, " GUM_PTR_FORMAT ");", &val);
  g_assert_cmpint (val, ==, 37);
}

SCRIPT_TESTCASE (s16_can_be_read)
{
  gint16 val = -12123;
  COMPILE_AND_LOAD_SCRIPT ("send(Memory.readS16(" GUM_PTR_FORMAT "));", &val);
  EXPECT_SEND_MESSAGE_WITH ("-12123");
}

SCRIPT_TESTCASE (u16_can_be_read)
{
  guint16 val = 12123;
  COMPILE_AND_LOAD_SCRIPT ("send(Memory.readU16(" GUM_PTR_FORMAT "));", &val);
  EXPECT_SEND_MESSAGE_WITH ("12123");
}

SCRIPT_TESTCASE (s32_can_be_read)
{
  gint32 val = -120123;
  COMPILE_AND_LOAD_SCRIPT ("send(Memory.readS32(" GUM_PTR_FORMAT "));", &val);
  EXPECT_SEND_MESSAGE_WITH ("-120123");
}

SCRIPT_TESTCASE (u32_can_be_read)
{
  guint32 val = 120123;
  COMPILE_AND_LOAD_SCRIPT ("send(Memory.readU32(" GUM_PTR_FORMAT "));", &val);
  EXPECT_SEND_MESSAGE_WITH ("120123");
}

SCRIPT_TESTCASE (s64_can_be_read)
{
  gint64 val = G_GINT64_CONSTANT (-1201239876783);
  COMPILE_AND_LOAD_SCRIPT ("send(Memory.readS64(" GUM_PTR_FORMAT "));", &val);
  EXPECT_SEND_MESSAGE_WITH ("-1201239876783");
}

SCRIPT_TESTCASE (u64_can_be_read)
{
  guint64 val = G_GUINT64_CONSTANT (1201239876783);
  COMPILE_AND_LOAD_SCRIPT ("send(Memory.readU64(" GUM_PTR_FORMAT "));", &val);
  EXPECT_SEND_MESSAGE_WITH ("1201239876783");
}

SCRIPT_TESTCASE (byte_array_can_be_read)
{
  guint8 val[3] = { 0x13, 0x37, 0x42 };
  COMPILE_AND_LOAD_SCRIPT ("send('stuff', Memory.readByteArray(" GUM_PTR_FORMAT
      ", 3));", val);
  EXPECT_SEND_MESSAGE_WITH_PAYLOAD_AND_DATA ("\"stuff\"", "13 37 42");
}

SCRIPT_TESTCASE (utf8_string_can_be_read)
{
  const gchar * str = "Bjøærheimsbygd";

  COMPILE_AND_LOAD_SCRIPT ("send(Memory.readUtf8String(" GUM_PTR_FORMAT "));",
      str);
  EXPECT_SEND_MESSAGE_WITH ("\"Bjøærheimsbygd\"");

  COMPILE_AND_LOAD_SCRIPT ("send(Memory.readUtf8String(" GUM_PTR_FORMAT
      ", 3));", str);
  EXPECT_SEND_MESSAGE_WITH ("\"Bjø\"");

  COMPILE_AND_LOAD_SCRIPT ("send(Memory.readUtf8String(" GUM_PTR_FORMAT
      ", 0));", str);
  EXPECT_SEND_MESSAGE_WITH ("\"\"");

  COMPILE_AND_LOAD_SCRIPT ("send(Memory.readUtf8String(" GUM_PTR_FORMAT
      ", -1));", str);
  EXPECT_SEND_MESSAGE_WITH ("\"Bjøærheimsbygd\"");

  COMPILE_AND_LOAD_SCRIPT ("send(Memory.readUtf8String(0));", str);
  EXPECT_SEND_MESSAGE_WITH ("null");
}

SCRIPT_TESTCASE (utf8_string_can_be_written)
{
  gchar str[6];

  strcpy (str, "Hello");
  COMPILE_AND_LOAD_SCRIPT ("Memory.writeUtf8String('Bye', " GUM_PTR_FORMAT ");",
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

  COMPILE_AND_LOAD_SCRIPT ("send(Memory.readUtf16String(" GUM_PTR_FORMAT "));",
      str);
  EXPECT_SEND_MESSAGE_WITH ("\"Bjørheimsbygd\"");

  COMPILE_AND_LOAD_SCRIPT ("send(Memory.readUtf16String(" GUM_PTR_FORMAT
      ", 3));", str);
  EXPECT_SEND_MESSAGE_WITH ("\"Bjø\"");

  COMPILE_AND_LOAD_SCRIPT ("send(Memory.readUtf16String(" GUM_PTR_FORMAT
      ", 0));", str);
  EXPECT_SEND_MESSAGE_WITH ("\"\"");

  COMPILE_AND_LOAD_SCRIPT ("send(Memory.readUtf16String(" GUM_PTR_FORMAT
      ", -1));", str);
  EXPECT_SEND_MESSAGE_WITH ("\"Bjørheimsbygd\"");

  COMPILE_AND_LOAD_SCRIPT ("send(Memory.readUtf16String(0));", str);
  EXPECT_SEND_MESSAGE_WITH ("null");

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

  COMPILE_AND_LOAD_SCRIPT ("send(Memory.readAnsiString(" GUM_PTR_FORMAT "));",
      str);
  EXPECT_SEND_MESSAGE_WITH ("\"Bjørheimsbygd\"");

  COMPILE_AND_LOAD_SCRIPT ("send(Memory.readAnsiString(" GUM_PTR_FORMAT
      ", 3));", str);
  EXPECT_SEND_MESSAGE_WITH ("\"Bjø\"");

  COMPILE_AND_LOAD_SCRIPT ("send(Memory.readAnsiString(" GUM_PTR_FORMAT
      ", 0));", str);
  EXPECT_SEND_MESSAGE_WITH ("\"\"");

  COMPILE_AND_LOAD_SCRIPT ("send(Memory.readAnsiString(" GUM_PTR_FORMAT
      ", -1));", str);
  EXPECT_SEND_MESSAGE_WITH ("\"Bjørheimsbygd\"");

  COMPILE_AND_LOAD_SCRIPT ("send(Memory.readAnsiString(0));", str);
  EXPECT_SEND_MESSAGE_WITH ("null");

  g_free (str_utf16);
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
      "SWord",
      "UWord",
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

    source = g_strconcat ("Memory.read", type_name[i], "(1328);", NULL);
    COMPILE_AND_LOAD_SCRIPT (source);
    EXPECT_ERROR_MESSAGE_WITH (1, "Error: access violation reading 0x530");
    g_free (source);
  }
}

SCRIPT_TESTCASE (invalid_write_results_in_exception)
{
  const gchar * primitive_type_name[] = {
      "U8",
  };
  const gchar * string_type_name[] = {
      "Utf8String"
  };
  guint i;

  for (i = 0; i != G_N_ELEMENTS (primitive_type_name); i++)
  {
    gchar * source;

    source = g_strconcat ("Memory.write", primitive_type_name[i], "(13, 1328);",
        NULL);
    COMPILE_AND_LOAD_SCRIPT (source);
    EXPECT_ERROR_MESSAGE_WITH (1, "Error: access violation writing to 0x530");
    g_free (source);
  }

  for (i = 0; i != G_N_ELEMENTS (string_type_name); i++)
  {
    gchar * source;

    source = g_strconcat ("Memory.write", string_type_name[i], "('Hey', 1328);",
        NULL);
    COMPILE_AND_LOAD_SCRIPT (source);
    EXPECT_ERROR_MESSAGE_WITH (1, "Error: access violation writing to 0x530");
    g_free (source);
  }
}

GUM_NOINLINE static int
target_function_int (int arg)
{
  int result = 0;
  int i;

  for (i = 0; i != 10; i++)
    result += i * arg;

  gum_dummy_global_to_trick_optimizer += result;

  return result;
}

GUM_NOINLINE static const gchar *
target_function_string (const gchar * arg)
{
  int i;

  for (i = 0; i != 10; i++)
    gum_dummy_global_to_trick_optimizer += i * arg[0];

  return arg;
}
