/*
 * Copyright (C) 2010-2016 Ole André Vadla Ravnås <oleavr@nowsecure.com>
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
  SCRIPT_TESTENTRY (message_can_be_received_with_data)
  SCRIPT_TESTENTRY (recv_may_specify_desired_message_type)
  SCRIPT_TESTENTRY (recv_can_be_waited_for_from_an_application_thread)
  SCRIPT_TESTENTRY (recv_can_be_waited_for_from_our_js_thread)
  SCRIPT_TESTENTRY (rpc_can_be_performed)
  SCRIPT_TESTENTRY (thread_can_be_forced_to_sleep)
  SCRIPT_TESTENTRY (timeout_can_be_scheduled)
  SCRIPT_TESTENTRY (timeout_can_be_cancelled)
  SCRIPT_TESTENTRY (interval_can_be_scheduled)
  SCRIPT_TESTENTRY (interval_can_be_cancelled)
  SCRIPT_TESTENTRY (callback_can_be_scheduled)
  SCRIPT_TESTENTRY (callback_can_be_scheduled_from_a_scheduled_callback)
  SCRIPT_TESTENTRY (callback_can_be_cancelled)
  SCRIPT_TESTENTRY (callback_can_be_scheduled_on_next_tick)
  SCRIPT_TESTENTRY (argument_can_be_read)
  SCRIPT_TESTENTRY (argument_can_be_replaced)
  SCRIPT_TESTENTRY (return_value_can_be_read)
  SCRIPT_TESTENTRY (return_value_can_be_replaced)
  SCRIPT_TESTENTRY (return_address_can_be_read)
  SCRIPT_TESTENTRY (register_can_be_read)
  SCRIPT_TESTENTRY (register_can_be_written)
  SCRIPT_TESTENTRY (system_error_can_be_read_from_interceptor_listener)
  SCRIPT_TESTENTRY (system_error_can_be_read_from_replacement_function)
  SCRIPT_TESTENTRY (system_error_can_be_replaced_from_interceptor_listener)
  SCRIPT_TESTENTRY (system_error_can_be_replaced_from_replacement_function)
  SCRIPT_TESTENTRY (invocations_are_bound_on_tls_object)
  SCRIPT_TESTENTRY (invocations_provide_thread_id)
  SCRIPT_TESTENTRY (invocations_provide_call_depth)
#if !defined (HAVE_QNX) && !defined (HAVE_MIPS)
  SCRIPT_TESTENTRY (invocations_provide_context_for_backtrace)
#endif
  SCRIPT_TESTENTRY (invocations_provide_context_serializable_to_json)
  SCRIPT_TESTENTRY (listener_can_be_detached)
  SCRIPT_TESTENTRY (listener_can_be_detached_by_destruction_mid_call)
  SCRIPT_TESTENTRY (all_listeners_can_be_detached)
  SCRIPT_TESTENTRY (function_can_be_replaced)
  SCRIPT_TESTENTRY (function_can_be_replaced_and_called_immediately)
  SCRIPT_TESTENTRY (function_can_be_reverted)
  SCRIPT_TESTENTRY (replaced_function_should_have_invocation_context)
  SCRIPT_TESTENTRY (instructions_can_be_probed)
  SCRIPT_TESTENTRY (interceptor_handles_invalid_arguments)
  SCRIPT_TESTENTRY (interceptor_on_enter_performance)
  SCRIPT_TESTENTRY (interceptor_on_leave_performance)
  SCRIPT_TESTENTRY (interceptor_on_enter_and_leave_performance)
  SCRIPT_TESTENTRY (pointer_can_be_read)
  SCRIPT_TESTENTRY (pointer_can_be_written)
  SCRIPT_TESTENTRY (memory_can_be_allocated)
  SCRIPT_TESTENTRY (memory_can_be_copied)
  SCRIPT_TESTENTRY (memory_can_be_duped)
  SCRIPT_TESTENTRY (memory_can_be_protected)
  SCRIPT_TESTENTRY (code_can_be_patched)
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
  SCRIPT_TESTENTRY (float_can_be_read)
  SCRIPT_TESTENTRY (float_can_be_written)
  SCRIPT_TESTENTRY (double_can_be_read)
  SCRIPT_TESTENTRY (double_can_be_written)
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
  SCRIPT_TESTENTRY (invalid_read_write_execute_results_in_exception)
  SCRIPT_TESTENTRY (memory_can_be_scanned)
  SCRIPT_TESTENTRY (memory_can_be_scanned_synchronously)
  SCRIPT_TESTENTRY (memory_scan_should_be_interruptible)
  SCRIPT_TESTENTRY (memory_scan_handles_unreadable_memory)
#ifdef G_OS_WIN32
  SCRIPT_TESTENTRY (memory_access_can_be_monitored)
#endif
  SCRIPT_TESTENTRY (frida_version_is_available)
  SCRIPT_TESTENTRY (process_arch_is_available)
  SCRIPT_TESTENTRY (process_platform_is_available)
  SCRIPT_TESTENTRY (process_page_size_is_available)
  SCRIPT_TESTENTRY (process_pointer_size_is_available)
#ifndef HAVE_QNX
  SCRIPT_TESTENTRY (process_debugger_status_is_available)
#endif
  SCRIPT_TESTENTRY (process_current_thread_id_is_available)
#ifndef HAVE_MIPS
  SCRIPT_TESTENTRY (process_threads_can_be_enumerated)
  SCRIPT_TESTENTRY (process_threads_can_be_enumerated_synchronously)
#endif
  SCRIPT_TESTENTRY (process_modules_can_be_enumerated)
  SCRIPT_TESTENTRY (process_modules_can_be_enumerated_synchronously)
  SCRIPT_TESTENTRY (process_module_can_be_looked_up_from_address)
  SCRIPT_TESTENTRY (process_module_can_be_looked_up_from_name)
  SCRIPT_TESTENTRY (process_ranges_can_be_enumerated)
  SCRIPT_TESTENTRY (process_ranges_can_be_enumerated_synchronously)
  SCRIPT_TESTENTRY (process_ranges_can_be_enumerated_with_neighbors_coalesced)
  SCRIPT_TESTENTRY (process_range_can_be_looked_up_from_address)
#ifdef HAVE_DARWIN
  SCRIPT_TESTENTRY (process_malloc_ranges_can_be_enumerated)
  SCRIPT_TESTENTRY (process_malloc_ranges_can_be_enumerated_synchronously)
#endif
#ifndef HAVE_QNX
  SCRIPT_TESTENTRY (module_imports_can_be_enumerated)
  SCRIPT_TESTENTRY (module_imports_can_be_enumerated_synchronously)
#endif
  SCRIPT_TESTENTRY (module_exports_can_be_enumerated)
  SCRIPT_TESTENTRY (module_exports_can_be_enumerated_synchronously)
  SCRIPT_TESTENTRY (module_exports_enumeration_performance)
  SCRIPT_TESTENTRY (module_ranges_can_be_enumerated)
  SCRIPT_TESTENTRY (module_ranges_can_be_enumerated_synchronously)
  SCRIPT_TESTENTRY (module_base_address_can_be_found)
  SCRIPT_TESTENTRY (module_export_can_be_found_by_name)
  SCRIPT_TESTENTRY (api_resolver_can_be_used_to_find_functions)
  SCRIPT_TESTENTRY (socket_connection_can_be_established)
  SCRIPT_TESTENTRY (socket_type_can_be_inspected)
#if !defined (HAVE_ANDROID) && !(defined (HAVE_LINUX) && defined (HAVE_ARM)) && \
  !(defined (HAVE_LINUX) && defined (HAVE_MIPS))
  SCRIPT_TESTENTRY (socket_endpoints_can_be_inspected)
#endif
#ifdef G_OS_UNIX
  SCRIPT_TESTENTRY (unix_fd_can_be_read_from)
  SCRIPT_TESTENTRY (unix_fd_can_be_written_to)
#endif
  SCRIPT_TESTENTRY (basic_hexdump_functionality_is_available)
  SCRIPT_TESTENTRY (hexdump_supports_native_pointer_conforming_object)
  SCRIPT_TESTENTRY (native_pointer_provides_is_null)
  SCRIPT_TESTENTRY (native_pointer_provides_arithmetic_operations)
  SCRIPT_TESTENTRY (native_pointer_to_match_pattern)
  SCRIPT_TESTENTRY (native_pointer_can_be_constructed_from_64bit_value)
  SCRIPT_TESTENTRY (native_function_can_be_invoked)
  SCRIPT_TESTENTRY (native_function_should_implement_call_and_apply)
  SCRIPT_TESTENTRY (system_function_can_be_invoked)
  SCRIPT_TESTENTRY (native_function_crash_results_in_exception)
  SCRIPT_TESTENTRY (nested_native_function_crash_is_handled_gracefully)
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
  SCRIPT_TESTENTRY (script_can_be_compiled_to_bytecode)
  SCRIPT_TESTENTRY (script_can_be_reloaded)
  SCRIPT_TESTENTRY (script_memory_usage)
  SCRIPT_TESTENTRY (source_maps_should_be_supported_for_our_runtime)
  SCRIPT_TESTENTRY (source_maps_should_be_supported_for_user_scripts)
  SCRIPT_TESTENTRY (types_handle_invalid_construction)
  SCRIPT_TESTENTRY (weak_callback_is_triggered_on_gc)
  SCRIPT_TESTENTRY (weak_callback_is_triggered_on_unload)
  SCRIPT_TESTENTRY (weak_callback_is_triggered_on_unbind)
  SCRIPT_TESTENTRY (globals_can_be_dynamically_generated)
  SCRIPT_TESTENTRY (exceptions_can_be_handled)
  SCRIPT_TESTENTRY (debugger_can_be_enabled)
  SCRIPT_TESTENTRY (objc_api_is_embedded)
  SCRIPT_TESTENTRY (java_api_is_embedded)
TEST_LIST_END ()

typedef struct _TestTrigger TestTrigger;

struct _TestTrigger
{
  volatile gboolean ready;
  volatile gboolean fired;
  GMutex mutex;
  GCond cond;
};

static gint gum_clobber_system_error (gint value);
static gint gum_toupper (gchar * str, gint limit);
static gint64 gum_classify_timestamp (gint64 timestamp);
static guint64 gum_square (guint64 value);
static gint gum_sum (gint count, ...);

#ifndef HAVE_ANDROID
static gboolean on_incoming_connection (GSocketService * service,
    GSocketConnection * connection, GObject * source_object,
    gpointer user_data);
static void on_read_ready (GObject * source_object, GAsyncResult * res,
    gpointer user_data);
#endif

static gpointer sleeping_dummy (gpointer data);

static gpointer invoke_target_function_int_worker (gpointer data);
static gpointer invoke_target_function_trigger (gpointer data);

static void measure_target_function_int_overhead (void);

static void on_message (GumScript * script, const gchar * message,
    GBytes * data, gpointer user_data);

static int target_function_int (int arg);
static const gchar * target_function_string (const gchar * arg);
static void target_function_callbacks (const gint value,
    void (* first) (const gint * value), void (* second) (const gint * value));
static void target_function_trigger (TestTrigger * trigger);
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
      "send(second.toString().indexOf(\"[object\") !== 0);"
      "send(first.address.toInt32() !== 0);"
      "send(first.size > 0);"
      "send(typeof first.mnemonic);"
      "send(typeof first.opStr);"
      "send(JSON.stringify(first) !== \"{}\");",
      target_function_int);
  EXPECT_SEND_MESSAGE_WITH ("\"string\"");
  EXPECT_SEND_MESSAGE_WITH ("\"string\"");
  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_SEND_MESSAGE_WITH ("\"string\"");
  EXPECT_SEND_MESSAGE_WITH ("\"string\"");
  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_NO_MESSAGES ();

  if (!RUNNING_ON_VALGRIND)
  {
    COMPILE_AND_LOAD_SCRIPT ("Instruction.parse(ptr(\"0x1\"));");
    EXPECT_ERROR_MESSAGE_WITH (ANY_LINE_NUMBER,
        "Error: access violation accessing 0x1");
  }
}

SCRIPT_TESTCASE (address_can_be_resolved_to_symbol)
{
#ifdef HAVE_ANDROID
  if (!g_test_slow ())
  {
    g_print ("<skipping, run in slow mode> ");
    return;
  }
#endif

  COMPILE_AND_LOAD_SCRIPT (
      "var sym = DebugSymbol.fromAddress(" GUM_PTR_CONST ");"
      "send(sym.name);"
      "send(sym.toString().indexOf(sym.name) !== -1);"
      "send(JSON.stringify(sym) !== \"{}\");",
      target_function_int);
  EXPECT_SEND_MESSAGE_WITH ("\"target_function_int\"");
  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_NO_MESSAGES ();
}

SCRIPT_TESTCASE (name_can_be_resolved_to_symbol)
{
  gchar * expected;

#ifdef HAVE_ANDROID
  if (!g_test_slow ())
  {
    g_print ("<skipping, run in slow mode> ");
    return;
  }
#endif

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
#ifdef HAVE_ANDROID
  if (!g_test_slow ())
  {
    g_print ("<skipping, run in slow mode> ");
    return;
  }
#endif

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
#ifdef HAVE_ANDROID
  if (!g_test_slow ())
  {
    g_print ("<skipping, run in slow mode> ");
    return;
  }
#endif

  COMPILE_AND_LOAD_SCRIPT ("send("
      "DebugSymbol.findFunctionsNamed(\"g_thread_new\").length >= 1"
  ");");
  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_NO_MESSAGES ();
}

SCRIPT_TESTCASE (functions_can_be_found_by_matching)
{
#ifdef HAVE_ANDROID
  if (!g_test_slow ())
  {
    g_print ("<skipping, run in slow mode> ");
    return;
  }
#endif

  COMPILE_AND_LOAD_SCRIPT ("send("
      "DebugSymbol.findFunctionsMatching(\"gum_symbol_details_from*\")"
          ".length >= 1"
  ");");
  EXPECT_SEND_MESSAGE_WITH ("true");
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

#ifdef G_OS_WIN32
  COMPILE_AND_LOAD_SCRIPT (
      "var impl = Module.findExportByName(\"user32.dll\", \"GetKeyState\");"
      "var f = new NativeFunction(impl, 'int16', ['int']);"
      "var result = f(0x41);"
      "send(typeof result);");
  EXPECT_SEND_MESSAGE_WITH ("\"number\"");
  EXPECT_NO_MESSAGES ();
#endif

  COMPILE_AND_LOAD_SCRIPT (
      "var classify = new NativeFunction(" GUM_PTR_CONST ", "
          "'int64', ['int64']);"
      "send(classify(new Int64(\"-42\")));"
      "send(classify(new Int64(\"0\")));"
      "send(classify(new Int64(\"42\")));",
      gum_classify_timestamp);
  EXPECT_SEND_MESSAGE_WITH ("\"-1\"");
  EXPECT_SEND_MESSAGE_WITH ("\"0\"");
  EXPECT_SEND_MESSAGE_WITH ("\"1\"");
  EXPECT_NO_MESSAGES ();

  COMPILE_AND_LOAD_SCRIPT (
      "var square = new NativeFunction(" GUM_PTR_CONST ", "
          "'uint64', ['uint64']);"
      "send(square(new UInt64(\"2\")));"
      "send(square(new UInt64(\"4\")));"
      "send(square(new UInt64(\"6\")));",
      gum_square);
  EXPECT_SEND_MESSAGE_WITH ("\"4\"");
  EXPECT_SEND_MESSAGE_WITH ("\"16\"");
  EXPECT_SEND_MESSAGE_WITH ("\"36\"");
  EXPECT_NO_MESSAGES ();
}

SCRIPT_TESTCASE (native_function_should_implement_call_and_apply)
{
  COMPILE_AND_LOAD_SCRIPT (
      "var f = new NativeFunction(" GUM_PTR_CONST ", 'int', ['int']);"
      "send(NativeFunction.prototype.call(f, 42));"
      "send(NativeFunction.prototype.apply(f, [42]));"
      "send(f.call(null, 42));"
      "send(f.apply(null, [42]));"
      "send(f.call(f, 42));"
      "send(f.apply(f, [42]));"
      "send(f.call(ptr(" GUM_PTR_CONST "), 42));"
      "send(f.apply(ptr(" GUM_PTR_CONST "), [42]));",
      target_function_int, target_function_nested_a, target_function_nested_a);
  EXPECT_SEND_MESSAGE_WITH ("1890");
  EXPECT_SEND_MESSAGE_WITH ("1890");
  EXPECT_SEND_MESSAGE_WITH ("1890");
  EXPECT_SEND_MESSAGE_WITH ("1890");
  EXPECT_SEND_MESSAGE_WITH ("1890");
  EXPECT_SEND_MESSAGE_WITH ("1890");
  EXPECT_SEND_MESSAGE_WITH ("16855020");
  EXPECT_SEND_MESSAGE_WITH ("16855020");
  EXPECT_NO_MESSAGES ();
}

SCRIPT_TESTCASE (system_function_can_be_invoked)
{
#ifdef G_OS_WIN32
  COMPILE_AND_LOAD_SCRIPT (
      "var f = new SystemFunction(" GUM_PTR_CONST ", 'int', ['int']);"

      "var result = f(13);"
      "send(result.value);"
      "send(result.lastError);"

      "result = f(37);"
      "send(result.value);"
      "send(result.lastError);", gum_clobber_system_error);
#else
  COMPILE_AND_LOAD_SCRIPT (
      "var f = new SystemFunction(" GUM_PTR_CONST ", 'int', ['int']);"

      "var result = f(13);"
      "send(result.value);"
      "send(result.errno);"

      "result = f(37);"
      "send(result.value);"
      "send(result.errno);", gum_clobber_system_error);
#endif

  EXPECT_SEND_MESSAGE_WITH ("26");
  EXPECT_SEND_MESSAGE_WITH ("13");

  EXPECT_SEND_MESSAGE_WITH ("74");
  EXPECT_SEND_MESSAGE_WITH ("37");

  EXPECT_NO_MESSAGES ();
}

static gint
gum_clobber_system_error (gint value)
{
#ifdef G_OS_WIN32
  SetLastError (value);
#else
  errno = value;
#endif

  return value * 2;
}

SCRIPT_TESTCASE (native_function_crash_results_in_exception)
{
  if (RUNNING_ON_VALGRIND)
  {
    g_print ("<skipping, not compatible with Valgrind> ");
    return;
  }

  COMPILE_AND_LOAD_SCRIPT (
      "var targetWithString = new NativeFunction(" GUM_PTR_CONST ", "
          "'pointer', ['pointer']);"
      "try {"
      "  targetWithString(NULL);"
      "} catch (e) {"
      "  send(e.type);"
      "}",
      target_function_string);
  EXPECT_SEND_MESSAGE_WITH ("\"access-violation\"");
}

SCRIPT_TESTCASE (nested_native_function_crash_is_handled_gracefully)
{
  if (RUNNING_ON_VALGRIND)
  {
    g_print ("<skipping, not compatible with Valgrind> ");
    return;
  }

  COMPILE_AND_LOAD_SCRIPT (
      "var targetWithCallback = new NativeFunction(" GUM_PTR_CONST ", "
          "'pointer', ['int', 'pointer', 'pointer']);"
      "var callback = new NativeCallback(function (value) {"
      "  send(Memory.readInt(value));"
      "}, 'void', ['pointer']);"
      "try {"
      "  targetWithCallback(42, callback, NULL);"
      "} catch (e) {"
      "  send(e.type);"
      "}",
      target_function_callbacks);
  EXPECT_SEND_MESSAGE_WITH ("42");
  EXPECT_SEND_MESSAGE_WITH ("\"access-violation\"");
  EXPECT_NO_MESSAGES ();
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
      "var toupper = new NativeCallback(function (str, limit) {"
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

#ifdef G_OS_UNIX

#define GUM_TEMP_FAILURE_RETRY(expression) \
  ({ \
    gssize __result; \
    \
    do __result = (gssize) (expression); \
    while (__result == -EINTR); \
    \
    __result; \
  })

SCRIPT_TESTCASE (unix_fd_can_be_read_from)
{
  gint fds[2];
  const guint8 message[7] = { 0x13, 0x37, 0xca, 0xfe, 0xba, 0xbe, 0xff };
  gssize res;

  g_assert_cmpint (socketpair (AF_UNIX, SOCK_STREAM, 0, fds), ==, 0);

  COMPILE_AND_LOAD_SCRIPT (
      "var stream = new UnixInputStream(%d, { autoClose: false });"
      "stream.read(1337)"
      ".then(function (buf) {"
          "send(buf.byteLength, buf);"
      "});",
      fds[0]);
  EXPECT_NO_MESSAGES ();
  res = GUM_TEMP_FAILURE_RETRY (write (fds[1], message, 1));
  g_assert_cmpint (res, ==, 1);
  EXPECT_SEND_MESSAGE_WITH_PAYLOAD_AND_DATA ("1", "13");
  EXPECT_NO_MESSAGES ();

  COMPILE_AND_LOAD_SCRIPT (
      "var stream = new UnixInputStream(%d, { autoClose: false });"
      "stream.readAll(7)"
      ".then(function (buf) {"
          "send(buf.byteLength, buf);"
      "});",
      fds[0]);
  EXPECT_NO_MESSAGES ();
  res = GUM_TEMP_FAILURE_RETRY (write (fds[1], message, 4));
  g_assert_cmpint (res, ==, 4);
  g_usleep (G_USEC_PER_SEC / 20);
  EXPECT_NO_MESSAGES ();
  res = GUM_TEMP_FAILURE_RETRY (write (fds[1], message + 4, 3));
  g_assert_cmpint (res, ==, 3);
  EXPECT_SEND_MESSAGE_WITH_PAYLOAD_AND_DATA ("7", "13 37 ca fe ba be ff");
  EXPECT_NO_MESSAGES ();

  res = GUM_TEMP_FAILURE_RETRY (write (fds[1], message, 2));
  g_assert_cmpint (res, ==, 2);
  close (fds[1]);
  COMPILE_AND_LOAD_SCRIPT (
      "var stream = new UnixInputStream(%d, { autoClose: false });"
      "stream.readAll(7)"
      ".catch(function (error) {"
          "send(error.toString(), error.partialData);"
      "});",
      fds[0]);
  EXPECT_SEND_MESSAGE_WITH ("\"Error: Short read\"", "13 37");
  EXPECT_NO_MESSAGES ();

  COMPILE_AND_LOAD_SCRIPT (
      "var stream = new UnixInputStream(%d, { autoClose: false });"
      "stream.close()"
      ".then(function (success) {"
          "send(success);"
          "stream.read(1337)"
          ".catch(function (error) {"
              "send(error.toString());"
          "});"
      "});",
      fds[0]);
  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_SEND_MESSAGE_WITH ("\"Error: Stream is already closed\"");
  EXPECT_NO_MESSAGES ();

  COMPILE_AND_LOAD_SCRIPT (
      "var stream = new UnixInputStream(%d, { autoClose: false });"
      "stream.close()"
      ".then(function (success) {"
          "send(success);"
          "stream.close()"
          ".then(function (success) {"
              "send(success);"
          "});"
      "});",
      fds[0]);
  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_NO_MESSAGES ();

  close (fds[0]);
}

SCRIPT_TESTCASE (unix_fd_can_be_written_to)
{
  gint fds[2];
  guint8 buffer[8];
  sig_t original_sigpipe_handler;

  original_sigpipe_handler = signal (SIGPIPE, SIG_IGN);

  g_assert_cmpint (socketpair (AF_UNIX, SOCK_STREAM, 0, fds), ==, 0);

  COMPILE_AND_LOAD_SCRIPT (
      "var stream = new UnixOutputStream(%d, { autoClose: false });"
      "stream.write([0x13])"
      ".then(function (size) {"
          "send(size);"
      "});",
      fds[0]);
  EXPECT_SEND_MESSAGE_WITH ("1");
  EXPECT_NO_MESSAGES ();
  g_assert_cmpint (read (fds[1], buffer, sizeof (buffer)), ==, 1);
  g_assert_cmphex (buffer[0], ==, 0x13);

  COMPILE_AND_LOAD_SCRIPT (
      "var stream = new UnixOutputStream(%d, { autoClose: false });"
      "stream.writeAll([0x13, 0x37, 0xca, 0xfe, 0xba, 0xbe, 0xff])"
      ".then(function (size) {"
          "send(size);"
      "});",
      fds[0]);
  EXPECT_SEND_MESSAGE_WITH ("7");
  EXPECT_NO_MESSAGES ();
  g_assert_cmpint (read (fds[1], buffer, sizeof (buffer)), ==, 7);
  g_assert_cmphex (buffer[0], ==, 0x13);
  g_assert_cmphex (buffer[1], ==, 0x37);
  g_assert_cmphex (buffer[2], ==, 0xca);
  g_assert_cmphex (buffer[3], ==, 0xfe);
  g_assert_cmphex (buffer[4], ==, 0xba);
  g_assert_cmphex (buffer[5], ==, 0xbe);
  g_assert_cmphex (buffer[6], ==, 0xff);

  close (fds[1]);

  COMPILE_AND_LOAD_SCRIPT (
      "var stream = new UnixOutputStream(%d, { autoClose: false });"
      "stream.writeAll([0x13, 0x37, 0xca, 0xfe, 0xba, 0xbe, 0xff])"
      ".catch(function (error) {"
          "send(error.partialSize);"
      "});",
      fds[0]);
  EXPECT_SEND_MESSAGE_WITH ("0");
  EXPECT_NO_MESSAGES ();

  close (fds[0]);

  signal (SIGPIPE, original_sigpipe_handler);
}

#endif

SCRIPT_TESTCASE (basic_hexdump_functionality_is_available)
{
  COMPILE_AND_LOAD_SCRIPT (
      "var str = Memory.allocUtf8String(\"Hello hex world! w00t\");"
      "var buf = Memory.readByteArray(str, 22);"
      "send(hexdump(buf));");
  EXPECT_SEND_MESSAGE_WITH ("\""
      "           0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F  "
          "0123456789ABCDEF\\n"
      "00000000  48 65 6c 6c 6f 20 68 65 78 20 77 6f 72 6c 64 21  "
          "Hello hex world!\\n"
      "00000010  20 77 30 30 74 00                                "
          " w00t.\"");
}

SCRIPT_TESTCASE (hexdump_supports_native_pointer_conforming_object)
{
  COMPILE_AND_LOAD_SCRIPT (
      "var obj = { handle: Memory.allocUtf8String(\"Hello hex world!\") };"
      "send(hexdump(obj, { length: 16 }));");
  EXPECT_SEND_MESSAGE_WITH ("\""
      "           0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F  "
          "0123456789ABCDEF\\n"
      "00000000  48 65 6c 6c 6f 20 68 65 78 20 77 6f 72 6c 64 21  "
          "Hello hex world!\"");
}

SCRIPT_TESTCASE (native_pointer_provides_is_null)
{
  COMPILE_AND_LOAD_SCRIPT (
      "send(ptr(\"0\").isNull());"
      "send(ptr(\"1337\").isNull());");
  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_SEND_MESSAGE_WITH ("false");
}

SCRIPT_TESTCASE (native_pointer_provides_arithmetic_operations)
{
  COMPILE_AND_LOAD_SCRIPT (
      "send(ptr(3).add(4).toInt32());"
      "send(ptr(7).sub(4).toInt32());"
      "send(ptr(6).and(3).toInt32());"
      "send(ptr(6).or(3).toInt32());"
      "send(ptr(6).xor(3).toInt32());"
      "send(ptr(63).shr(4).toInt32());"
      "send(ptr(1).shl(3).toInt32());");
  EXPECT_SEND_MESSAGE_WITH ("7");
  EXPECT_SEND_MESSAGE_WITH ("3");
  EXPECT_SEND_MESSAGE_WITH ("2");
  EXPECT_SEND_MESSAGE_WITH ("7");
  EXPECT_SEND_MESSAGE_WITH ("5");
  EXPECT_SEND_MESSAGE_WITH ("3");
  EXPECT_SEND_MESSAGE_WITH ("8");
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
  EXPECT_SEND_MESSAGE_WITH ("\"00 00 00 00\"");
  EXPECT_SEND_MESSAGE_WITH ("\"0a 00 00 00\"");
  EXPECT_SEND_MESSAGE_WITH ("\"1b 0a 00 00\"");
  EXPECT_SEND_MESSAGE_WITH ("\"b2 a1 00 00\"");
  EXPECT_SEND_MESSAGE_WITH ("\"c3 b2 a1 00\"");
  EXPECT_SEND_MESSAGE_WITH ("\"d4 c3 b2 a1\"");
# else
  EXPECT_SEND_MESSAGE_WITH ("\"00 00 00 00\"");
  EXPECT_SEND_MESSAGE_WITH ("\"00 00 00 0a\"");
  EXPECT_SEND_MESSAGE_WITH ("\"00 00 0a 1b\"");
  EXPECT_SEND_MESSAGE_WITH ("\"00 00 a1 b2\"");
  EXPECT_SEND_MESSAGE_WITH ("\"00 a1 b2 c3\"");
  EXPECT_SEND_MESSAGE_WITH ("\"a1 b2 c3 d4\"");
# endif
#else
# if G_BYTE_ORDER == G_LITTLE_ENDIAN
  EXPECT_SEND_MESSAGE_WITH ("\"00 00 00 00 00 00 00 00\"");
  EXPECT_SEND_MESSAGE_WITH ("\"0a 00 00 00 00 00 00 00\"");
  EXPECT_SEND_MESSAGE_WITH ("\"1b 0a 00 00 00 00 00 00\"");
  EXPECT_SEND_MESSAGE_WITH ("\"b2 a1 00 00 00 00 00 00\"");
  EXPECT_SEND_MESSAGE_WITH ("\"c3 b2 a1 00 00 00 00 00\"");
  EXPECT_SEND_MESSAGE_WITH ("\"d4 c3 b2 a1 00 00 00 00\"");
  EXPECT_SEND_MESSAGE_WITH ("\"b8 a7 f6 e5 d4 c3 b2 a1\"");
# else
  EXPECT_SEND_MESSAGE_WITH ("\"00 00 00 00 00 00 00 00\"");
  EXPECT_SEND_MESSAGE_WITH ("\"00 00 00 00 00 00 00 0a\"");
  EXPECT_SEND_MESSAGE_WITH ("\"00 00 00 00 00 00 0a 1b\"");
  EXPECT_SEND_MESSAGE_WITH ("\"00 00 00 00 00 00 a1 b2\"");
  EXPECT_SEND_MESSAGE_WITH ("\"00 00 00 00 00 a1 b2 c3\"");
  EXPECT_SEND_MESSAGE_WITH ("\"00 00 00 00 a1 b2 c3 d4\"");
  EXPECT_SEND_MESSAGE_WITH ("\"a1 b2 c3 d4 e5 f6 a7 b8\"");
# endif
#endif
}

SCRIPT_TESTCASE (native_pointer_can_be_constructed_from_64bit_value)
{
  COMPILE_AND_LOAD_SCRIPT (
      "send(ptr(0x1FFFFFFFF).equals(ptr(uint64(0x1FFFFFFFF))));"
      "send(ptr(0x2FFFFFFFF).equals(ptr(int64(0x2FFFFFFFF))));");
  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_SEND_MESSAGE_WITH ("true");
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

static gint64
gum_classify_timestamp (gint64 timestamp)
{
  if (timestamp < 0)
    return -1;
  else if (timestamp > 0)
    return 1;
  else
    return 0;
}

static guint64
gum_square (guint64 value)
{
  return value * value;
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

SCRIPT_TESTCASE (socket_connection_can_be_established)
{
  fixture->timeout = 10000;

  COMPILE_AND_LOAD_SCRIPT (
      "Socket.listen({"
      "  backlog: 1,"
      "})"
      ".then(function (listener) {"
      "  listener.accept()"
      "  .then(function (client) {"
      "    return client.input.readAll(5)"
      "    .then(function (data) {"
      "      send('server read', data);"
      "      client.close();"
      "      listener.close();"
      "    });"
      "  })"
      "  .catch(function (error) {"
      "    send('error: ' + error.message);"
      "  });"
      ""
      "  return Socket.connect({"
      "    family: 'ipv4',"
      "    host: 'localhost',"
      "    port: listener.port,"
      "  })"
      "  .then(function (connection) {"
      "    return connection.setNoDelay(true)"
      "    .then(function () {"
      "      return connection.output.writeAll([0x31, 0x33, 0x33, 0x37, 0x0a])"
      "      .then(function () {"
      "        return connection.close();"
      "      });"
      "    });"
      "  })"
      "  .catch(function (error) {"
      "    send('error: ' + error.message);"
      "  });"
      "})"
      ".catch(function (error) {"
      "  send('error: ' + error.message);"
      "});");
  EXPECT_SEND_MESSAGE_WITH_PAYLOAD_AND_DATA ("\"server read\"",
      "31 33 33 37 0a");

#ifdef G_OS_UNIX
  {
    const gchar * tmp_dir;

#ifdef HAVE_ANDROID
    tmp_dir = "/data/local/tmp";
#else
    tmp_dir = g_get_tmp_dir ();
#endif

    COMPILE_AND_LOAD_SCRIPT (
        "var getpid = new NativeFunction("
        "    Module.findExportByName(null, 'getpid'), 'int', []);"
        "var unlink = new NativeFunction("
        "    Module.findExportByName(null, 'unlink'), 'int', ['pointer']);"
        ""
        "Socket.listen({"
        "  type: 'path',"
        "  path: '%s/frida-gum-test-listener-' + getpid(),"
        "  backlog: 1,"
        "})"
        ".then(function (listener) {"
        "  listener.accept()"
        "  .then(function (client) {"
        "    return client.input.readAll(5)"
        "    .then(function (data) {"
        "      send('server read', data);"
        "      client.close();"
        "      listener.close();"
        "    });"
        "  })"
        "  .catch(function (error) {"
        "    send('error: ' + error.message);"
        "  });"
        ""
        "  return Socket.connect({"
        "    type: 'path',"
        "    path: listener.path,"
        "  })"
        "  .then(function (connection) {"
        "    unlink(Memory.allocUtf8String(listener.path));"
        "    return connection.output.writeAll([0x31, 0x33, 0x33, 0x37, 0x0a])"
        "    .then(function () {"
        "      return connection.close();"
        "    });"
        "  })"
        "  .catch(function (error) {"
        "    send('error: ' + error.message);"
        "  });"
        "})"
        ".catch(function (error) {"
        "  send('error: ' + error.message);"
        "});", tmp_dir);
    EXPECT_SEND_MESSAGE_WITH_PAYLOAD_AND_DATA ("\"server read\"",
        "31 33 33 37 0a");
  }
#endif
}

SCRIPT_TESTCASE (socket_type_can_be_inspected)
{
  int fd;
  struct sockaddr_in addr = { 0, };
  const guint port = 39876;

  fd = socket (AF_INET, SOCK_STREAM, 0);
  COMPILE_AND_LOAD_SCRIPT ("send(Socket.type(%d));", fd);
  EXPECT_SEND_MESSAGE_WITH ("\"tcp\"");
  addr.sin_family = AF_INET;
  addr.sin_port = GUINT16_TO_BE (port);
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
  GumThreadId test_thread_id;

  if (!g_test_slow ())
  {
    g_print ("<skipping, run in slow mode> ");
    return;
  }

  test_thread_id = gum_process_get_current_thread_id ();

  COMPILE_AND_LOAD_SCRIPT (
    "Stalker.follow(%" G_GSIZE_FORMAT ", {"
    "  events: {"
    "    call: true,"
    "    ret: false,"
    "    exec: false"
    "  },"
    "  onReceive: function (events) {"
    "    send('onReceive: ' + (events.byteLength > 0));"
    "  },"
    "  onCallSummary: function (summary) {"
    "    send('onCallSummary: ' + (Object.keys(summary).length > 0));"
    "  }"
    "});"
    "recv('stop', function (message) {"
    "  Stalker.unfollow(%" G_GSIZE_FORMAT ");"
    "});", test_thread_id, test_thread_id);
  g_usleep (1);
  EXPECT_NO_MESSAGES ();
  POST_MESSAGE ("{\"type\":\"stop\"}");
  EXPECT_SEND_MESSAGE_WITH ("\"onCallSummary: true\"");
  EXPECT_SEND_MESSAGE_WITH ("\"onReceive: true\"");
}

SCRIPT_TESTCASE (call_can_be_probed)
{
  GumThreadId test_thread_id;

  if (!g_test_slow ())
  {
    g_print ("<skipping, run in slow mode> ");
    return;
  }

  test_thread_id = gum_process_get_current_thread_id ();

  COMPILE_AND_LOAD_SCRIPT (
    "Stalker.addCallProbe(" GUM_PTR_CONST ", function (args) {"
    "  send(args[0].toInt32());"
    "});"
    "Stalker.follow(%" G_GSIZE_FORMAT ");"
    "recv('stop', function (message) {"
    "  Stalker.unfollow(%" G_GSIZE_FORMAT ");"
    "});"
    "send('ready');", target_function_int, test_thread_id, test_thread_id);
  EXPECT_SEND_MESSAGE_WITH ("\"ready\"");
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

SCRIPT_TESTCASE (process_page_size_is_available)
{
  COMPILE_AND_LOAD_SCRIPT ("send(Process.pageSize);");
  EXPECT_SEND_MESSAGE_WITH ("%d", gum_query_page_size ());
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

SCRIPT_TESTCASE (process_current_thread_id_is_available)
{
  COMPILE_AND_LOAD_SCRIPT ("send(typeof Process.getCurrentThreadId());");
  EXPECT_SEND_MESSAGE_WITH ("\"number\"");
}

SCRIPT_TESTCASE (process_threads_can_be_enumerated)
{
  if (RUNNING_ON_VALGRIND)
  {
    g_print ("<skipping, not compatible with Valgrind> ");
    return;
  }

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
  gboolean done = FALSE;
  GThread * thread_a, * thread_b;

  if (RUNNING_ON_VALGRIND)
  {
    g_print ("<skipping, not compatible with Valgrind> ");
    return;
  }

  thread_a = g_thread_new ("script-test-sleeping-dummy-a", sleeping_dummy,
      &done);
  thread_b = g_thread_new ("script-test-sleeping-dummy-b", sleeping_dummy,
      &done);

  COMPILE_AND_LOAD_SCRIPT ("send(Process.enumerateThreadsSync().length >= 2);");
  EXPECT_SEND_MESSAGE_WITH ("true");

  done = TRUE;
  g_thread_join (thread_b);
  g_thread_join (thread_a);
}

static gpointer
sleeping_dummy (gpointer data)
{
  volatile gboolean * done = (gboolean *) data;

  while (!(*done))
    g_thread_yield ();

  return NULL;
}

SCRIPT_TESTCASE (process_modules_can_be_enumerated)
{
  COMPILE_AND_LOAD_SCRIPT (
      "Process.enumerateModules({"
        "onMatch: function (module) {"
        "  send('onMatch');"
        "  send(typeof module.name === 'string');"
        "  send(typeof module.path === 'string');"
        "  send(module.base instanceof NativePointer);"
        "  send(typeof module.size === 'number');"
        "  send(JSON.stringify(module) !== \"{}\");"
        "  return 'stop';"
        "},"
        "onComplete: function () {"
        "  send('onComplete');"
        "}"
      "});");
  EXPECT_SEND_MESSAGE_WITH ("\"onMatch\"");
  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_SEND_MESSAGE_WITH ("\"onComplete\"");
}

SCRIPT_TESTCASE (process_modules_can_be_enumerated_synchronously)
{
  COMPILE_AND_LOAD_SCRIPT ("send(Process.enumerateModulesSync().length > 1);");
  EXPECT_SEND_MESSAGE_WITH ("true");
}

SCRIPT_TESTCASE (process_module_can_be_looked_up_from_address)
{
#ifndef HAVE_LINUX
  GModule * m;
  gpointer f;
  gboolean found;

  m = g_module_open (SYSTEM_MODULE_NAME, G_MODULE_BIND_LAZY);
  found = g_module_symbol (m, SYSTEM_MODULE_EXPORT, &f);
  g_assert (found);
  g_module_close (m);

  COMPILE_AND_LOAD_SCRIPT (
      "send(Process.findModuleByAddress(" GUM_PTR_CONST ") !== null);",
      f);
  EXPECT_SEND_MESSAGE_WITH ("true");

  COMPILE_AND_LOAD_SCRIPT (
      "send(Object.keys(Process.getModuleByAddress(" GUM_PTR_CONST
      ")).length > 0);",
      f);
  EXPECT_SEND_MESSAGE_WITH ("true");
#endif

  COMPILE_AND_LOAD_SCRIPT (
      "var someModule = Process.enumerateModulesSync()[1];"
      "var foundModule = Process.findModuleByAddress(someModule.base);"
      "send(foundModule !== null);"
      "send(foundModule.name === someModule.name);");
  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_NO_MESSAGES ();
}


SCRIPT_TESTCASE (process_module_can_be_looked_up_from_name)
{
  COMPILE_AND_LOAD_SCRIPT (
      "send(Process.findModuleByName('%s') !== null);",
      SYSTEM_MODULE_NAME);
  EXPECT_SEND_MESSAGE_WITH ("true");

  COMPILE_AND_LOAD_SCRIPT (
      "send(Object.keys(Process.getModuleByName('%s')).length > 0);",
      SYSTEM_MODULE_NAME);
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

SCRIPT_TESTCASE (process_ranges_can_be_enumerated_with_neighbors_coalesced)
{
  COMPILE_AND_LOAD_SCRIPT (
      "var a = Process.enumerateRangesSync('--x');"
      "var b = Process.enumerateRangesSync({"
        "protection: '--x',"
        "coalesce: true"
      "});"
      "send(b.length <= a.length);");
  EXPECT_SEND_MESSAGE_WITH ("true");
}

SCRIPT_TESTCASE (process_range_can_be_looked_up_from_address)
{
  GModule * m;
  gpointer f;
  gboolean found;

  m = g_module_open (SYSTEM_MODULE_NAME, G_MODULE_BIND_LAZY);
  found = g_module_symbol (m, SYSTEM_MODULE_EXPORT, &f);
  g_assert (found);
  g_module_close (m);

  COMPILE_AND_LOAD_SCRIPT (
      "send(Process.findRangeByAddress(" GUM_PTR_CONST ") !== null);",
      f);
  EXPECT_SEND_MESSAGE_WITH ("true");

  COMPILE_AND_LOAD_SCRIPT (
      "var someRange = Process.enumerateRangesSync('r-x')[1];"
      "var foundRange = Process.findRangeByAddress(someRange.base);"
      "send(foundRange !== null);"
      "send(foundRange.base.equals(someRange.base));");
  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_NO_MESSAGES ();

  COMPILE_AND_LOAD_SCRIPT (
      "send(Object.keys(Process.getRangeByAddress(" GUM_PTR_CONST
      ")).length > 0);",
      f);
  EXPECT_SEND_MESSAGE_WITH ("true");
}

#ifdef HAVE_DARWIN

SCRIPT_TESTCASE (process_malloc_ranges_can_be_enumerated)
{
  if (!g_test_slow ())
  {
    g_print ("<skipping, run in slow mode> ");
    return;
  }

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
  if (!g_test_slow ())
  {
    g_print ("<skipping, run in slow mode> ");
    return;
  }

  COMPILE_AND_LOAD_SCRIPT (
      "send(Process.enumerateMallocRangesSync().length > 1);");
  EXPECT_SEND_MESSAGE_WITH ("true");
}

#endif

SCRIPT_TESTCASE (module_imports_can_be_enumerated)
{
  COMPILE_AND_LOAD_SCRIPT (
      "Module.enumerateImports(\"" GUM_TESTS_MODULE_NAME "\", {"
        "onMatch: function (imp) {"
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

SCRIPT_TESTCASE (module_imports_can_be_enumerated_synchronously)
{
  COMPILE_AND_LOAD_SCRIPT (
      "send(Module.enumerateImportsSync(\"" GUM_TESTS_MODULE_NAME "\")"
      ".length > 1);");
  EXPECT_SEND_MESSAGE_WITH ("true");
}

SCRIPT_TESTCASE (module_exports_can_be_enumerated)
{
  COMPILE_AND_LOAD_SCRIPT (
      "Module.enumerateExports(\"%s\", {"
        "onMatch: function (exp) {"
        "  send('onMatch');"
        "  send(typeof exp.type === 'string');"
        "  send(typeof exp.name === 'string');"
        "  send(exp.address instanceof NativePointer);"
        "  send(JSON.stringify(exp) !== \"{}\");"
        "  return 'stop';"
        "},"
        "onComplete: function () {"
        "  send('onComplete');"
        "}"
      "});", SYSTEM_MODULE_NAME);
  EXPECT_SEND_MESSAGE_WITH ("\"onMatch\"");
  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_SEND_MESSAGE_WITH ("true");
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

SCRIPT_TESTCASE (api_resolver_can_be_used_to_find_functions)
{
#ifdef G_OS_WIN32
  const gchar * query = "exports:*!_open*";
#else
  const gchar * query = "exports:*!open*";
#endif

  COMPILE_AND_LOAD_SCRIPT (
      "var resolver = new ApiResolver('module');"
      "resolver.enumerateMatches('%s', {"
      "  onMatch: function (match) {"
      "    send('onMatch');"
      "    return 'stop';"
      "  },"
      "  onComplete: function () {"
      "    send('onComplete');"
      "  }"
      "});",
      query);
  EXPECT_SEND_MESSAGE_WITH ("\"onMatch\"");
  EXPECT_SEND_MESSAGE_WITH ("\"onComplete\"");

  COMPILE_AND_LOAD_SCRIPT (
      "var resolver = new ApiResolver('module');"
      "var matches = resolver.enumerateMatchesSync('%s');"
      "send(matches.length > 0);",
      query);
  EXPECT_SEND_MESSAGE_WITH ("true");
}

SCRIPT_TESTCASE (invalid_script_should_return_null)
{
  GError * err = NULL;

  g_assert (gum_script_backend_create_sync (fixture->backend, "testcase", "'",
      NULL, NULL) == NULL);

  g_assert (gum_script_backend_create_sync (fixture->backend, "testcase", "'",
      NULL, &err) == NULL);
  g_assert (err != NULL);
  g_assert (g_str_has_prefix (err->message, "Script(line 1): SyntaxError: "));
}

SCRIPT_TESTCASE (array_buffer_can_be_created)
{
  COMPILE_AND_LOAD_SCRIPT ("new ArrayBuffer(16);");
  EXPECT_NO_MESSAGES ();
}

SCRIPT_TESTCASE (rpc_can_be_performed)
{
  COMPILE_AND_LOAD_SCRIPT (
      "rpc.exports.foo = function (a, b) {"
          "var result = a + b;"
          "if (result >= 0)"
              "return result;"
          "else "
              "throw new Error('No');"
      "};"
      "rpc.exports.bar = function (a, b) {"
          "return new Promise(function (resolve, reject) {"
              "var result = a + b;"
              "if (result >= 0)"
                  "resolve(result);"
              "else "
                  "reject(new Error('Nope'));"
          "});"
      "};"
      "rpc.exports.badger = function () {"
          "var buf = Memory.allocUtf8String(\"Yo\");"
          "return Memory.readByteArray(buf, 2);"
      "};");
  EXPECT_NO_MESSAGES ();

  POST_MESSAGE ("[\"frida:rpc\",1,\"list\"]");
  EXPECT_SEND_MESSAGE_WITH ("[\"frida:rpc\",1,\"ok\","
      "[\"foo\",\"bar\",\"badger\"]]");

  POST_MESSAGE ("[\"frida:rpc\",2,\"call\",\"foo\",[1,2]]");
  EXPECT_SEND_MESSAGE_WITH ("[\"frida:rpc\",2,\"ok\",3]");

  POST_MESSAGE ("[\"frida:rpc\",3,\"call\",\"foo\",[1,-2]]");
  EXPECT_SEND_MESSAGE_WITH_PREFIX ("[\"frida:rpc\",3,\"error\",\"No\",");

  POST_MESSAGE ("[\"frida:rpc\",4,\"call\",\"bar\",[3,4]]");
  EXPECT_SEND_MESSAGE_WITH ("[\"frida:rpc\",4,\"ok\",7]");

  POST_MESSAGE ("[\"frida:rpc\",5,\"call\",\"bar\",[3,-4]]");
  EXPECT_SEND_MESSAGE_WITH_PREFIX ("[\"frida:rpc\",5,\"error\",\"Nope\",");

  POST_MESSAGE ("[\"frida:rpc\",6,\"call\",\"baz\",[]]");
  EXPECT_SEND_MESSAGE_WITH ("[\"frida:rpc\",6,\"error\","
      "\"Unable to find method 'baz'\"]");

  POST_MESSAGE ("[\"frida:rpc\",7,\"call\",\"badger\",[]]");
  EXPECT_SEND_MESSAGE_WITH_PAYLOAD_AND_DATA ("[\"frida:rpc\",7,\"ok\",{}]",
      "59 6f");
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

SCRIPT_TESTCASE (message_can_be_received_with_data)
{
  const guint8 data_to_send[2] = { 0x13, 0x37 };
  GBytes * bytes;

  COMPILE_AND_LOAD_SCRIPT (
      "recv(function (message, data) {"
      "  if (message.type === 'ping')"
      "    send('pong', data);"
      "});");
  EXPECT_NO_MESSAGES ();

  bytes = g_bytes_new_static (data_to_send, sizeof (data_to_send));
  gum_script_post (fixture->script, "{\"type\":\"ping\"}", bytes);
  g_bytes_unref (bytes);

  EXPECT_SEND_MESSAGE_WITH_PAYLOAD_AND_DATA ("\"pong\"", "13 37");
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

SCRIPT_TESTCASE (recv_can_be_waited_for_from_an_application_thread)
{
  GThread * worker_thread;
  GumInvokeTargetContext ctx;

  COMPILE_AND_LOAD_SCRIPT (
      "Interceptor.attach(" GUM_PTR_CONST ", {"
      "  onEnter: function (args) {"
      "    var op = recv('poke', function (pokeMessage) {"
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

SCRIPT_TESTCASE (recv_can_be_waited_for_from_our_js_thread)
{
  /*
   * We do the wait() in a setTimeout() as our test fixture loads the
   * script synchronously...
   */
  COMPILE_AND_LOAD_SCRIPT (
      "setTimeout(function () {"
      "  var op = recv('poke', function (pokeMessage) {"
      "    send('pokeBack');"
      "  });"
      "  op.wait();"
      "  send('pokeReceived');"
      "}, 0);", target_function_int);
  EXPECT_NO_MESSAGES ();

  POST_MESSAGE ("{\"type\":\"poke\"}");
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

  COMPILE_AND_LOAD_SCRIPT (
      "setTimeout(function (value) {"
      "  send(value);"
      "}, uint64(20), 1338);");
  EXPECT_NO_MESSAGES ();

  g_usleep (25000);
  EXPECT_SEND_MESSAGE_WITH ("1338");

  COMPILE_AND_LOAD_SCRIPT (
      "setTimeout(function () {"
      "  send(1227);"
      "});");
  g_usleep (10000);
  EXPECT_SEND_MESSAGE_WITH ("1227");
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
      "setInterval(function (value) {"
      "  send(value);"
      "}, 20, 1337);");
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

SCRIPT_TESTCASE (callback_can_be_scheduled)
{
  COMPILE_AND_LOAD_SCRIPT (
      "setImmediate(function () {"
      "  send(1337);"
      "});");
  EXPECT_SEND_MESSAGE_WITH ("1337");
  EXPECT_NO_MESSAGES ();
}

SCRIPT_TESTCASE (callback_can_be_scheduled_from_a_scheduled_callback)
{
  COMPILE_AND_LOAD_SCRIPT (
      "setImmediate(function () {"
      "  send(1337);"
      "  Script.nextTick(function () { send(1338); });"
      "  setImmediate(function () { send(1339); });"
      "});");
  EXPECT_SEND_MESSAGE_WITH ("1337");
  EXPECT_SEND_MESSAGE_WITH ("1338");
  EXPECT_SEND_MESSAGE_WITH ("1339");
  EXPECT_NO_MESSAGES ();
}

SCRIPT_TESTCASE (callback_can_be_cancelled)
{
  COMPILE_AND_LOAD_SCRIPT (
      "var id = setImmediate(function () {"
      "  send(1337);"
      "});"
      "clearImmediate(id);");
  g_usleep (25000);
  EXPECT_NO_MESSAGES ();
}

SCRIPT_TESTCASE (callback_can_be_scheduled_on_next_tick)
{
  COMPILE_AND_LOAD_SCRIPT (
      "Script.nextTick(send, 1337, [0x13, 0x37, 0x0a]);");
  EXPECT_SEND_MESSAGE_WITH_PAYLOAD_AND_DATA ("1337", "13 37 0a");
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

  COMPILE_AND_LOAD_SCRIPT (
      "Interceptor.attach(" GUM_PTR_CONST ", {"
      "  onLeave: function (retval) {"
      "    retval.replace({ handle: ptr(1338) });"
      "  }"
      "});", target_function_int);
  EXPECT_NO_MESSAGES ();
  g_assert_cmpint (target_function_int (7), ==, 1338);
  EXPECT_NO_MESSAGES ();

  COMPILE_AND_LOAD_SCRIPT (
      "var savedRetval = null;"
      "Interceptor.attach(" GUM_PTR_CONST  ", {"
      "  onLeave: function (retval) {"
      "    savedRetval = retval;"
      "  }"
      "});"
      "recv('try-replace', function () {"
      "  savedRetval.replace(1337);"
      "});", target_function_int);
  EXPECT_NO_MESSAGES ();
  target_function_int (7);
  EXPECT_NO_MESSAGES ();
  POST_MESSAGE ("{\"type\":\"try-replace\"}");
  EXPECT_ERROR_MESSAGE_WITH (ANY_LINE_NUMBER, "Error: invalid operation");
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
  COMPILE_AND_LOAD_SCRIPT (
      "Interceptor.attach(" GUM_PTR_CONST ", {"
      "  onLeave: function () {"
      "    send(this.context." GUM_RETURN_VALUE_REGISTER_NAME ".toInt32());"
      "  }"
      "});", target_function_int);

  EXPECT_NO_MESSAGES ();
  target_function_int (42);
  EXPECT_SEND_MESSAGE_WITH ("1890");
}

SCRIPT_TESTCASE (register_can_be_written)
{
  COMPILE_AND_LOAD_SCRIPT (
      "Interceptor.attach(" GUM_PTR_CONST ", {"
      "  onLeave: function () {"
      "    this.context." GUM_RETURN_VALUE_REGISTER_NAME " = ptr(1337);"
      "  }"
      "});", target_function_int);

  EXPECT_NO_MESSAGES ();
  g_assert_cmpint (target_function_int (42), ==, 1337);
  EXPECT_NO_MESSAGES ();
}

SCRIPT_TESTCASE (system_error_can_be_read_from_interceptor_listener)
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

SCRIPT_TESTCASE (system_error_can_be_read_from_replacement_function)
{
  GumInterceptor * interceptor;

  interceptor = gum_interceptor_obtain ();

  /* Replacement should be used regardless: */
  gum_interceptor_ignore_current_thread (interceptor);

#ifdef G_OS_WIN32
  COMPILE_AND_LOAD_SCRIPT (
      "Interceptor.replace(" GUM_PTR_CONST ","
      "    new NativeCallback(function (arg) {"
      "  send(this.lastError);"
      "  return 0;"
      "}, 'int', ['int']));", target_function_int);

  SetLastError (13);
  target_function_int (7);
  SetLastError (37);
  target_function_int (7);
#else
  COMPILE_AND_LOAD_SCRIPT (
      "Interceptor.replace(" GUM_PTR_CONST ","
      "    new NativeCallback(function (arg) {"
      "  send(this.errno);"
      "  return 0;"
      "}, 'int', ['int']));", target_function_int);

  errno = 13;
  target_function_int (7);
  errno = 37;
  target_function_int (7);
#endif
  EXPECT_SEND_MESSAGE_WITH ("13");
  EXPECT_SEND_MESSAGE_WITH ("37");

  gum_interceptor_unignore_current_thread (interceptor);

  g_object_unref (interceptor);
}

SCRIPT_TESTCASE (system_error_can_be_replaced_from_interceptor_listener)
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

SCRIPT_TESTCASE (system_error_can_be_replaced_from_replacement_function)
{
#ifdef G_OS_WIN32
  COMPILE_AND_LOAD_SCRIPT (
      "Interceptor.replace(" GUM_PTR_CONST ","
      "    new NativeCallback(function (arg) {"
      "  this.lastError = 1337;"
      "  return 0;"
      "}, 'int', ['int']));", target_function_int);

  SetLastError (42);
  target_function_int (7);
  g_assert_cmpint (GetLastError (), ==, 1337);
#else
  COMPILE_AND_LOAD_SCRIPT (
      "Interceptor.replace(" GUM_PTR_CONST ","
      "    new NativeCallback(function (arg) {"
      "  this.errno = 1337;"
      "  return 0;"
      "}, 'int', ['int']));", target_function_int);

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

SCRIPT_TESTCASE (invocations_provide_thread_id)
{
  guint i;

  COMPILE_AND_LOAD_SCRIPT (
      "Interceptor.attach(" GUM_PTR_CONST ", {"
      "  onEnter: function (args) {"
      "    send(this.threadId);"
      "  },"
      "  onLeave: function (retval) {"
      "    send(this.threadId);"
      "  }"
      "});",
      target_function_int);
  EXPECT_NO_MESSAGES ();

  target_function_int (7);
  for (i = 0; i != 2; i++)
  {
    TestScriptMessageItem * item;
    gint id;

    item = test_script_fixture_pop_message (fixture);
    id = 0;
    sscanf (item->message, "{\"type\":\"send\",\"payload\":%d}", &id);
    g_assert (id != 0);
    test_script_message_item_free (item);
    g_assert_cmpint (id, ==, gum_process_get_current_thread_id ());
  }
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
  if (RUNNING_ON_VALGRIND)
  {
    g_print ("<skipping, not compatible with Valgrind> ");
    return;
  }

  COMPILE_AND_LOAD_SCRIPT (
      "var mode = '%s';"
      "Interceptor.attach(" GUM_PTR_CONST ", {"
      "  onEnter: function (args) {"
      "    send(Thread.backtrace(this.context, Backtracer.ACCURATE)"
      "        .length > 0);"
      "  },"
      "  onLeave: function (retval) {"
      "    if (mode === 'slow')"
      "      send(Thread.backtrace(this.context, Backtracer.FUZZY).length > 0);"
      "  }"
      "});",
      g_test_slow () ? "slow" : "fast",
      target_function_int);

  EXPECT_NO_MESSAGES ();
  target_function_int (7);
  EXPECT_SEND_MESSAGE_WITH ("true");
  if (g_test_slow ())
    EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_NO_MESSAGES ();
}

SCRIPT_TESTCASE (invocations_provide_context_serializable_to_json)
{
  COMPILE_AND_LOAD_SCRIPT (
      "Interceptor.attach(" GUM_PTR_CONST ", {"
      "  onEnter: function (args) {"
      "    send(JSON.stringify(this.context) !== \"{}\");"
      "  },"
      "  onLeave: function (retval) {"
      "    send(JSON.stringify(this.context) !== \"{}\");"
      "  }"
      "});",
      target_function_int);

  EXPECT_NO_MESSAGES ();
  target_function_int (7);
  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_NO_MESSAGES ();
}

SCRIPT_TESTCASE (listener_can_be_detached)
{
  COMPILE_AND_LOAD_SCRIPT (
      "var firstListener, secondListener;"
      ""
      "firstListener = Interceptor.attach(" GUM_PTR_CONST ", {"
      "  onEnter: function (args) {"
      "    send(1);"
      "    firstListener.detach();"
      "  },"
      "  onLeave: function (retval) {"
      "    send(2);"
      "  }"
      "});"
      ""
      "secondListener = Interceptor.attach(" GUM_PTR_CONST ", {"
      "  onEnter: function (args) {"
      "    send(3);"
      "  },"
      "  onLeave: function (retval) {"
      "    send(4);"
      "    secondListener.detach();"
      "  }"
      "});",
      target_function_int, target_function_int);

  EXPECT_NO_MESSAGES ();
  target_function_int (42);
  EXPECT_SEND_MESSAGE_WITH ("1");
  EXPECT_SEND_MESSAGE_WITH ("3");
  EXPECT_SEND_MESSAGE_WITH ("4");
  EXPECT_NO_MESSAGES ();
  target_function_int (42);
  EXPECT_NO_MESSAGES ();
}

SCRIPT_TESTCASE (listener_can_be_detached_by_destruction_mid_call)
{
  const guint repeats = 10;
  guint i;
  TestTrigger trigger;

  g_mutex_init (&trigger.mutex);
  g_cond_init (&trigger.cond);

  for (i = 0; i != repeats; i++)
  {
    GThread * invoker_thread;

    g_mutex_lock (&trigger.mutex);
    trigger.ready = FALSE;
    trigger.fired = FALSE;
    g_mutex_unlock (&trigger.mutex);

    COMPILE_AND_LOAD_SCRIPT (
        "Interceptor.attach(" GUM_PTR_CONST ", {"
        "  onEnter: function (args) {"
        "  },"
        "  onLeave: function (retval) {"
        "  }"
        "});",
        target_function_trigger);

    invoker_thread = g_thread_new ("script-invoker-thread",
        invoke_target_function_trigger, &trigger);

    g_mutex_lock (&trigger.mutex);
    while (!trigger.ready)
      g_cond_wait (&trigger.cond, &trigger.mutex);
    g_mutex_unlock (&trigger.mutex);

    g_mutex_lock (&trigger.mutex);
    trigger.fired = TRUE;
    g_cond_signal (&trigger.cond);
    g_mutex_unlock (&trigger.mutex);

    UNLOAD_SCRIPT ();

    g_thread_join (invoker_thread);
  }

  g_cond_clear (&trigger.cond);
  g_mutex_clear (&trigger.mutex);
}

static gpointer
invoke_target_function_trigger (gpointer data)
{
  TestTrigger * trigger = (TestTrigger *) data;

  target_function_trigger (trigger);

  return NULL;
}

SCRIPT_TESTCASE (all_listeners_can_be_detached)
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
      "Interceptor.replace(" GUM_PTR_CONST ","
      "    new NativeCallback(function (arg) {"
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

SCRIPT_TESTCASE (function_can_be_replaced_and_called_immediately)
{
  COMPILE_AND_LOAD_SCRIPT (
      "var address = " GUM_PTR_CONST ";"
      "Interceptor.replace(address,"
      "    new NativeCallback(function (arg) {"
      "  send(arg);"
      "  return 1337;"
      "}, 'int', ['int']));"
      "var f = new NativeFunction(address, 'int', ['int']);"
      "f(7);"
      "Interceptor.flush();"
      "f(8);",
      target_function_int);
  EXPECT_SEND_MESSAGE_WITH ("8");
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

SCRIPT_TESTCASE (replaced_function_should_have_invocation_context)
{
  COMPILE_AND_LOAD_SCRIPT (
      "Interceptor.replace(" GUM_PTR_CONST ", new NativeCallback(function (arg) {"
      "  send(this.returnAddress instanceof NativePointer);"
      "  return 0;"
      "}, 'int', ['int']));",
      target_function_int);

  EXPECT_NO_MESSAGES ();
  target_function_int (7);
  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_NO_MESSAGES ();
}

SCRIPT_TESTCASE (instructions_can_be_probed)
{
  COMPILE_AND_LOAD_SCRIPT (
      "Interceptor.attach(" GUM_PTR_CONST ", function () {"
      "  send(!!this.context);"
      "});", target_function_int);

  EXPECT_NO_MESSAGES ();

  target_function_int (42);
  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_NO_MESSAGES ();

  target_function_int (42);
  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_NO_MESSAGES ();
}

SCRIPT_TESTCASE (interceptor_handles_invalid_arguments)
{
  if (RUNNING_ON_VALGRIND)
  {
    g_print ("<skipping, not compatible with Valgrind> ");
    return;
  }

  COMPILE_AND_LOAD_SCRIPT (
      "Interceptor.attach(ptr(\"0x1\"), {"
      "  onEnter: function (args) {"
      "  }"
      "});");
  EXPECT_ERROR_MESSAGE_WITH (ANY_LINE_NUMBER,
      "Error: access violation accessing 0x1");

  COMPILE_AND_LOAD_SCRIPT (
      "Interceptor.replace(ptr(\"0x1\"), new NativeCallback(function (arg) {"
      "}, 'void', []));");
  EXPECT_ERROR_MESSAGE_WITH (ANY_LINE_NUMBER,
      "Error: access violation accessing 0x1");
}

SCRIPT_TESTCASE (interceptor_on_enter_performance)
{
  COMPILE_AND_LOAD_SCRIPT (
      "Interceptor.attach(" GUM_PTR_CONST ", {"
      "  onEnter: function (args) {"
      "  }"
      "});", target_function_int);

#if 1
  measure_target_function_int_overhead ();
#else
  while (TRUE)
    target_function_int (7);
#endif
}

SCRIPT_TESTCASE (interceptor_on_leave_performance)
{
  COMPILE_AND_LOAD_SCRIPT (
      "Interceptor.attach(" GUM_PTR_CONST ", {"
      "  onLeave: function (retval) {"
      "  }"
      "});", target_function_int);

#if 1
  measure_target_function_int_overhead ();
#else
  while (TRUE)
    target_function_int (7);
#endif
}

SCRIPT_TESTCASE (interceptor_on_enter_and_leave_performance)
{
  COMPILE_AND_LOAD_SCRIPT (
      "Interceptor.attach(" GUM_PTR_CONST ", {"
      "  onEnter: function (args) {"
      "  },"
      "  onLeave: function (retval) {"
      "  }"
      "});", target_function_int);

#if 1
  measure_target_function_int_overhead ();
#else
  while (TRUE)
    target_function_int (7);
#endif
}

static void
measure_target_function_int_overhead (void)
{
  GTimer * timer;
  guint measurement[1000], i, t_min, t_max, t_total, t_avg;

  timer = g_timer_new ();

  for (i = 0; i != G_N_ELEMENTS (measurement); i++)
  {
    target_function_int (7);
  }

  for (i = 0; i != G_N_ELEMENTS (measurement); i++)
  {
    gdouble elapsed;

    g_timer_reset (timer);
    target_function_int (7);
    elapsed = g_timer_elapsed (timer, NULL);

    measurement[i] = elapsed * G_USEC_PER_SEC;
  }

  t_min = G_MAXUINT;
  t_max = 0;
  t_total = 0;
  for (i = 0; i != G_N_ELEMENTS (measurement); i++)
  {
    guint m = measurement[i];

    t_min = MIN (m, t_min);
    t_max = MAX (m, t_max);
    t_total += m;
  }
  t_avg = t_total / G_N_ELEMENTS (measurement);

  g_print ("min=%u max=%u avg=%u ", t_min, t_max, t_avg);

  g_timer_destroy (timer);
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

  COMPILE_AND_LOAD_SCRIPT (
      "Memory.scan(" GUM_PTR_CONST ", uint64(7), '13 37', {"
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

SCRIPT_TESTCASE (memory_can_be_scanned_synchronously)
{
  guint8 haystack[] = { 0x01, 0x02, 0x13, 0x37, 0x03, 0x13, 0x37 };

  COMPILE_AND_LOAD_SCRIPT (
      "Memory.scanSync(" GUM_PTR_CONST ", 7, '13 37')"
      ".forEach(function (match) {"
      "  send('match offset=' + match.address.sub(" GUM_PTR_CONST
           ").toInt32() + ' size=' + match.size);"
      "});"
      "send('done');",
      haystack, haystack);
  EXPECT_SEND_MESSAGE_WITH ("\"match offset=2 size=2\"");
  EXPECT_SEND_MESSAGE_WITH ("\"match offset=5 size=2\"");
  EXPECT_SEND_MESSAGE_WITH ("\"done\"");

  COMPILE_AND_LOAD_SCRIPT (
      "Memory.scanSync(" GUM_PTR_CONST ", uint64(7), '13 37')"
      ".forEach(function (match) {"
      "  send('match offset=' + match.address.sub(" GUM_PTR_CONST
           ").toInt32() + ' size=' + match.size);"
      "});"
      "send('done');",
      haystack, haystack);
  EXPECT_SEND_MESSAGE_WITH ("\"match offset=2 size=2\"");
  EXPECT_SEND_MESSAGE_WITH ("\"match offset=5 size=2\"");
  EXPECT_SEND_MESSAGE_WITH ("\"done\"");
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
  if (RUNNING_ON_VALGRIND)
  {
    g_print ("<skipping, not compatible with Valgrind> ");
    return;
  }

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
  EXPECT_SEND_MESSAGE_WITH ("\"onError: access violation accessing 0x530\"");
  EXPECT_SEND_MESSAGE_WITH ("\"onComplete\"");

  COMPILE_AND_LOAD_SCRIPT (
      "try {"
        "Memory.scanSync(ptr(\"1328\"), 7, '13 37');"
      "} catch (e) {"
        "send(e.message);"
      "}");
  EXPECT_SEND_MESSAGE_WITH ("\"access violation accessing 0x530\"");
}

#ifdef G_OS_WIN32

SCRIPT_TESTCASE (memory_access_can_be_monitored)
{
  volatile guint8 * a, * b;
  guint page_size;

  if (GUM_DUK_IS_SCRIPT_BACKEND (fixture->backend))
  {
    g_print ("<skipping, not yet implemented in the Duktape runtime> ");
    return;
  }

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
  TestScriptMessageItem * item;
  gsize p;

  COMPILE_AND_LOAD_SCRIPT (
      "var p = Memory.alloc(8);"
      "Memory.writePointer(p, ptr(\"1337\"));"
      "send(Memory.readPointer(p).toInt32() === 1337);");
  EXPECT_SEND_MESSAGE_WITH ("true");

  COMPILE_AND_LOAD_SCRIPT (
      "var p = Memory.alloc(uint64(8));"
      "Memory.writePointer(p, ptr(\"1337\"));"
      "send(Memory.readPointer(p).toInt32() === 1337);");
  EXPECT_SEND_MESSAGE_WITH ("true");

  COMPILE_AND_LOAD_SCRIPT (
      "var p = Memory.alloc(Process.pageSize);"
      "send(p);");
  item = test_script_fixture_pop_message (fixture);
  p = 0;
  sscanf (item->message, "{\"type\":\"send\",\"payload\":"
      "\"0x%" G_GSIZE_MODIFIER "x\"}", &p);
  g_assert (p != 0);
  test_script_message_item_free (item);
  g_assert_cmpuint (p & (gum_query_page_size () - 1), ==, 0);

  COMPILE_AND_LOAD_SCRIPT(
      "var p = Memory.alloc(5);"
      "send('p', Memory.readByteArray(p, 5));");
  EXPECT_SEND_MESSAGE_WITH_PAYLOAD_AND_DATA("\"p\"", "00 00 00 00 00");
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
      "Memory.copy(" GUM_PTR_CONST ".add(3), " GUM_PTR_CONST ", uint64(2));",
      to, from);
  g_assert_cmphex (to[0], ==, 'H');
  g_assert_cmphex (to[1], ==, 'e');
  g_assert_cmphex (to[2], ==, 'i');
  g_assert_cmphex (to[3], ==, 'H');
  g_assert_cmphex (to[4], ==, 'e');

  if (!RUNNING_ON_VALGRIND)
  {
    COMPILE_AND_LOAD_SCRIPT (
        "Memory.copy(" GUM_PTR_CONST ", ptr(\"1337\"), 1);", to);
    EXPECT_ERROR_MESSAGE_WITH (1, "Error: access violation accessing 0x539");
  }
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

  COMPILE_AND_LOAD_SCRIPT (
      "var p = Memory.dup(" GUM_PTR_CONST ", uint64(2));"
      "Memory.writeU8(p, 0x12);"
      "send('p', Memory.readByteArray(p, 2));"
      "send('buf', Memory.readByteArray(" GUM_PTR_CONST ", 2));",
      buf, buf);
  EXPECT_SEND_MESSAGE_WITH_PAYLOAD_AND_DATA ("\"p\"", "12 37");
  EXPECT_SEND_MESSAGE_WITH_PAYLOAD_AND_DATA ("\"buf\"", "13 37");
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
  UNLOAD_SCRIPT ();

  gum_try_read_and_write_at (buf, 0, &exception_on_read, &exception_on_write);
  g_assert (!exception_on_read);
  g_assert (exception_on_write);

  COMPILE_AND_LOAD_SCRIPT (
      "send(Memory.protect(" GUM_PTR_CONST ", uint64(1), '---'));",
      buf, gum_query_page_size ());
  EXPECT_SEND_MESSAGE_WITH ("true");

  /* avoid overlapping signal handlers */
  UNLOAD_SCRIPT ();

  gum_try_read_and_write_at (buf, 0, &exception_on_read, &exception_on_write);
  g_assert (exception_on_read);
  g_assert (exception_on_write);

  gum_free_pages (buf);
}

SCRIPT_TESTCASE (code_can_be_patched)
{
  guint8 * code;

  code = gum_alloc_n_pages (1, GUM_PAGE_RW);
  code[7] = 0xc3;
  gum_mprotect (code, gum_query_page_size (), GUM_PAGE_RX);

  COMPILE_AND_LOAD_SCRIPT ("Memory.patchCode(" GUM_PTR_CONST ", 1, "
      "function (ptr) {"
          "Memory.writeU8(ptr, 0x90);"
      "});", code + 7);
  g_assert_cmphex (code[7], ==, 0x90);

  gum_free_pages (code);
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
  COMPILE_AND_LOAD_SCRIPT (
      "var value = Memory.readS64(" GUM_PTR_CONST ");"
      "send(value instanceof Int64);"
      "send(value);",
      &val);
  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_SEND_MESSAGE_WITH ("\"-1201239876783\"");
}

SCRIPT_TESTCASE (s64_can_be_written)
{
  gint64 val = 0;
  COMPILE_AND_LOAD_SCRIPT ("Memory.writeS64(" GUM_PTR_CONST
      ", new Int64(\"-1201239876783\"));", &val);
  g_assert_cmpint (val, ==, G_GINT64_CONSTANT (-1201239876783));
}

SCRIPT_TESTCASE (u64_can_be_read)
{
  guint64 val = G_GUINT64_CONSTANT (1201239876783);
  COMPILE_AND_LOAD_SCRIPT (
      "var value = Memory.readU64(" GUM_PTR_CONST ");"
      "send(value instanceof UInt64);"
      "send(value);",
      &val);
  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_SEND_MESSAGE_WITH ("\"1201239876783\"");
}

SCRIPT_TESTCASE (u64_can_be_written)
{
  gint64 val = 0;
  COMPILE_AND_LOAD_SCRIPT ("Memory.writeU64(" GUM_PTR_CONST
      ", new UInt64(\"1201239876783\"));", &val);
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

  COMPILE_AND_LOAD_SCRIPT ("Memory.writeShort(" GUM_PTR_CONST
    ", int64(-1234));", &val);
  g_assert_cmpint (val, ==, -1234);
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

  COMPILE_AND_LOAD_SCRIPT ("Memory.writeUShort(" GUM_PTR_CONST
      ", uint64(1234));", &val);
  g_assert_cmpint (val, ==, 1234);
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
  EXPECT_SEND_MESSAGE_WITH ("\"-123\"");
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
  EXPECT_SEND_MESSAGE_WITH ("\"4294967295\"");
}

SCRIPT_TESTCASE (ulong_can_be_written)
{
  unsigned long val = 0;
  COMPILE_AND_LOAD_SCRIPT ("Memory.writeULong(" GUM_PTR_CONST ", 4294967295);",
    &val);
  g_assert_cmpint (val, ==, 4294967295);
}

SCRIPT_TESTCASE (float_can_be_read)
{
  float val = 123.456f;
  COMPILE_AND_LOAD_SCRIPT ("send(Math.abs(Memory.readFloat(" GUM_PTR_CONST
      ") - 123.456) < 0.00001);", &val);
  EXPECT_SEND_MESSAGE_WITH ("true");
}

SCRIPT_TESTCASE (float_can_be_written)
{
  float val = 0.f;
  COMPILE_AND_LOAD_SCRIPT ("Memory.writeFloat(" GUM_PTR_CONST ", 123.456);",
      &val);
  g_assert_cmpfloat (ABS (val - 123.456f), <, 0.00001f);
}

SCRIPT_TESTCASE (double_can_be_read)
{
  double val = 123.456;
  COMPILE_AND_LOAD_SCRIPT ("send(Math.abs(Memory.readDouble(" GUM_PTR_CONST
      ") - 123.456)  < 0.00001);", &val);
  EXPECT_SEND_MESSAGE_WITH ("true");
}

SCRIPT_TESTCASE (double_can_be_written)
{
  double val = 0.0;
  COMPILE_AND_LOAD_SCRIPT ("Memory.writeDouble(" GUM_PTR_CONST ", 123.456);",
      &val);
  g_assert_cmpfloat (ABS (val - 123.456), <, 0.00001);
}

SCRIPT_TESTCASE (byte_array_can_be_read)
{
  guint8 buf[3] = { 0x13, 0x37, 0x42 };
  COMPILE_AND_LOAD_SCRIPT (
      "var buffer = Memory.readByteArray(" GUM_PTR_CONST ", 3);"
      "send('badger', buffer);"
      "send('badger', Memory.readByteArray(" GUM_PTR_CONST ", int64(3)));"
      "send('badger', Memory.readByteArray(" GUM_PTR_CONST ", uint64(3)));"
      "var emptyBuffer = Memory.readByteArray(" GUM_PTR_CONST ", 0);"
      "send('snake', emptyBuffer);"
      "send(buffer instanceof ArrayBuffer);"
      "send(emptyBuffer instanceof ArrayBuffer);",
      buf, buf, buf, buf);
  EXPECT_SEND_MESSAGE_WITH_PAYLOAD_AND_DATA ("\"badger\"", "13 37 42");
  EXPECT_SEND_MESSAGE_WITH_PAYLOAD_AND_DATA ("\"badger\"", "13 37 42");
  EXPECT_SEND_MESSAGE_WITH_PAYLOAD_AND_DATA ("\"badger\"", "13 37 42");
  EXPECT_SEND_MESSAGE_WITH_PAYLOAD_AND_DATA ("\"snake\"", "");
  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_SEND_MESSAGE_WITH ("true");
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

  COMPILE_AND_LOAD_SCRIPT ("send(Memory.readCString(" GUM_PTR_CONST
      ", int64(-1)));", str);
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
      ", 4));", str);
  EXPECT_SEND_MESSAGE_WITH ("\"Bjø\"");

  COMPILE_AND_LOAD_SCRIPT ("send(Memory.readUtf8String(" GUM_PTR_CONST
      ", 0));", str);
  EXPECT_SEND_MESSAGE_WITH ("\"\"");

  COMPILE_AND_LOAD_SCRIPT ("send(Memory.readUtf8String(" GUM_PTR_CONST
      ", -1));", str);
  EXPECT_SEND_MESSAGE_WITH ("\"Bjøærheimsbygd\"");

  COMPILE_AND_LOAD_SCRIPT ("send(Memory.readUtf8String(" GUM_PTR_CONST
      ", int64(-1)));", str);
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

  COMPILE_AND_LOAD_SCRIPT ("send(Memory.readUtf16String(" GUM_PTR_CONST
      ", int64(-1)));", str);
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

  COMPILE_AND_LOAD_SCRIPT ("send(Memory.readAnsiString(" GUM_PTR_CONST
      ", int64(-1)));", str);
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
      "Float",
      /*
       * We don't know if the compiler will decide to access the lower or higher
       * part first, so we can't know the exact error message for these.
       * Hence we limit this part of the test to 64 bit builds...
       */
#if GLIB_SIZEOF_VOID_P == 8
      "Double",
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

  if (RUNNING_ON_VALGRIND)
  {
    g_print ("<skipping, not compatible with Valgrind> ");
    return;
  }

  for (i = 0; i != G_N_ELEMENTS (type_name); i++)
  {
    gchar * source;

    source = g_strconcat ("Memory.read", type_name[i], "(ptr(\"1328\"));",
        NULL);
    COMPILE_AND_LOAD_SCRIPT (source);
    EXPECT_ERROR_MESSAGE_WITH (1, "Error: access violation accessing 0x530");
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
      "Float",
      "Double",
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

  if (RUNNING_ON_VALGRIND)
  {
    g_print ("<skipping, not compatible with Valgrind> ");
    return;
  }

  for (i = 0; i != G_N_ELEMENTS (primitive_type_name); i++)
  {
    gchar * source;

    source = g_strconcat ("Memory.write", primitive_type_name[i],
        "(ptr(\"1328\"), 13);", NULL);
    COMPILE_AND_LOAD_SCRIPT (source);
    EXPECT_ERROR_MESSAGE_WITH (1, "Error: access violation accessing 0x530");
    g_free (source);
  }

  for (i = 0; i != G_N_ELEMENTS (string_type_name); i++)
  {
    gchar * source;

    source = g_strconcat ("Memory.write", string_type_name[i],
        "(ptr(\"1328\"), 'Hey');", NULL);
    COMPILE_AND_LOAD_SCRIPT (source);
    EXPECT_ERROR_MESSAGE_WITH (1, "Error: access violation accessing 0x530");
    g_free (source);
  }
}

SCRIPT_TESTCASE (invalid_read_write_execute_results_in_exception)
{
  if (RUNNING_ON_VALGRIND)
  {
    g_print ("<skipping, not compatible with Valgrind> ");
    return;
  }

  COMPILE_AND_LOAD_SCRIPT ("Memory.readU8(ptr(\"1328\"));");
  EXPECT_ERROR_MESSAGE_WITH (1, "Error: access violation accessing 0x530");
  EXPECT_NO_MESSAGES ();

  COMPILE_AND_LOAD_SCRIPT ("Memory.writeU8(ptr(\"1328\"), 42);");
  EXPECT_ERROR_MESSAGE_WITH (1, "Error: access violation accessing 0x530");
  EXPECT_NO_MESSAGES ();

  COMPILE_AND_LOAD_SCRIPT ("var data = Memory.alloc(Process.pageSize);"
      "var f = new NativeFunction(data, 'void', []);"
      "try {"
      "  f();"
      "} catch (e) {"
      "  send(e.toString().indexOf('Error: access violation accessing 0x')"
      "      === 0);"
      "}");
  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_NO_MESSAGES ();
}

SCRIPT_TESTCASE (script_can_be_compiled_to_bytecode)
{
  GError * error;
  GBytes * code;
  GumScript * script;

  error = NULL;
  code = gum_script_backend_compile_sync (fixture->backend, "send(1337);\noops;", NULL,
      &error);
  if (GUM_DUK_IS_SCRIPT_BACKEND (fixture->backend))
  {
    g_assert (code != NULL);
    g_assert (error == NULL);

    g_assert (gum_script_backend_compile_sync (fixture->backend, "'", NULL,
        NULL) == NULL);

    g_assert (gum_script_backend_compile_sync (fixture->backend, "'", NULL,
        &error) == NULL);
    g_assert (error != NULL);
    g_assert (g_str_has_prefix (error->message,
        "Script(line 1): SyntaxError: "));
    g_clear_error (&error);
  }
  else
  {
    g_assert (code == NULL);
    g_assert (error != NULL);
    g_assert_cmpstr (error->message, ==, "not yet supported by the V8 runtime");
    g_clear_error (&error);

    code = g_bytes_new (NULL, 0);
  }

  script = gum_script_backend_create_from_bytes_sync (fixture->backend,
      "testcase", code, NULL, &error);
  if (GUM_DUK_IS_SCRIPT_BACKEND (fixture->backend))
  {
    TestScriptMessageItem * item;

    g_assert (script != NULL);
    g_assert (error == NULL);

    gum_script_set_message_handler (script, test_script_fixture_store_message,
        fixture, NULL);

    gum_script_load_sync (script, NULL);

    EXPECT_SEND_MESSAGE_WITH ("1337");

    item = test_script_fixture_pop_message (fixture);
    g_assert (strstr (item->message, "ReferenceError") != NULL);
    g_assert (strstr (item->message, "agent.js") == NULL);
    g_assert (strstr (item->message, "testcase.js") != NULL);
    test_script_message_item_free (item);

    EXPECT_NO_MESSAGES ();

    g_object_unref (script);
  }
  else
  {
    g_assert (script == NULL);
    g_assert (error != NULL);
    g_assert_cmpstr (error->message, ==, "not yet supported by the V8 runtime");
    g_clear_error (&error);
  }

  g_bytes_unref (code);
}

SCRIPT_TESTCASE (script_can_be_reloaded)
{
  COMPILE_AND_LOAD_SCRIPT (
      "send(typeof global.badger);"
      "global.badger = 42;");
  EXPECT_SEND_MESSAGE_WITH ("\"undefined\"");
  gum_script_load_sync (fixture->script, NULL);
  EXPECT_NO_MESSAGES ();
  gum_script_unload_sync (fixture->script, NULL);
  gum_script_unload_sync (fixture->script, NULL);
  EXPECT_NO_MESSAGES ();
  gum_script_load_sync (fixture->script, NULL);
  EXPECT_SEND_MESSAGE_WITH ("\"undefined\"");
}

SCRIPT_TESTCASE (script_memory_usage)
{
  GumScript * script;
  GTimer * timer;
  guint before, after;

  if (!GUM_DUK_IS_SCRIPT_BACKEND (fixture->backend))
  {
    g_print ("<skipping, measurement only valid for the Duktape runtime> ");
    return;
  }

  /* Warm up */
  script = gum_script_backend_create_sync (fixture->backend, "testcase",
      "'use strict';", NULL, NULL);
  gum_script_load_sync (script, NULL);
  gum_script_unload_sync (script, NULL);
  g_object_unref (script);

  timer = g_timer_new ();

  before = gum_peek_private_memory_usage ();

  g_timer_reset (timer);
  script = gum_script_backend_create_sync (fixture->backend, "testcase",
      "'use strict';", NULL, NULL);
  g_print ("created in %u ms\n",
      (guint) (g_timer_elapsed (timer, NULL) * 1000.0));

  g_timer_reset (timer);
  gum_script_load_sync (script, NULL);
  g_print ("loaded in %u ms\n",
      (guint) (g_timer_elapsed (timer, NULL) * 1000.0));

  after = gum_peek_private_memory_usage ();
  g_print ("memory usage: %u bytes\n", after - before);

  g_timer_reset (timer);
  gum_script_unload_sync (script, NULL);
  g_print ("unloaded in %u ms\n",
      (guint) (g_timer_elapsed (timer, NULL) * 1000.0));

  g_object_unref (script);
}

SCRIPT_TESTCASE (source_maps_should_be_supported_for_our_runtime)
{
  TestScriptMessageItem * item;

  COMPILE_AND_LOAD_SCRIPT ("hexdump(null);");

  item = test_script_fixture_pop_message (fixture);
  g_assert (strstr (item->message, " (frida/runtime/hexdump.js:") != NULL);
  test_script_message_item_free (item);

  EXPECT_NO_MESSAGES ();
}

SCRIPT_TESTCASE (source_maps_should_be_supported_for_user_scripts)
{
  TestScriptMessageItem * item;

  /*
   * index.js
   * --------
   * 01 'use strict';
   * 02
   * 03 var math = require('./math');
   * 04
   * 05 try {
   * 06   math.add(5, 2);
   * 07 } catch (e) {
   * 08   send(e.stack);
   * 09 }
   * 10
   * 11 setTimeout(function () {
   * 12   throw new Error('Oops!');
   * 13 }, 0);
   *
   * math.js
   * -------
   * 01 'use strict';
   * 02
   * 03 module.exports = {
   * 04   add: function (a, b) {
   * 05     throw new Error('Not yet implemented');
   * 06   }
   * 07 };
   */

  COMPILE_AND_LOAD_SCRIPT (
      "(function e(t,n,r){function s(o,u){if(!n[o]){if(!t[o]){var a=typeof requ"
      "ire==\"function\"&&require;if(!u&&a)return a(o,!0);if(i)return i(o,!0);v"
      "ar f=new Error(\"Cannot find module '\"+o+\"'\");throw f.code=\"MODULE_N"
      "OT_FOUND\",f}var l=n[o]={exports:{}};t[o][0].call(l.exports,function(e){"
      "var n=t[o][1][e];return s(n?n:e)},l,l.exports,e,t,n,r)}return n[o].expor"
      "ts}var i=typeof require==\"function\"&&require;for(var o=0;o<r.length;o+"
      "+)s(r[o]);return s})({1:[function(require,module,exports){"          "\n"
      "'use strict';"                                                       "\n"
      ""                                                                    "\n"
      "var math = require('./math');"                                       "\n"
      ""                                                                    "\n"
      "try {"                                                               "\n"
      /* testcase.js:7 => index.js:6 */
      "  math.add(5, 2);"                                                   "\n"
      "} catch (e) {"                                                       "\n"
      "  send(e.stack);"                                                    "\n"
      "}"                                                                   "\n"
      ""                                                                    "\n"
      "setTimeout(function () {"                                            "\n"
      /* testcase.js:13 => index.js:12 */
      "  throw new Error('Oops!');"                                         "\n"
      "}, 0);"                                                              "\n"
      ""                                                                    "\n"
      "},{\"./math\":2}],2:[function(require,module,exports){"              "\n"
      "'use strict';"                                                       "\n"
      ""                                                                    "\n"
      "module.exports = {"                                                  "\n"
      "  add: function (a, b) {"                                            "\n"
      /* testcase.js:21 => math.js:5 */
      "    throw new Error('Not yet implemented');"                         "\n"
      "  }"                                                                 "\n"
      "};"                                                                  "\n"
      ""                                                                    "\n"
      "},{}]},{},[1])"                                                      "\n"
      "//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJzb3"
      "VyY2VzIjpbIm5vZGVfbW9kdWxlcy9mcmlkYS9ub2RlX21vZHVsZXMvYnJvd3NlcmlmeS9ub2"
      "RlX21vZHVsZXMvYnJvd3Nlci1wYWNrL19wcmVsdWRlLmpzIiwiaW5kZXguanMiLCJtYXRoLm"
      "pzIl0sIm5hbWVzIjpbXSwibWFwcGluZ3MiOiJBQUFBO0FDQUE7QUFDQTtBQUNBO0FBQ0E7QU"
      "FDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUNiQT"
      "tBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBIiwiZmlsZSI6ImdlbmVyYXRlZC"
      "5qcyIsInNvdXJjZVJvb3QiOiIifQ=="                                      "\n"
  );

  item = test_script_fixture_pop_message (fixture);
  if (!GUM_DUK_IS_SCRIPT_BACKEND (fixture->backend))
    g_assert (strstr (item->message, "testcase.js") == NULL);
  g_assert (strstr (item->message, "\"type\":\"send\"") != NULL);
  if (GUM_DUK_IS_SCRIPT_BACKEND (fixture->backend))
  {
    g_assert (strstr (item->message,
        "\"payload\":\"Error: Not yet implemented\\n"
        "    at math.js:5\\n"
        "    at index.js:6\\n"
        "    at call (native)\\n"
        "    at s (node_modules/frida/node_modules/browserify/node_modules/"
            "browser-pack/_prelude.js:1)\\n"
        "    at e (node_modules/frida/node_modules/browserify/node_modules/"
            "browser-pack/_prelude.js:1)\\n")
        != NULL);
  }
  else
  {
    g_assert (strstr (item->message,
        "\"payload\":\"Error: Not yet implemented\\n"
        "    at Object.add (math.js:5:1)\\n"
        "    at Object.1../math (index.js:6:1)\\n"
        "    at s (node_modules/frida/node_modules/browserify/node_modules/"
            "browser-pack/_prelude.js:1:1)\\n"
        "    at e (node_modules/frida/node_modules/browserify/node_modules/"
            "browser-pack/_prelude.js:1:1)\\n"
        "    at node_modules/frida/node_modules/browserify/node_modules/"
            "browser-pack/_prelude.js:1:1\"") != NULL);
  }
  test_script_message_item_free (item);

  item = test_script_fixture_pop_message (fixture);
  g_assert (strstr (item->message, "testcase.js") == NULL);
  g_assert (strstr (item->message, "\"type\":\"error\"") != NULL);
  g_assert (strstr (item->message, "\"description\":\"Error: Oops!\"") != NULL);
  if (GUM_DUK_IS_SCRIPT_BACKEND (fixture->backend))
  {
    g_assert (strstr (item->message, "\"stack\":\"Error: Oops!\\n"
        "    at index.js:12\\n") != NULL);
  }
  else
  {
    g_assert (strstr (item->message, "\"stack\":\"Error: Oops!\\n"
        "    at index.js:12:1\\n") != NULL);
  }
  g_assert (strstr (item->message, "\"fileName\":\"index.js\"") != NULL);
  g_assert (strstr (item->message, "\"lineNumber\":12") != NULL);
  g_assert (strstr (item->message, "\"columnNumber\":1") != NULL);
  test_script_message_item_free (item);
}

SCRIPT_TESTCASE (types_handle_invalid_construction)
{
  /* FIXME: there seems to be a TryCatch issue with V8 on mac-x86_64 */
#if !(defined (HAVE_MAC) && GLIB_SIZEOF_VOID_P == 8)
  COMPILE_AND_LOAD_SCRIPT (
      "try {"
      "  NativePointer(\"0x1234\")"
      "} catch (e) {"
      "  send(e.message);"
      "}");
  EXPECT_SEND_MESSAGE_WITH ("\"use `new NativePointer()` to create a new "
      "instance, or use one of the two shorthands: `ptr()` and `NULL`\"");

  COMPILE_AND_LOAD_SCRIPT (
      "try {"
      "  NativeFunction(ptr(\"0x1234\"), 'void', []);"
      "} catch (e) {"
      "  send(e.message);"
      "}");
  EXPECT_SEND_MESSAGE_WITH ("\"use `new NativeFunction()` to create a new "
      "instance\"");

  COMPILE_AND_LOAD_SCRIPT (
      "try {"
      "  NativeCallback(function () {}, 'void', []);"
      "} catch (e) {"
      "  send(e.message);"
      "}");
  EXPECT_SEND_MESSAGE_WITH ("\"use `new NativeCallback()` to create a new "
      "instance\"");

  COMPILE_AND_LOAD_SCRIPT (
      "try {"
      "  File(\"/foo\", \"r\");"
      "} catch (e) {"
      "  send(e.message);"
      "}");
  EXPECT_SEND_MESSAGE_WITH ("\"use `new File()` to create a new instance\"");
#endif
}

SCRIPT_TESTCASE (weak_callback_is_triggered_on_gc)
{
  if (GUM_DUK_IS_SCRIPT_BACKEND (fixture->backend))
  {
    g_print ("<skipping, not yet implemented in the Duktape runtime> ");
    return;
  }

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

SCRIPT_TESTCASE (globals_can_be_dynamically_generated)
{
  COMPILE_AND_LOAD_SCRIPT (
      "var lengthBefore = Object.getOwnPropertyNames(global).length;"
      "Script.setGlobalAccessHandler({"
      "  get: function (property) {"
      "    if (property === 'badger')"
      "      return 1337;"
      "  },"
      "  enumerate: function () {"
      "    return ['badger'];"
      "  },"
      "});"
      "var lengthAfter = Object.getOwnPropertyNames(global).length;"
      "send('badger' in global);"
      "send(badger);"
      "send(typeof badger);"
      "send(lengthAfter === lengthBefore + 1);"
      "send(snake);");
  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_SEND_MESSAGE_WITH ("1337");
  EXPECT_SEND_MESSAGE_WITH ("\"number\"");
  EXPECT_SEND_MESSAGE_WITH ("true");
  if (GUM_DUK_IS_SCRIPT_BACKEND (fixture->backend))
  {
    EXPECT_ERROR_MESSAGE_WITH (ANY_LINE_NUMBER,
        "ReferenceError: identifier 'snake' undefined");
  }
  else
  {
    EXPECT_ERROR_MESSAGE_WITH (ANY_LINE_NUMBER,
        "ReferenceError: snake is not defined");
  }
  EXPECT_NO_MESSAGES ();

  COMPILE_AND_LOAD_SCRIPT (
      "var totalGetCalls = 0;"
      "Script.setGlobalAccessHandler({"
      "  get: function (property) {"
      "    totalGetCalls++;"
      "  },"
      "  enumerate: function () {"
      "    return [];"
      "  },"
      "});"
      "(1, eval)('mushroom = 42;');"
      "send(totalGetCalls);"
      "send(mushroom);"
      "send(totalGetCalls);");
  EXPECT_SEND_MESSAGE_WITH ("0");
  EXPECT_SEND_MESSAGE_WITH ("42");
  EXPECT_SEND_MESSAGE_WITH ("0");
  EXPECT_NO_MESSAGES ();
}

SCRIPT_TESTCASE (exceptions_can_be_handled)
{
  gpointer page;
  gboolean exception_on_read, exception_on_write;

  COMPILE_AND_LOAD_SCRIPT (
      "Process.setExceptionHandler(function (ex) {"
      "  send('w00t');"
      "});");

  EXPECT_NO_MESSAGES ();

  page = gum_alloc_n_pages (1, GUM_PAGE_RW);
  gum_mprotect (page, gum_query_page_size (), GUM_PAGE_NO_ACCESS);
  gum_try_read_and_write_at (page, 0, &exception_on_read, &exception_on_write);
  g_assert (exception_on_read);
  g_assert (exception_on_write);
  gum_free_pages (page);

  EXPECT_SEND_MESSAGE_WITH ("\"w00t\"");
  EXPECT_SEND_MESSAGE_WITH ("\"w00t\"");
  EXPECT_NO_MESSAGES ();
}

#include "script-dukdebugserver.c"
#include "script-v8debugserver.c"

SCRIPT_TESTCASE (debugger_can_be_enabled)
{
  GumScript * badger, * snake;
  GMainLoop * loop;
  const guint16 port = 5858;

  if (!g_test_slow ())
  {
    g_print ("<skipping, run in slow mode> ");
    return;
  }

  badger = gum_script_backend_create_sync (fixture->backend, "badger",
      "setInterval(function () {\n"
      "  send('badger');\n"
      "}, 1000);", NULL, NULL);
  gum_script_set_message_handler (badger, on_message, "badger", NULL);
  gum_script_load_sync (badger, NULL);

  snake = gum_script_backend_create_sync (fixture->backend, "snake",
      "setInterval(function () {\n"
      "  send('snake');\n"
      "}, 1000);", NULL, NULL);
  gum_script_set_message_handler (snake, on_message, "snake", NULL);
  gum_script_load_sync (snake, NULL);

  loop = g_main_loop_new (g_main_context_get_thread_default (), FALSE);

  if (GUM_DUK_IS_SCRIPT_BACKEND (fixture->backend))
  {
    GumDukDebugServer * server;

    server = gum_duk_debug_server_new (fixture->backend, port);

    g_print ("Debugger enabled. You may now connect to port %u and upwards\n",
        port);
    g_main_loop_run (loop);

    gum_duk_debug_server_free (server);
  }
  else
  {
    GumV8DebugServer * server;

    server = gum_v8_debug_server_new (fixture->backend, port);

    g_print ("Debugger enabled. You may now connect to port %u.\n", port);
    g_main_loop_run (loop);

    gum_v8_debug_server_free (server);
  }

  g_main_loop_unref (loop);
}

SCRIPT_TESTCASE (objc_api_is_embedded)
{
  COMPILE_AND_LOAD_SCRIPT ("send(typeof ObjC.available);");
  EXPECT_SEND_MESSAGE_WITH ("\"boolean\"");
}

SCRIPT_TESTCASE (java_api_is_embedded)
{
  COMPILE_AND_LOAD_SCRIPT ("send(typeof Java.available);");
  EXPECT_SEND_MESSAGE_WITH ("\"boolean\"");
}

static void
on_message (GumScript * script,
            const gchar * message,
            GBytes * data,
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

  /*
   * Throw in a dummy call to an external function so the platform's default ABI
   * is used at call-sites. Because this function is static there is otherwise
   * a chance that the compiler will invent its own calling convention, and any
   * JS-defined replacement function (NativeCallback) will be prone to clobber
   * registers used by the custom calling convention.
   */
  fflush (stdout);

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

GUM_NOINLINE static void
target_function_callbacks (const gint value,
                           void (* first) (const gint * value),
                           void (* second) (const gint * value))
{
  int i;

  for (i = 0; i != 10; i++)
    gum_script_dummy_global_to_trick_optimizer += i * value;

  first (&value);

  second (&value);
}

GUM_NOINLINE static void
target_function_trigger (TestTrigger * trigger)
{
  g_mutex_lock (&trigger->mutex);
  trigger->ready = TRUE;
  g_cond_signal (&trigger->cond);
  g_mutex_unlock (&trigger->mutex);

  g_mutex_lock (&trigger->mutex);
  while (!trigger->fired)
    g_cond_wait (&trigger->cond, &trigger->mutex);
  g_mutex_unlock (&trigger->mutex);
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
