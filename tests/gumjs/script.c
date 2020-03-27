/*
 * Copyright (C) 2010-2020 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 * Copyright (C) 2015 Marc Hartmayer <hello@hartmayer.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "script-fixture.c"

TESTLIST_BEGIN (script)
  TESTENTRY (invalid_script_should_return_null)
  TESTENTRY (strict_mode_should_be_enforced)
  TESTENTRY (array_buffer_can_be_created)
  TESTENTRY (message_can_be_sent)
  TESTENTRY (message_can_be_sent_with_data)
  TESTENTRY (message_can_be_received)
  TESTENTRY (message_can_be_received_with_data)
  TESTENTRY (recv_may_specify_desired_message_type)
  TESTENTRY (recv_can_be_waited_for_from_an_application_thread)
  TESTENTRY (recv_can_be_waited_for_from_two_application_threads)
  TESTENTRY (recv_can_be_waited_for_from_our_js_thread)
  TESTENTRY (recv_wait_in_an_application_thread_should_throw_on_unload)
  TESTENTRY (recv_wait_in_our_js_thread_should_throw_on_unload)
  TESTENTRY (rpc_can_be_performed)
  TESTENTRY (message_can_be_logged)
  TESTENTRY (thread_can_be_forced_to_sleep)
  TESTENTRY (timeout_can_be_scheduled)
  TESTENTRY (timeout_can_be_cancelled)
  TESTENTRY (interval_can_be_scheduled)
  TESTENTRY (interval_can_be_cancelled)
  TESTENTRY (callback_can_be_scheduled)
  TESTENTRY (callback_can_be_scheduled_from_a_scheduled_callback)
  TESTENTRY (callback_can_be_cancelled)
  TESTENTRY (callback_can_be_scheduled_on_next_tick)
  TESTENTRY (timer_cancellation_apis_should_be_forgiving)

  TESTGROUP_BEGIN ("Interceptor")
    TESTENTRY (argument_can_be_read)
    TESTENTRY (argument_can_be_replaced)
    TESTENTRY (return_value_can_be_read)
    TESTENTRY (return_value_can_be_replaced)
    TESTENTRY (return_address_can_be_read)
    TESTENTRY (register_can_be_read)
    TESTENTRY (register_can_be_written)
    TESTENTRY (system_error_can_be_read_from_interceptor_listener)
    TESTENTRY (system_error_can_be_read_from_replacement_function)
    TESTENTRY (system_error_can_be_replaced_from_interceptor_listener)
    TESTENTRY (system_error_can_be_replaced_from_replacement_function)
    TESTENTRY (invocations_are_bound_on_tls_object)
    TESTENTRY (invocations_provide_thread_id)
    TESTENTRY (invocations_provide_call_depth)
#if !defined (HAVE_QNX) && !defined (HAVE_MIPS)
    TESTENTRY (invocations_provide_context_for_backtrace)
#endif
    TESTENTRY (invocations_provide_context_serializable_to_json)
    TESTENTRY (listener_can_be_detached)
    TESTENTRY (listener_can_be_detached_by_destruction_mid_call)
    TESTENTRY (all_listeners_can_be_detached)
    TESTENTRY (function_can_be_replaced)
    TESTENTRY (function_can_be_replaced_and_called_immediately)
    TESTENTRY (function_can_be_reverted)
    TESTENTRY (replaced_function_should_have_invocation_context)
    TESTENTRY (instructions_can_be_probed)
    TESTENTRY (interceptor_should_support_native_pointer_values)
    TESTENTRY (interceptor_handles_invalid_arguments)
  TESTGROUP_END ()
  TESTGROUP_BEGIN ("Interceptor/Performance")
    TESTENTRY (interceptor_on_enter_performance)
    TESTENTRY (interceptor_on_leave_performance)
    TESTENTRY (interceptor_on_enter_and_leave_performance)
  TESTGROUP_END ()

  TESTGROUP_BEGIN ("Memory")
    TESTENTRY (pointer_can_be_read)
    TESTENTRY (pointer_can_be_read_legacy_style)
    TESTENTRY (pointer_can_be_written)
    TESTENTRY (pointer_can_be_written_legacy_style)
    TESTENTRY (memory_can_be_allocated)
    TESTENTRY (memory_can_be_copied)
    TESTENTRY (memory_can_be_duped)
    TESTENTRY (memory_can_be_protected)
    TESTENTRY (code_can_be_patched)
    TESTENTRY (s8_can_be_read)
    TESTENTRY (s8_can_be_written)
    TESTENTRY (u8_can_be_read)
    TESTENTRY (u8_can_be_written)
    TESTENTRY (s16_can_be_read)
    TESTENTRY (s16_can_be_written)
    TESTENTRY (u16_can_be_read)
    TESTENTRY (u16_can_be_written)
    TESTENTRY (s32_can_be_read)
    TESTENTRY (s32_can_be_written)
    TESTENTRY (u32_can_be_read)
    TESTENTRY (u32_can_be_written)
    TESTENTRY (s64_can_be_read)
    TESTENTRY (s64_can_be_written)
    TESTENTRY (u64_can_be_read)
    TESTENTRY (u64_can_be_written)
    TESTENTRY (short_can_be_read)
    TESTENTRY (short_can_be_written)
    TESTENTRY (ushort_can_be_read)
    TESTENTRY (ushort_can_be_written)
    TESTENTRY (int_can_be_read)
    TESTENTRY (int_can_be_written)
    TESTENTRY (uint_can_be_read)
    TESTENTRY (uint_can_be_written)
    TESTENTRY (long_can_be_read)
    TESTENTRY (long_can_be_written)
    TESTENTRY (ulong_can_be_read)
    TESTENTRY (ulong_can_be_written)
    TESTENTRY (float_can_be_read)
    TESTENTRY (float_can_be_written)
    TESTENTRY (double_can_be_read)
    TESTENTRY (double_can_be_written)
    TESTENTRY (byte_array_can_be_read)
    TESTENTRY (byte_array_can_be_written)
    TESTENTRY (c_string_can_be_read)
    TESTENTRY (utf8_string_can_be_read)
    TESTENTRY (utf8_string_can_be_written)
    TESTENTRY (utf8_string_can_be_allocated)
    TESTENTRY (utf16_string_can_be_read)
    TESTENTRY (utf16_string_can_be_written)
    TESTENTRY (utf16_string_can_be_allocated)
#ifdef G_OS_WIN32
    TESTENTRY (ansi_string_can_be_read_in_code_page_936)
    TESTENTRY (ansi_string_can_be_read_in_code_page_1252)
    TESTENTRY (ansi_string_can_be_written_in_code_page_936)
    TESTENTRY (ansi_string_can_be_written_in_code_page_1252)
    TESTENTRY (ansi_string_can_be_allocated_in_code_page_936)
    TESTENTRY (ansi_string_can_be_allocated_in_code_page_1252)
#endif
    TESTENTRY (invalid_read_results_in_exception)
    TESTENTRY (invalid_write_results_in_exception)
    TESTENTRY (invalid_read_write_execute_results_in_exception)
    TESTENTRY (memory_can_be_scanned)
    TESTENTRY (memory_can_be_scanned_synchronously)
    TESTENTRY (memory_scan_should_be_interruptible)
    TESTENTRY (memory_scan_handles_unreadable_memory)
    TESTENTRY (memory_access_can_be_monitored)
    TESTENTRY (memory_access_can_be_monitored_one_range)
  TESTGROUP_END ()

  TESTENTRY (frida_version_is_available)
  TESTENTRY (frida_heap_size_can_be_queried)

  TESTGROUP_BEGIN ("Process")
    TESTENTRY (process_arch_is_available)
    TESTENTRY (process_platform_is_available)
    TESTENTRY (process_page_size_is_available)
    TESTENTRY (process_pointer_size_is_available)
    TESTENTRY (process_should_support_nested_signal_handling)
#ifndef HAVE_QNX
    TESTENTRY (process_debugger_status_is_available)
#endif
    TESTENTRY (process_id_is_available)
    TESTENTRY (process_current_thread_id_is_available)
    TESTENTRY (process_threads_can_be_enumerated)
    TESTENTRY (process_threads_can_be_enumerated_legacy_style)
    TESTENTRY (process_modules_can_be_enumerated)
    TESTENTRY (process_modules_can_be_enumerated_legacy_style)
    TESTENTRY (process_module_can_be_looked_up_from_address)
    TESTENTRY (process_module_can_be_looked_up_from_name)
    TESTENTRY (process_ranges_can_be_enumerated)
    TESTENTRY (process_ranges_can_be_enumerated_legacy_style)
    TESTENTRY (process_ranges_can_be_enumerated_with_neighbors_coalesced)
    TESTENTRY (process_range_can_be_looked_up_from_address)
#ifdef HAVE_DARWIN
    TESTENTRY (process_malloc_ranges_can_be_enumerated)
    TESTENTRY (process_malloc_ranges_can_be_enumerated_legacy_style)
#endif
  TESTGROUP_END ()

  TESTGROUP_BEGIN ("Module")
#ifndef HAVE_QNX
    TESTENTRY (module_imports_can_be_enumerated)
    TESTENTRY (module_imports_can_be_enumerated_legacy_style)
#endif
    TESTENTRY (module_exports_can_be_enumerated)
    TESTENTRY (module_exports_can_be_enumerated_legacy_style)
    TESTENTRY (module_exports_enumeration_performance)
    TESTENTRY (module_symbols_can_be_enumerated)
    TESTENTRY (module_symbols_can_be_enumerated_legacy_style)
    TESTENTRY (module_ranges_can_be_enumerated)
    TESTENTRY (module_ranges_can_be_enumerated_legacy_style)
    TESTENTRY (module_base_address_can_be_found)
    TESTENTRY (module_export_can_be_found_by_name)
    TESTENTRY (module_can_be_loaded)
    TESTENTRY (module_can_be_forcibly_initialized)
  TESTGROUP_END ()

  TESTGROUP_BEGIN ("ApiResolver")
    TESTENTRY (api_resolver_can_be_used_to_find_functions)
    TESTENTRY (api_resolver_can_be_used_to_find_functions_legacy_style)
  TESTGROUP_END ()

  TESTGROUP_BEGIN ("Socket")
    TESTENTRY (socket_connection_can_be_established)
    TESTENTRY (socket_connection_can_be_established_with_tls)
    TESTENTRY (socket_connection_should_not_leak_on_error)
    TESTENTRY (socket_type_can_be_inspected)
#if !defined (HAVE_ANDROID) && !(defined (HAVE_LINUX) && \
    defined (HAVE_ARM)) && !(defined (HAVE_LINUX) && defined (HAVE_MIPS))
    TESTENTRY (socket_endpoints_can_be_inspected)
#endif
  TESTGROUP_END ()

  TESTGROUP_BEGIN ("Stream")
#ifdef G_OS_UNIX
    TESTENTRY (unix_fd_can_be_read_from)
    TESTENTRY (unix_fd_can_be_written_to)
#endif
  TESTGROUP_END ()

  TESTGROUP_BEGIN ("Hexdump")
    TESTENTRY (basic_hexdump_functionality_is_available)
    TESTENTRY (hexdump_supports_native_pointer_conforming_object)
  TESTGROUP_END ()

  TESTGROUP_BEGIN ("NativePointer")
    TESTENTRY (native_pointer_provides_is_null)
    TESTENTRY (native_pointer_provides_arithmetic_operations)
    TESTENTRY (native_pointer_provides_uint32_conversion_functionality)
    TESTENTRY (native_pointer_provides_ptrauth_functionality)
    TESTENTRY (native_pointer_to_match_pattern)
    TESTENTRY (native_pointer_can_be_constructed_from_64bit_value)
  TESTGROUP_END ()

  TESTGROUP_BEGIN ("ArrayBuffer")
    TESTENTRY (array_buffer_can_wrap_memory_region)
    TESTENTRY (array_buffer_can_be_unwrapped)
  TESTGROUP_END ()

  TESTGROUP_BEGIN ("UInt64")
    TESTENTRY (uint64_provides_arithmetic_operations)
  TESTGROUP_END ()

  TESTGROUP_BEGIN ("Int64")
    TESTENTRY (int64_provides_arithmetic_operations)
  TESTGROUP_END ()

  TESTGROUP_BEGIN ("NativeFunction")
    TESTENTRY (native_function_can_be_invoked)
    TESTENTRY (native_function_can_be_intercepted_when_thread_is_ignored)
    TESTENTRY (native_function_should_implement_call_and_apply)
    TESTENTRY (system_function_can_be_invoked)
    TESTENTRY (native_function_crash_results_in_exception)
    TESTENTRY (nested_native_function_crash_is_handled_gracefully)
    TESTENTRY (variadic_native_function_can_be_invoked)
    TESTENTRY (variadic_native_function_args_smaller_than_int_should_be_promoted)
    TESTENTRY (variadic_native_function_float_args_should_be_promoted_to_double)
    TESTENTRY (native_function_is_a_native_pointer)
  TESTGROUP_END ()

  TESTGROUP_BEGIN ("NativeCallback")
    TESTENTRY (native_callback_can_be_invoked)
    TESTENTRY (native_callback_is_a_native_pointer)
    TESTENTRY (native_callback_memory_should_be_eagerly_reclaimed)
  TESTGROUP_END ()

  TESTGROUP_BEGIN ("DebugSymbol")
    TESTENTRY (address_can_be_resolved_to_symbol)
    TESTENTRY (name_can_be_resolved_to_symbol)
    TESTENTRY (function_can_be_found_by_name)
    TESTENTRY (functions_can_be_found_by_name)
    TESTENTRY (functions_can_be_found_by_matching)
  TESTGROUP_END ()

  TESTGROUP_BEGIN ("CModule")
    TESTENTRY (cmodule_can_be_defined)
    TESTENTRY (cmodule_symbols_can_be_provided)
    TESTENTRY (cmodule_should_report_parsing_errors)
    TESTENTRY (cmodule_should_report_linking_errors)
    TESTENTRY (cmodule_should_provide_lifecycle_hooks)
    TESTENTRY (cmodule_can_be_used_with_interceptor_attach)
    TESTENTRY (cmodule_can_be_used_with_interceptor_replace)
    TESTENTRY (cmodule_can_be_used_with_stalker_transform)
    TESTENTRY (cmodule_can_be_used_with_stalker_callout)
    TESTENTRY (cmodule_can_be_used_with_stalker_call_probe)
    TESTENTRY (cmodule_can_be_used_with_module_map)
    TESTENTRY (cmodule_should_provide_some_builtin_string_functions)
    TESTENTRY (cmodule_should_support_floating_point)
    TESTENTRY (cmodule_should_support_varargs)
    TESTENTRY (cmodule_should_support_global_callbacks)
    TESTENTRY (cmodule_should_provide_access_to_cpu_registers)
  TESTGROUP_END ()

  TESTGROUP_BEGIN ("Instruction")
    TESTENTRY (instruction_can_be_parsed)
    TESTENTRY (instruction_can_be_generated)
    TESTENTRY (instruction_can_be_relocated)
  TESTGROUP_END ()

  TESTGROUP_BEGIN ("File")
    TESTENTRY (file_can_be_written_to)
  TESTGROUP_END ()

  TESTGROUP_BEGIN ("Database")
    TESTENTRY (inline_sqlite_database_can_be_queried)
    TESTENTRY (external_sqlite_database_can_be_queried)
    TESTENTRY (external_sqlite_database_can_be_opened_with_flags)
  TESTGROUP_END ()

  TESTGROUP_BEGIN ("Stalker")
#if defined (HAVE_I386) || defined (HAVE_ARM64)
    TESTENTRY (execution_can_be_traced)
    TESTENTRY (execution_can_be_traced_with_custom_transformer)
    TESTENTRY (execution_can_be_traced_with_faulty_transformer)
    TESTENTRY (execution_can_be_traced_during_immediate_native_function_call)
    TESTENTRY (execution_can_be_traced_during_scheduled_native_function_call)
    TESTENTRY (execution_can_be_traced_after_native_function_call_from_hook)
    TESTENTRY (call_can_be_probed)
#endif
    TESTENTRY (stalker_events_can_be_parsed)
  TESTGROUP_END ()

  TESTENTRY (script_can_be_compiled_to_bytecode)
  TESTENTRY (script_can_be_reloaded)
  TESTENTRY (script_should_not_leak_if_destroyed_before_load)
  TESTENTRY (script_memory_usage)
  TESTENTRY (source_maps_should_be_supported_for_our_runtime)
  TESTENTRY (source_maps_should_be_supported_for_user_scripts)
  TESTENTRY (types_handle_invalid_construction)
  TESTENTRY (weak_callback_is_triggered_on_gc)
  TESTENTRY (weak_callback_is_triggered_on_unload)
  TESTENTRY (weak_callback_is_triggered_on_unbind)
  TESTENTRY (globals_can_be_dynamically_generated)
  TESTENTRY (exceptions_can_be_handled)
  TESTENTRY (debugger_can_be_enabled)
  TESTENTRY (objc_api_is_embedded)
  TESTENTRY (java_api_is_embedded)
TESTLIST_END ()

typedef struct _TestTrigger TestTrigger;

struct _TestTrigger
{
  volatile gboolean ready;
  volatile gboolean fired;
  GMutex mutex;
  GCond cond;
};

static gboolean ignore_thread (GumInterceptor * interceptor);
static gboolean unignore_thread (GumInterceptor * interceptor);

static gint gum_clobber_system_error (gint value);
static gint gum_assert_variadic_uint8_values_are_sane (gpointer a, gpointer b,
    gpointer c, gpointer d, ...);
static gint gum_get_answer_to_life_universe_and_everything (void);
static gint gum_toupper (gchar * str, gint limit);
static gint64 gum_classify_timestamp (gint64 timestamp);
static guint64 gum_square (guint64 value);
static gint gum_sum (gint count, ...);
static gint gum_add_pointers_and_float_fixed (gpointer a, gpointer b, float c);
static gint gum_add_pointers_and_float_variadic (gpointer a, ...);

#ifndef HAVE_ANDROID
static gboolean on_incoming_connection (GSocketService * service,
    GSocketConnection * connection, GObject * source_object,
    gpointer user_data);
static void on_read_ready (GObject * source_object, GAsyncResult * res,
    gpointer user_data);
#endif

#if defined (HAVE_I386) || defined (HAVE_ARM64)
static gpointer run_stalked_through_hooked_function (gpointer data);
static gpointer run_stalked_through_target_function (gpointer data);
#endif

static gpointer sleeping_dummy (gpointer data);

static gpointer invoke_target_function_int_worker (gpointer data);
static gpointer invoke_target_function_trigger (gpointer data);

static void measure_target_function_int_overhead (void);
static int compare_measurements (gconstpointer element_a,
    gconstpointer element_b);

static gboolean check_exception_handling_testable (void);

static void on_script_message (GumScript * script, const gchar * message,
    GBytes * data, gpointer user_data);
static void on_incoming_debug_message (GumInspectorServer * server,
    const gchar * message, gpointer user_data);
static void on_outgoing_debug_message (const gchar * message,
    gpointer user_data);

static int target_function_int (int arg);
static const guint8 * target_function_base_plus_offset (const guint8 * base,
    int offset);
static const gchar * target_function_string (const gchar * arg);
static void target_function_callbacks (const gint value,
    void (* first) (const gint * value), void (* second) (const gint * value));
static void target_function_trigger (TestTrigger * trigger);
static int target_function_nested_a (int arg);
static int target_function_nested_b (int arg);
static int target_function_nested_c (int arg);

gint gum_script_dummy_global_to_trick_optimizer = 0;

TESTCASE (instruction_can_be_parsed)
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

  if (!gum_process_is_debugger_attached () && !RUNNING_ON_VALGRIND)
  {
    COMPILE_AND_LOAD_SCRIPT ("Instruction.parse(ptr(\"0x1\"));");
    EXPECT_ERROR_MESSAGE_WITH (ANY_LINE_NUMBER,
        "Error: access violation accessing 0x1");
  }

#if defined (HAVE_I386) && GLIB_SIZEOF_VOID_P == 8
  COMPILE_AND_LOAD_SCRIPT (
      "var code = Memory.alloc(Process.pageSize);"

      "var cw = new X86Writer(code, { pc: ptr(0x1000) });"
      "send(cw.pc);"
      "send(cw.offset);"
      "cw.putU8(0xab);" /* stosd */
      "send(cw.pc);"
      "send(cw.offset);"
      "send(cw.code.equals(cw.base.add(1)));"
      "cw.putMovRegU32('eax', 42);"
      "cw.putCallRegOffsetPtr('rax', 12);"
      "cw.flush();"

      "var stosd = Instruction.parse(code);"
      "send(stosd.mnemonic);"
      "send(stosd.regsRead);"
      "send(stosd.regsWritten);"
      "send(stosd.groups);"

      "var mov = Instruction.parse(stosd.next);"
      "send(mov.mnemonic);"
      "var operands = mov.operands;"
      "send(operands.length);"
      "send(operands[0].type);"
      "send(operands[0].value);"
      "send(operands[0].size);"
      "send(operands[1].type);"
      "send(operands[1].value);"
      "send(operands[1].size);"
      "send(mov.regsRead);"
      "send(mov.regsWritten);"
      "send(mov.groups);"

      "var call = Instruction.parse(mov.next);"
      "send(call.mnemonic);"
      "operands = call.operands;"
      "send(operands[0].type);"
      "var memProps = Object.keys(operands[0].value);"
      "memProps.sort();"
      "send(memProps);"
      "send(operands[0].value.base);"
      "send(operands[0].value.scale);"
      "send(operands[0].value.disp);"
      "send(call.groups);");

  EXPECT_SEND_MESSAGE_WITH ("\"0x1000\"");
  EXPECT_SEND_MESSAGE_WITH ("0");
  EXPECT_SEND_MESSAGE_WITH ("\"0x1001\"");
  EXPECT_SEND_MESSAGE_WITH ("1");
  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_SEND_MESSAGE_WITH ("\"stosd\"");
  EXPECT_SEND_MESSAGE_WITH ("[\"eax\",\"rdi\",\"rflags\"]");
  EXPECT_SEND_MESSAGE_WITH ("[\"rdi\"]");
  EXPECT_SEND_MESSAGE_WITH ("[]");

  EXPECT_SEND_MESSAGE_WITH ("\"mov\"");
  EXPECT_SEND_MESSAGE_WITH ("2");
  EXPECT_SEND_MESSAGE_WITH ("\"reg\"");
  EXPECT_SEND_MESSAGE_WITH ("\"eax\"");
  EXPECT_SEND_MESSAGE_WITH ("4");
  EXPECT_SEND_MESSAGE_WITH ("\"imm\"");
  EXPECT_SEND_MESSAGE_WITH ("42");
  EXPECT_SEND_MESSAGE_WITH ("4");
  EXPECT_SEND_MESSAGE_WITH ("[]");
  EXPECT_SEND_MESSAGE_WITH ("[]");
  EXPECT_SEND_MESSAGE_WITH ("[]");

  EXPECT_SEND_MESSAGE_WITH ("\"call\"");
  EXPECT_SEND_MESSAGE_WITH ("\"mem\"");
  EXPECT_SEND_MESSAGE_WITH ("[\"base\",\"disp\",\"scale\"]");
  EXPECT_SEND_MESSAGE_WITH ("\"rax\"");
  EXPECT_SEND_MESSAGE_WITH ("1");
  EXPECT_SEND_MESSAGE_WITH ("12");
  EXPECT_SEND_MESSAGE_WITH ("[\"call\",\"mode64\"]");
#elif defined (HAVE_ARM)
  COMPILE_AND_LOAD_SCRIPT (
      "var code = Memory.alloc(Process.pageSize);"

      "var tw = new ThumbWriter(code);"
      "tw.putLdrRegU32('r0', 42);"
      "tw.putBlImm(code.add(64));"
      /* sxtb.w r3, r7, ror 16 */
      "tw.putInstruction(0xfa4f); tw.putInstruction(0xf3a7);"
      /* vdup.8 d3, d7[1] */
      "tw.putInstruction(0xffb3); tw.putInstruction(0x3c07);"
      "tw.flush();"

      "var ldr = Instruction.parse(code.or(1));"
      "send(ldr.mnemonic);"
      "var operands = ldr.operands;"
      "send(operands.length);"
      "send(operands[0].type);"
      "send(operands[0].value);"
      "send(operands[1].type);"
      "send(operands[1].value.base);"
      "send(operands[1].value.scale);"
      "var disp = operands[1].value.disp;"
      "send(ldr.address.add(4 + disp).readU32());"

      "var bl = Instruction.parse(ldr.next);"
      "send(bl.mnemonic);"
      "operands = bl.operands;"
      "send(operands[0].type);"
      "send(ptr(operands[0].value).equals(code.add(64)));"

      "var sxtb = Instruction.parse(bl.next);"
      "send(sxtb.mnemonic);"
      "operands = sxtb.operands;"
      "send(typeof operands[0].shift);"
      "send(operands[1].shift.type);"
      "send(operands[1].shift.value);"

      "var vdup = Instruction.parse(sxtb.next);"
      "send(vdup.mnemonic);"
      "operands = vdup.operands;"
      "send(typeof operands[0].vectorIndex);"
      "send(operands[1].vectorIndex);"

      "var aw = new ArmWriter(code);"
      "aw.putInstruction(0xe00380f7);" /* strd r8, sb, [r3], -r7 */
      "aw.flush();"

      "var strdeq = Instruction.parse(code);"
      "send(strdeq.mnemonic);"
      "operands = strdeq.operands;"
      "send(operands[0].subtracted);"
      "send(operands[1].subtracted);"
      "send(operands[2].subtracted);"
      "send(operands[3].subtracted);");

  EXPECT_SEND_MESSAGE_WITH ("\"ldr\"");
  EXPECT_SEND_MESSAGE_WITH ("2");
  EXPECT_SEND_MESSAGE_WITH ("\"reg\"");
  EXPECT_SEND_MESSAGE_WITH ("\"r0\"");
  EXPECT_SEND_MESSAGE_WITH ("\"mem\"");
  EXPECT_SEND_MESSAGE_WITH ("\"pc\"");
  EXPECT_SEND_MESSAGE_WITH ("1");
  EXPECT_SEND_MESSAGE_WITH ("42");

  EXPECT_SEND_MESSAGE_WITH ("\"bl\"");
  EXPECT_SEND_MESSAGE_WITH ("\"imm\"");
  EXPECT_SEND_MESSAGE_WITH ("true");

  EXPECT_SEND_MESSAGE_WITH ("\"sxtb.w\"");
  EXPECT_SEND_MESSAGE_WITH ("\"undefined\"");
  EXPECT_SEND_MESSAGE_WITH ("\"ror\"");
  EXPECT_SEND_MESSAGE_WITH ("16");

  EXPECT_SEND_MESSAGE_WITH ("\"vdup.8\"");
  EXPECT_SEND_MESSAGE_WITH ("\"undefined\"");
  EXPECT_SEND_MESSAGE_WITH ("1");

  EXPECT_SEND_MESSAGE_WITH ("\"strd\"");
  EXPECT_SEND_MESSAGE_WITH ("false");
  EXPECT_SEND_MESSAGE_WITH ("false");
  EXPECT_SEND_MESSAGE_WITH ("false");
  EXPECT_SEND_MESSAGE_WITH ("true");
#elif defined (HAVE_ARM64)
  COMPILE_AND_LOAD_SCRIPT (
      "var code = Memory.alloc(Process.pageSize);"

      "var cw = new Arm64Writer(code);"
      "cw.putLdrRegU64('x0', 42);"
      "cw.putStrRegRegOffset('x0', 'x7', 32);"
      "cw.putInstruction(0xcb422020);" /* sub x0, x1, x2, lsr #8 */
      "cw.putInstruction(0x8b230841);" /* add x1, x2, w3, uxtb #2 */
      "cw.putInstruction(0x4ee28420);" /* add.2d v0, v1, v2 */
      "cw.putInstruction(0x9eae00e5);" /* fmov.d x5, v7[1] */
      "cw.flush();"

      "var ldr = Instruction.parse(code);"
      "send(ldr.mnemonic);"
      "var operands = ldr.operands;"
      "send(operands.length);"
      "send(operands[0].type);"
      "send(operands[0].value);"
      "send(operands[1].type);"
      "send(ptr(operands[1].value).readU64().valueOf());"

      "var str = Instruction.parse(ldr.next);"
      "send(str.mnemonic);"
      "operands = str.operands;"
      "send(operands[1].type);"
      "var memProps = Object.keys(operands[1].value);"
      "memProps.sort();"
      "send(memProps);"
      "send(operands[1].value.base);"
      "send(operands[1].value.disp);"

      "var sub = Instruction.parse(str.next);"
      "send(sub.mnemonic);"
      "operands = sub.operands;"
      "send(typeof operands[0].shift);"
      "send(typeof operands[1].shift);"
      "send(operands[2].shift.type);"
      "send(operands[2].shift.value);"

      "var add = Instruction.parse(sub.next);"
      "send(add.mnemonic);"
      "operands = add.operands;"
      "send(typeof operands[0].ext);"
      "send(typeof operands[1].ext);"
      "send(operands[2].ext);"

      "var vadd = Instruction.parse(add.next);"
      "send(vadd.mnemonic);"
      "operands = vadd.operands;"
      "send(operands[0].vas);"
      "send(operands[1].vas);"
      "send(operands[2].vas);"

      "var fmov = Instruction.parse(vadd.next);"
      "send(fmov.mnemonic);"
      "operands = fmov.operands;"
      "send(typeof operands[0].vectorIndex);"
      "send(operands[1].vectorIndex);");

  EXPECT_SEND_MESSAGE_WITH ("\"ldr\"");
  EXPECT_SEND_MESSAGE_WITH ("2");
  EXPECT_SEND_MESSAGE_WITH ("\"reg\"");
  EXPECT_SEND_MESSAGE_WITH ("\"x0\"");
  EXPECT_SEND_MESSAGE_WITH ("\"imm\"");
  EXPECT_SEND_MESSAGE_WITH ("42");

  EXPECT_SEND_MESSAGE_WITH ("\"str\"");
  EXPECT_SEND_MESSAGE_WITH ("\"mem\"");
  EXPECT_SEND_MESSAGE_WITH ("[\"base\",\"disp\"]");
  EXPECT_SEND_MESSAGE_WITH ("\"x7\"");
  EXPECT_SEND_MESSAGE_WITH ("32");

  EXPECT_SEND_MESSAGE_WITH ("\"sub\"");
  EXPECT_SEND_MESSAGE_WITH ("\"undefined\"");
  EXPECT_SEND_MESSAGE_WITH ("\"undefined\"");
  EXPECT_SEND_MESSAGE_WITH ("\"lsr\"");
  EXPECT_SEND_MESSAGE_WITH ("8");

  EXPECT_SEND_MESSAGE_WITH ("\"add\"");
  EXPECT_SEND_MESSAGE_WITH ("\"undefined\"");
  EXPECT_SEND_MESSAGE_WITH ("\"undefined\"");
  EXPECT_SEND_MESSAGE_WITH ("\"uxtb\"");

  EXPECT_SEND_MESSAGE_WITH ("\"add\"");
  EXPECT_SEND_MESSAGE_WITH ("\"2d\"");
  EXPECT_SEND_MESSAGE_WITH ("\"2d\"");
  EXPECT_SEND_MESSAGE_WITH ("\"2d\"");

  EXPECT_SEND_MESSAGE_WITH ("\"fmov\"");
  EXPECT_SEND_MESSAGE_WITH ("\"undefined\"");
  EXPECT_SEND_MESSAGE_WITH ("1");
#endif
}

TESTCASE (instruction_can_be_generated)
{
#if defined (HAVE_I386)
  COMPILE_AND_LOAD_SCRIPT (
      "var callback = new NativeCallback(function (a, b) {"
      "  return a * b;"
      "}, 'int', ['int', 'int']);"

      "var page = Memory.alloc(Process.pageSize);"

      "Memory.patchCode(page, 64, function (code) {"
        "var cw = new X86Writer(code, { pc: page });"

        "cw.putMovRegU32('eax', 42);"

        "var stackAlignOffset = Process.pointerSize;"
        "cw.putSubRegImm('xsp', stackAlignOffset);"

        "cw.putCallAddressWithArguments(callback, ['eax', 7]);"

        "cw.putAddRegImm('xsp', stackAlignOffset);"

        "cw.putJmpShortLabel('badger');"

        "cw.putMovRegU32('eax', 43);"

        "cw.putLabel('badger');"
        "cw.putRet();"

        "cw.flush();"
        "send(cw.offset > 30);"
      "});"

      "var f = new NativeFunction(page, 'int', []);"
      "send(f());");

  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_SEND_MESSAGE_WITH ("294");
  EXPECT_NO_MESSAGES ();

  COMPILE_AND_LOAD_SCRIPT (
      "var code = Memory.alloc(16);"
      "var cw = new X86Writer(code);"
      "cw.putMovRegU32('rax', 42);");
  EXPECT_ERROR_MESSAGE_WITH (ANY_LINE_NUMBER, "Error: invalid argument");
#endif
}

TESTCASE (instruction_can_be_relocated)
{
#if defined (HAVE_I386)
  COMPILE_AND_LOAD_SCRIPT (
      "var page = Memory.alloc(Process.pageSize);"

      "var impl1 = page.add(0);"
      "var impl2 = page.add(64);"

      "Memory.patchCode(impl1, 16, function (code) {"
        "var cw = new X86Writer(code, { pc: impl1 });"
        "cw.putMovRegU32('eax', 42);"
        "cw.putRet();"
        "cw.flush();"
      "});"

      "Memory.patchCode(impl2, 16, function (code) {"
        "var cw = new X86Writer(code, { pc: impl2 });"
        "var rl = new X86Relocator(impl1, cw);"

        "send(rl.input);"

        "send(rl.readOne());"
        "send(rl.input.toString());"
        "send(rl.writeOne());"

        "send(rl.eob);"
        "send(rl.eoi);"

        "send(rl.readOne());"
        "send(rl.input.toString());"
        "send(rl.writeOne());"

        "send(rl.readOne());"
        "send(rl.eob);"
        "send(rl.eoi);"

        "cw.flush();"
      "});"

      "var f = new NativeFunction(impl2, 'int', []);"
      "send(f());");

  EXPECT_SEND_MESSAGE_WITH ("null");

  EXPECT_SEND_MESSAGE_WITH ("5");
  EXPECT_SEND_MESSAGE_WITH ("\"mov eax, 0x2a\"");
  EXPECT_SEND_MESSAGE_WITH ("true");

  EXPECT_SEND_MESSAGE_WITH ("false");
  EXPECT_SEND_MESSAGE_WITH ("false");

  EXPECT_SEND_MESSAGE_WITH ("6");
  EXPECT_SEND_MESSAGE_WITH ("\"ret\"");
  EXPECT_SEND_MESSAGE_WITH ("true");

  EXPECT_SEND_MESSAGE_WITH ("0");
  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_SEND_MESSAGE_WITH ("true");

  EXPECT_SEND_MESSAGE_WITH ("42");

  EXPECT_NO_MESSAGES ();
#endif
}

TESTCASE (address_can_be_resolved_to_symbol)
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

TESTCASE (name_can_be_resolved_to_symbol)
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

TESTCASE (function_can_be_found_by_name)
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

TESTCASE (functions_can_be_found_by_name)
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

TESTCASE (functions_can_be_found_by_matching)
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

TESTCASE (native_function_can_be_invoked)
{
  gchar str[7];

  COMPILE_AND_LOAD_SCRIPT (
      "var f = new NativeFunction(" GUM_PTR_CONST ", 'int', []);"
      "send(f());",
      gum_get_answer_to_life_universe_and_everything);
  EXPECT_SEND_MESSAGE_WITH ("42");
  EXPECT_NO_MESSAGES ();

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

  COMPILE_AND_LOAD_SCRIPT (
      "var sum = new NativeFunction(" GUM_PTR_CONST ", "
          "'int', ['pointer', 'pointer', 'float']);"
      "send(sum(ptr(3), ptr(4), 42.0));",
      gum_add_pointers_and_float_fixed);
  EXPECT_SEND_MESSAGE_WITH ("49");
  EXPECT_NO_MESSAGES ();

#ifdef G_OS_WIN32
  COMPILE_AND_LOAD_SCRIPT (
      "var impl = Module.getExportByName(\"user32.dll\", \"GetKeyState\");"
      "var f = new NativeFunction(impl, 'int16', ['int']);"
      "var result = f(0x41);"
      "send(typeof result);");
  EXPECT_SEND_MESSAGE_WITH ("\"number\"");
  EXPECT_NO_MESSAGES ();
#endif

  COMPILE_AND_LOAD_SCRIPT (
      "var classify = new NativeFunction(" GUM_PTR_CONST ", "
          "'int64', ['int64']);"
      "send(classify(int64(\"-42\")));"
      "send(classify(int64(\"0\")));"
      "send(classify(int64(\"42\")));",
      gum_classify_timestamp);
  EXPECT_SEND_MESSAGE_WITH ("\"-1\"");
  EXPECT_SEND_MESSAGE_WITH ("\"0\"");
  EXPECT_SEND_MESSAGE_WITH ("\"1\"");
  EXPECT_NO_MESSAGES ();

  COMPILE_AND_LOAD_SCRIPT (
      "var square = new NativeFunction(" GUM_PTR_CONST ", "
          "'uint64', ['uint64']);"
      "send(square(uint64(\"2\")));"
      "send(square(uint64(\"4\")));"
      "send(square(uint64(\"6\")));",
      gum_square);
  EXPECT_SEND_MESSAGE_WITH ("\"4\"");
  EXPECT_SEND_MESSAGE_WITH ("\"16\"");
  EXPECT_SEND_MESSAGE_WITH ("\"36\"");
  EXPECT_NO_MESSAGES ();
}

TESTCASE (native_function_can_be_intercepted_when_thread_is_ignored)
{
  GumInterceptor * interceptor;
  GMainContext * js_context;
  GSource * source;

  interceptor = gum_interceptor_obtain ();

  js_context = gum_script_scheduler_get_js_context (
      gum_script_backend_get_scheduler ());

  source = g_idle_source_new ();
  g_source_set_callback (source, (GSourceFunc) ignore_thread,
      g_object_ref (interceptor), g_object_unref);
  g_source_attach (source, js_context);
  g_source_unref (source);

  COMPILE_AND_LOAD_SCRIPT (
      "var impl = " GUM_PTR_CONST ";"
      "Interceptor.attach(impl, {"
      "  onEnter: function (args) {"
      "    send('>');"
      "  },"
      "  onLeave: function (retval) {"
      "    send('<');"
      "  }"
      "});"
      "Interceptor.flush();"
      "var f = new NativeFunction(impl, 'int', ['int']);"
      "send(f(42));",
      target_function_nested_a);

  EXPECT_SEND_MESSAGE_WITH ("\">\"");
  EXPECT_SEND_MESSAGE_WITH ("\"<\"");
  EXPECT_SEND_MESSAGE_WITH ("16855020");
  EXPECT_NO_MESSAGES ();

  source = g_idle_source_new ();
  g_source_set_callback (source, (GSourceFunc) unignore_thread,
      g_object_ref (interceptor), g_object_unref);
  g_source_attach (source, js_context);
  g_source_unref (source);

  g_object_unref (interceptor);
}

static gboolean
ignore_thread (GumInterceptor * interceptor)
{
  gum_interceptor_ignore_current_thread (interceptor);

  return FALSE;
}

static gboolean
unignore_thread (GumInterceptor * interceptor)
{
  gum_interceptor_unignore_current_thread (interceptor);

  return FALSE;
}

TESTCASE (native_function_should_implement_call_and_apply)
{
  COMPILE_AND_LOAD_SCRIPT (
      "var f = new NativeFunction(" GUM_PTR_CONST ", 'int', []);"
      "send(f.call());"
      "send(f.call(f));"
      "send(f.apply(f));"
      "send(f.apply(f, undefined));"
      "send(f.apply(f, null));"
      "send(f.apply(f, []));",
      gum_get_answer_to_life_universe_and_everything);
  EXPECT_SEND_MESSAGE_WITH ("42");
  EXPECT_SEND_MESSAGE_WITH ("42");
  EXPECT_SEND_MESSAGE_WITH ("42");
  EXPECT_SEND_MESSAGE_WITH ("42");
  EXPECT_SEND_MESSAGE_WITH ("42");
  EXPECT_SEND_MESSAGE_WITH ("42");
  EXPECT_NO_MESSAGES ();

  COMPILE_AND_LOAD_SCRIPT (
      "var f = new NativeFunction(" GUM_PTR_CONST ", 'int', ['int']);"
      "send(NativeFunction.prototype.call(f, 42));"
      "send(NativeFunction.prototype.apply(f, [42]));"
      "send(f.call(undefined, 42));"
      "send(f.apply(undefined, [42]));"
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
  EXPECT_SEND_MESSAGE_WITH ("1890");
  EXPECT_SEND_MESSAGE_WITH ("1890");
  EXPECT_SEND_MESSAGE_WITH ("16855020");
  EXPECT_SEND_MESSAGE_WITH ("16855020");
  EXPECT_NO_MESSAGES ();

  COMPILE_AND_LOAD_SCRIPT (
      "var f = new NativeFunction(" GUM_PTR_CONST ", 'pointer', "
      "    ['pointer', 'int']);"
      "send(f.call(null, ptr(4), 3));"
      "send(f.apply(null, [ptr(4), 3]));",
      target_function_base_plus_offset);
  EXPECT_SEND_MESSAGE_WITH ("\"0x7\"");
  EXPECT_SEND_MESSAGE_WITH ("\"0x7\"");
  EXPECT_NO_MESSAGES ();
}

TESTCASE (system_function_can_be_invoked)
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

TESTCASE (native_function_crash_results_in_exception)
{
  if (!check_exception_handling_testable ())
    return;

  COMPILE_AND_LOAD_SCRIPT (
      "var targetWithString = new NativeFunction(" GUM_PTR_CONST ", 'pointer', "
          "['pointer'], {"
          "abi: 'default',"
          "scheduling: 'exclusive',"
          "exceptions: 'steal',"
      "});"
      "try {"
      "  targetWithString(NULL);"
      "} catch (e) {"
      "  send(e.type);"
      "}",
      target_function_string);
  EXPECT_SEND_MESSAGE_WITH ("\"access-violation\"");
}

TESTCASE (nested_native_function_crash_is_handled_gracefully)
{
  if (!check_exception_handling_testable ())
    return;

  COMPILE_AND_LOAD_SCRIPT (
      "var targetWithCallback = new NativeFunction(" GUM_PTR_CONST ", "
          "'pointer', ['int', 'pointer', 'pointer']);"
      "var callback = new NativeCallback(function (value) {"
      "  send(value.readInt());"
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

TESTCASE (variadic_native_function_can_be_invoked)
{
  COMPILE_AND_LOAD_SCRIPT (
      "var sum = new NativeFunction(" GUM_PTR_CONST ", "
          "'int', ['int', '...', 'int']);"
      "send(sum(0));"
      "send(sum(1, 1));"
      "send(sum(3, 1, 2, 3));",
      gum_sum);
  EXPECT_SEND_MESSAGE_WITH ("0");
  EXPECT_SEND_MESSAGE_WITH ("1");
  EXPECT_SEND_MESSAGE_WITH ("6");
  EXPECT_NO_MESSAGES ();
}

TESTCASE (variadic_native_function_args_smaller_than_int_should_be_promoted)
{
  COMPILE_AND_LOAD_SCRIPT (
      "var f = new NativeFunction(" GUM_PTR_CONST ", 'int', "
          "['pointer', 'pointer', 'pointer', 'pointer', '...', "
          "'uint8', 'pointer', 'uint8']);"
      "var val = NULL.not();"
      "send(f(val, val, val, val, 13, val, 37));",
      gum_assert_variadic_uint8_values_are_sane);
  EXPECT_SEND_MESSAGE_WITH ("42");
}

static gint
gum_assert_variadic_uint8_values_are_sane (gpointer a,
                                           gpointer b,
                                           gpointer c,
                                           gpointer d,
                                           ...)
{
  va_list args;
  gint e;
  gint g;

  va_start (args, d);
  e = va_arg (args, gint);
  va_arg (args, gpointer);
  g = va_arg (args, gint);
  va_end (args);

  g_assert_cmphex (e, ==, 13);
  g_assert_cmphex (g, ==, 37);

  return 42;
}

TESTCASE (variadic_native_function_float_args_should_be_promoted_to_double)
{
  COMPILE_AND_LOAD_SCRIPT (
      "var sum = new NativeFunction(" GUM_PTR_CONST ", "
          "'int', ['pointer', '...', 'pointer', 'float']);"
      "send(sum(ptr(3), NULL));"
      "send(sum(ptr(3), ptr(4), 42.0, NULL));"
      "send(sum(ptr(3), ptr(4), 42.0, ptr(100), 200.0, NULL));",
      gum_add_pointers_and_float_variadic);
  EXPECT_SEND_MESSAGE_WITH ("3");
  EXPECT_SEND_MESSAGE_WITH ("49");
  EXPECT_SEND_MESSAGE_WITH ("349");
  EXPECT_NO_MESSAGES ();
}

TESTCASE (native_function_is_a_native_pointer)
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

TESTCASE (native_callback_can_be_invoked)
{
  gint (* toupper_impl) (gchar * str, gint limit);
  gchar str[7];

  COMPILE_AND_LOAD_SCRIPT (
      "var toupper = new NativeCallback(function (str, limit) {"
      "  var count = 0;"
      "  while (count < limit || limit === -1) {"
      "    var p = str.add(count);"
      "    var b = p.readU8();"
      "    if (b === 0)"
      "      break;"
      "    p.writeU8(String.fromCharCode(b).toUpperCase().charCodeAt(0));"
      "    count++;"
      "  }"
      "  return (limit === -1) ? -count : count;"
      "}, 'int', ['pointer', 'int']);"
      "gc();"
      "send(toupper);");

  toupper_impl = EXPECT_SEND_MESSAGE_WITH_POINTER ();
  g_assert_nonnull (toupper_impl);

  strcpy (str, "badger");
  g_assert_cmpint (toupper_impl (str, 3), ==, 3);
  g_assert_cmpstr (str, ==, "BADger");
  g_assert_cmpint (toupper_impl (str, -1), ==, -6);
  g_assert_cmpstr (str, ==, "BADGER");
}

TESTCASE (native_callback_is_a_native_pointer)
{
  COMPILE_AND_LOAD_SCRIPT (
      "var cb = new NativeCallback(function () {}, 'void', []);"
      "send(cb instanceof NativePointer);");
  EXPECT_SEND_MESSAGE_WITH ("true");
}

TESTCASE (native_callback_memory_should_be_eagerly_reclaimed)
{
  guint usage_before, usage_after;
  gboolean difference_is_less_than_2x;

  COMPILE_AND_LOAD_SCRIPT (
      "var iterationsRemaining = null;"
      "recv('start', onStartRequest);"
      "function onStartRequest(message) {"
      "  iterationsRemaining = message.iterations;"
      "  processNext();"
      "}"
      "function processNext() {"
      "  var cb = new NativeCallback(function () {}, 'void', []);"
      "  if (--iterationsRemaining === 0) {"
      "    recv('start', onStartRequest);"
      "    gc();"
      "    send('done');"
      "  } else {"
      "    setTimeout(processNext, 0);"
      "  }"
      "}");
  EXPECT_NO_MESSAGES ();

  PUSH_TIMEOUT (20000);

  POST_MESSAGE ("{\"type\":\"start\",\"iterations\":5000}");
  EXPECT_SEND_MESSAGE_WITH ("\"done\"");
  EXPECT_NO_MESSAGES ();

  usage_before = gum_peek_private_memory_usage ();

  POST_MESSAGE ("{\"type\":\"start\",\"iterations\":5000}");
  EXPECT_SEND_MESSAGE_WITH ("\"done\"");
  EXPECT_NO_MESSAGES ();

  usage_after = gum_peek_private_memory_usage ();

  POP_TIMEOUT ();

  difference_is_less_than_2x = usage_after < usage_before * 2;
  if (!difference_is_less_than_2x)
  {
    g_printerr ("\n\n"
        "Oops, memory usage is not looking good:\n"
        "\tusage before: %u\n"
        "\t    vs after: %u\n\n",
        usage_before, usage_after);
    g_assert_true (difference_is_less_than_2x);
  }
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

TESTCASE (unix_fd_can_be_read_from)
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

TESTCASE (unix_fd_can_be_written_to)
{
  gint fds[2];
  guint8 buffer[8];
  sig_t original_sigpipe_handler;

  if (gum_process_is_debugger_attached ())
  {
    g_print ("<skipping, debugger is attached> ");
    return;
  }

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

TESTCASE (basic_hexdump_functionality_is_available)
{
  COMPILE_AND_LOAD_SCRIPT (
      "var str = Memory.allocUtf8String(\"Hello hex world! w00t\");"
      "var buf = str.readByteArray(22);"
      "send(hexdump(buf));");
  EXPECT_SEND_MESSAGE_WITH ("\""
      "           0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F  "
          "0123456789ABCDEF\\n"
      "00000000  48 65 6c 6c 6f 20 68 65 78 20 77 6f 72 6c 64 21  "
          "Hello hex world!\\n"
      "00000010  20 77 30 30 74 00                                "
          " w00t.\"");

  COMPILE_AND_LOAD_SCRIPT (
      "var str = Memory.allocUtf8String(\"Hello hex world! w00t\");"
      "send(hexdump(str, { address: uint64('0x100000000'), length: 22 }));");
  EXPECT_SEND_MESSAGE_WITH ("\""
      "            0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F  "
          "0123456789ABCDEF\\n"
      "100000000  48 65 6c 6c 6f 20 68 65 78 20 77 6f 72 6c 64 21  "
          "Hello hex world!\\n"
      "100000010  20 77 30 30 74 00                                "
          " w00t.\"");
}

TESTCASE (hexdump_supports_native_pointer_conforming_object)
{
  const gchar * message = "Hello hex world!";

  COMPILE_AND_LOAD_SCRIPT (
      "var obj = { handle: " GUM_PTR_CONST "  };"
      "send(hexdump(obj, { address: NULL, length: 16 }));", message);
  EXPECT_SEND_MESSAGE_WITH ("\""
      "           0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F  "
          "0123456789ABCDEF\\n"
      "00000000  48 65 6c 6c 6f 20 68 65 78 20 77 6f 72 6c 64 21  "
          "Hello hex world!\"");
}

TESTCASE (native_pointer_provides_is_null)
{
  COMPILE_AND_LOAD_SCRIPT (
      "send(ptr(\"0\").isNull());"
      "send(ptr(\"1337\").isNull());");
  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_SEND_MESSAGE_WITH ("false");
}

TESTCASE (native_pointer_provides_arithmetic_operations)
{
  COMPILE_AND_LOAD_SCRIPT (
      "send(ptr(3).add(4).toInt32());"
      "send(ptr(7).sub(4).toInt32());"
      "send(ptr(6).and(3).toInt32());"
      "send(ptr(6).or(3).toInt32());"
      "send(ptr(6).xor(3).toInt32());"
      "send(ptr(63).shr(4).toInt32());"
      "send(ptr(1).shl(3).toInt32());"
      "send(ptr(0).not().toInt32());");
  EXPECT_SEND_MESSAGE_WITH ("7");
  EXPECT_SEND_MESSAGE_WITH ("3");
  EXPECT_SEND_MESSAGE_WITH ("2");
  EXPECT_SEND_MESSAGE_WITH ("7");
  EXPECT_SEND_MESSAGE_WITH ("5");
  EXPECT_SEND_MESSAGE_WITH ("3");
  EXPECT_SEND_MESSAGE_WITH ("8");
  EXPECT_SEND_MESSAGE_WITH ("-1");
}

TESTCASE (native_pointer_provides_uint32_conversion_functionality)
{
  COMPILE_AND_LOAD_SCRIPT ("send(ptr(1).toUInt32());");
  EXPECT_SEND_MESSAGE_WITH ("1");
}

TESTCASE (native_pointer_provides_ptrauth_functionality)
{
#ifdef HAVE_PTRAUTH
  COMPILE_AND_LOAD_SCRIPT (
      "var original = ptr(1);"

      "var a = original.sign();"
      "send(a.equals(original));"
      "send(a.strip().equals(original));"

      "send(original.sign('ia').equals(a));"
      "send(original.sign('ib').equals(a));"
      "send(original.sign('da').equals(a));"
      "send(original.sign('db').equals(a));"

      "var b = original.sign('ia', ptr(1337));"
      "send(b.equals(a));"
      "var c = original.sign('ia', 1337);"
      "send(c.equals(b));"
      "var d = original.sign('ia', ptr(1337).blend(42));"
      "send(d.equals(b));"

      "try {"
          "original.sign('x');"
      "} catch (e) {"
          "send(e.message);"
      "}");

  EXPECT_SEND_MESSAGE_WITH ("false");
  EXPECT_SEND_MESSAGE_WITH ("true");

  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_SEND_MESSAGE_WITH ("false");
  EXPECT_SEND_MESSAGE_WITH ("false");
  EXPECT_SEND_MESSAGE_WITH ("false");

  EXPECT_SEND_MESSAGE_WITH ("false");
  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_SEND_MESSAGE_WITH ("false");

  EXPECT_SEND_MESSAGE_WITH ("\"invalid key\"");
#else
  COMPILE_AND_LOAD_SCRIPT (
      "var original = ptr(1);"
      "send(original.sign() === original);"
      "send(original.strip() === original);"
      "send(original.blend(42) === original);");

  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_SEND_MESSAGE_WITH ("true");
#endif

  EXPECT_NO_MESSAGES ();
}

TESTCASE (native_pointer_to_match_pattern)
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

TESTCASE (native_pointer_can_be_constructed_from_64bit_value)
{
  COMPILE_AND_LOAD_SCRIPT (
      "send(ptr(uint64(0x1ffffffff)).equals(ptr(0x1ffffffff)));"
      "send(ptr(int64(0x2ffffffff)).equals(ptr(0x2ffffffff)));");
  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_SEND_MESSAGE_WITH ("true");

#if GLIB_SIZEOF_VOID_P == 4
  COMPILE_AND_LOAD_SCRIPT (
      "send(ptr(int64(-150450112)).equals(ptr('0xf7085040')));");
  EXPECT_SEND_MESSAGE_WITH ("true");
#elif GLIB_SIZEOF_VOID_P == 8
  COMPILE_AND_LOAD_SCRIPT (
      "send(ptr(int64(-1)).equals(ptr('0xffffffffffffffff')));");
  EXPECT_SEND_MESSAGE_WITH ("true");
#endif
}

TESTCASE (array_buffer_can_wrap_memory_region)
{
  guint8 val[2] = { 13, 37 };

  COMPILE_AND_LOAD_SCRIPT (
      "var val = new Uint8Array(ArrayBuffer.wrap(" GUM_PTR_CONST ", 2));"
      "send(val.length);"
      "send(val[0]);"
      "send(val[1]);"
      "val[0] = 42;"
      "val[1] = 24;",
      val);
  EXPECT_SEND_MESSAGE_WITH ("2");
  EXPECT_SEND_MESSAGE_WITH ("13");
  EXPECT_SEND_MESSAGE_WITH ("37");
  g_assert_cmpint (val[0], ==, 42);
  g_assert_cmpint (val[1], ==, 24);

  COMPILE_AND_LOAD_SCRIPT (
      "var val = new Uint8Array(ArrayBuffer.wrap(" GUM_PTR_CONST ", 0));"
      "send(val.length);"
      "send(typeof val[0]);",
      val);
  EXPECT_SEND_MESSAGE_WITH ("0");
  EXPECT_SEND_MESSAGE_WITH ("\"undefined\"");

  COMPILE_AND_LOAD_SCRIPT (
      "var val = new Uint8Array(ArrayBuffer.wrap(NULL, 0));"
      "send(val.length);"
      "send(typeof val[0]);");
  EXPECT_SEND_MESSAGE_WITH ("0");
  EXPECT_SEND_MESSAGE_WITH ("\"undefined\"");
}

TESTCASE (array_buffer_can_be_unwrapped)
{
  gchar str[5 + 1];

  COMPILE_AND_LOAD_SCRIPT (
      "var toupper = new NativeFunction(" GUM_PTR_CONST ", "
          "'int', ['pointer', 'int']);"
      "var buf = new ArrayBuffer(2 + 1);"
      "var bytes = new Uint8Array(buf);"
      "bytes[0] = 'h'.charCodeAt(0);"
      "bytes[1] = 'i'.charCodeAt(0);"
      "send(toupper(buf.unwrap(), -1));"
      "send(bytes[0]);"
      "send(bytes[1]);",
      gum_toupper, str);
  EXPECT_SEND_MESSAGE_WITH ("-2");
  EXPECT_SEND_MESSAGE_WITH ("72");
  EXPECT_SEND_MESSAGE_WITH ("73");
  EXPECT_NO_MESSAGES ();

  strcpy (str, "snake");
  COMPILE_AND_LOAD_SCRIPT (
      "var toupper = new NativeFunction(" GUM_PTR_CONST ", "
          "'int', ['pointer', 'int']);"
      "var buf = ArrayBuffer.wrap(" GUM_PTR_CONST ", 5 + 1);"
      "send(toupper(buf.unwrap(), -1));",
      gum_toupper, str);
  EXPECT_SEND_MESSAGE_WITH ("-5");
  EXPECT_NO_MESSAGES ();
  g_assert_cmpstr (str, ==, "SNAKE");
}

TESTCASE (uint64_provides_arithmetic_operations)
{
  COMPILE_AND_LOAD_SCRIPT (
      "send(uint64(3).add(4).toNumber());"
      "send(uint64(7).sub(4).toNumber());"
      "send(uint64(6).and(3).toNumber());"
      "send(uint64(6).or(3).toNumber());"
      "send(uint64(6).xor(3).toNumber());"
      "send(uint64(63).shr(4).toNumber());"
      "send(uint64(1).shl(3).toNumber());"
      "send(uint64(0).not().toString());");
  EXPECT_SEND_MESSAGE_WITH ("7");
  EXPECT_SEND_MESSAGE_WITH ("3");
  EXPECT_SEND_MESSAGE_WITH ("2");
  EXPECT_SEND_MESSAGE_WITH ("7");
  EXPECT_SEND_MESSAGE_WITH ("5");
  EXPECT_SEND_MESSAGE_WITH ("3");
  EXPECT_SEND_MESSAGE_WITH ("8");
  EXPECT_SEND_MESSAGE_WITH ("\"18446744073709551615\"");
}

TESTCASE (int64_provides_arithmetic_operations)
{
  COMPILE_AND_LOAD_SCRIPT (
      "send(int64(3).add(4).toNumber());"
      "send(int64(7).sub(4).toNumber());"
      "send(int64(6).and(3).toNumber());"
      "send(int64(6).or(3).toNumber());"
      "send(int64(6).xor(3).toNumber());"
      "send(int64(63).shr(4).toNumber());"
      "send(int64(1).shl(3).toNumber());"
      "send(int64(0).not().toNumber());");
  EXPECT_SEND_MESSAGE_WITH ("7");
  EXPECT_SEND_MESSAGE_WITH ("3");
  EXPECT_SEND_MESSAGE_WITH ("2");
  EXPECT_SEND_MESSAGE_WITH ("7");
  EXPECT_SEND_MESSAGE_WITH ("5");
  EXPECT_SEND_MESSAGE_WITH ("3");
  EXPECT_SEND_MESSAGE_WITH ("8");
  EXPECT_SEND_MESSAGE_WITH ("-1");
}

static gint
gum_get_answer_to_life_universe_and_everything (void)
{
  return 42;
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
  va_list args;
  gint i;

  va_start (args, count);
  for (i = 0; i != count; i++)
    total += va_arg (args, gint);
  va_end (args);

  return total;
}

static gint
gum_add_pointers_and_float_fixed (gpointer a,
                                  gpointer b,
                                  float c)
{
  return GPOINTER_TO_SIZE (a) + GPOINTER_TO_SIZE (b) + (int) c;
}

static gint
gum_add_pointers_and_float_variadic (gpointer a,
                                     ...)
{
  gint total = GPOINTER_TO_SIZE (a);
  va_list args;
  gpointer p;

  va_start (args, a);
  while ((p = va_arg (args, gpointer)) != NULL)
  {
    total += GPOINTER_TO_SIZE (p);
    total += (int) va_arg (args, double); /* float is promoted to double */
  }
  va_end (args);

  return total;
}

TESTCASE (file_can_be_written_to)
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
      "log.write(" GUM_PTR_CONST ".readByteArray(4));"
      "log.write(\"!\\n\");"
      "log.close();",
      d00d);
  EXPECT_NO_MESSAGES ();
}

TESTCASE (inline_sqlite_database_can_be_queried)
{
  COMPILE_AND_LOAD_SCRIPT (
      "var db = SqliteDatabase.openInline('"
          "H4sIAMMIT1kAA+3ZsU7DMBAG4HMC7VChROpQut0IqGJhYCWJDAq4LbhGoqNRDYqgpIo"
          "CO8y8JM/AC+CKFNhgLfo/+U7n0/kBTp5cqKJ2fFNWc1vzAcUkBB0xE1HYxIrwsdHUYX"
          "P/TUj7m+nWcjhy5A8AAAAAAADA//W8Ldq9fl+8dGp7fe8WrlyscphpmRjJJkmV5M8e7"
          "xQzzkdGnkjN5zofJnrKZ3LKySQb8IOdOzbyyvBo7ONSqQHbW/f14Lt7Z/1S7+uh1Hn2"
          "c/rJ1rbiVI3T3b8s8QAAAAAAAACw3pZ/80H0RtG7TwAAAAAAAACwnuKgRT0RxMdVMbN"
          "teu0edkSLukLQaen2Hj8AoNOJGgAwAAA="
      "');\n"

      /* 1: bindInteger() */
      "var s = db.prepare('SELECT name, age FROM people WHERE age = ?');\n"
      "s.bindInteger(1, 42);\n"
      "send(s.step());\n"
      "send(s.step());\n"
      "s.reset();\n"
      "s.bindInteger(1, 7);\n"
      "send(s.step());\n"

      /* 2: bindFloat() */
      "s = db.prepare('SELECT name FROM people WHERE karma <= ?');\n"
      "s.bindFloat(1, 117.5);\n"
      "send(s.step());\n"
      "send(s.step());\n"

      /* 3: bindText() */
      "s = db.prepare('SELECT age FROM people WHERE name = ?');\n"
      "s.bindText(1, 'Joe');\n"
      "send(s.step());\n"

      /* 4: bindBlob() */
      "s = db.prepare('SELECT name FROM people WHERE avatar = ?');\n"
      "s.bindBlob(1, [0x13, 0x37]);\n"
      "send(s.step());\n"
      "send(s.step());\n"

      /* 5: bindNull() */
      "s = db.prepare('INSERT INTO people VALUES (?, ?, ?, ?, ?)');\n"
      "s.bindInteger(1, 3);\n"
      "s.bindText(2, 'Alice');\n"
      "s.bindInteger(3, 40);\n"
      "s.bindInteger(4, 150);\n"
      "s.bindNull(5);\n"
      "send(s.step());\n"
      "s = db.prepare('SELECT * FROM people WHERE name = \"Alice\"');\n"
      "send(s.step());\n"
      "send(s.step());\n"

      /* 6: blob column */
      "s = db.prepare('SELECT avatar FROM people WHERE name = ?');\n"
      "s.bindText(1, 'Frida');\n"
      "send('avatar', s.step()[0]);\n"
      "send(s.step());\n"
      "s.reset();\n"
      "s.bindText(1, 'Joe');\n"
      "send(s.step());\n"
      "send(s.step());\n");

  /* 1: bindInteger() */
  EXPECT_SEND_MESSAGE_WITH ("[\"Joe\",42]");
  EXPECT_SEND_MESSAGE_WITH ("null");
  EXPECT_SEND_MESSAGE_WITH ("[\"Frida\",7]");

  /* 2: bindFloat() */
  EXPECT_SEND_MESSAGE_WITH ("[\"Joe\"]");
  EXPECT_SEND_MESSAGE_WITH ("null");

  /* 3: bindText() */
  EXPECT_SEND_MESSAGE_WITH ("[42]");

  /* 4: bindBlob() */
  EXPECT_SEND_MESSAGE_WITH ("[\"Frida\"]");
  EXPECT_SEND_MESSAGE_WITH ("null");

  /* 5: bindNull() */
  EXPECT_SEND_MESSAGE_WITH ("null");
  EXPECT_SEND_MESSAGE_WITH ("[3,\"Alice\",40,150,null]");
  EXPECT_SEND_MESSAGE_WITH ("null");

  /* 6: blob column */
  EXPECT_SEND_MESSAGE_WITH_PAYLOAD_AND_DATA ("\"avatar\"", "13 37");
  EXPECT_SEND_MESSAGE_WITH ("null");
  EXPECT_SEND_MESSAGE_WITH ("[null]");
  EXPECT_SEND_MESSAGE_WITH ("null");
  EXPECT_NO_MESSAGES ();
}

TESTCASE (external_sqlite_database_can_be_queried)
{
  TestScriptMessageItem * item;

  if (!g_test_slow ())
  {
    g_print ("<skipping, run in slow mode> ");
    return;
  }

  COMPILE_AND_LOAD_SCRIPT (
      "var db = SqliteDatabase.open('/tmp/gum-test.db');\n"
      "db.exec(\""
          "PRAGMA foreign_keys=OFF;"
          "BEGIN TRANSACTION;"
          "CREATE TABLE people ("
              "id INTEGER PRIMARY KEY ASC,"
              "name TEXT NOT NULL,"
              "age INTEGER NOT NULL,"
              "karma NUMERIC NOT NULL,"
              "avatar BLOB"
          ");"
          "INSERT INTO people VALUES (1, 'Joe', 42, 117, NULL);"
          "INSERT INTO people VALUES (2, 'Frida', 7, 140, X'1337');"
          "COMMIT;"
      "\");\n"
      "send(db.dump());\n"
      "db.close();\n");

  item = test_script_fixture_pop_message (fixture);
  g_print ("%s\n", item->message);
  test_script_message_item_free (item);
}

TESTCASE (external_sqlite_database_can_be_opened_with_flags)
{
  if (!g_test_slow ())
  {
    g_print ("<skipping, run in slow mode> ");
    return;
  }

  COMPILE_AND_LOAD_SCRIPT (
      "var db = null;\n"

      "try {\n"
          "db = SqliteDatabase.open('/tmp/gum-test-dont-create.db',"
            "{ flags: ['readwrite'] });\n"
          "send('fail');\n"
          "db.close();\n"
      "} catch (e) {\n"
          "send('not exists');\n"
      "}\n"

      "try {\n"
          "db = SqliteDatabase.open('/tmp/gum-test-dont-create2.db',"
            "{ flags: ['readonly'] });\n"
          "send('fail');\n"
          "db.close();\n"
      "} catch (e) {\n"
          "send('not exists again');\n"
      "}\n"

      "try {\n"
          "db = SqliteDatabase.open('/tmp/gum-test-dont-write.db',"
            "{ flags: ['readonly', 'create'] });\n"
          "send('fail');\n"
          "db.close();\n"
      "} catch (e) {\n"
          "send('invalid flags');\n"
      "}\n"

      "db = SqliteDatabase.open('/tmp/gum-test-can-write.db',"
        "{ flags: ['readwrite', 'create'] });\n"
      "try {\n"
          "db.exec(\""
              "PRAGMA foreign_keys=OFF;"
              "BEGIN TRANSACTION;"
              "CREATE TABLE people ("
                  "id INTEGER PRIMARY KEY ASC,"
                  "name TEXT NOT NULL,"
                  "age INTEGER NOT NULL,"
                  "karma NUMERIC NOT NULL,"
                  "avatar BLOB"
              ");"
              "INSERT INTO people VALUES (1, 'Joe', 42, 117, NULL);"
              "INSERT INTO people VALUES (2, 'Frida', 7, 140, X'1337');"
              "COMMIT;"
          "\");\n"
          "send('can write');\n"
      "} catch (e) {\n"
          "send('fail');\n"
      "}\n"
      "db.close();\n");

  EXPECT_SEND_MESSAGE_WITH ("\"not exists\"");
  EXPECT_SEND_MESSAGE_WITH ("\"not exists again\"");
  EXPECT_SEND_MESSAGE_WITH ("\"invalid flags\"");
  EXPECT_SEND_MESSAGE_WITH ("\"can write\"");
  EXPECT_NO_MESSAGES ();
}

TESTCASE (socket_connection_can_be_established)
{
#ifdef HAVE_ANDROID
  if (!g_test_slow ())
  {
    g_print ("<skipping, run in slow mode> ");
    return;
  }
#endif

  PUSH_TIMEOUT (10000);

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
        "    Module.getExportByName(null, 'getpid'), 'int', []);"
        "var unlink = new NativeFunction("
        "    Module.getExportByName(null, 'unlink'), 'int', ['pointer']);"
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

TESTCASE (socket_connection_can_be_established_with_tls)
{
  gboolean done;

  if (!g_test_slow ())
  {
    g_print ("<skipping, run in slow mode> ");
    return;
  }

  PUSH_TIMEOUT (10000);

  COMPILE_AND_LOAD_SCRIPT (
      "Socket.connect({"
      "  family: 'ipv4',"
      "  host: 'www.google.com',"
      "  port: 443,"
      "  tls: true,"
      "})"
      ".then(function (connection) {"
      "  return connection.setNoDelay(true)"
      "  .then(function () {"
      "    var request = ["
      "      'GET / HTTP/1.1',"
      "      'Connection: close',"
      "      'Host: www.google.com',"
      "      'Accept: text/html',"
      "      'User-Agent: Frida/" FRIDA_VERSION "',"
      "      '',"
      "      '',"
      "    ].join('\\r\\n');"
      "    var rawRequest = [];"
      "    for (var i = 0; i !== request.length; i++)"
      "      rawRequest.push(request.charCodeAt(i));"
      "    send('request', rawRequest);"
      "    return connection.output.writeAll(rawRequest)"
      "    .then(function () {"
      "      return connection.input.read(128 * 1024);"
      "    })"
      "    .then(function (data) {"
      "      send('response', data);"
      "    });"
      "  });"
      "})"
      ".catch(function (error) {"
      "  send('error: ' + error.message);"
      "});");

  g_printerr ("\n\n");

  done = FALSE;
  while (!done)
  {
    TestScriptMessageItem * item;

    item = test_script_fixture_pop_message (fixture);

    if (item->raw_data != NULL)
    {
      gboolean is_request;
      const guint8 * raw_chunk;
      gsize size;
      gchar * chunk;

      is_request = strstr (item->message, "\"request\"") != NULL;

      raw_chunk = g_bytes_get_data (item->raw_data, &size);
      chunk = g_strndup ((const gchar *) raw_chunk, size);

      g_printerr ("*** %s %" G_GSIZE_MODIFIER "u bytes\n%s",
          is_request ? "Sent" : "Received",
          size,
          chunk);

      g_free (chunk);

      done = !is_request;
    }
    else
    {
      g_printerr ("Got: %s\n", item->message);
    }

    test_script_message_item_free (item);
  }
}

TESTCASE (socket_connection_should_not_leak_on_error)
{
  PUSH_TIMEOUT (5000);
  COMPILE_AND_LOAD_SCRIPT (
      "var tries = 0;"
      "var port = 28300;"
      "var firstErrorMessage = null;"
      ""
      "tryNext();"
      ""
      "function tryNext() {"
      "  tries++;"
      "  if (tries === 200) {"
      "    send('done');"
      "    return;"
      "  }"
      ""
      "  Socket.connect({"
      "    family: 'ipv4',"
      "    host: 'localhost',"
      "    port: port,"
      "  })"
      "  .then(function (connection) {"
      "    console.log('success');"
      "    tries--;"
      "    port++;"
      "    tryNext();"
      "  })"
      "  .catch(function (error) {"
      "    if (firstErrorMessage === null) {"
      "      firstErrorMessage = error.message;"
      "    } else if (error.message !== firstErrorMessage) {"
      "      send('Expected \"' + firstErrorMessage + '\" but got \"' +"
      "          error.message + '\"');"
      "      return;"
      "    }"
      "    console.log('tries=' + tries + ' error=\"' + error.message + '\"');"
      "    tryNext();"
      "  });"
      "}");
  EXPECT_SEND_MESSAGE_WITH ("\"done\"");
}

TESTCASE (socket_type_can_be_inspected)
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
  g_assert_cmpint (fd, >=, 0);
  COMPILE_AND_LOAD_SCRIPT ("send(Socket.type(%d));", fd);
  EXPECT_SEND_MESSAGE_WITH ("null");
  close (fd);
#endif
}

#ifndef HAVE_ANDROID

TESTCASE (socket_endpoints_can_be_inspected)
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

    g_assert_true (g_socket_connect (socket, server_address, NULL, NULL));

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

#if defined (HAVE_I386) || defined (HAVE_ARM64)

#include "stalkerdummychannel.h"

TESTCASE (execution_can_be_traced)
{
  GumThreadId test_thread_id;

  test_thread_id = gum_process_get_current_thread_id ();

  COMPILE_AND_LOAD_SCRIPT (
      "var testsRange = Process.getModuleByName('%s');"
      "Stalker.exclude(testsRange);"

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
      "});",

      GUM_TESTS_MODULE_NAME,
      test_thread_id,
      test_thread_id);
  g_usleep (1);
  EXPECT_NO_MESSAGES ();

  POST_MESSAGE ("{\"type\":\"stop\"}");
  EXPECT_SEND_MESSAGE_WITH ("\"onCallSummary: true\"");
  EXPECT_SEND_MESSAGE_WITH ("\"onReceive: true\"");
}

TESTCASE (execution_can_be_traced_with_custom_transformer)
{
  GumThreadId test_thread_id;

  test_thread_id = gum_process_get_current_thread_id ();

  COMPILE_AND_LOAD_SCRIPT (
      "var testsRange = Process.getModuleByName('%s');"
      "Stalker.exclude(testsRange);"

      "var instructionsSeen = 0;"
      "Stalker.follow(%" G_GSIZE_FORMAT ", {"
      "  transform: function (iterator) {"
      "    var instruction;"

      "    while ((instruction = iterator.next()) !== null) {"
      "      if (instructionsSeen === 0) {"
      "        iterator.putCallout(onBeforeFirstInstruction);"
      "      }"

      "      iterator.keep();"

      "      instructionsSeen++;"
      "    }"
      "  }"
      "});"

      "function onBeforeFirstInstruction (context) {"
      "  console.log(JSON.stringify(context, null, 2));"
      "}"

      "recv('stop', function (message) {"
      "  Stalker.unfollow(%" G_GSIZE_FORMAT ");"
      "  send(instructionsSeen > 0);"
      "});",

      GUM_TESTS_MODULE_NAME,
      test_thread_id,
      test_thread_id);
  g_usleep (1);
  EXPECT_NO_MESSAGES ();

  POST_MESSAGE ("{\"type\":\"stop\"}");
  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_NO_MESSAGES ();
}

TESTCASE (execution_can_be_traced_with_faulty_transformer)
{
  GumThreadId test_thread_id;

  test_thread_id = gum_process_get_current_thread_id ();

  COMPILE_AND_LOAD_SCRIPT (
      "var testsRange = Process.getModuleByName('%s');"
      "Stalker.exclude(testsRange);"

      "Stalker.follow(%" G_GSIZE_FORMAT ", {"
      "  transform: function (iterator) {"
      "    throw new Error('Oh no I am buggy');"
      "  }"
      "});",

      GUM_TESTS_MODULE_NAME,
      test_thread_id);
  g_usleep (1);
  EXPECT_ERROR_MESSAGE_WITH (ANY_LINE_NUMBER, "Error: Oh no I am buggy");
  EXPECT_NO_MESSAGES ();

  g_assert (
      !gum_stalker_is_following_me (gum_script_get_stalker (fixture->script)));
}

TESTCASE (execution_can_be_traced_during_immediate_native_function_call)
{
  COMPILE_AND_LOAD_SCRIPT (
      "var testsRange = Process.getModuleByName('%s');"
      "Stalker.exclude(testsRange);"

      "var a = new NativeFunction(" GUM_PTR_CONST ", 'int', ['int'], "
          "{ traps: 'all', exceptions: 'propagate' });"

      "var flushing = false;"
      "Stalker.follow({"
      "  events: {"
      "    call: true,"
      "  },"
      "  onCallSummary: function (summary) {"
      "    if (!flushing)"
      "      return;"
      "    var key = a.strip().toString();"
      "    send(key in summary);"
      "    send(summary[key]);"
      "  }"
      "});"

      "a(42);"
      "a(42);"

      "Stalker.unfollow();"

      "flushing = true;"
      "Stalker.flush();"
      "flushing = false;",

      GUM_TESTS_MODULE_NAME,
      target_function_nested_a);
  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_SEND_MESSAGE_WITH ("2");
  EXPECT_NO_MESSAGES ();
}

TESTCASE (execution_can_be_traced_during_scheduled_native_function_call)
{
  COMPILE_AND_LOAD_SCRIPT (
      "var testsRange = Process.getModuleByName('%s');"
      "Stalker.exclude(testsRange);"

      "var a = new NativeFunction(" GUM_PTR_CONST ", 'int', ['int'], "
          "{ traps: 'all' });"

      "var flushing = false;"
      "Stalker.follow({"
      "  events: {"
      "    call: true,"
      "  },"
      "  onCallSummary: function (summary) {"
      "    if (!flushing)"
      "      return;"
      "    var key = a.strip().toString();"
      "    send(key in summary);"
      "    send(summary[key]);"
      "  }"
      "});"

      "setImmediate(function () {"
        "a(42);"
        "a(42);"

        "Stalker.unfollow();"

        "flushing = true;"
        "Stalker.flush();"
        "flushing = false;"
      "});",

      GUM_TESTS_MODULE_NAME,
      target_function_nested_a);
  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_SEND_MESSAGE_WITH ("2");
  EXPECT_NO_MESSAGES ();
}

TESTCASE (execution_can_be_traced_after_native_function_call_from_hook)
{
  StalkerDummyChannel channel;
  GThread * thread;
  GumThreadId thread_id;

  sdc_init (&channel);

  thread = g_thread_new ("stalker-test-target",
      run_stalked_through_hooked_function, &channel);
  thread_id = sdc_await_thread_id (&channel);

  COMPILE_AND_LOAD_SCRIPT (
      "var testsRange = Process.getModuleByName('%s');"
      "Stalker.exclude(testsRange);"

      "var targetThreadId = %" G_GSIZE_FORMAT ";"
      "var targetFuncInt = " GUM_PTR_CONST ";"
      "var targetFuncNestedA = new NativeFunction(" GUM_PTR_CONST ", 'int', "
          "['int'], { traps: 'all' });"

      "Interceptor.attach(targetFuncInt, function () {"
      "  targetFuncNestedA(1337);"
      "});"

      "Stalker.queueDrainInterval = 0;"

      "Stalker.follow(targetThreadId, {"
      "  events: {"
      "    call: true,"
      "  },"
      "  onCallSummary: function (summary) {"
      "    [targetFuncInt, targetFuncNestedA].forEach(function (target) {"
      "      var key = target.strip().toString();"
      "      send(key in summary);"
      "      send(summary[key]);"
      "    });"
      "  }"
      "});"

      "recv('stop', function (message) {"
      "  Stalker.unfollow(targetThreadId);"
      "  Stalker.flush();"
      "});"

      "send('ready');",

      GUM_TESTS_MODULE_NAME,
      thread_id,
      target_function_int,
      target_function_nested_a);
  EXPECT_SEND_MESSAGE_WITH ("\"ready\"");

  EXPECT_NO_MESSAGES ();
  sdc_put_follow_confirmation (&channel);

  sdc_await_run_confirmation (&channel);

  POST_MESSAGE ("{\"type\":\"stop\"}");
  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_SEND_MESSAGE_WITH ("1");
  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_SEND_MESSAGE_WITH ("2");
  EXPECT_NO_MESSAGES ();

  sdc_put_finish_confirmation (&channel);

  g_thread_join (thread);

  sdc_finalize (&channel);
}

static gpointer
run_stalked_through_hooked_function (gpointer data)
{
  StalkerDummyChannel * channel = data;

  sdc_put_thread_id (channel, gum_process_get_current_thread_id ());

  sdc_await_follow_confirmation (channel);

  target_function_int (42);

  target_function_nested_a (1338);

  sdc_put_run_confirmation (channel);

  sdc_await_finish_confirmation (channel);

  return NULL;
}

TESTCASE (call_can_be_probed)
{
  StalkerDummyChannel channel;
  GThread * thread;
  GumThreadId thread_id;

  sdc_init (&channel);

  thread = g_thread_new ("stalker-test-target",
      run_stalked_through_target_function, &channel);
  thread_id = sdc_await_thread_id (&channel);

  COMPILE_AND_LOAD_SCRIPT (
      "var targetThreadId = %" G_GSIZE_FORMAT ";"

      "Stalker.addCallProbe(" GUM_PTR_CONST ", function (args) {"
      "  send(args[0].toInt32());"
      "});"

      "Stalker.follow(targetThreadId);"

      "recv('stop', function (message) {"
      "  Stalker.unfollow(targetThreadId);"
      "});"

      "send('ready');",

      thread_id,
      target_function_int);
  EXPECT_SEND_MESSAGE_WITH ("\"ready\"");

  EXPECT_NO_MESSAGES ();
  sdc_put_follow_confirmation (&channel);
  EXPECT_SEND_MESSAGE_WITH ("1337");

  POST_MESSAGE ("{\"type\":\"stop\"}");

  g_thread_join (thread);

  sdc_finalize (&channel);
}

static gpointer
run_stalked_through_target_function (gpointer data)
{
  StalkerDummyChannel * channel = data;

  sdc_put_thread_id (channel, gum_process_get_current_thread_id ());

  sdc_await_follow_confirmation (channel);

  target_function_int (1337);

  return NULL;
}

#endif

TESTCASE (stalker_events_can_be_parsed)
{
  GumEvent ev;

  ev.type = GUM_CALL;
  ev.call.location = GSIZE_TO_POINTER (7);
  ev.call.target = GSIZE_TO_POINTER (12);
  ev.call.depth = 42;
  COMPILE_AND_LOAD_SCRIPT ("send(Stalker.parse(" GUM_PTR_CONST ".readByteArray("
      "%" G_GSIZE_FORMAT ")));", &ev, sizeof (ev));
  EXPECT_SEND_MESSAGE_WITH ("[[\"call\",\"0x7\",\"0xc\",42]]");

  COMPILE_AND_LOAD_SCRIPT ("send(Stalker.parse(new ArrayBuffer(0)));");
  EXPECT_SEND_MESSAGE_WITH ("[]");

  COMPILE_AND_LOAD_SCRIPT ("send(Stalker.parse(new ArrayBuffer(1)));");
  EXPECT_ERROR_MESSAGE_WITH (ANY_LINE_NUMBER, "Error: invalid buffer shape");

  COMPILE_AND_LOAD_SCRIPT ("send(Stalker.parse(new ArrayBuffer(%" G_GSIZE_FORMAT
      ")));", sizeof (GumEvent));
  EXPECT_ERROR_MESSAGE_WITH (ANY_LINE_NUMBER, "Error: invalid event type");
}

TESTCASE (frida_version_is_available)
{
  COMPILE_AND_LOAD_SCRIPT ("send(typeof Frida.version);");
  EXPECT_SEND_MESSAGE_WITH ("\"string\"");
}

TESTCASE (frida_heap_size_can_be_queried)
{
  COMPILE_AND_LOAD_SCRIPT ("send(typeof Frida.heapSize);");
  EXPECT_SEND_MESSAGE_WITH ("\"number\"");
}

TESTCASE (process_arch_is_available)
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

TESTCASE (process_platform_is_available)
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

TESTCASE (process_page_size_is_available)
{
  COMPILE_AND_LOAD_SCRIPT ("send(Process.pageSize);");
  EXPECT_SEND_MESSAGE_WITH ("%d", gum_query_page_size ());
}

TESTCASE (process_pointer_size_is_available)
{
  COMPILE_AND_LOAD_SCRIPT ("send(Process.pointerSize);");
  EXPECT_SEND_MESSAGE_WITH (G_STRINGIFY (GLIB_SIZEOF_VOID_P));
}

TESTCASE (process_should_support_nested_signal_handling)
{
#ifdef HAVE_LINUX
  gpointer page;

  page = gum_alloc_n_pages (1, GUM_PAGE_NO_ACCESS);

  COMPILE_AND_LOAD_SCRIPT ("Process.setExceptionHandler(function (details) {"
          "Memory.protect(" GUM_PTR_CONST ", Process.pageSize, 'rw-');"
          "try {"
              "ptr(42).readU8();"
          "} catch (e) {"
              "send('error');"
          "};"
          "return true;"
      "});", page);

  *((guint8 *) page) = 1;
  EXPECT_SEND_MESSAGE_WITH ("\"error\"");

  gum_free_pages ((gpointer) page);
#else
  g_print ("<skipping, only supported on Linux for now> ");
#endif
}

TESTCASE (process_debugger_status_is_available)
{
  COMPILE_AND_LOAD_SCRIPT ("send(Process.isDebuggerAttached());");
  if (gum_process_is_debugger_attached ())
    EXPECT_SEND_MESSAGE_WITH ("true");
  else
    EXPECT_SEND_MESSAGE_WITH ("false");
}

TESTCASE (process_id_is_available)
{
  TestScriptMessageItem * item;
  gint pid;

  COMPILE_AND_LOAD_SCRIPT ("send(Process.id);");

  item = test_script_fixture_pop_message (fixture);
  pid = 0;
  sscanf (item->message, "{\"type\":\"send\",\"payload\":%d}", &pid);
  g_assert_cmpint (pid, ==, gum_process_get_id ());
  test_script_message_item_free (item);
}

TESTCASE (process_current_thread_id_is_available)
{
  COMPILE_AND_LOAD_SCRIPT ("send(typeof Process.getCurrentThreadId());");
  EXPECT_SEND_MESSAGE_WITH ("\"number\"");
}

TESTCASE (process_threads_can_be_enumerated)
{
#ifdef HAVE_LINUX
  if (!check_exception_handling_testable ())
    return;
#endif

#ifdef HAVE_MIPS
  if (!g_test_slow ())
  {
    g_print ("<skipping, run in slow mode> ");
    return;
  }
#endif

  COMPILE_AND_LOAD_SCRIPT (
      "var threads = Process.enumerateThreads();"
      "send(threads.length > 0);");
  EXPECT_SEND_MESSAGE_WITH ("true");
}

TESTCASE (process_threads_can_be_enumerated_legacy_style)
{
  gboolean done = FALSE;
  GThread * thread_a, * thread_b;

#ifdef HAVE_LINUX
  if (!check_exception_handling_testable ())
    return;
#endif

#if defined (HAVE_ANDROID) || defined (HAVE_MIPS)
  if (!g_test_slow ())
  {
    g_print ("<skipping, run in slow mode> ");
    return;
  }
#endif

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

TESTCASE (process_modules_can_be_enumerated)
{
  COMPILE_AND_LOAD_SCRIPT (
      "var modules = Process.enumerateModules();"
      "send(modules.length > 0);"
      "var m = modules[0];"
      "send(typeof m.name === 'string');"
      "send(typeof m.path === 'string');"
      "send(m.base instanceof NativePointer);"
      "send(typeof m.size === 'number');"
      "send(JSON.stringify(m) !== \"{}\");");
  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_SEND_MESSAGE_WITH ("true");
}

TESTCASE (process_modules_can_be_enumerated_legacy_style)
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

  COMPILE_AND_LOAD_SCRIPT ("send(Process.enumerateModulesSync().length > 1);");
  EXPECT_SEND_MESSAGE_WITH ("true");
}

TESTCASE (process_module_can_be_looked_up_from_address)
{
#ifndef HAVE_LINUX
  GModule * m;
  gpointer f;
  gboolean found;

  m = g_module_open (SYSTEM_MODULE_NAME, G_MODULE_BIND_LAZY);
  found = g_module_symbol (m, SYSTEM_MODULE_EXPORT, &f);
  g_assert_true (found);
  g_module_close (m);

  COMPILE_AND_LOAD_SCRIPT (
      "send(Process.findModuleByAddress(" GUM_PTR_CONST ".strip()) !== null);",
      f);
  EXPECT_SEND_MESSAGE_WITH ("true");

  COMPILE_AND_LOAD_SCRIPT (
      "send(Object.keys(Process.getModuleByAddress(" GUM_PTR_CONST
      ".strip())).length > 0);",
      f);
  EXPECT_SEND_MESSAGE_WITH ("true");
#endif

  COMPILE_AND_LOAD_SCRIPT (
      "var someModule = Process.enumerateModules()[1];"
      "var foundModule = Process.findModuleByAddress(someModule.base);"
      "send(foundModule !== null);"
      "send(foundModule.name === someModule.name);");
  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_NO_MESSAGES ();

  COMPILE_AND_LOAD_SCRIPT (
      "var map = new ModuleMap();"
      "var someModule = Process.enumerateModules()[1];"

      "send(map.has(someModule.base));"
      "send(map.has(ptr(1)));"

      "var foundModule = map.find(someModule.base);"
      "send(foundModule !== null);"
      "send(foundModule.name === someModule.name);"
      "send(map.find(ptr(1)));"

      "map.update();"
      "foundModule = map.get(someModule.base);"
      "send(foundModule.name === someModule.name);"
      "try {"
      "  map.get(ptr(1));"
      "} catch (e) {"
      "  send(e.message);"
      "}"

      "send(map.findName(someModule.base) === someModule.name);"
      "send(map.findName(ptr(1)));"
      "send(map.getName(someModule.base) === someModule.name);"
      "try {"
      "  map.getName(ptr(1));"
      "} catch (e) {"
      "  send(e.message);"
      "}"

      "send(map.findPath(someModule.base) === someModule.path);"
      "send(map.findPath(ptr(1)));"
      "send(map.getPath(someModule.base) === someModule.path);"
      "try {"
      "  map.getPath(ptr(1));"
      "} catch (e) {"
      "  send(e.message);"
      "}");

  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_SEND_MESSAGE_WITH ("false");

  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_SEND_MESSAGE_WITH ("null");

  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_SEND_MESSAGE_WITH ("\"unable to find module containing 0x1\"");

  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_SEND_MESSAGE_WITH ("null");
  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_SEND_MESSAGE_WITH ("\"unable to find module containing 0x1\"");

  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_SEND_MESSAGE_WITH ("null");
  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_SEND_MESSAGE_WITH ("\"unable to find module containing 0x1\"");

  EXPECT_NO_MESSAGES ();

#ifdef HAVE_DARWIN
  COMPILE_AND_LOAD_SCRIPT (
      "var systemModule = Process.enumerateModules()"
      "  .filter(function (m) {"
      "    return m.path.indexOf('/System/') === 0;"
      "  })[0];"
      "var map = new ModuleMap(function (module) {"
      "  return module.path.indexOf('/System/') === -1;"
      "});"
      "var foundModule = map.find(systemModule.base);"
      "send(foundModule === null);");
  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_NO_MESSAGES ();
#endif
}

TESTCASE (process_module_can_be_looked_up_from_name)
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

TESTCASE (process_ranges_can_be_enumerated)
{
  COMPILE_AND_LOAD_SCRIPT (
      "var ranges = Process.enumerateRanges('--x');"
      "send(ranges.length > 0);");
  EXPECT_SEND_MESSAGE_WITH ("true");
}

TESTCASE (process_ranges_can_be_enumerated_legacy_style)
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

  COMPILE_AND_LOAD_SCRIPT (
      "send(Process.enumerateRangesSync('--x').length > 1);");
  EXPECT_SEND_MESSAGE_WITH ("true");
}

TESTCASE (process_ranges_can_be_enumerated_with_neighbors_coalesced)
{
  COMPILE_AND_LOAD_SCRIPT (
      "var a = Process.enumerateRanges('--x');"
      "var b = Process.enumerateRanges({"
        "protection: '--x',"
        "coalesce: true"
      "});"
      "send(b.length <= a.length);");
  EXPECT_SEND_MESSAGE_WITH ("true");
}

TESTCASE (process_range_can_be_looked_up_from_address)
{
  GModule * m;
  gpointer f;
  gboolean found;

  m = g_module_open (SYSTEM_MODULE_NAME, G_MODULE_BIND_LAZY);
  found = g_module_symbol (m, SYSTEM_MODULE_EXPORT, &f);
  g_assert_true (found);
  g_module_close (m);

  COMPILE_AND_LOAD_SCRIPT (
      "send(Process.findRangeByAddress(" GUM_PTR_CONST ".strip()) !== null);",
      f);
  EXPECT_SEND_MESSAGE_WITH ("true");

  COMPILE_AND_LOAD_SCRIPT (
      "var someRange = Process.enumerateRanges('r-x')[1];"
      "var foundRange = Process.findRangeByAddress(someRange.base);"
      "send(foundRange !== null);"
      "send(foundRange.base.equals(someRange.base));");
  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_NO_MESSAGES ();

  COMPILE_AND_LOAD_SCRIPT (
      "send(Object.keys(Process.getRangeByAddress(" GUM_PTR_CONST
      ".strip())).length > 0);",
      f);
  EXPECT_SEND_MESSAGE_WITH ("true");
}

#ifdef HAVE_DARWIN

TESTCASE (process_malloc_ranges_can_be_enumerated)
{
  if (!g_test_slow ())
  {
    g_print ("<skipping, run in slow mode> ");
    return;
  }

  COMPILE_AND_LOAD_SCRIPT (
      "var ranges = Process.enumerateMallocRanges();"
      "send(ranges.length > 0);");
  EXPECT_SEND_MESSAGE_WITH ("true");
}

TESTCASE (process_malloc_ranges_can_be_enumerated_legacy_style)
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

  COMPILE_AND_LOAD_SCRIPT (
      "send(Process.enumerateMallocRangesSync().length > 0);");
  EXPECT_SEND_MESSAGE_WITH ("true");
}

#endif

TESTCASE (module_imports_can_be_enumerated)
{
  COMPILE_AND_LOAD_SCRIPT (
      "var imports = Process.getModuleByName('%s').enumerateImports();"
      "send(imports.length > 0);",
      GUM_TESTS_MODULE_NAME);
  EXPECT_SEND_MESSAGE_WITH ("true");
}

TESTCASE (module_imports_can_be_enumerated_legacy_style)
{
  COMPILE_AND_LOAD_SCRIPT (
      "var imports = Module.enumerateImports('%s');"
      "send(imports.length > 0);",
      GUM_TESTS_MODULE_NAME);
  EXPECT_SEND_MESSAGE_WITH ("true");

  COMPILE_AND_LOAD_SCRIPT (
      "Module.enumerateImports('%s', {"
        "onMatch: function (imp) {"
        "  send('onMatch');"
        "  return 'stop';"
        "},"
        "onComplete: function () {"
        "  send('onComplete');"
        "}"
      "});",
      GUM_TESTS_MODULE_NAME);
  EXPECT_SEND_MESSAGE_WITH ("\"onMatch\"");
  EXPECT_SEND_MESSAGE_WITH ("\"onComplete\"");

  COMPILE_AND_LOAD_SCRIPT (
      "var imports = Module.enumerateImportsSync('%s');"
      "send(imports.length > 0);",
      GUM_TESTS_MODULE_NAME);
  EXPECT_SEND_MESSAGE_WITH ("true");
}

TESTCASE (module_exports_can_be_enumerated)
{
  COMPILE_AND_LOAD_SCRIPT (
      "var exports = Process.getModuleByName('%s').enumerateExports();"
      "send(exports.length > 0);"
      "var e = exports[0];"
      "send(typeof e.type === 'string');"
      "send(typeof e.name === 'string');"
      "send(e.address instanceof NativePointer);"
      "send(JSON.stringify(e) !== \"{}\");",
      SYSTEM_MODULE_NAME);
  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_SEND_MESSAGE_WITH ("true");
}

TESTCASE (module_exports_can_be_enumerated_legacy_style)
{
  COMPILE_AND_LOAD_SCRIPT (
      "var exports = Module.enumerateExports('%s');"
      "send(exports.length > 0);",
      SYSTEM_MODULE_NAME);
  EXPECT_SEND_MESSAGE_WITH ("true");

  COMPILE_AND_LOAD_SCRIPT (
      "Module.enumerateExports('%s', {"
        "onMatch: function (exp) {"
        "  send('onMatch');"
        "  return 'stop';"
        "},"
        "onComplete: function () {"
        "  send('onComplete');"
        "}"
      "});",
      SYSTEM_MODULE_NAME);
  EXPECT_SEND_MESSAGE_WITH ("\"onMatch\"");
  EXPECT_SEND_MESSAGE_WITH ("\"onComplete\"");

  COMPILE_AND_LOAD_SCRIPT (
      "var exports = Module.enumerateExportsSync('%s');"
      "send(exports.length > 0);",
      SYSTEM_MODULE_NAME);
  EXPECT_SEND_MESSAGE_WITH ("true");
}

TESTCASE (module_exports_enumeration_performance)
{
  TestScriptMessageItem * item;
  gint duration;

  COMPILE_AND_LOAD_SCRIPT (
      "var module = Process.getModuleByName('%s');"
      "var start = Date.now();"
      "module.enumerateExports();"
      "send(Date.now() - start);",
      SYSTEM_MODULE_NAME);
  item = test_script_fixture_pop_message (fixture);
  sscanf (item->message, "{\"type\":\"send\",\"payload\":%d}", &duration);
  g_print ("<%d ms> ", duration);
  test_script_message_item_free (item);
}

TESTCASE (module_symbols_can_be_enumerated)
{
#if defined (HAVE_DARWIN) || defined (HAVE_LINUX)
  COMPILE_AND_LOAD_SCRIPT (
      "var symbols = Process.getModuleByName('%s').enumerateSymbols();"
      "send(symbols.length > 0);"
      "var s = symbols[0];"
      "send(typeof s.isGlobal === 'boolean');"
      "send(typeof s.type === 'string');"
      "send(typeof s.name === 'string');"
      "send(s.address instanceof NativePointer);"
      "send(JSON.stringify(s) !== \"{}\");",
      GUM_TESTS_MODULE_NAME);
  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_SEND_MESSAGE_WITH ("true");
#else
  g_print ("<skipping on this platform> ");
#endif
}

TESTCASE (module_symbols_can_be_enumerated_legacy_style)
{
#if defined (HAVE_DARWIN) || defined (HAVE_LINUX)
  COMPILE_AND_LOAD_SCRIPT (
      "var symbols = Module.enumerateSymbols('%s');"
      "send(symbols.length > 0);",
      GUM_TESTS_MODULE_NAME);
  EXPECT_SEND_MESSAGE_WITH ("true");

  COMPILE_AND_LOAD_SCRIPT (
      "Module.enumerateSymbols('%s', {"
        "onMatch: function (sym) {"
        "  send('onMatch');"
        "  return 'stop';"
        "},"
        "onComplete: function () {"
        "  send('onComplete');"
        "}"
      "});",
      GUM_TESTS_MODULE_NAME);
  EXPECT_SEND_MESSAGE_WITH ("\"onMatch\"");
  EXPECT_SEND_MESSAGE_WITH ("\"onComplete\"");

  COMPILE_AND_LOAD_SCRIPT (
      "var symbols = Module.enumerateSymbolsSync('%s');"
      "send(symbols.length > 0);",
      GUM_TESTS_MODULE_NAME);
  EXPECT_SEND_MESSAGE_WITH ("true");
#else
  g_print ("<skipping on this platform> ");
#endif
}

TESTCASE (module_ranges_can_be_enumerated)
{
  COMPILE_AND_LOAD_SCRIPT (
      "var ranges = Process.getModuleByName('%s').enumerateRanges('--x');"
      "send(ranges.length > 0);",
      SYSTEM_MODULE_NAME);
  EXPECT_SEND_MESSAGE_WITH ("true");
}

TESTCASE (module_ranges_can_be_enumerated_legacy_style)
{
  COMPILE_AND_LOAD_SCRIPT (
      "var ranges = Module.enumerateRanges('%s', '--x');"
      "send(ranges.length > 0);",
      SYSTEM_MODULE_NAME);
  EXPECT_SEND_MESSAGE_WITH ("true");

  COMPILE_AND_LOAD_SCRIPT (
      "Module.enumerateRanges('%s', '--x', {"
        "onMatch: function (range) {"
        "  send('onMatch');"
        "  return 'stop';"
        "},"
        "onComplete: function () {"
        "  send('onComplete');"
        "}"
      "});",
      SYSTEM_MODULE_NAME);
  EXPECT_SEND_MESSAGE_WITH ("\"onMatch\"");
  EXPECT_SEND_MESSAGE_WITH ("\"onComplete\"");

  COMPILE_AND_LOAD_SCRIPT (
      "var ranges = Module.enumerateRangesSync('%s', '--x');"
      "send(ranges.length > 0);",
      SYSTEM_MODULE_NAME);
  EXPECT_SEND_MESSAGE_WITH ("true");
}

TESTCASE (module_base_address_can_be_found)
{
  COMPILE_AND_LOAD_SCRIPT (
      "var sysModuleName = '%s';"
      "var badModuleName = 'nope_' + sysModuleName;"

      "var base = Module.findBaseAddress(sysModuleName);"
      "send(base !== null);"

      "send(Module.findBaseAddress(badModuleName) === null);"

      "try {"
          "send(Module.getBaseAddress(sysModuleName).equals(base));"

          "Module.getBaseAddress(badModuleName);"
          "send('should not get here');"
      "} catch (e) {"
          "send(/unable to find module/.test(e.message));"
      "}",
      SYSTEM_MODULE_NAME);

  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_SEND_MESSAGE_WITH ("true");

  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_SEND_MESSAGE_WITH ("true");
}

TESTCASE (module_export_can_be_found_by_name)
{
  COMPILE_AND_LOAD_SCRIPT (
      "var sysModuleName = '%s';"
      "var sysModuleExport = '%s';"
      "var badModuleName = 'nope_' + sysModuleName;"
      "var badModuleExport = sysModuleExport + '_does_not_exist';"

      "var impl = Module.findExportByName(sysModuleName, sysModuleExport);"
      "send(impl !== null);"

      "send(Module.findExportByName(badModuleName, badModuleExport) === null);"

      "try {"
          "send(Module.getExportByName(sysModuleName, sysModuleExport)"
              ".equals(impl));"

          "Module.getExportByName(badModuleName, badModuleExport);"
          "send('should not get here');"
      "} catch (e) {"
          "send(/unable to find export/.test(e.message));"
      "}",
      SYSTEM_MODULE_NAME, SYSTEM_MODULE_EXPORT);

  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_SEND_MESSAGE_WITH ("true");

  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_SEND_MESSAGE_WITH ("true");

#ifdef G_OS_WIN32
  HMODULE mod;
  gpointer actual_address;
  char actual_address_str[32];

  mod = GetModuleHandle (_T ("kernel32.dll"));
  g_assert_nonnull (mod);
  actual_address = GetProcAddress (mod, "Sleep");
  g_assert_nonnull (actual_address);
  sprintf_s (actual_address_str, sizeof (actual_address_str),
      "\"%" G_GSIZE_MODIFIER "x\"", GPOINTER_TO_SIZE (actual_address));

  COMPILE_AND_LOAD_SCRIPT (
      "send(Module.findExportByName('kernel32.dll', 'Sleep').toString(16));");
  EXPECT_SEND_MESSAGE_WITH (actual_address_str);
#endif
}

TESTCASE (module_can_be_loaded)
{
  COMPILE_AND_LOAD_SCRIPT (
      "var moduleName = '%s';"
      "var moduleExport = '%s';"
      "var m = Module.load(moduleName);"
      "send(m.getExportByName(moduleExport).equals("
          "Module.getExportByName(moduleName, moduleExport)));"
      "try {"
      "  Module.load(moduleName + '_nope');"
      "  send('success');"
      "} catch (e) {"
      "  send('error');"
      "}",
      SYSTEM_MODULE_NAME, SYSTEM_MODULE_EXPORT);
  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_SEND_MESSAGE_WITH ("\"error\"");
}

TESTCASE (module_can_be_forcibly_initialized)
{
  COMPILE_AND_LOAD_SCRIPT ("Module.ensureInitialized('%s');",
      SYSTEM_MODULE_NAME);
  EXPECT_NO_MESSAGES ();

  COMPILE_AND_LOAD_SCRIPT (
      "Module.ensureInitialized('DefinitelyNotAValidModuleName');");
  EXPECT_ERROR_MESSAGE_WITH (ANY_LINE_NUMBER,
      "Error: unable to find module 'DefinitelyNotAValidModuleName'");
  EXPECT_NO_MESSAGES ();
}

#ifdef G_OS_WIN32
# define API_RESOLVER_TEST_QUERY "exports:*!_open*"
#else
# define API_RESOLVER_TEST_QUERY "exports:*!open*"
#endif

TESTCASE (api_resolver_can_be_used_to_find_functions)
{
  COMPILE_AND_LOAD_SCRIPT (
      "var resolver = new ApiResolver('module');"
      "var matches = resolver.enumerateMatches('%s');"
      "send(matches.length > 0);",
      API_RESOLVER_TEST_QUERY);
  EXPECT_SEND_MESSAGE_WITH ("true");
}

TESTCASE (api_resolver_can_be_used_to_find_functions_legacy_style)
{
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
      API_RESOLVER_TEST_QUERY);
  EXPECT_SEND_MESSAGE_WITH ("\"onMatch\"");
  EXPECT_SEND_MESSAGE_WITH ("\"onComplete\"");

  COMPILE_AND_LOAD_SCRIPT (
      "var resolver = new ApiResolver('module');"
      "var matches = resolver.enumerateMatchesSync('%s');"
      "send(matches.length > 0);",
      API_RESOLVER_TEST_QUERY);
  EXPECT_SEND_MESSAGE_WITH ("true");
}

TESTCASE (invalid_script_should_return_null)
{
  GError * err = NULL;

  g_assert_null (gum_script_backend_create_sync (fixture->backend, "testcase",
      "'", NULL, NULL));

  g_assert_null (gum_script_backend_create_sync (fixture->backend, "testcase",
      "'", NULL, &err));
  g_assert_nonnull (err);
  g_assert_true (g_str_has_prefix (err->message,
      "Script(line 1): SyntaxError: "));
}

TESTCASE (strict_mode_should_be_enforced)
{
  COMPILE_AND_LOAD_SCRIPT (
      "function run() {"
      "  oops = 1337;"
      "}"
      "run();");
  EXPECT_ERROR_MESSAGE_WITH (ANY_LINE_NUMBER,
      GUM_DUK_IS_SCRIPT_BACKEND (fixture->backend)
      ? "ReferenceError: identifier 'oops' undefined"
      : "ReferenceError: oops is not defined");
}

TESTCASE (array_buffer_can_be_created)
{
  COMPILE_AND_LOAD_SCRIPT ("new ArrayBuffer(16);");
  EXPECT_NO_MESSAGES ();
}

TESTCASE (rpc_can_be_performed)
{
  COMPILE_AND_LOAD_SCRIPT (
      "rpc.exports.foo = function (a, b) {"
          "var result = a + b;"
          "if (result >= 0)"
              "return result;"
          "else "
              "throw new Error('no');"
      "};"
      "rpc.exports.bar = function (a, b) {"
          "return new Promise(function (resolve, reject) {"
              "var result = a + b;"
              "if (result >= 0)"
                  "resolve(result);"
              "else "
                  "reject(new Error('nope'));"
          "});"
      "};"
      "rpc.exports.badger = function () {"
          "var buf = Memory.allocUtf8String(\"Yo\");"
          "return buf.readByteArray(2);"
      "};");
  EXPECT_NO_MESSAGES ();

  POST_MESSAGE ("[\"frida:rpc\",1,\"list\"]");
  EXPECT_SEND_MESSAGE_WITH ("[\"frida:rpc\",1,\"ok\","
      "[\"foo\",\"bar\",\"badger\"]]");

  POST_MESSAGE ("[\"frida:rpc\",2,\"call\",\"foo\",[1,2]]");
  EXPECT_SEND_MESSAGE_WITH ("[\"frida:rpc\",2,\"ok\",3]");

  POST_MESSAGE ("[\"frida:rpc\",3,\"call\",\"foo\",[1,-2]]");
  EXPECT_SEND_MESSAGE_WITH_PREFIX ("[\"frida:rpc\",3,\"error\",\"no\",");

  POST_MESSAGE ("[\"frida:rpc\",4,\"call\",\"bar\",[3,4]]");
  EXPECT_SEND_MESSAGE_WITH ("[\"frida:rpc\",4,\"ok\",7]");

  POST_MESSAGE ("[\"frida:rpc\",5,\"call\",\"bar\",[3,-4]]");
  EXPECT_SEND_MESSAGE_WITH_PREFIX ("[\"frida:rpc\",5,\"error\",\"nope\",");

  POST_MESSAGE ("[\"frida:rpc\",6,\"call\",\"baz\",[]]");
  EXPECT_SEND_MESSAGE_WITH ("[\"frida:rpc\",6,\"error\","
      "\"unable to find method 'baz'\"]");

  POST_MESSAGE ("[\"frida:rpc\",7,\"call\",\"badger\",[]]");
  EXPECT_SEND_MESSAGE_WITH_PAYLOAD_AND_DATA ("[\"frida:rpc\",7,\"ok\",{}]",
      "59 6f");
}

TESTCASE (message_can_be_sent)
{
  COMPILE_AND_LOAD_SCRIPT ("send(1234);");
  EXPECT_SEND_MESSAGE_WITH ("1234");
}

TESTCASE (message_can_be_sent_with_data)
{
  COMPILE_AND_LOAD_SCRIPT ("send(1234, [0x13, 0x37]);");
  EXPECT_SEND_MESSAGE_WITH_PAYLOAD_AND_DATA ("1234", "13 37");
}

TESTCASE (message_can_be_received)
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

TESTCASE (message_can_be_received_with_data)
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

TESTCASE (recv_may_specify_desired_message_type)
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
  volatile gint started;
  volatile gint finished;
};

TESTCASE (recv_can_be_waited_for_from_an_application_thread)
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
  ctx.started = 0;
  ctx.finished = 0;
  worker_thread = g_thread_new ("script-test-worker-thread",
      invoke_target_function_int_worker, &ctx);
  while (ctx.started == 0)
    g_usleep (G_USEC_PER_SEC / 200);

  g_usleep (G_USEC_PER_SEC / 25);
  EXPECT_NO_MESSAGES ();
  g_assert_cmpint (ctx.finished, ==, 0);

  POST_MESSAGE ("{\"type\":\"poke\"}");
  g_thread_join (worker_thread);
  g_assert_cmpint (ctx.finished, ==, 1);
  EXPECT_SEND_MESSAGE_WITH ("\"pokeBack\"");
  EXPECT_SEND_MESSAGE_WITH ("\"pokeReceived\"");
  EXPECT_NO_MESSAGES ();
}

TESTCASE (recv_can_be_waited_for_from_two_application_threads)
{
  GThread * worker_thread1, * worker_thread2;
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
  ctx.started = 0;
  ctx.finished = 0;
  worker_thread1 = g_thread_new ("script-test-worker-thread",
      invoke_target_function_int_worker, &ctx);
  g_usleep (G_USEC_PER_SEC / 25);
  worker_thread2 = g_thread_new ("script-test-worker-thread",
      invoke_target_function_int_worker, &ctx);
  while (ctx.started != 2)
    g_usleep (G_USEC_PER_SEC / 200);

  g_usleep (G_USEC_PER_SEC / 25);
  EXPECT_NO_MESSAGES ();
  g_assert_cmpint (ctx.finished, ==, 0);

  POST_MESSAGE ("{\"type\":\"poke\"}");
  g_thread_join (worker_thread1);
  g_assert_cmpint (ctx.finished, ==, 1);
  EXPECT_SEND_MESSAGE_WITH ("\"pokeBack\"");
  EXPECT_SEND_MESSAGE_WITH ("\"pokeReceived\"");
  EXPECT_NO_MESSAGES ();
  POST_MESSAGE ("{\"type\":\"poke\"}");
  g_thread_join (worker_thread2);
  g_assert_cmpint (ctx.finished, ==, 2);
  EXPECT_SEND_MESSAGE_WITH ("\"pokeBack\"");
  EXPECT_SEND_MESSAGE_WITH ("\"pokeReceived\"");
  EXPECT_NO_MESSAGES ();
}

TESTCASE (recv_can_be_waited_for_from_our_js_thread)
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
      "}, 0);");
  EXPECT_NO_MESSAGES ();

  POST_MESSAGE ("{\"type\":\"poke\"}");
  EXPECT_SEND_MESSAGE_WITH ("\"pokeBack\"");
  EXPECT_SEND_MESSAGE_WITH ("\"pokeReceived\"");
  EXPECT_NO_MESSAGES ();
}

TESTCASE (recv_wait_in_an_application_thread_should_throw_on_unload)
{
  GThread * worker_thread;
  GumInvokeTargetContext ctx;

  COMPILE_AND_LOAD_SCRIPT (
      "Interceptor.attach(" GUM_PTR_CONST ", {"
      "  onEnter: function (args) {"
      "    var op = recv('poke', function (pokeMessage) {"
      "      send('pokeBack');"
      "    });"
      "    try {"
      "      op.wait();"
      "      send('pokeReceived');"
      "    } catch (e) {"
      "      send('oops: ' + e.message);"
      "    }"
      "  }"
      "});", target_function_int);
  EXPECT_NO_MESSAGES ();

  ctx.script = fixture->script;
  ctx.started = 0;
  ctx.finished = 0;
  worker_thread = g_thread_new ("script-test-worker-thread",
      invoke_target_function_int_worker, &ctx);
  while (ctx.started == 0)
    g_usleep (G_USEC_PER_SEC / 200);

  g_usleep (G_USEC_PER_SEC / 25);
  EXPECT_NO_MESSAGES ();
  g_assert_cmpint (ctx.finished, ==, 0);

  UNLOAD_SCRIPT ();
  g_thread_join (worker_thread);
  g_assert_cmpint (ctx.finished, ==, 1);
  EXPECT_SEND_MESSAGE_WITH ("\"oops: script is unloading\"");
  EXPECT_NO_MESSAGES ();
}

TESTCASE (recv_wait_in_our_js_thread_should_throw_on_unload)
{
  COMPILE_AND_LOAD_SCRIPT (
      "setTimeout(function () {"
      "  var op = recv('poke', function (pokeMessage) {"
      "    send('pokeBack');"
      "  });"
      "  try {"
      "    op.wait();"
      "    send('pokeReceived');"
      "  } catch (e) {"
      "    send('oops: ' + e.message);"
      "  }"
      "}, 0);");
  EXPECT_NO_MESSAGES ();

  UNLOAD_SCRIPT ();
  EXPECT_SEND_MESSAGE_WITH ("\"oops: script is unloading\"");
  EXPECT_NO_MESSAGES ();
}

static gpointer
invoke_target_function_int_worker (gpointer data)
{
  GumInvokeTargetContext * ctx = (GumInvokeTargetContext *) data;

  g_atomic_int_inc (&ctx->started);
  target_function_int (42);
  g_atomic_int_inc (&ctx->finished);

  return NULL;
}

TESTCASE (message_can_be_logged)
{
  DISABLE_LOG_MESSAGE_HANDLING ();

  COMPILE_AND_LOAD_SCRIPT ("console.log('Hello', undefined, null, 1337, "
      "'world', true, { color: 'pink' });");
  EXPECT_LOG_MESSAGE_WITH ("info", "Hello undefined null 1337 world "
      "true [object Object]");

  COMPILE_AND_LOAD_SCRIPT ("console.warn('Trouble is coming');");
  EXPECT_LOG_MESSAGE_WITH ("warning", "Trouble is coming");

  COMPILE_AND_LOAD_SCRIPT ("console.error('Oh noes');");
  EXPECT_LOG_MESSAGE_WITH ("error", "Oh noes");
}

TESTCASE (thread_can_be_forced_to_sleep)
{
  GTimer * timer = g_timer_new ();
  COMPILE_AND_LOAD_SCRIPT ("Thread.sleep(0.25);");
  g_assert_cmpfloat (g_timer_elapsed (timer, NULL), >=, 0.2f);
  EXPECT_NO_MESSAGES ();
  g_timer_destroy (timer);
}

TESTCASE (timeout_can_be_scheduled)
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

TESTCASE (timeout_can_be_cancelled)
{
  COMPILE_AND_LOAD_SCRIPT (
      "var timeout = setTimeout(function () {"
      "  send(1337);"
      "}, 20);"
      "clearTimeout(timeout);");
  g_usleep (25000);
  EXPECT_NO_MESSAGES ();
}

TESTCASE (interval_can_be_scheduled)
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

TESTCASE (interval_can_be_cancelled)
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

TESTCASE (callback_can_be_scheduled)
{
  COMPILE_AND_LOAD_SCRIPT (
      "setImmediate(function () {"
      "  send(1337);"
      "});");
  EXPECT_SEND_MESSAGE_WITH ("1337");
  EXPECT_NO_MESSAGES ();
}

TESTCASE (callback_can_be_scheduled_from_a_scheduled_callback)
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

TESTCASE (callback_can_be_cancelled)
{
  COMPILE_AND_LOAD_SCRIPT (
      "var id = setImmediate(function () {"
      "  send(1337);"
      "});"
      "clearImmediate(id);");
  g_usleep (25000);
  EXPECT_NO_MESSAGES ();
}

TESTCASE (callback_can_be_scheduled_on_next_tick)
{
  COMPILE_AND_LOAD_SCRIPT (
      "Script.nextTick(send, 1337, [0x13, 0x37, 0x0a]);");
  EXPECT_SEND_MESSAGE_WITH_PAYLOAD_AND_DATA ("1337", "13 37 0a");
  EXPECT_NO_MESSAGES ();
}

TESTCASE (timer_cancellation_apis_should_be_forgiving)
{
  COMPILE_AND_LOAD_SCRIPT (
      "clearTimeout(undefined);"
      "clearInterval(undefined);"
      "clearImmediate(undefined);");
  EXPECT_NO_MESSAGES ();
}

TESTCASE (argument_can_be_read)
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

TESTCASE (argument_can_be_replaced)
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

TESTCASE (return_value_can_be_read)
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

TESTCASE (return_value_can_be_replaced)
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

TESTCASE (return_address_can_be_read)
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

TESTCASE (register_can_be_read)
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

TESTCASE (register_can_be_written)
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

TESTCASE (system_error_can_be_read_from_interceptor_listener)
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

TESTCASE (system_error_can_be_read_from_replacement_function)
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

TESTCASE (system_error_can_be_replaced_from_interceptor_listener)
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

TESTCASE (system_error_can_be_replaced_from_replacement_function)
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

TESTCASE (invocations_are_bound_on_tls_object)
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

TESTCASE (invocations_provide_thread_id)
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
    g_assert_cmpuint (id, !=, 0);
    test_script_message_item_free (item);
    g_assert_cmpint (id, ==, gum_process_get_current_thread_id ());
  }
}

TESTCASE (invocations_provide_call_depth)
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

TESTCASE (invocations_provide_context_for_backtrace)
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

TESTCASE (invocations_provide_context_serializable_to_json)
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

TESTCASE (listener_can_be_detached)
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

TESTCASE (listener_can_be_detached_by_destruction_mid_call)
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

TESTCASE (all_listeners_can_be_detached)
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

TESTCASE (function_can_be_replaced)
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

TESTCASE (function_can_be_replaced_and_called_immediately)
{
  COMPILE_AND_LOAD_SCRIPT (
      "var address = " GUM_PTR_CONST ";"
      "Interceptor.replace(address,"
      "    new NativeCallback(function (arg) {"
      "  send(arg);"
      "  return 1337;"
      "}, 'int', ['int']));"
      "var f = new NativeFunction(address, 'int', ['int'],"
      "    { scheduling: 'exclusive' });"
      "f(7);"
      "Interceptor.flush();"
      "f(8);",
      target_function_int);
  EXPECT_SEND_MESSAGE_WITH ("8");
  EXPECT_NO_MESSAGES ();
}

TESTCASE (function_can_be_reverted)
{
  COMPILE_AND_LOAD_SCRIPT (
      "Interceptor.replace(" GUM_PTR_CONST ", new NativeCallback("
      "  function (arg) {"
      "    send(arg);"
      "    return 1337;"
      "  }, 'int', ['int']));"
      "Interceptor.revert(" GUM_PTR_CONST ");",
      target_function_int, target_function_int);

  EXPECT_NO_MESSAGES ();
  target_function_int (7);
  EXPECT_NO_MESSAGES ();
}

TESTCASE (replaced_function_should_have_invocation_context)
{
  COMPILE_AND_LOAD_SCRIPT (
      "Interceptor.replace(" GUM_PTR_CONST ", new NativeCallback("
      "  function (arg) {"
      "    send(this.returnAddress instanceof NativePointer);"
      "    return 0;"
      "  }, 'int', ['int']));",
      target_function_int);

  EXPECT_NO_MESSAGES ();
  target_function_int (7);
  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_NO_MESSAGES ();
}

TESTCASE (instructions_can_be_probed)
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

TESTCASE (interceptor_should_support_native_pointer_values)
{
  COMPILE_AND_LOAD_SCRIPT (
      "var value = { handle: " GUM_PTR_CONST " };"
      "Interceptor.attach(value, {"
      "  onEnter: function (args) {"
      "    send(args[0].toInt32());"
      "  }"
      "});", target_function_int);
  EXPECT_NO_MESSAGES ();
  target_function_int (42);
  EXPECT_SEND_MESSAGE_WITH ("42");

  COMPILE_AND_LOAD_SCRIPT (
      "var value = { handle: " GUM_PTR_CONST " };"
      "Interceptor.replace(value,"
      "    new NativeCallback(function (arg) {"
      "  return 1337;"
      "}, 'int', ['int']));",
      target_function_int);
  EXPECT_NO_MESSAGES ();
  g_assert_cmpint (target_function_int (7), ==, 1337);
  EXPECT_NO_MESSAGES ();
}

TESTCASE (interceptor_handles_invalid_arguments)
{
  if (!check_exception_handling_testable ())
    return;

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

TESTCASE (interceptor_on_enter_performance)
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

TESTCASE (interceptor_on_leave_performance)
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

TESTCASE (interceptor_on_enter_and_leave_performance)
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
  guint i, n;
  gdouble measurement[1000], t_min, t_max, t_median;

  n = G_N_ELEMENTS (measurement);

  timer = g_timer_new ();

  for (i = 0; i != n; i++)
  {
    target_function_int (7);
  }

  for (i = 0; i != n; i++)
  {
    g_timer_reset (timer);
    target_function_int (7);
    measurement[i] = g_timer_elapsed (timer, NULL);
  }

  qsort (measurement, n, sizeof (gdouble), compare_measurements);

  t_min = measurement[0];
  t_max = measurement[n - 1];
  g_assert (n % 2 == 0);
  t_median = (measurement[n / 2] + measurement[(n / 2) - 1]) / 2.0;

  g_print ("<min: %.1f µs, max: %.1f µs, median: %.1f µs> ",
      t_min * (gdouble) G_USEC_PER_SEC,
      t_max * (gdouble) G_USEC_PER_SEC,
      t_median * (gdouble) G_USEC_PER_SEC);

  g_timer_destroy (timer);
}

static int
compare_measurements (gconstpointer element_a,
                      gconstpointer element_b)
{
  const gdouble a = *(const gdouble *) element_a;
  const gdouble b = *(const gdouble *) element_b;

  if (a > b)
    return 1;

  if (a < b)
    return -1;

  return 0;
}

TESTCASE (memory_can_be_scanned)
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

TESTCASE (memory_can_be_scanned_synchronously)
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

TESTCASE (memory_scan_should_be_interruptible)
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

TESTCASE (memory_scan_handles_unreadable_memory)
{
  if (!check_exception_handling_testable ())
    return;

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

TESTCASE (memory_access_can_be_monitored)
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

TESTCASE (memory_access_can_be_monitored_one_range)
{
  volatile guint8 * a;
  guint page_size;

  a = gum_alloc_n_pages (2, GUM_PAGE_RW);
  page_size = gum_query_page_size ();

  COMPILE_AND_LOAD_SCRIPT (
      "MemoryAccessMonitor.enable({ base: " GUM_PTR_CONST ", size: %u }, {"
        "onAccess: function (details) {"
          "send([details.operation, !!details.from, details.address,"
            "details.rangeIndex, details.pageIndex, details.pagesCompleted,"
            "details.pagesTotal]);"
        "}"
      "});",
      a + page_size, page_size);
  EXPECT_NO_MESSAGES ();

  a[0] = 1;
  a[page_size - 1] = 2;
  EXPECT_NO_MESSAGES ();

  a[page_size] = 3;
  EXPECT_SEND_MESSAGE_WITH ("[\"write\",true,\"0x%" G_GSIZE_MODIFIER "x\","
      "0,0,1,1]", GPOINTER_TO_SIZE (a + page_size));

  gum_free_pages ((gpointer) a);
}

TESTCASE (pointer_can_be_read)
{
  gpointer val = GSIZE_TO_POINTER (0x1337000);
  COMPILE_AND_LOAD_SCRIPT (
      "send(" GUM_PTR_CONST ".readPointer().toString());", &val);
  EXPECT_SEND_MESSAGE_WITH ("\"0x1337000\"");
}

TESTCASE (pointer_can_be_read_legacy_style)
{
  gpointer val = GSIZE_TO_POINTER (0x1337000);
  COMPILE_AND_LOAD_SCRIPT (
      "send(Memory.readPointer(" GUM_PTR_CONST ").toString());", &val);
  EXPECT_SEND_MESSAGE_WITH ("\"0x1337000\"");
}

TESTCASE (pointer_can_be_written)
{
  gpointer vals[2] = { NULL, NULL };
  COMPILE_AND_LOAD_SCRIPT (
      GUM_PTR_CONST ".writePointer(ptr(\"0x1337000\"))"
      ".add(Process.pointerSize).writePointer(ptr(\"0x1338000\"))",
      vals);
  g_assert_cmphex (GPOINTER_TO_SIZE (vals[0]), ==, 0x1337000);
  g_assert_cmphex (GPOINTER_TO_SIZE (vals[1]), ==, 0x1338000);
}

TESTCASE (pointer_can_be_written_legacy_style)
{
  gpointer val = NULL;
  COMPILE_AND_LOAD_SCRIPT (
      "Memory.writePointer(" GUM_PTR_CONST ", ptr(\"0x1337000\"));", &val);
  g_assert_cmphex (GPOINTER_TO_SIZE (val), ==, 0x1337000);
}

TESTCASE (memory_can_be_allocated)
{
  gsize p;

  COMPILE_AND_LOAD_SCRIPT (
      "var p = Memory.alloc(8);"
      "p.writePointer(ptr('1337'));"
      "send(p.readPointer().toInt32() === 1337);");
  EXPECT_SEND_MESSAGE_WITH ("true");

  COMPILE_AND_LOAD_SCRIPT (
      "var p = Memory.alloc(uint64(8));"
      "p.writePointer(ptr('1337'));"
      "send(p.readPointer().toInt32() === 1337);");
  EXPECT_SEND_MESSAGE_WITH ("true");

  COMPILE_AND_LOAD_SCRIPT (
      "var p = Memory.alloc(Process.pageSize);"
      "send(p);");
  p = GPOINTER_TO_SIZE (EXPECT_SEND_MESSAGE_WITH_POINTER ());
  g_assert_cmpuint (p, !=, 0);
  g_assert_cmpuint (p & (gum_query_page_size () - 1), ==, 0);

  COMPILE_AND_LOAD_SCRIPT(
      "var p = Memory.alloc(5);"
      "send('p', p.readByteArray(5));");
  EXPECT_SEND_MESSAGE_WITH_PAYLOAD_AND_DATA("\"p\"", "00 00 00 00 00");
}

TESTCASE (memory_can_be_copied)
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

  /* TODO: investigate */
#if !(defined (HAVE_LINUX) && defined (HAVE_I386) && GLIB_SIZEOF_VOID_P == 4)
  if (!gum_process_is_debugger_attached () && !RUNNING_ON_VALGRIND)
  {
    COMPILE_AND_LOAD_SCRIPT (
        "Memory.copy(" GUM_PTR_CONST ", ptr(\"1337\"), 1);", to);
    EXPECT_ERROR_MESSAGE_WITH (1, "Error: access violation accessing 0x539");
  }
#endif
}

TESTCASE (memory_can_be_duped)
{
  guint8 buf[3] = { 0x13, 0x37, 0x42 };

  COMPILE_AND_LOAD_SCRIPT (
      "var p = Memory.dup(" GUM_PTR_CONST ", 3);"
      "p.writeU8(0x12);"
      "send('p', p.readByteArray(3));"
      "send('buf', " GUM_PTR_CONST ".readByteArray(3));",
      buf, buf);
  EXPECT_SEND_MESSAGE_WITH_PAYLOAD_AND_DATA ("\"p\"", "12 37 42");
  EXPECT_SEND_MESSAGE_WITH_PAYLOAD_AND_DATA ("\"buf\"", "13 37 42");

  COMPILE_AND_LOAD_SCRIPT (
      "var p = Memory.dup(" GUM_PTR_CONST ", uint64(2));"
      "p.writeU8(0x12);"
      "send('p', p.readByteArray(2));"
      "send('buf', " GUM_PTR_CONST ".readByteArray(2));",
      buf, buf);
  EXPECT_SEND_MESSAGE_WITH_PAYLOAD_AND_DATA ("\"p\"", "12 37");
  EXPECT_SEND_MESSAGE_WITH_PAYLOAD_AND_DATA ("\"buf\"", "13 37");
}

TESTCASE (memory_can_be_protected)
{
  gpointer buf;
  gboolean exception_on_read, exception_on_write;

  buf = gum_alloc_n_pages (1, GUM_PAGE_RW);

  COMPILE_AND_LOAD_SCRIPT (
      "send(Memory.protect(" GUM_PTR_CONST ", 1, 'r--'));",
      buf, gum_query_page_size ());
  EXPECT_SEND_MESSAGE_WITH ("true");

  if (gum_process_is_debugger_attached ())
  {
    g_print ("<only partially tested, debugger is attached> ");

    gum_free_pages (buf);

    return;
  }

  /* avoid overlapping signal handlers */
  UNLOAD_SCRIPT ();

  gum_try_read_and_write_at (buf, 0, &exception_on_read, &exception_on_write);
  g_assert_false (exception_on_read);
  g_assert_true (exception_on_write);

  COMPILE_AND_LOAD_SCRIPT (
      "send(Memory.protect(" GUM_PTR_CONST ", uint64(1), '---'));",
      buf, gum_query_page_size ());
  EXPECT_SEND_MESSAGE_WITH ("true");

  /* avoid overlapping signal handlers */
  UNLOAD_SCRIPT ();

  gum_try_read_and_write_at (buf, 0, &exception_on_read, &exception_on_write);
  g_assert_true (exception_on_read);
  g_assert_true (exception_on_write);

  gum_free_pages (buf);
}

TESTCASE (code_can_be_patched)
{
  guint8 * code;

  code = gum_alloc_n_pages (1, GUM_PAGE_RW);
  code[7] = 0xc3;
  gum_mprotect (code, gum_query_page_size (), GUM_PAGE_RX);

  COMPILE_AND_LOAD_SCRIPT ("Memory.patchCode(" GUM_PTR_CONST ", 1, "
      "function (ptr) {"
          "ptr.writeU8(0x90);"
      "});", code + 7);
  g_assert_cmphex (code[7], ==, 0x90);

  gum_free_pages (code);
}

TESTCASE (s8_can_be_read)
{
  gint8 val = -42;
  COMPILE_AND_LOAD_SCRIPT ("send(" GUM_PTR_CONST ".readS8());", &val);
  EXPECT_SEND_MESSAGE_WITH ("-42");
}

TESTCASE (s8_can_be_written)
{
  gint8 val = 0;
  COMPILE_AND_LOAD_SCRIPT (GUM_PTR_CONST ".writeS8(-42);", &val);
  g_assert_cmpint (val, ==, -42);
}

TESTCASE (u8_can_be_read)
{
  guint8 val = 42;
  COMPILE_AND_LOAD_SCRIPT ("send(" GUM_PTR_CONST ".readU8());", &val);
  EXPECT_SEND_MESSAGE_WITH ("42");
}

TESTCASE (u8_can_be_written)
{
  guint8 val = 0;
  COMPILE_AND_LOAD_SCRIPT (GUM_PTR_CONST ".writeU8(42);", &val);
  g_assert_cmpint (val, ==, 42);
}

TESTCASE (s16_can_be_read)
{
  gint16 val = -12123;
  COMPILE_AND_LOAD_SCRIPT ("send(" GUM_PTR_CONST ".readS16());", &val);
  EXPECT_SEND_MESSAGE_WITH ("-12123");
}

TESTCASE (s16_can_be_written)
{
  gint16 val = 0;
  COMPILE_AND_LOAD_SCRIPT (GUM_PTR_CONST ".writeS16(-12123);", &val);
  g_assert_cmpint (val, ==, -12123);
}

TESTCASE (u16_can_be_read)
{
  guint16 val = 12123;
  COMPILE_AND_LOAD_SCRIPT ("send(" GUM_PTR_CONST ".readU16());", &val);
  EXPECT_SEND_MESSAGE_WITH ("12123");
}

TESTCASE (u16_can_be_written)
{
  guint16 val = 0;
  COMPILE_AND_LOAD_SCRIPT (GUM_PTR_CONST ".writeU16(12123);", &val);
  g_assert_cmpint (val, ==, 12123);
}

TESTCASE (s32_can_be_read)
{
  gint32 val = -120123;
  COMPILE_AND_LOAD_SCRIPT ("send(" GUM_PTR_CONST ".readS32());", &val);
  EXPECT_SEND_MESSAGE_WITH ("-120123");
}

TESTCASE (s32_can_be_written)
{
  gint32 val = 0;
  COMPILE_AND_LOAD_SCRIPT (GUM_PTR_CONST ".writeS32(-120123);", &val);
  g_assert_cmpint (val, ==, -120123);
}

TESTCASE (u32_can_be_read)
{
  guint32 val = 120123;
  COMPILE_AND_LOAD_SCRIPT ("send(" GUM_PTR_CONST ".readU32());", &val);
  EXPECT_SEND_MESSAGE_WITH ("120123");
}

TESTCASE (u32_can_be_written)
{
  guint32 val = 0;
  COMPILE_AND_LOAD_SCRIPT (GUM_PTR_CONST ".writeU32(120123);", &val);
  g_assert_cmpint (val, ==, 120123);
}

TESTCASE (s64_can_be_read)
{
  gint64 val = G_GINT64_CONSTANT (-1201239876783);
  COMPILE_AND_LOAD_SCRIPT (
      "var value = " GUM_PTR_CONST ".readS64();"
      "send(value instanceof Int64);"
      "send(value);",
      &val);
  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_SEND_MESSAGE_WITH ("\"-1201239876783\"");
}

TESTCASE (s64_can_be_written)
{
  gint64 val = 0;
  COMPILE_AND_LOAD_SCRIPT (
      GUM_PTR_CONST ".writeS64(int64('-1201239876783'));", &val);
  g_assert_cmpint (val, ==, G_GINT64_CONSTANT (-1201239876783));
}

TESTCASE (u64_can_be_read)
{
  guint64 val = G_GUINT64_CONSTANT (1201239876783);
  COMPILE_AND_LOAD_SCRIPT (
      "var value = " GUM_PTR_CONST ".readU64();"
      "send(value instanceof UInt64);"
      "send(value);",
      &val);
  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_SEND_MESSAGE_WITH ("\"1201239876783\"");
}

TESTCASE (u64_can_be_written)
{
  gint64 val = 0;
  COMPILE_AND_LOAD_SCRIPT (
      GUM_PTR_CONST ".writeU64(uint64('1201239876783'));", &val);
  g_assert_cmpint (val, ==, G_GUINT64_CONSTANT (1201239876783));
}

TESTCASE (short_can_be_read)
{
  short val = -12123;
  COMPILE_AND_LOAD_SCRIPT ("send(" GUM_PTR_CONST ".readShort());", &val);
  EXPECT_SEND_MESSAGE_WITH ("-12123");
}

TESTCASE (short_can_be_written)
{
  short val = 0;
  COMPILE_AND_LOAD_SCRIPT (GUM_PTR_CONST ".writeShort(-12123);", &val);
  g_assert_cmpint (val, ==, -12123);

  COMPILE_AND_LOAD_SCRIPT (GUM_PTR_CONST ".writeShort(int64(-1234));", &val);
  g_assert_cmpint (val, ==, -1234);
}

TESTCASE (ushort_can_be_read)
{
  unsigned short val = 12123;
  COMPILE_AND_LOAD_SCRIPT ("send(" GUM_PTR_CONST ".readUShort());", &val);
  EXPECT_SEND_MESSAGE_WITH ("12123");
}

TESTCASE (ushort_can_be_written)
{
  unsigned short val = 0;
  COMPILE_AND_LOAD_SCRIPT (GUM_PTR_CONST ".writeUShort(12123);", &val);
  g_assert_cmpint (val, ==, 12123);

  COMPILE_AND_LOAD_SCRIPT (GUM_PTR_CONST ".writeUShort(uint64(1234));", &val);
  g_assert_cmpint (val, ==, 1234);
}

TESTCASE (int_can_be_read)
{
  int val = -120123;
  COMPILE_AND_LOAD_SCRIPT ("send(" GUM_PTR_CONST ".readInt());", &val);
  EXPECT_SEND_MESSAGE_WITH ("-120123");
}

TESTCASE (int_can_be_written)
{
  int val = 0;
  COMPILE_AND_LOAD_SCRIPT (GUM_PTR_CONST ".writeInt(-120123);", &val);
  g_assert_cmpint (val, ==, -120123);
}

TESTCASE (uint_can_be_read)
{
  unsigned int val = 120123;
  COMPILE_AND_LOAD_SCRIPT ("send(" GUM_PTR_CONST ".readUInt());", &val);
  EXPECT_SEND_MESSAGE_WITH ("120123");
}

TESTCASE (uint_can_be_written)
{
  unsigned int val = 0;
  COMPILE_AND_LOAD_SCRIPT (GUM_PTR_CONST ".writeUInt(120123);", &val);
  g_assert_cmpint (val, ==, 120123);
}

TESTCASE (long_can_be_read)
{
  long val = -123;
  COMPILE_AND_LOAD_SCRIPT ("send(" GUM_PTR_CONST ".readLong());", &val);
  EXPECT_SEND_MESSAGE_WITH ("\"-123\"");
}

TESTCASE (long_can_be_written)
{
  long val = 0;
  COMPILE_AND_LOAD_SCRIPT (GUM_PTR_CONST ".writeLong(1350966097);", &val);
  g_assert_cmpint (val, ==, 1350966097);
}

TESTCASE (ulong_can_be_read)
{
  unsigned long val = 4294967295UL;
  COMPILE_AND_LOAD_SCRIPT ("send(" GUM_PTR_CONST ".readULong());", &val);
  EXPECT_SEND_MESSAGE_WITH ("\"4294967295\"");
}

TESTCASE (ulong_can_be_written)
{
  unsigned long val = 0;
  COMPILE_AND_LOAD_SCRIPT (GUM_PTR_CONST ".writeULong(4294967295);", &val);
  g_assert_cmpint (val, ==, 4294967295UL);
}

TESTCASE (float_can_be_read)
{
  float val = 123.456f;
  COMPILE_AND_LOAD_SCRIPT ("send(Math.abs(" GUM_PTR_CONST ".readFloat()"
      " - 123.456) < 0.00001);", &val);
  EXPECT_SEND_MESSAGE_WITH ("true");
}

TESTCASE (float_can_be_written)
{
  float val = 0.f;
  COMPILE_AND_LOAD_SCRIPT (GUM_PTR_CONST ".writeFloat(123.456);", &val);
  g_assert_cmpfloat (ABS (val - 123.456f), <, 0.00001f);
}

TESTCASE (double_can_be_read)
{
  double val = 123.456;
  COMPILE_AND_LOAD_SCRIPT ("send(Math.abs(" GUM_PTR_CONST ".readDouble()"
      " - 123.456) < 0.00001);", &val);
  EXPECT_SEND_MESSAGE_WITH ("true");
}

TESTCASE (double_can_be_written)
{
  double val = 0.0;
  COMPILE_AND_LOAD_SCRIPT (GUM_PTR_CONST ".writeDouble(123.456);", &val);
  g_assert_cmpfloat (ABS (val - 123.456), <, 0.00001);
}

TESTCASE (byte_array_can_be_read)
{
  guint8 buf[3] = { 0x13, 0x37, 0x42 };
  COMPILE_AND_LOAD_SCRIPT (
      "var buffer = " GUM_PTR_CONST ".readByteArray(3);"
      "send('badger', buffer);"
      "send('badger', " GUM_PTR_CONST ".readByteArray(int64(3)));"
      "send('badger', " GUM_PTR_CONST ".readByteArray(uint64(3)));"
      "var emptyBuffer = " GUM_PTR_CONST ".readByteArray(0);"
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

TESTCASE (byte_array_can_be_written)
{
  guint8 val[4] = { 0x00, 0x00, 0x00, 0xff };
  const guint8 other[3] = { 0x01, 0x02, 0x03 };

  COMPILE_AND_LOAD_SCRIPT (
      GUM_PTR_CONST ".writeByteArray([0x13, 0x37, 0x42]);",
      val);
  EXPECT_NO_MESSAGES ();
  g_assert_cmpint (val[0], ==, 0x13);
  g_assert_cmpint (val[1], ==, 0x37);
  g_assert_cmpint (val[2], ==, 0x42);
  g_assert_cmpint (val[3], ==, 0xff);

  COMPILE_AND_LOAD_SCRIPT (
      "var other = " GUM_PTR_CONST ".readByteArray(3);"
      GUM_PTR_CONST ".writeByteArray(other);",
      other, val);
  EXPECT_NO_MESSAGES ();
  g_assert_cmpint (val[0], ==, 0x01);
  g_assert_cmpint (val[1], ==, 0x02);
  g_assert_cmpint (val[2], ==, 0x03);
  g_assert_cmpint (val[3], ==, 0xff);

  COMPILE_AND_LOAD_SCRIPT (
      "var bytes = new Uint8Array(2);"
      "bytes[0] = 4;"
      "bytes[1] = 5;"
      GUM_PTR_CONST ".writeByteArray(bytes);",
      val);
  EXPECT_NO_MESSAGES ();
  g_assert_cmpint (val[0], ==, 0x04);
  g_assert_cmpint (val[1], ==, 0x05);
  g_assert_cmpint (val[2], ==, 0x03);
}

TESTCASE (c_string_can_be_read)
{
  const gchar * str = "Hello";
  const gchar * uni = "Bjøærheimsbygd";

  COMPILE_AND_LOAD_SCRIPT ("send(" GUM_PTR_CONST ".readCString());",
      str);
  EXPECT_SEND_MESSAGE_WITH ("\"Hello\"");

  COMPILE_AND_LOAD_SCRIPT ("send(" GUM_PTR_CONST ".readCString(3));",
      str);
  EXPECT_SEND_MESSAGE_WITH ("\"Hel\"");

  COMPILE_AND_LOAD_SCRIPT ("send(" GUM_PTR_CONST ".readCString(0));",
      str);
  EXPECT_SEND_MESSAGE_WITH ("\"\"");

  COMPILE_AND_LOAD_SCRIPT ("send(" GUM_PTR_CONST ".readCString(-1));",
      str);
  EXPECT_SEND_MESSAGE_WITH ("\"Hello\"");

  COMPILE_AND_LOAD_SCRIPT ("send(" GUM_PTR_CONST ".readCString(int64(-1)));",
      str);
  EXPECT_SEND_MESSAGE_WITH ("\"Hello\"");

  COMPILE_AND_LOAD_SCRIPT ("send(ptr('0').readCString());", str);
  EXPECT_SEND_MESSAGE_WITH ("null");

  COMPILE_AND_LOAD_SCRIPT ("send(" GUM_PTR_CONST ".readCString(4));", uni);
  EXPECT_SEND_MESSAGE_WITH ("\"Bjø\"");

  COMPILE_AND_LOAD_SCRIPT ("send(" GUM_PTR_CONST ".readCString(3));", uni);
  EXPECT_SEND_MESSAGE_WITH ("\"Bj\357\277\275\"");
}

TESTCASE (utf8_string_can_be_read)
{
  const gchar * str = "Bjøærheimsbygd";

  COMPILE_AND_LOAD_SCRIPT ("send(" GUM_PTR_CONST ".readUtf8String());", str);
  EXPECT_SEND_MESSAGE_WITH ("\"Bjøærheimsbygd\"");

  COMPILE_AND_LOAD_SCRIPT ("send(" GUM_PTR_CONST ".readUtf8String(4));", str);
  EXPECT_SEND_MESSAGE_WITH ("\"Bjø\"");

  COMPILE_AND_LOAD_SCRIPT ("send(" GUM_PTR_CONST ".readUtf8String(0));", str);
  EXPECT_SEND_MESSAGE_WITH ("\"\"");

  COMPILE_AND_LOAD_SCRIPT ("send(" GUM_PTR_CONST ".readUtf8String(-1));", str);
  EXPECT_SEND_MESSAGE_WITH ("\"Bjøærheimsbygd\"");

  COMPILE_AND_LOAD_SCRIPT ("send(" GUM_PTR_CONST ".readUtf8String(int64(-1)));",
      str);
  EXPECT_SEND_MESSAGE_WITH ("\"Bjøærheimsbygd\"");

  COMPILE_AND_LOAD_SCRIPT ("send(ptr('0').readUtf8String());", str);
  EXPECT_SEND_MESSAGE_WITH ("null");

  COMPILE_AND_LOAD_SCRIPT ("send(" GUM_PTR_CONST ".readUtf8String(3));", str);
  EXPECT_ERROR_MESSAGE_WITH (ANY_LINE_NUMBER,
      "Error: can't decode byte 0xc3 in position 2");
}

TESTCASE (utf8_string_can_be_written)
{
  gchar str[6];

  strcpy (str, "Hello");
  COMPILE_AND_LOAD_SCRIPT (GUM_PTR_CONST ".writeUtf8String('Bye');", str);
  g_assert_cmpstr (str, ==, "Bye");
  g_assert_cmphex (str[4], ==, 'o');
  g_assert_cmphex (str[5], ==, '\0');
}

TESTCASE (utf8_string_can_be_allocated)
{
  COMPILE_AND_LOAD_SCRIPT ("send("
      "Memory.allocUtf8String('Bjørheimsbygd').readUtf8String()"
      ");");
  EXPECT_SEND_MESSAGE_WITH ("\"Bjørheimsbygd\"");
}

TESTCASE (utf16_string_can_be_read)
{
  const gchar * str_utf8 = "Bjørheimsbygd";
  gunichar2 * str = g_utf8_to_utf16 (str_utf8, -1, NULL, NULL, NULL);

  COMPILE_AND_LOAD_SCRIPT ("send(" GUM_PTR_CONST ".readUtf16String());", str);
  EXPECT_SEND_MESSAGE_WITH ("\"Bjørheimsbygd\"");

  COMPILE_AND_LOAD_SCRIPT ("send(" GUM_PTR_CONST ".readUtf16String(3));", str);
  EXPECT_SEND_MESSAGE_WITH ("\"Bjø\"");

  COMPILE_AND_LOAD_SCRIPT ("send(" GUM_PTR_CONST ".readUtf16String(0));", str);
  EXPECT_SEND_MESSAGE_WITH ("\"\"");

  COMPILE_AND_LOAD_SCRIPT ("send(" GUM_PTR_CONST ".readUtf16String(-1));", str);
  EXPECT_SEND_MESSAGE_WITH ("\"Bjørheimsbygd\"");

  COMPILE_AND_LOAD_SCRIPT ("send("
      GUM_PTR_CONST ".readUtf16String(int64(-1))"
      ");",
      str);
  EXPECT_SEND_MESSAGE_WITH ("\"Bjørheimsbygd\"");

  COMPILE_AND_LOAD_SCRIPT ("send(ptr('0').readUtf16String());", str);
  EXPECT_SEND_MESSAGE_WITH ("null");

  g_free (str);
}

TESTCASE (utf16_string_can_be_written)
{
  gunichar2 * str = g_utf8_to_utf16 ("Hello", -1, NULL, NULL, NULL);

  COMPILE_AND_LOAD_SCRIPT (GUM_PTR_CONST ".writeUtf16String('Bye');", str);
  g_assert_cmphex (str[0], ==, 'B');
  g_assert_cmphex (str[1], ==, 'y');
  g_assert_cmphex (str[2], ==, 'e');
  g_assert_cmphex (str[3], ==, '\0');
  g_assert_cmphex (str[4], ==, 'o');
  g_assert_cmphex (str[5], ==, '\0');

  g_free (str);
}

TESTCASE (utf16_string_can_be_allocated)
{
  COMPILE_AND_LOAD_SCRIPT ("send("
      "Memory.allocUtf16String('Bjørheimsbygd').readUtf16String()"
      ");");
  EXPECT_SEND_MESSAGE_WITH ("\"Bjørheimsbygd\"");
}

#ifdef G_OS_WIN32

TESTCASE (ansi_string_can_be_read_in_code_page_936)
{
  CPINFOEX cpi;
  const gchar * str_utf8;
  WCHAR * str_utf16;
  gchar str[13 + 1];

  GetCPInfoEx (CP_THREAD_ACP, 0, &cpi);
  if (cpi.CodePage != 936)
  {
    g_print ("<skipping, only available on systems with ANSI code page 936> ");
    return;
  }

  str_utf8 = "test测试.";
  str_utf16 = g_utf8_to_utf16 (str_utf8, -1, NULL, NULL, NULL);
  WideCharToMultiByte (CP_THREAD_ACP, 0, str_utf16, -1, str, sizeof (str),
      NULL, NULL);

  COMPILE_AND_LOAD_SCRIPT ("send(Memory.readAnsiString(" GUM_PTR_CONST "));",
      str);
  EXPECT_SEND_MESSAGE_WITH ("\"test测试.\"");

  COMPILE_AND_LOAD_SCRIPT ("send(Memory.readAnsiString(" GUM_PTR_CONST
      ", 5));", str);
  EXPECT_SEND_MESSAGE_WITH ("\"test?\"");

  COMPILE_AND_LOAD_SCRIPT ("send(Memory.readAnsiString(" GUM_PTR_CONST
      ", 6));", str);
  EXPECT_SEND_MESSAGE_WITH ("\"test测\"");

  COMPILE_AND_LOAD_SCRIPT ("send(Memory.readAnsiString(" GUM_PTR_CONST
      ", 0));", str);
  EXPECT_SEND_MESSAGE_WITH ("\"\"");

  COMPILE_AND_LOAD_SCRIPT ("send(Memory.readAnsiString(" GUM_PTR_CONST
      ", -1));", str);
  EXPECT_SEND_MESSAGE_WITH ("\"test测试.\"");

  COMPILE_AND_LOAD_SCRIPT ("send(Memory.readAnsiString(" GUM_PTR_CONST
      ", int64(-1)));", str);
  EXPECT_SEND_MESSAGE_WITH ("\"test测试.\"");

  COMPILE_AND_LOAD_SCRIPT ("send(Memory.readAnsiString(ptr(\"0\")));", str);
  EXPECT_SEND_MESSAGE_WITH ("null");

  g_free (str_utf16);

  str_utf8 = "Bjørheimsbygd";
  str_utf16 = g_utf8_to_utf16 (str_utf8, -1, NULL, NULL, NULL);
  WideCharToMultiByte (CP_THREAD_ACP, 0, str_utf16, -1, str, sizeof (str),
      NULL, NULL);

  COMPILE_AND_LOAD_SCRIPT ("send(" GUM_PTR_CONST ".readAnsiString());", str);
  EXPECT_SEND_MESSAGE_WITH ("\"Bj?rheimsbygd\"");

  g_free (str_utf16);
}

TESTCASE (ansi_string_can_be_read_in_code_page_1252)
{
  CPINFOEX cpi;
  const gchar * str_utf8;
  WCHAR * str_utf16;
  gchar str[13 + 1];

  GetCPInfoEx (CP_THREAD_ACP, 0, &cpi);
  if (cpi.CodePage != 1252)
  {
    g_print ("<skipping, only available on systems with ANSI code page 1252> ");
    return;
  }

  str_utf8 = "Bjørheimsbygd";
  str_utf16 = g_utf8_to_utf16 (str_utf8, -1, NULL, NULL, NULL);
  WideCharToMultiByte (CP_THREAD_ACP, 0, str_utf16, -1, str, sizeof (str),
      NULL, NULL);

  COMPILE_AND_LOAD_SCRIPT ("send(" GUM_PTR_CONST ".readAnsiString());", str);
  EXPECT_SEND_MESSAGE_WITH ("\"Bjørheimsbygd\"");

  COMPILE_AND_LOAD_SCRIPT ("send(" GUM_PTR_CONST ".readAnsiString(3));", str);
  EXPECT_SEND_MESSAGE_WITH ("\"Bjø\"");

  COMPILE_AND_LOAD_SCRIPT ("send(" GUM_PTR_CONST ".readAnsiString(0));", str);
  EXPECT_SEND_MESSAGE_WITH ("\"\"");

  COMPILE_AND_LOAD_SCRIPT ("send(" GUM_PTR_CONST ".readAnsiString(-1));", str);
  EXPECT_SEND_MESSAGE_WITH ("\"Bjørheimsbygd\"");

  COMPILE_AND_LOAD_SCRIPT ("send(" GUM_PTR_CONST ".readAnsiString(int64(-1)));",
      str);
  EXPECT_SEND_MESSAGE_WITH ("\"Bjørheimsbygd\"");

  COMPILE_AND_LOAD_SCRIPT ("send(ptr('0').readAnsiString());", str);
  EXPECT_SEND_MESSAGE_WITH ("null");

  g_free (str_utf16);
}

TESTCASE (ansi_string_can_be_written_in_code_page_936)
{
  CPINFOEX cpi;
  gchar str_ansi[13 + 1];
  gunichar2 str_utf16[13 + 1];
  gchar * str_utf8;

  GetCPInfoEx (CP_THREAD_ACP, 0, &cpi);
  if (cpi.CodePage != 936)
  {
    g_print ("<skipping, only available on systems with ANSI code page 936> ");
    return;
  }

  strcpy (str_ansi, "truncate-plz");
  COMPILE_AND_LOAD_SCRIPT (GUM_PTR_CONST ".writeAnsiString('test测试.');",
      str_ansi);
  MultiByteToWideChar (CP_THREAD_ACP, 0, str_ansi, -1,
      str_utf16, sizeof (str_utf16));
  str_utf8 = g_utf16_to_utf8 (str_utf16, -1, NULL, NULL, NULL);
  g_assert_cmpstr (str_utf8, == , "test测试.");
  g_free (str_utf8);
  g_assert_cmphex (str_ansi[9], == , '\0');
  g_assert_cmphex (str_ansi[10], == , 'l');
  g_assert_cmphex (str_ansi[11], == , 'z');
  g_assert_cmphex (str_ansi[12], == , '\0');

  COMPILE_AND_LOAD_SCRIPT (GUM_PTR_CONST ".writeAnsiString('Bjørheimsbygd');",
      str_ansi);
  MultiByteToWideChar (CP_THREAD_ACP, 0, str_ansi, -1,
      str_utf16, sizeof (str_utf16));
  str_utf8 = g_utf16_to_utf8 (str_utf16, -1, NULL, NULL, NULL);
  g_assert_cmpstr (str_utf8, == , "Bj?rheimsbygd");
  g_free (str_utf8);
}

TESTCASE (ansi_string_can_be_written_in_code_page_1252)
{
  CPINFOEX cpi;
  gchar str_ansi[16 + 1];
  gunichar2 str_utf16[16 + 1];
  gchar * str_utf8;

  GetCPInfoEx (CP_THREAD_ACP, 0, &cpi);
  if (cpi.CodePage != 1252)
  {
    g_print ("<skipping, only available on systems with ANSI code page 1252> ");
    return;
  }

  strcpy (str_ansi, "Kjempeforhaustar");
  COMPILE_AND_LOAD_SCRIPT (GUM_PTR_CONST ".writeAnsiString('Bjørheimsbygd');",
      str_ansi);
  MultiByteToWideChar (CP_THREAD_ACP, 0, str_ansi, -1,
      str_utf16, sizeof (str_utf16));
  str_utf8 = g_utf16_to_utf8 (str_utf16, -1, NULL, NULL, NULL);
  g_assert_cmpstr (str_utf8, == , "Bjørheimsbygd");
  g_free (str_utf8);
  g_assert_cmphex (str_ansi[13], == , '\0');
  g_assert_cmphex (str_ansi[14], == , 'a');
  g_assert_cmphex (str_ansi[15], == , 'r');
  g_assert_cmphex (str_ansi[16], == , '\0');
}

TESTCASE (ansi_string_can_be_allocated_in_code_page_936)
{
  CPINFOEX cpi;

  GetCPInfoEx (CP_THREAD_ACP, 0, &cpi);
  if (cpi.CodePage != 936)
  {
    g_print ("<skipping, only available on systems with ANSI code page 936> ");
    return;
  }

  COMPILE_AND_LOAD_SCRIPT ("send("
      "Memory.allocAnsiString('test测试.').readAnsiString()"
      ");");
  EXPECT_SEND_MESSAGE_WITH ("\"test测试.\"");
}

TESTCASE (ansi_string_can_be_allocated_in_code_page_1252)
{
  CPINFOEX cpi;

  GetCPInfoEx (CP_THREAD_ACP, 0, &cpi);
  if (cpi.CodePage != 1252)
  {
    g_print ("<skipping, only available on systems with ANSI code page 1252> ");
    return;
  }

  COMPILE_AND_LOAD_SCRIPT ("send("
      "Memory.allocAnsiString('Bjørheimsbygd').readAnsiString()"
      ");");
  EXPECT_SEND_MESSAGE_WITH ("\"Bjørheimsbygd\"");
}

#endif

TESTCASE (invalid_read_results_in_exception)
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
      "Double",
      "S64",
      "U64",
      "Utf8String",
      "Utf16String",
#ifdef G_OS_WIN32
      "AnsiString"
#endif
  };
  guint i;

  if (!check_exception_handling_testable ())
    return;

  for (i = 0; i != G_N_ELEMENTS (type_name); i++)
  {
    gchar * source;

    source = g_strconcat ("ptr('1328').read", type_name[i], "();", NULL);
    COMPILE_AND_LOAD_SCRIPT (source);

#if GLIB_SIZEOF_VOID_P == 8
    EXPECT_ERROR_MESSAGE_WITH (ANY_LINE_NUMBER,
        "Error: access violation accessing 0x530");
#else
    /*
     * On 32-bit platforms, when reading 64-bit values we must read 32-bits at a
     * time. The compiler is at liberty to read either the high or low part
     * first, and hence we may not fault on the first part of the value, but
     * rather on the second. The ordering is likely dependent on endianness.
     */
    EXPECT_ERROR_MESSAGE_MATCHING (ANY_LINE_NUMBER,
        "Error: access violation accessing 0x53(0|4)");
#endif

    g_free (source);
  }
}

TESTCASE (invalid_write_results_in_exception)
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
      "S64",
      "U64"
  };
  const gchar * string_type_name[] = {
      "Utf8String",
      "Utf16String"
  };
  guint i;

  if (!check_exception_handling_testable ())
    return;

  for (i = 0; i != G_N_ELEMENTS (primitive_type_name); i++)
  {
    gchar * source;

    source = g_strconcat ("ptr('1328').write", primitive_type_name[i], "(13);",
        NULL);
    COMPILE_AND_LOAD_SCRIPT (source);

#if GLIB_SIZEOF_VOID_P == 8
    EXPECT_ERROR_MESSAGE_WITH (ANY_LINE_NUMBER,
        "Error: access violation accessing 0x530");
#else
    /* See note in previous test. */
    EXPECT_ERROR_MESSAGE_MATCHING (ANY_LINE_NUMBER,
        "Error: access violation accessing 0x53(0|4)");
#endif

    g_free (source);
  }

  for (i = 0; i != G_N_ELEMENTS (string_type_name); i++)
  {
    gchar * source;

    source = g_strconcat ("ptr('1328').write", string_type_name[i], "('Hey');",
        NULL);
    COMPILE_AND_LOAD_SCRIPT (source);

#if GLIB_SIZEOF_VOID_P == 8
    EXPECT_ERROR_MESSAGE_WITH (ANY_LINE_NUMBER,
        "Error: access violation accessing 0x530");
#else
    /* See note in previous test. */
    EXPECT_ERROR_MESSAGE_MATCHING (ANY_LINE_NUMBER,
        "Error: access violation accessing 0x53(0|4)");
#endif

    g_free (source);
  }
}

TESTCASE (invalid_read_write_execute_results_in_exception)
{
  if (!check_exception_handling_testable ())
    return;

  COMPILE_AND_LOAD_SCRIPT ("ptr('1328').readU8();");
  EXPECT_ERROR_MESSAGE_WITH (ANY_LINE_NUMBER,
      "Error: access violation accessing 0x530");
  EXPECT_NO_MESSAGES ();

  COMPILE_AND_LOAD_SCRIPT ("ptr('1328').writeU8(42);");
  EXPECT_ERROR_MESSAGE_WITH (ANY_LINE_NUMBER,
      "Error: access violation accessing 0x530");
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

TESTCASE (cmodule_can_be_defined)
{
  int (* add_impl) (int a, int b);

  COMPILE_AND_LOAD_SCRIPT (
      "var m = new CModule('"
      ""
      "int\\n"
      "add (int a,\\n"
      "     int b)\\n"
      "{\\n"
      "  return a + b;\\n"
      "}"
      "');"
      "send(m.add);");

  add_impl = EXPECT_SEND_MESSAGE_WITH_POINTER ();
  g_assert_nonnull (add_impl);
  g_assert_cmpint (add_impl (3, 4), ==, 7);
}

TESTCASE (cmodule_symbols_can_be_provided)
{
  int a = 42;
  int b = 1337;
  int (* get_magic_impl) (void);

  COMPILE_AND_LOAD_SCRIPT (
      "var m = new CModule('"
      ""
      "extern int a;\\n"
      "extern int b;\\n"
      "\\n"
      "int\\n"
      "get_magic (void)\\n"
      "{\\n"
      "  return a + b;\\n"
      "}"
      "', { a: " GUM_PTR_CONST ", b: " GUM_PTR_CONST " });"
      "send(m.get_magic);",
      &a, &b);

  get_magic_impl = EXPECT_SEND_MESSAGE_WITH_POINTER ();
  g_assert_nonnull (get_magic_impl);
  g_assert_cmpint (get_magic_impl (), ==, 1379);
}

TESTCASE (cmodule_should_report_parsing_errors)
{
  COMPILE_AND_LOAD_SCRIPT ("new CModule('void foo (int a');");
  EXPECT_ERROR_MESSAGE_MATCHING (ANY_LINE_NUMBER,
      "Error: Compilation failed.+");
}

TESTCASE (cmodule_should_report_linking_errors)
{
  COMPILE_AND_LOAD_SCRIPT ("new CModule('"
      "extern int v; int f (void) { return v; }');");
  EXPECT_ERROR_MESSAGE_WITH (ANY_LINE_NUMBER,
      "Error: Linking failed: tcc: error: undefined symbol 'v'");
}

TESTCASE (cmodule_should_provide_lifecycle_hooks)
{
  COMPILE_AND_LOAD_SCRIPT (
      "var m = new CModule('"
      ""
      "extern void notify (int n);\\n"
      "\\n"
      "void\\n"
      "init (void)\\n"
      "{\\n"
      "  notify (1);\\n"
      "}\\n"
      "\\n"
      "void\\n"
      "finalize (void)\\n"
      "{\\n"
      "  notify (2);\\n"
      "}\\n"
      "', {"
      "  notify: new NativeCallback(function (n) { send(n); }, 'void', ['int'])"
      "});");
  EXPECT_SEND_MESSAGE_WITH ("1");
  EXPECT_NO_MESSAGES ();

  UNLOAD_SCRIPT ();
  EXPECT_SEND_MESSAGE_WITH ("2");
  EXPECT_NO_MESSAGES ();
}

TESTCASE (cmodule_can_be_used_with_interceptor_attach)
{
  int seen_argval = -1;
  int seen_retval = -1;
  gpointer seen_return_address = NULL;
  guint seen_thread_id = 0;
  guint seen_depth = G_MAXUINT;
  int seen_function_data = -1;
  int seen_thread_state_calls = -1;
  int seen_invocation_state_arg = -1;

  COMPILE_AND_LOAD_SCRIPT (
      "var cm = new CModule('"
      "  #include <gum/guminterceptor.h>\\n"
      "\\n"
      "  typedef struct _ThreadState ThreadState;\\n"
      "  typedef struct _InvState InvState;\\n"
      "\\n"
      "  struct _ThreadState\\n"
      "  {\\n"
      "    int calls;\\n"
      "  };\\n"
      "\\n"
      "  struct _InvState\\n"
      "  {\\n"
      "    int arg;\\n"
      "  };\\n"
      "\\n"
      "  extern int seenArgval;\\n"
      "  extern int seenRetval;\\n"
      "  extern gpointer seenReturnAddress;\\n"
      "  extern guint seenThreadId;\\n"
      "  extern guint seenDepth;\\n"
      "  extern int seenFunctionData;\\n"
      "  extern int seenThreadStateCalls;\\n"
      "  extern int seenInvocationStateArg;\\n"
      "\\n"
      "  void\\n"
      "  onEnter (GumInvocationContext * ic)\\n"
      "  {\\n"
      "    int arg = (int) gum_invocation_context_get_nth_argument (ic, 0);\\n"
      "\\n"
      "    seenArgval = arg;\\n"
      "    gum_invocation_context_replace_nth_argument (ic, 0,\\n"
      "        (gpointer) (arg + 1));\\n"
      "\\n"
      "    seenReturnAddress =\\n"
      "        gum_invocation_context_get_return_address (ic);\\n"
      "    seenThreadId = gum_invocation_context_get_thread_id (ic);\\n"
      "    seenDepth = gum_invocation_context_get_depth (ic);\\n"
      "\\n"
      "    seenFunctionData = GUM_IC_GET_FUNC_DATA (ic, int);\\n"
      "\\n"
      "    ThreadState * ts = GUM_IC_GET_THREAD_DATA (ic, ThreadState);\\n"
      "    ts->calls++;\\n"
      "\\n"
      "    InvState * is = GUM_IC_GET_INVOCATION_DATA (ic, InvState);\\n"
      "    is->arg = seenArgval;\\n"
      "  }\\n"
      "\\n"
      "  void\\n"
      "  onLeave (GumInvocationContext * ic)\\n"
      "  {\\n"
      "    seenRetval = (int) gum_invocation_context_get_return_value (ic);\\n"
      "    gum_invocation_context_replace_return_value (ic, (gpointer) 42);\\n"
      "\\n"
      "    ThreadState * ts = GUM_IC_GET_THREAD_DATA (ic, ThreadState);\\n"
      "    seenThreadStateCalls = ts->calls;\\n"
      "\\n"
      "    InvState * is = GUM_IC_GET_INVOCATION_DATA (ic, InvState);\\n"
      "    seenInvocationStateArg = is->arg;\\n"
      "  }\\n"
      "', {"
      "  seenArgval: " GUM_PTR_CONST ","
      "  seenRetval: " GUM_PTR_CONST ","
      "  seenReturnAddress: " GUM_PTR_CONST ","
      "  seenThreadId: " GUM_PTR_CONST ","
      "  seenDepth: " GUM_PTR_CONST ","
      "  seenFunctionData: " GUM_PTR_CONST ","
      "  seenThreadStateCalls: " GUM_PTR_CONST ","
      "  seenInvocationStateArg: " GUM_PTR_CONST
      "});"
      "Interceptor.attach(" GUM_PTR_CONST ", cm, ptr(1911));",
      &seen_argval,
      &seen_retval,
      &seen_return_address,
      &seen_thread_id,
      &seen_depth,
      &seen_function_data,
      &seen_thread_state_calls,
      &seen_invocation_state_arg,
      target_function_int);

  EXPECT_NO_MESSAGES ();

  g_assert_cmpint (target_function_int (1), ==, 42);
  g_assert_cmpint (seen_argval, ==, 1);
  g_assert_cmpint (seen_retval, ==, 90);
  g_assert_nonnull (seen_return_address);
  g_assert_cmpuint (seen_thread_id, ==, gum_process_get_current_thread_id ());
  g_assert_cmpuint (seen_depth, ==, 0);
  g_assert_cmpint (seen_function_data, ==, 1911);
  g_assert_cmpint (seen_thread_state_calls, ==, 1);
  g_assert_cmpint (seen_invocation_state_arg, ==, 1);

  target_function_int (12);
  g_assert_cmpint (seen_thread_state_calls, ==, 2);
  g_assert_cmpint (seen_invocation_state_arg, ==, 12);
}

TESTCASE (cmodule_can_be_used_with_interceptor_replace)
{
  int seen_replacement_data = -1;

  COMPILE_AND_LOAD_SCRIPT (
      "var m = new CModule('"
      "#include <gum/guminterceptor.h>\\n"
      "\\n"
      "extern int seenReplacementData;\\n"
      "\\n"
      "int\\n"
      "dummy (int arg)\\n"
      "{\\n"
      "  GumInvocationContext * ic =\\n"
      "      gum_interceptor_get_current_invocation ();\\n"
      "  seenReplacementData = GUM_IC_GET_REPLACEMENT_DATA (ic, int);\\n"
      "\\n"
      "  return 1337;\\n"
      "}\\n"
      "', { seenReplacementData: " GUM_PTR_CONST " });"
      "Interceptor.replace(" GUM_PTR_CONST ", m.dummy, ptr(1911));",
      &seen_replacement_data, target_function_int);

  EXPECT_NO_MESSAGES ();
  g_assert_cmpint (target_function_int (7), ==, 1337);
  g_assert_cmpint (seen_replacement_data, ==, 1911);

  gum_script_unload_sync (fixture->script, NULL);
  g_assert_cmpint (target_function_int (7), ==, 315);
}

TESTCASE (cmodule_can_be_used_with_stalker_transform)
{
  GumThreadId test_thread_id;
  guint num_transforms = 0;
  gsize seen_user_data = 0;

  if (!g_test_slow ())
  {
    g_print ("<skipping, run in slow mode> ");
    return;
  }

  test_thread_id = gum_process_get_current_thread_id ();

  COMPILE_AND_LOAD_SCRIPT (
      "var m = new CModule('"
      "#include <stdio.h>\\n"
      "#include <gum/gumstalker.h>\\n"
      "\\n"
      "static void on_ret (GumCpuContext * cpu_context, gpointer user_data);\\n"
      "\\n"
      "extern guint numTransforms;\\n"
      "extern gpointer seenUserData;\\n"
      "\\n"
      "void\\n"
      "transform (GumStalkerIterator * iterator,\\n"
      "           GumStalkerWriter * output,\\n"
      "           gpointer user_data)\\n"
      "{\\n"
      "  printf (\"\\\\ntransform()\\\\n\");\\n"
      "  cs_insn * insn = NULL;\\n"
      "  while (gum_stalker_iterator_next (iterator, &insn))\\n"
      "  {\\n"
      "    printf (\"\\\\t%%s %%s\\\\n\", insn->mnemonic, insn->op_str);\\n"
      "#if defined (HAVE_I386)\\n"
      "    if (insn->id == X86_INS_RET)\\n"
      "    {\\n"
      "      gum_x86_writer_put_nop (output);\\n"
      "      gum_stalker_iterator_put_callout (iterator, on_ret, NULL,\\n"
      "          NULL);\\n"
      "    }\\n"
      "#elif defined (HAVE_ARM64)\\n"
      "    if (insn->id == ARM64_INS_RET)\\n"
      "    {\\n"
      "      gum_arm64_writer_put_nop (output);\\n"
      "      gum_stalker_iterator_put_callout (iterator, on_ret, NULL,\\n"
      "          NULL);\\n"
      "    }\\n"
      "#endif\\n"
      "    gum_stalker_iterator_keep (iterator);\\n"
      "  }\\n"
      "  numTransforms++;\\n"
      "  seenUserData = user_data;\\n"
      "}\\n"
      "\\n"
      "static void\\n"
      "on_ret (GumCpuContext * cpu_context,"
      "        gpointer user_data)\\n"
      "{\\n"
      "  // printf (\"\\\\non_ret() cpu_context=%%p\\\\n\", cpu_context);\\n"
      "}\\n"
      "', {"
      "  numTransforms: " GUM_PTR_CONST ","
      "  seenUserData: " GUM_PTR_CONST
      "});"
      "var instructionsSeen = 0;"
      "Stalker.follow(%" G_GSIZE_FORMAT ", {"
      "  transform: m.transform,"
      "  data: ptr(3)"
      "});"
      "recv('stop', function (message) {"
      "  Stalker.unfollow(%" G_GSIZE_FORMAT ");"
      "  send('done');"
      "});",
      &num_transforms,
      &seen_user_data,
      test_thread_id,
      test_thread_id);
  g_usleep (1);
  EXPECT_NO_MESSAGES ();
  POST_MESSAGE ("{\"type\":\"stop\"}");
  EXPECT_SEND_MESSAGE_WITH ("\"done\"");
  EXPECT_NO_MESSAGES ();
  g_assert_true (num_transforms > 0);
  g_assert_cmphex (seen_user_data, ==, 3);
}

TESTCASE (cmodule_can_be_used_with_stalker_callout)
{
  GumThreadId test_thread_id;
  guint num_callouts = 0;
  gsize seen_user_data = 0;

  if (!g_test_slow ())
  {
    g_print ("<skipping, run in slow mode> ");
    return;
  }

  test_thread_id = gum_process_get_current_thread_id ();

  COMPILE_AND_LOAD_SCRIPT (
      "var m = new CModule('"
      "#include <stdio.h>\\n"
      "#include <gum/gumstalker.h>\\n"
      "\\n"
      "extern guint numCallouts;\\n"
      "extern gpointer seenUserData;\\n"
      "\\n"
      "void\\n"
      "onBeforeFirstInstruction (GumCpuContext * cpu_context,"
      "                          gpointer user_data)\\n"
      "{\\n"
      "  printf (\"cpu_context=%%p\\\\n\", cpu_context);\\n"
      "  numCallouts++;\\n"
      "  seenUserData = user_data;\\n"
      "}\\n"
      "', {"
      "  numCallouts: " GUM_PTR_CONST ","
      "  seenUserData: " GUM_PTR_CONST
      "});"
      "var instructionsSeen = 0;"
      "Stalker.follow(%" G_GSIZE_FORMAT ", {"
      "  transform: function (iterator) {"
      "    var instruction;"

      "    while ((instruction = iterator.next()) !== null) {"
      "      if (instructionsSeen === 0) {"
      "        iterator.putCallout(m.onBeforeFirstInstruction, ptr(7));"
      "      }"

      "      iterator.keep();"

      "      instructionsSeen++;"
      "    }"
      "  }"
      "});"
      "recv('stop', function (message) {"
      "  Stalker.unfollow(%" G_GSIZE_FORMAT ");"
      "  send(instructionsSeen > 0);"
      "});",
      &num_callouts,
      &seen_user_data,
      test_thread_id,
      test_thread_id);
  g_usleep (1);
  EXPECT_NO_MESSAGES ();
  POST_MESSAGE ("{\"type\":\"stop\"}");
  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_NO_MESSAGES ();
  g_assert_true (num_callouts > 0);
  g_assert_cmphex (seen_user_data, ==, 7);
}

TESTCASE (cmodule_can_be_used_with_stalker_call_probe)
{
  GumThreadId test_thread_id;

  if (!g_test_slow ())
  {
    g_print ("<skipping, run in slow mode> ");
    return;
  }

  test_thread_id = gum_process_get_current_thread_id ();

  COMPILE_AND_LOAD_SCRIPT (
      "var m = new CModule('"
      "#include <stdio.h>\\n"
      "#include <gum/gumstalker.h>\\n"
      "\\n"
      "extern void send (gpointer v);\\n"
      ""
      "void\\n"
      "onCall (GumCallSite * site,"
      "        gpointer user_data)\\n"
      "{\\n"
      "  printf (\"block_address=%%p\\\\n\", site->block_address);\\n"
      "  send (user_data);\\n"
      "}\\n"
      "', {"
      "  send: new NativeCallback(function (v) { send(v.toUInt32()); }, "
          "'void', ['pointer'])"
      "});"
      "Stalker.addCallProbe(" GUM_PTR_CONST ", m.onCall, ptr(12));"
      "Stalker.follow(%" G_GSIZE_FORMAT ");"
      "recv('stop', function (message) {"
      "  Stalker.unfollow(%" G_GSIZE_FORMAT ");"
      "});"
      "send('ready');",
      target_function_int,
      test_thread_id,
      test_thread_id);
  EXPECT_SEND_MESSAGE_WITH ("\"ready\"");
  target_function_int (1337);
  EXPECT_SEND_MESSAGE_WITH ("12");
  POST_MESSAGE ("{\"type\":\"stop\"}");
  EXPECT_NO_MESSAGES ();
}

TESTCASE (cmodule_can_be_used_with_module_map)
{
  COMPILE_AND_LOAD_SCRIPT (
      "var modules = new ModuleMap();"
      ""
      "var cm = new CModule('"
      "#include <gum/gummodulemap.h>\\n"
      "\\n"
      "const gchar *\\n"
      "find (GumModuleMap * map,\\n"
      "      gconstpointer address)\\n"
      "{\\n"
      "  const GumModuleDetails * m;\\n"
      "\\n"
      "  m = gum_module_map_find (map, GUM_ADDRESS (address));\\n"
      "  if (m == NULL)\\n"
      "    return NULL;\\n"
      "\\n"
      "  return m->name;\\n"
      "}');"
      ""
      "var find = new NativeFunction(cm.find, 'pointer', "
          "['pointer', 'pointer']);"
      "send(find(modules, modules.values()[0].base).isNull());"
      "send(find(modules, NULL).isNull());");
  EXPECT_SEND_MESSAGE_WITH ("false");
  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_NO_MESSAGES ();
}

TESTCASE (cmodule_should_provide_some_builtin_string_functions)
{
  guint8 buf[2] = { 0, 0 };
  int (* score_impl) (const char * str);

  COMPILE_AND_LOAD_SCRIPT (
      "var m = new CModule('"
      "#include <glib.h>\\n"
      "#include <string.h>\\n"
      "\\n"
      "extern guint8 buf[2];"
      ""
      "int\\n"
      "score (const char * str)\\n"
      "{\\n"
      "  if (strlen (str) == 1)\\n"
      "    return 1;\\n"
      "  if (strcmp (str, \"1234\") == 0)\\n"
      "    return 2;\\n"
      "  if (strstr (str, \"badger\") == str + 4)\\n"
      "    return 3;\\n"
      "  if (strchr (str, \\'!\\') == str + 3)\\n"
      "    return 4;\\n"
      "  if (strrchr (str, \\'/\\') == str + 8)\\n"
      "    return 5;\\n"
      "  if (strlen (str) == 2)\\n"
      "  {\\n"
      "    memcpy (buf, str, 2);\\n"
      "    return 6;\\n"
      "  }\\n"
      "  if (strlen (str) == 3)\\n"
      "  {\\n"
      "    memmove (buf, str + 1, 2);\\n"
      "    return 7;\\n"
      "  }\\n"
      "  if (strlen (str) == 4)\\n"
      "  {\\n"
      "    memset (buf, 88, 2);\\n"
      "    return 8;\\n"
      "  }\\n"
      "  if (strncmp (str, \"w00t\", 4) == 0)\\n"
      "    return 9;\\n"
      "  return -1;\\n"
      "}"
      "', { buf: " GUM_PTR_CONST " });"
      "send(m.score);",
      buf);

  score_impl = EXPECT_SEND_MESSAGE_WITH_POINTER ();
  g_assert_nonnull (score_impl);

  g_assert_cmpint (score_impl ("x"), ==, 1);
  g_assert_cmpint (score_impl ("1234"), ==, 2);
  g_assert_cmpint (score_impl ("Goodbadger"), ==, 3);
  g_assert_cmpint (score_impl ("Yay!"), ==, 4);
  g_assert_cmpint (score_impl ("/path/to/file"), ==, 5);

  g_assert_cmphex (buf[0], ==, 0);
  g_assert_cmphex (buf[1], ==, 0);
  g_assert_cmpint (score_impl ("xy"), ==, 6);
  g_assert_cmphex (buf[0], ==, 'x');
  g_assert_cmphex (buf[1], ==, 'y');

  memset (buf, 0, sizeof (buf));
  g_assert_cmpint (score_impl ("xyz"), ==, 7);
  g_assert_cmphex (buf[0], ==, 'y');
  g_assert_cmphex (buf[1], ==, 'z');

  memset (buf, 0, sizeof (buf));
  g_assert_cmpint (score_impl ("xyzx"), ==, 8);
  g_assert_cmphex (buf[0], ==, 'X');
  g_assert_cmphex (buf[1], ==, 'X');

  g_assert_cmpint (score_impl ("w00tage"), ==, 9);
}

TESTCASE (cmodule_should_support_floating_point)
{
  COMPILE_AND_LOAD_SCRIPT (
      "var m = new CModule([\n"
      "  '#include <glib.h>',\n"
      "  '',\n"
      "  'gdouble',\n"
      "  'measure (void)',\n"
      "  '{',\n"
      "  '  return 42.0;',\n"
      "  '}',\n"
      "].join('\\n'));\n"
      "\n"
      "var measure = new NativeFunction(m.measure, 'double', []);\n"
      "send(measure().toFixed(0));\n");
  EXPECT_SEND_MESSAGE_WITH ("\"42\"");
  EXPECT_NO_MESSAGES ();
}

TESTCASE (cmodule_should_support_varargs)
{
  COMPILE_AND_LOAD_SCRIPT (
      "var m = new CModule([\n"
      "  '#include <glib.h>',\n"
      "  '#include <stdio.h>',\n"
      "  '',\n"
      "  'typedef struct _MediumObj MediumObj;',\n"
      "  'typedef struct _LargeObj LargeObj;',\n"
      "  '',\n"
      "  'struct _MediumObj',\n"
      "  '{',\n"
      "  '  guint64 a;',\n"
      "  '  guint64 b;',\n"
      "  '};',\n"
      "  '',\n"
      "  'struct _LargeObj',\n"
      "  '{',\n"
      "  '  guint64 a;',\n"
      "  '  guint64 b;',\n"
      "  '  guint8 c;',\n"
      "  '};',\n"
      "  '',\n"
      "  'extern void deliver (const gchar * m1, const gchar * m2);',\n"
      "  '',\n"
      "  'static void log (guint8 a1, guint16 a2, guint8 a3, guint8 a4,',\n"
      "  '    guint8 a5, guint8 a6, guint8 a7, guint8 a8, guint8 a9,',\n"
      "  '    guint8 a10, const gchar * format, ...);',\n"
      "  'static void log_special (const gchar * format, ...);',\n"
      "  '',\n"
      "  'void',\n"
      "  'sayHello (const gchar * name,',\n"
      "  '          guint8 x,',\n"
      "  '          guint8 y)',\n"
      "  '{',\n"
      "  '  // printf (\"Hello %%s, x=%%u, y=%%u\\\\n\", name, x, y);',\n"
      "  '  log (201, 202, 203, 204, 205, 206, 207, 208, 209, 210,',\n"
      "  '      \"Hello %%s, x=%%u, y=%%u\", name, x, y);',\n"
      "  '  {',\n"
      "  '    MediumObj m = { 100, 101 };',\n"
      "  '    LargeObj l = { 150, 151, 152 };',\n"
      "  '    log_special (\"slsm\", (guint8) 42, l, (guint8) 24, m);',\n"
      "  '  }',\n"
      "  '}',\n"
      "  '',\n"
      "  'static void',\n"
      "  'log (guint8 a1,',\n"
      "  '     guint16 a2,',\n"
      "  '     guint8 a3,',\n"
      "  '     guint8 a4,',\n"
      "  '     guint8 a5,',\n"
      "  '     guint8 a6,',\n"
      "  '     guint8 a7,',\n"
      "  '     guint8 a8,',\n"
      "  '     guint8 a9,',\n"
      "  '     guint8 a10,',\n"
      "  '     const gchar * format,',\n"
      "  '     ...)',\n"
      "  '{',\n"
      "  '  gchar * m1, * m2;',\n"
      "  '  va_list args;',\n"
      "  '',\n"
      "  '  m1 = g_strdup_printf (\"%%u %%u %%u %%u %%u %%u %%u %%u %%u %%u\","
          "',\n"
      "  '      a1, a2, a3, a4, a5, a6, a7, a8, a9, a10);',\n"
      "  '',\n"
      "  '  va_start (args, format);',\n"
      "  '  m2 = g_strdup_vprintf (format, args);',\n"
      "  '  va_end (args);',\n"
      "  '',\n"
      "  '  deliver (m1, m2);',\n"
      "  '',\n"
      "  '  g_free (m2);',\n"
      "  '  g_free (m1);',\n"
      "  '}',\n"
      "  '',\n"
      "  'static void',\n"
      "  'log_special (const gchar * format,',\n"
      "  '             ...)',\n"
      "  '{',\n"
      "  '  GString * message;',\n"
      "  '  va_list args;',\n"
      "  '  const gchar * p;',\n"
      "  '',\n"
      "  '  message = g_string_new (\"Yo\");',\n"
      "  '',\n"
      "  '  va_start (args, format);',\n"
      "  '',\n"
      "  '  p = format;',\n"
      "  '  while (*p != \\'\\\\0\\')',\n"
      "  '  {',\n"
      "  '    g_string_append_c (message, \\' \\');',\n"
      "  '',\n"
      "  '    switch (*p)',\n"
      "  '    {',\n"
      "  '      case \\'s\\':',\n"
      "  '      {',\n"
      "  '        guint8 v = va_arg (args, guint8);',\n"
      "  '        g_string_append_printf (message, \"%%u\", v);',\n"
      "  '        break;',\n"
      "  '      }',\n"
      "  '      case \\'m\\':',\n"
      "  '      {',\n"
      "  '        MediumObj v = va_arg (args, MediumObj);',\n"
      "  '        g_string_append_printf (message, \"(%%\" G_GINT64_MODIFIER',"
      "  '            \"u, %%\" G_GINT64_MODIFIER \"u)\", v.a, v.b);',\n"
      "  '        break;',\n"
      "  '      }',\n"
      "  '      case \\'l\\':',\n"
      "  '      {',\n"
      "  '        LargeObj v = va_arg (args, LargeObj);',\n"
      "  '        g_string_append_printf (message, \"(%%\" G_GINT64_MODIFIER',"
      "  '            \"u, %%\" G_GINT64_MODIFIER \"u, %%u)\", v.a, v.b, v.c);"
          "',\n"
      "  '        break;',\n"
      "  '      }',\n"
      "  '      default:',\n"
      "  '        printf (\"Oops!\\\\n\");',\n"
      "  '        break;',\n"
      "  '    }',\n"
      "  '',\n"
      "  '    p++;',\n"
      "  '  }',\n"
      "  '',\n"
      "  '  va_end (args);',\n"
      "  '',\n"
      "  '  deliver (\"Also\", message->str);',\n"
      "  '',\n"
      "  '  g_string_free (message, TRUE);',\n"
      "  '}',\n"
      "].join('\\n'), {\n"
      "  deliver: new NativeCallback(function (m1, m2) {\n"
      "    send([m1.readUtf8String(), m2.readUtf8String()]);\n"
      "  }, 'void', ['pointer', 'pointer'])\n"
      "});\n"
      "\n"
      "var sayHello = new NativeFunction(m.sayHello, 'void',\n"
      "    ['pointer', 'uint8', 'uint8']);\n"
      "sayHello(Memory.allocUtf8String('World'), 42, 24);\n");

  EXPECT_SEND_MESSAGE_WITH ("[\"201 202 203 204 205 206 207 208 209 210\","
      "\"Hello World, x=42, y=24\"]");
  EXPECT_SEND_MESSAGE_WITH ("[\"Also\",\"Yo 42 (150, 151, 152) 24 (100, 101)"
      "\"]");
  EXPECT_NO_MESSAGES ();
}

TESTCASE (cmodule_should_support_global_callbacks)
{
  COMPILE_AND_LOAD_SCRIPT (
      "var cb = new NativeCallback(function (n) { send(n); }, 'void', ['int']);"
      "var cbPtr = Memory.alloc(Process.pointerSize);"
      "cbPtr.writePointer(cb);"
      ""
      "var m = new CModule('"
      "\\n"
      "extern void notify1 (int n);\\n"
      "extern void (* notify2) (int n);\\n"
      "extern void (* notify3) (int n);\\n"
      "\\n"
      "static void notify3_impl (int n);\\n"
      "\\n"
      "void\\n"
      "init (void)\\n"
      "{\\n"
      "  notify1 (42);\\n"
      "  notify2 (43);\\n"
      "  notify3 = notify3_impl;\\n"
      "  notify3 (44);\\n"
      "}\\n"
      "\\n"
      "static void\\n"
      "notify3_impl (int n)\\n"
      "{\\n"
      "  notify1 (n);\\n"
      "}\\n"
      "\\n"
      "', {"
      "  notify1: cb,"
      "  notify2: cbPtr,"
      "  notify3: Memory.alloc(Process.pointerSize)"
      "});");
  EXPECT_SEND_MESSAGE_WITH ("42");
  EXPECT_SEND_MESSAGE_WITH ("43");
  EXPECT_SEND_MESSAGE_WITH ("44");
  EXPECT_NO_MESSAGES ();
}

TESTCASE (cmodule_should_provide_access_to_cpu_registers)
{
  int seen_value = -1;
#if defined (HAVE_I386) && GLIB_SIZEOF_VOID_P == 4
# define GUM_IC_GET_FIRST_ARG(ic) *((int *) ((ic)->cpu_context->esp + 4))
#elif defined (HAVE_I386) && GLIB_SIZEOF_VOID_P == 8
# ifdef G_OS_WIN32
# define GUM_IC_GET_FIRST_ARG(ic) (ic)->cpu_context->rcx
# else
# define GUM_IC_GET_FIRST_ARG(ic) (ic)->cpu_context->rdi
# endif
#elif defined (HAVE_ARM)
# define GUM_IC_GET_FIRST_ARG(ic) (ic)->cpu_context->r[0]
#elif defined (HAVE_ARM64)
# define GUM_IC_GET_FIRST_ARG(ic) (ic)->cpu_context->x[0]
#elif defined (HAVE_MIPS)
# define GUM_IC_GET_FIRST_ARG(ic) (ic)->cpu_context->a0
#endif

  COMPILE_AND_LOAD_SCRIPT (
      "var cm = new CModule('"
      "  #include <gum/guminterceptor.h>\\n"
      "\\n"
      "  extern int seenValue;\\n"
      ""
      "  void\\n"
      "  onEnter (GumInvocationContext * ic)\\n"
      "  {\\n"
      "    seenValue = " G_STRINGIFY (GUM_IC_GET_FIRST_ARG (ic)) ";\\n"
      "  }\\n"
      "\\n"
      "', { seenValue: " GUM_PTR_CONST "});"
      "Interceptor.attach(" GUM_PTR_CONST ", cm);",
      &seen_value,
      target_function_int);

  EXPECT_NO_MESSAGES ();

  target_function_int (42);
  g_assert_cmpint (seen_value, ==, 42);
}

TESTCASE (script_can_be_compiled_to_bytecode)
{
  GError * error;
  GBytes * code;
  GumScript * script;

  error = NULL;
  code = gum_script_backend_compile_sync (fixture->backend, "testcase",
      "send(1337);\noops;", NULL, &error);
  if (GUM_DUK_IS_SCRIPT_BACKEND (fixture->backend))
  {
    g_assert_nonnull (code);
    g_assert_null (error);

    g_assert_null (gum_script_backend_compile_sync (fixture->backend,
        "failcase1", "'", NULL, NULL));

    g_assert_null (gum_script_backend_compile_sync (fixture->backend,
        "failcase2", "'", NULL, &error));
    g_assert_nonnull (error);
    g_assert_true (g_str_has_prefix (error->message,
        "Script(line 1): SyntaxError: "));
    g_clear_error (&error);
  }
  else
  {
    g_assert_null (code);
    g_assert_nonnull (error);
    g_assert_cmpstr (error->message, ==, "not yet supported by the V8 runtime");
    g_clear_error (&error);

    code = g_bytes_new (NULL, 0);
  }

  script = gum_script_backend_create_from_bytes_sync (fixture->backend, code,
      NULL, &error);
  if (GUM_DUK_IS_SCRIPT_BACKEND (fixture->backend))
  {
    TestScriptMessageItem * item;

    g_assert_nonnull (script);
    g_assert_null (error);

    gum_script_set_message_handler (script, test_script_fixture_store_message,
        fixture, NULL);

    gum_script_load_sync (script, NULL);

    EXPECT_SEND_MESSAGE_WITH ("1337");

    item = test_script_fixture_pop_message (fixture);
    g_assert_nonnull (strstr (item->message, "ReferenceError"));
    g_assert_null (strstr (item->message, "agent.js"));
    g_assert_nonnull (strstr (item->message, "testcase.js"));
    test_script_message_item_free (item);

    EXPECT_NO_MESSAGES ();

    g_object_unref (script);
  }
  else
  {
    g_assert_null (script);
    g_assert_nonnull (error);
    g_assert_cmpstr (error->message, ==, "not yet supported by the V8 runtime");
    g_clear_error (&error);
  }

  g_bytes_unref (code);
}

TESTCASE (script_can_be_reloaded)
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

TESTCASE (script_should_not_leak_if_destroyed_before_load)
{
  GumExceptor * exceptor;
  guint ref_count_before;
  GumScript * script;

  exceptor = gum_exceptor_obtain ();
  ref_count_before = G_OBJECT (exceptor)->ref_count;

  script = gum_script_backend_create_sync (fixture->backend, "testcase",
      "console.log('Hello World');", NULL, NULL);
  g_object_unref (script);

  g_assert_cmpuint (G_OBJECT (exceptor)->ref_count, ==, ref_count_before);
  g_object_unref (exceptor);
}

TESTCASE (script_memory_usage)
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
      "var foo = 42;", NULL, NULL);
  gum_script_load_sync (script, NULL);
  gum_script_unload_sync (script, NULL);
  g_object_unref (script);

  timer = g_timer_new ();

  before = gum_peek_private_memory_usage ();

  g_timer_reset (timer);
  script = gum_script_backend_create_sync (fixture->backend, "testcase",
      "var foo = 42;", NULL, NULL);
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

TESTCASE (source_maps_should_be_supported_for_our_runtime)
{
  TestScriptMessageItem * item;

  COMPILE_AND_LOAD_SCRIPT ("hexdump(null);");

  item = test_script_fixture_pop_message (fixture);
  g_assert_nonnull (strstr (item->message, " (frida/runtime/hexdump.js:"));
  test_script_message_item_free (item);

  EXPECT_NO_MESSAGES ();
}

TESTCASE (source_maps_should_be_supported_for_user_scripts)
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
   * 05     throw new Error('not yet implemented');
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
      "    throw new Error('not yet implemented');"                         "\n"
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
      "// And potentially some trailing code..."                            "\n"
  );

  item = test_script_fixture_pop_message (fixture);
  if (!GUM_DUK_IS_SCRIPT_BACKEND (fixture->backend))
    g_assert_null (strstr (item->message, "testcase.js"));
  g_assert_nonnull (strstr (item->message, "\"type\":\"send\""));
  if (GUM_DUK_IS_SCRIPT_BACKEND (fixture->backend))
  {
    g_assert_nonnull (strstr (item->message,
        "\"payload\":\"Error: not yet implemented\\n"
        "    at math.js:5\\n"
        "    at index.js:6\\n"
        "    at s (node_modules/frida/node_modules/browserify/node_modules/"
            "browser-pack/_prelude.js:1)\\n"
        "    at e (node_modules/frida/node_modules/browserify/node_modules/"
            "browser-pack/_prelude.js:1)\\n"));
  }
  else
  {
    g_assert_nonnull (strstr (item->message,
        "\"payload\":\"Error: not yet implemented\\n"
        "    at Object.add (math.js:5:1)\\n"
        "    at Object.1../math (index.js:6:1)\\n"
        "    at s (node_modules/frida/node_modules/browserify/node_modules/"
            "browser-pack/_prelude.js:1:1)\\n"
        "    at e (node_modules/frida/node_modules/browserify/node_modules/"
            "browser-pack/_prelude.js:1:1)\\n"
        "    at node_modules/frida/node_modules/browserify/node_modules/"
            "browser-pack/_prelude.js:1:1\""));
  }
  test_script_message_item_free (item);

  item = test_script_fixture_pop_message (fixture);
  g_assert_null (strstr (item->message, "testcase.js"));
  g_assert_nonnull (strstr (item->message, "\"type\":\"error\""));
  g_assert_nonnull (strstr (item->message, "\"description\":\"Error: Oops!\""));
  if (GUM_DUK_IS_SCRIPT_BACKEND (fixture->backend))
  {
    g_assert_nonnull (strstr (item->message, "\"stack\":\"Error: Oops!\\n"
        "    at index.js:12\\n"));
  }
  else
  {
    g_assert_nonnull (strstr (item->message, "\"stack\":\"Error: Oops!\\n"
        "    at index.js:12:1\\n"));
  }
  g_assert_nonnull (strstr (item->message, "\"fileName\":\"index.js\""));
  g_assert_nonnull (strstr (item->message, "\"lineNumber\":12"));
  g_assert_nonnull (strstr (item->message, "\"columnNumber\":1"));
  test_script_message_item_free (item);
}

TESTCASE (types_handle_invalid_construction)
{
  /* FIXME: there seems to be a TryCatch issue with V8 on macos-x86_64 */
#if !(defined (HAVE_MACOS) && GLIB_SIZEOF_VOID_P == 8)
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

TESTCASE (weak_callback_is_triggered_on_gc)
{
  COMPILE_AND_LOAD_SCRIPT (
      "(function () {"
      "  var val = {};"
      "  WeakRef.bind(val, onWeakNotify);"
      "})();"
      "function onWeakNotify() {"
      "  send(\"weak notify\");"
      "}"
      "gc();");
  EXPECT_SEND_MESSAGE_WITH ("\"weak notify\"");
  EXPECT_NO_MESSAGES ();
}

TESTCASE (weak_callback_is_triggered_on_unload)
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

TESTCASE (weak_callback_is_triggered_on_unbind)
{
  COMPILE_AND_LOAD_SCRIPT (
      "var val = {};"
      "var id = WeakRef.bind(val, function () {"
      "  send(\"weak notify\");"
      "});"
      "WeakRef.unbind(id);");
  EXPECT_SEND_MESSAGE_WITH ("\"weak notify\"");
}

TESTCASE (globals_can_be_dynamically_generated)
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

TESTCASE (exceptions_can_be_handled)
{
  gpointer page;
  gboolean exception_on_read, exception_on_write;

  if (!check_exception_handling_testable ())
    return;

  COMPILE_AND_LOAD_SCRIPT (
      "Process.setExceptionHandler(function (ex) {"
      "  send('w00t');"
      "});");

  EXPECT_NO_MESSAGES ();

  page = gum_alloc_n_pages (1, GUM_PAGE_RW);
  gum_mprotect (page, gum_query_page_size (), GUM_PAGE_NO_ACCESS);
  gum_try_read_and_write_at (page, 0, &exception_on_read, &exception_on_write);
  g_assert_true (exception_on_read);
  g_assert_true (exception_on_write);
  gum_free_pages (page);

  EXPECT_SEND_MESSAGE_WITH ("\"w00t\"");
  EXPECT_SEND_MESSAGE_WITH ("\"w00t\"");
  EXPECT_NO_MESSAGES ();
}

TESTCASE (debugger_can_be_enabled)
{
  GumScript * badger, * snake;
  GumInspectorServer * server;
  GError * error;

  if (!g_test_slow ())
  {
    g_print ("<skipping, run in slow mode> ");
    return;
  }

  badger = gum_script_backend_create_sync (fixture->backend, "badger",
      "var badgerTimer = setInterval(function () {\n"
      "  send('badger');\n"
      "}, 1000);", NULL, NULL);
  gum_script_set_message_handler (badger, on_script_message, "badger", NULL);
  gum_script_load_sync (badger, NULL);

  snake = gum_script_backend_create_sync (fixture->backend, "snake",
      "var snakeTimer = setInterval(function () {\n"
      "  send('snake');\n"
      "}, 1000);", NULL, NULL);
  gum_script_set_message_handler (snake, on_script_message, "snake", NULL);
  gum_script_load_sync (snake, NULL);

  server = gum_inspector_server_new ();
  g_signal_connect (server, "message", G_CALLBACK (on_incoming_debug_message),
      fixture->backend);
  gum_script_backend_set_debug_message_handler (fixture->backend,
      on_outgoing_debug_message, server, NULL);

  error = NULL;
  if (gum_inspector_server_start (server, &error))
  {
    guint port;
    GMainLoop * loop;

    g_object_get (server, "port", &port, NULL);
    g_print ("Inspector server running on port %u.\n", port);

    loop = g_main_loop_new (g_main_context_get_thread_default (), FALSE);
    g_main_loop_run (loop);
    g_main_loop_unref (loop);
  }
  else
  {
    g_printerr ("Inspector server failed to start: %s\n", error->message);

    g_error_free (error);
  }

  g_object_unref (server);

  g_object_unref (snake);
  g_object_unref (badger);
}

TESTCASE (objc_api_is_embedded)
{
  COMPILE_AND_LOAD_SCRIPT ("send(typeof ObjC.available);");
  EXPECT_SEND_MESSAGE_WITH ("\"boolean\"");
}

TESTCASE (java_api_is_embedded)
{
  COMPILE_AND_LOAD_SCRIPT ("send(typeof Java.available);");
  EXPECT_SEND_MESSAGE_WITH ("\"boolean\"");
}

static gboolean
check_exception_handling_testable (void)
{
  if (gum_process_is_debugger_attached ())
  {
    g_print ("<skipping, debugger is attached> ");
    return FALSE;
  }

  if (RUNNING_ON_VALGRIND)
  {
    g_print ("<skipping, not compatible with Valgrind> ");
    return FALSE;
  }

  return TRUE;
}

static void
on_script_message (GumScript * script,
                   const gchar * message,
                   GBytes * data,
                   gpointer user_data)
{
  gchar * sender = user_data;
  g_print ("Message from %s: %s\n", sender, message);
}

static void
on_incoming_debug_message (GumInspectorServer * server,
                           const gchar * message,
                           gpointer user_data)
{
  GumScriptBackend * backend = user_data;

  gum_script_backend_post_debug_message (backend, message);
}

static void
on_outgoing_debug_message (const gchar * message,
                           gpointer user_data)
{
  GumInspectorServer * server = user_data;

  gum_inspector_server_post_message (server, message);
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

GUM_NOINLINE static const guint8 *
target_function_base_plus_offset (const guint8 * base,
                                  int offset)
{
  gum_script_dummy_global_to_trick_optimizer += offset;

  fflush (stdout);

  return base + offset;
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
