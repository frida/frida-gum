/*
 * Copyright (C) 2015 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "kscript-fixture.c"

TEST_LIST_BEGIN (kscript)
  KSCRIPT_TESTENTRY (kernel_threads_can_be_enumerated)
  KSCRIPT_TESTENTRY (kernel_threads_can_be_enumerated_synchronously)
  KSCRIPT_TESTENTRY (memory_ranges_can_be_enumerated)
  KSCRIPT_TESTENTRY (memory_ranges_can_be_enumerated_synchronously)
  KSCRIPT_TESTENTRY (memory_ranges_can_be_enumerated_with_neighbors_coalesced)
  KSCRIPT_TESTENTRY (byte_array_can_be_read)
  KSCRIPT_TESTENTRY (byte_array_can_be_written)
  KSCRIPT_TESTENTRY (invalid_read_results_in_exception)
  KSCRIPT_TESTENTRY (invalid_write_results_in_exception)
TEST_LIST_END ()

KSCRIPT_TESTCASE (kernel_threads_can_be_enumerated)
{
  if (!g_test_slow ())
  {
    g_print ("<may cause kernel panic, run in slow mode> ");
    return;
  }

  COMPILE_AND_LOAD_SCRIPT (
      "Kernel.enumerateThreads({"
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

KSCRIPT_TESTCASE (kernel_threads_can_be_enumerated_synchronously)
{
  if (!g_test_slow ())
  {
    g_print ("<may cause kernel panic, run in slow mode> ");
    return;
  }

  COMPILE_AND_LOAD_SCRIPT ("send(Kernel.enumerateThreadsSync().length > 1);");
  EXPECT_SEND_MESSAGE_WITH ("true");
}

KSCRIPT_TESTCASE (memory_ranges_can_be_enumerated)
{
  COMPILE_AND_LOAD_SCRIPT (
      "Memory.enumerateRanges('r--', {"
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

KSCRIPT_TESTCASE (memory_ranges_can_be_enumerated_synchronously)
{
  COMPILE_AND_LOAD_SCRIPT (
      "send(Memory.enumerateRangesSync('r--').length > 1);");
  EXPECT_SEND_MESSAGE_WITH ("true");
}

KSCRIPT_TESTCASE (memory_ranges_can_be_enumerated_with_neighbors_coalesced)
{
  COMPILE_AND_LOAD_SCRIPT (
      "var a = Memory.enumerateRangesSync('r--');"
      "var b = Memory.enumerateRangesSync({"
        "protection: 'r--',"
        "coalesce: true"
      "});"
      "send(b.length <= a.length);");
  EXPECT_SEND_MESSAGE_WITH ("true");
}

KSCRIPT_TESTCASE (byte_array_can_be_read)
{
  COMPILE_AND_LOAD_SCRIPT (
      "var address = Memory.enumerateRangesSync('r--')[0].base;"
      "send(Memory.readByteArray(address, 3).byteLength === 3);"
      "send('snake', Memory.readByteArray(address, 0));"
      "send('mushroom', Memory.readByteArray(address, -1));");
  EXPECT_SEND_MESSAGE_WITH_PAYLOAD_AND_DATA ("true", NULL);
  EXPECT_SEND_MESSAGE_WITH_PAYLOAD_AND_DATA ("\"snake\"", "");
  EXPECT_SEND_MESSAGE_WITH_PAYLOAD_AND_DATA ("\"mushroom\"", "");
}

KSCRIPT_TESTCASE (byte_array_can_be_written)
{
  if (!g_test_slow ())
  {
    g_print ("<potentially dangerous, run in slow mode> ");
    return;
  }

  COMPILE_AND_LOAD_SCRIPT (
      "var address = Memory.enumerateRangesSync('rw-')[0].base;"
      "var bytes = Memory.readByteArray(address, 3);"
      "Memory.writeByteArray(address, bytes);");
  EXPECT_NO_MESSAGES ();
}

KSCRIPT_TESTCASE (invalid_read_results_in_exception)
{
  COMPILE_AND_LOAD_SCRIPT ("Memory.readByteArray(ptr(\"1328\"), 3)");
  EXPECT_ERROR_MESSAGE_WITH (1, "Error: access violation reading 0x530");
}

KSCRIPT_TESTCASE (invalid_write_results_in_exception)
{
  COMPILE_AND_LOAD_SCRIPT ("Memory.writeByteArray(ptr(\"1328\"), [1, 2, 3])");
  EXPECT_ERROR_MESSAGE_WITH (1, "Error: access violation writing to 0x530");
}

