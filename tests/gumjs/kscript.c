/*
 * Copyright (C) 2015 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "kscript-fixture.c"

TEST_LIST_BEGIN (kscript)
  KSCRIPT_TESTENTRY (api_availability_can_be_queried)
  KSCRIPT_TESTENTRY (memory_ranges_can_be_enumerated)
  KSCRIPT_TESTENTRY (memory_ranges_can_be_enumerated_synchronously)
  KSCRIPT_TESTENTRY (memory_ranges_can_be_enumerated_with_neighbors_coalesced)
  KSCRIPT_TESTENTRY (byte_array_can_be_read)
  KSCRIPT_TESTENTRY (byte_array_can_be_written)
TEST_LIST_END ()

KSCRIPT_TESTCASE (api_availability_can_be_queried)
{
  COMPILE_AND_LOAD_SCRIPT ("send(Kernel.available);");
  EXPECT_SEND_MESSAGE_WITH ("true");
}

KSCRIPT_TESTCASE (memory_ranges_can_be_enumerated)
{
  COMPILE_AND_LOAD_SCRIPT (
      "Kernel.enumerateRanges('r--', {"
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
      "send(Kernel.enumerateRangesSync('r--').length > 1);");
  EXPECT_SEND_MESSAGE_WITH ("true");
}

KSCRIPT_TESTCASE (memory_ranges_can_be_enumerated_with_neighbors_coalesced)
{
  COMPILE_AND_LOAD_SCRIPT (
      "var a = Kernel.enumerateRangesSync('r--');"
      "var b = Kernel.enumerateRangesSync({"
        "protection: 'r--',"
        "coalesce: true"
      "});"
      "send(b.length <= a.length);");
  EXPECT_SEND_MESSAGE_WITH ("true");
}

KSCRIPT_TESTCASE (byte_array_can_be_read)
{
  COMPILE_AND_LOAD_SCRIPT (
      "var address = Kernel.enumerateRangesSync('r--')[0].base;"
      "send(Kernel.readByteArray(address, 3).byteLength === 3);"
      "send('snake', Kernel.readByteArray(address, 0));");
  EXPECT_SEND_MESSAGE_WITH_PAYLOAD_AND_DATA ("true", NULL);
  EXPECT_SEND_MESSAGE_WITH_PAYLOAD_AND_DATA ("\"snake\"", "");
  EXPECT_NO_MESSAGES ();
}

KSCRIPT_TESTCASE (byte_array_can_be_written)
{
  if (!g_test_slow ())
  {
    g_print ("<potentially dangerous, run in slow mode> ");
    return;
  }

  COMPILE_AND_LOAD_SCRIPT (
      "var address = Kernel.enumerateRangesSync('rw-')[0].base;"
      "var bytes = Kernel.readByteArray(address, 3);"
      "Kernel.writeByteArray(address, bytes);");
  EXPECT_NO_MESSAGES ();
}

