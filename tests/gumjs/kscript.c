/*
 * Copyright (C) 2015-2019 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "kscript-fixture.c"

TESTLIST_BEGIN (kscript)
  TESTENTRY (api_availability_can_be_queried)
  TESTENTRY (modules_can_be_enumerated)
  TESTENTRY (modules_can_be_enumerated_legacy_style)
  TESTENTRY (memory_ranges_can_be_enumerated)
  TESTENTRY (memory_ranges_can_be_enumerated_legacy_style)
  TESTENTRY (memory_ranges_can_be_enumerated_with_neighbors_coalesced)
  TESTENTRY (module_ranges_can_be_enumerated)
  TESTENTRY (module_ranges_can_be_enumerated_legacy_style)
  TESTENTRY (byte_array_can_be_read)
  TESTENTRY (byte_array_can_be_written)
TESTLIST_END ()

TESTCASE (api_availability_can_be_queried)
{
  COMPILE_AND_LOAD_SCRIPT ("send(Kernel.available);");
  EXPECT_SEND_MESSAGE_WITH ("true");
}

TESTCASE (modules_can_be_enumerated)
{
  COMPILE_AND_LOAD_SCRIPT (
      "var modules = Kernel.enumerateModules();"
      "send(modules.length > 0);");
  EXPECT_SEND_MESSAGE_WITH ("true");
}

TESTCASE (modules_can_be_enumerated_legacy_style)
{
  COMPILE_AND_LOAD_SCRIPT (
      "Kernel.enumerateModules({"
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

  COMPILE_AND_LOAD_SCRIPT ("send(Kernel.enumerateModulesSync().length > 0);");
  EXPECT_SEND_MESSAGE_WITH ("true");
}

TESTCASE (memory_ranges_can_be_enumerated)
{
  COMPILE_AND_LOAD_SCRIPT (
      "var ranges = Kernel.enumerateRanges('r--');"
      "send(ranges.length > 0);");
  EXPECT_SEND_MESSAGE_WITH ("true");
}

TESTCASE (memory_ranges_can_be_enumerated_legacy_style)
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

  COMPILE_AND_LOAD_SCRIPT (
      "send(Kernel.enumerateRangesSync('r--').length > 0);");
  EXPECT_SEND_MESSAGE_WITH ("true");
}

TESTCASE (memory_ranges_can_be_enumerated_with_neighbors_coalesced)
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

TESTCASE (module_ranges_can_be_enumerated)
{
  COMPILE_AND_LOAD_SCRIPT (
      "var ranges = Kernel.enumerateModuleRanges('Kernel', 'r--');"
      "send(ranges.length > 0);");
  EXPECT_SEND_MESSAGE_WITH ("true");
}

TESTCASE (module_ranges_can_be_enumerated_legacy_style)
{
  COMPILE_AND_LOAD_SCRIPT (
      "Kernel.enumerateModuleRanges('Kernel', 'r--', {"
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
      "send(Kernel.enumerateModuleRangesSync('Kernel', 'r--').length > 0);");
  EXPECT_SEND_MESSAGE_WITH ("true");
}

TESTCASE (byte_array_can_be_read)
{
  COMPILE_AND_LOAD_SCRIPT (
      "var address = Kernel.enumerateRangesSync('r--')[0].base;"
      "send(Kernel.readByteArray(address, 3).byteLength === 3);"
      "send('snake', Kernel.readByteArray(address, 0));");
  EXPECT_SEND_MESSAGE_WITH_PAYLOAD_AND_DATA ("true", NULL);
  EXPECT_SEND_MESSAGE_WITH_PAYLOAD_AND_DATA ("\"snake\"", "");
  EXPECT_NO_MESSAGES ();
}

TESTCASE (byte_array_can_be_written)
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

