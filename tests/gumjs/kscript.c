/*
 * Copyright (C) 2015 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "kscript-fixture.c"

TEST_LIST_BEGIN (kscript)
  KSCRIPT_TESTENTRY (memory_ranges_can_be_enumerated)
TEST_LIST_END ()

KSCRIPT_TESTCASE (memory_ranges_can_be_enumerated)
{
  COMPILE_AND_LOAD_SCRIPT (
      "Memory.enumerateRanges('---', {"
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

