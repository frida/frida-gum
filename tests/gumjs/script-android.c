/*
 * Copyright (C) 2016 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "script-android-fixture.c"

TEST_LIST_BEGIN (script_android)
  SCRIPT_TESTENTRY (android_version_can_be_determined)
TEST_LIST_END ()

SCRIPT_TESTCASE (android_version_can_be_determined)
{
  COMPILE_AND_LOAD_SCRIPT (
      "Java.perform(function () {"
          "send(Java.androidVersion);"
      "});");
  EXPECT_SEND_MESSAGE_WITH ("true");
}
