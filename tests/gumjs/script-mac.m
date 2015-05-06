/*
 * Copyright (C) 2015 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "script-fixture.c"

#import <Cocoa/Cocoa.h>

TEST_LIST_BEGIN (script_mac)
  SCRIPT_TESTENTRY (objc_performance)
TEST_LIST_END ()

SCRIPT_TESTCASE (objc_performance)
{
  TestScriptMessageItem * item;
  gint duration;

  COMPILE_AND_LOAD_SCRIPT (
      "ObjC.use(\"NSObject\");"
      "var start = Date.now();"
      "ObjC.use(\"NSWindow\");"
      "var end = Date.now();"
      "send(end - start);");
  item = test_script_fixture_pop_message (fixture);
  sscanf (item->message, "{\"type\":\"send\",\"payload\":%d}", &duration);
  g_print ("<%d ms> ", duration);
  test_script_message_item_free (item);
}
