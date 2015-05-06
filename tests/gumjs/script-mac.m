/*
 * Copyright (C) 2015 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#define SCRIPT_SUITE "/ObjC"
#include "script-fixture.c"

#import <Cocoa/Cocoa.h>

TEST_LIST_BEGIN (script_mac)
  SCRIPT_TESTENTRY (class_method_can_be_invoked)
  SCRIPT_TESTENTRY (pointer_can_be_cast_to_instance)
  SCRIPT_TESTENTRY (method_implementation_can_be_overridden)
  SCRIPT_TESTENTRY (performance)
TEST_LIST_END ()

SCRIPT_TESTCASE (class_method_can_be_invoked)
{
  COMPILE_AND_LOAD_SCRIPT (
      "var NSDate = ObjC.use(\"NSDate\");"
      "var now = NSDate.date();"
      "send(now && typeof now === 'object');");
  EXPECT_SEND_MESSAGE_WITH ("true");
}

SCRIPT_TESTCASE (pointer_can_be_cast_to_instance)
{
  @autoreleasepool
  {
    NSString * str = [NSString stringWithUTF8String:"Badger"];

    COMPILE_AND_LOAD_SCRIPT (
        "var NSString = ObjC.use(\"NSString\");"
        "var str = ObjC.cast(" GUM_PTR_CONST ", NSString);"
        "send(str.toString());",
        str);
    EXPECT_SEND_MESSAGE_WITH ("\"Badger\"");
  }
}

SCRIPT_TESTCASE (method_implementation_can_be_overridden)
{
  @autoreleasepool
  {
    NSString * str = [NSString stringWithUTF8String:"Badger"];

    COMPILE_AND_LOAD_SCRIPT (
        "var NSString = ObjC.use(\"NSString\");"
        "NSString.description.implementation ="
            "ObjC.implement(NSString.description, function (handle, selector) {"
                "return NSString.stringWithUTF8String_(Memory.allocUtf8String(\"Snakes\")).handle;"
            "});");
    EXPECT_NO_MESSAGES ();

    NSString * desc = [str description];
    EXPECT_NO_MESSAGES ();

    g_assert_cmpstr (desc.UTF8String, ==, "Snakes");
  }
}

SCRIPT_TESTCASE (performance)
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
