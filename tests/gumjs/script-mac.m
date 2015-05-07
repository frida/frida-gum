/*
 * Copyright (C) 2015 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#define SCRIPT_SUITE "/ObjC"
#include "script-fixture.c"

#import <Cocoa/Cocoa.h>

TEST_LIST_BEGIN (script_mac)
  SCRIPT_TESTENTRY (classes_can_be_enumerated)
  SCRIPT_TESTENTRY (object_enumeration_should_contain_parent_methods)
  SCRIPT_TESTENTRY (class_enumeration_should_not_contain_instance_methods)
  SCRIPT_TESTENTRY (instance_enumeration_should_not_contain_class_methods)
  SCRIPT_TESTENTRY (class_can_be_retrieved)
  SCRIPT_TESTENTRY (class_method_can_be_invoked)
  SCRIPT_TESTENTRY (object_can_be_constructed_from_pointer)
  SCRIPT_TESTENTRY (method_implementation_can_be_overridden)
  SCRIPT_TESTENTRY (attempt_to_access_an_inexistent_method_should_throw)
  SCRIPT_TESTENTRY (performance)
TEST_LIST_END ()

SCRIPT_TESTCASE (classes_can_be_enumerated)
{
  @autoreleasepool
  {
    COMPILE_AND_LOAD_SCRIPT (
        "var numClasses = Object.keys(ObjC.classes).length;"
        "send(numClasses > 100);"
        "var count = 0;"
        "for (var className in ObjC.classes) {"
          "if (ObjC.classes.hasOwnProperty(className)) {"
            "count++;"
          "}"
        "}"
        "send(count === numClasses);");
    EXPECT_SEND_MESSAGE_WITH ("true");
    EXPECT_SEND_MESSAGE_WITH ("true");
  }
}

SCRIPT_TESTCASE (object_enumeration_should_contain_parent_methods)
{
  @autoreleasepool
  {
    COMPILE_AND_LOAD_SCRIPT (
        "var keys = Object.keys(ObjC.classes.NSDate);"
        "send(keys.includes(\"conformsToProtocol_\"));");
    EXPECT_SEND_MESSAGE_WITH ("true");
  }
}

SCRIPT_TESTCASE (class_enumeration_should_not_contain_instance_methods)
{
  @autoreleasepool
  {
    COMPILE_AND_LOAD_SCRIPT (
        "var keys = Object.keys(ObjC.classes.NSDate);"
        "send(keys.includes(\"dateWithTimeIntervalSinceNow_\"));"
        "send(keys.includes(\"initWithTimeIntervalSinceReferenceDate_\"));");
    EXPECT_SEND_MESSAGE_WITH ("true");
    EXPECT_SEND_MESSAGE_WITH ("false");
  }
}

SCRIPT_TESTCASE (instance_enumeration_should_not_contain_class_methods)
{
  @autoreleasepool
  {
    COMPILE_AND_LOAD_SCRIPT (
        "var keys = Object.keys(ObjC.classes.NSDate.date());"
        "send(keys.includes(\"initWithTimeIntervalSinceReferenceDate_\"));"
        "send(keys.includes(\"dateWithTimeIntervalSinceNow_\"));");
    EXPECT_SEND_MESSAGE_WITH ("true");
    EXPECT_SEND_MESSAGE_WITH ("false");
  }
}

SCRIPT_TESTCASE (class_can_be_retrieved)
{
  @autoreleasepool
  {
    COMPILE_AND_LOAD_SCRIPT (
        "var NSDate = ObjC.classes.NSDate;"
        "send(\"NSDate\" in ObjC.classes);");
    EXPECT_SEND_MESSAGE_WITH ("true");
  }
}

SCRIPT_TESTCASE (class_method_can_be_invoked)
{
  @autoreleasepool
  {
    COMPILE_AND_LOAD_SCRIPT (
        "var NSDate = ObjC.classes.NSDate;"
        "var now = NSDate.date();"
        "send(now && typeof now === 'object');");
    EXPECT_SEND_MESSAGE_WITH ("true");
  }
}

SCRIPT_TESTCASE (object_can_be_constructed_from_pointer)
{
  @autoreleasepool
  {
    NSString * str = [NSString stringWithUTF8String:"Badger"];

    COMPILE_AND_LOAD_SCRIPT (
        "var str = new ObjC.Object(" GUM_PTR_CONST ");"
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
        "var NSString = ObjC.classes.NSString;"
        "var method = NSString[\"- description\"];"
        "method.implementation ="
            "ObjC.implement(method, function (handle, selector) {"
                "return NSString.stringWithUTF8String_(Memory.allocUtf8String(\"Snakes\")).handle;"
            "});");
    EXPECT_NO_MESSAGES ();

    NSString * desc = [str description];
    EXPECT_NO_MESSAGES ();

    g_assert_cmpstr (desc.UTF8String, ==, "Snakes");
  }
}

SCRIPT_TESTCASE (attempt_to_access_an_inexistent_method_should_throw)
{
  @autoreleasepool
  {
    COMPILE_AND_LOAD_SCRIPT ("ObjC.classes.NSDate.snakesAndMushrooms();");
    EXPECT_ERROR_MESSAGE_WITH (ANY_LINE_NUMBER,
        "Error: Unable to find method 'snakesAndMushrooms'");
  }
}

SCRIPT_TESTCASE (performance)
{
  @autoreleasepool
  {
    TestScriptMessageItem * item;
    gint duration;

    COMPILE_AND_LOAD_SCRIPT (
        "ObjC.classes.NSObject;"
        "var start = Date.now();"
        "Object.keys(ObjC.classes.NSWindow);"
        "var end = Date.now();"
        "send(end - start);");
    item = test_script_fixture_pop_message (fixture);
    sscanf (item->message, "{\"type\":\"send\",\"payload\":%d}", &duration);
    g_print ("<%d ms> ", duration);
    test_script_message_item_free (item);
  }
}
