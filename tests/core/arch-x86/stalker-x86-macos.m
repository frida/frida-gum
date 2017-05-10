/*
 * Copyright (C) 2014 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "stalker-x86-fixture.c"

#import <Cocoa/Cocoa.h>

TEST_LIST_BEGIN (stalker_macos)
  STALKER_TESTENTRY (cocoa)
TEST_LIST_END ()

STALKER_TESTCASE (cocoa)
{
  if (!g_test_slow ())
  {
    g_print ("<skipping, run in slow mode> ");
    return;
  }

  fixture->sink->mask = (GumEventType) GUM_CALL;

  gum_stalker_follow_me (fixture->stalker, GUM_EVENT_SINK (fixture->sink));

  @autoreleasepool
  {
    [NSApplication sharedApplication];
    [NSApp setActivationPolicy:NSApplicationActivationPolicyRegular];
    id menu = [[NSMenu new] autorelease];
    id menu_item = [[NSMenuItem new] autorelease];
    [menu addItem:menu_item];
    [NSApp setMainMenu:menu];
    id app_menu = [[NSMenu new] autorelease];
    id app_name = [[NSProcessInfo processInfo] processName];
    id quit_title = [@"Quit " stringByAppendingString:app_name];
    id quit_menu_item = [[[NSMenuItem alloc]
        initWithTitle:quit_title
               action:@selector (terminate:)
        keyEquivalent:@"q"] autorelease];
    [app_menu addItem:quit_menu_item];
    [menu_item setSubmenu:app_menu];
    id window = [[NSWindow alloc]
        initWithContentRect:NSMakeRect (0, 0, 200, 200)
                  styleMask:NSTitledWindowMask
                    backing:NSBackingStoreBuffered
                      defer:NO];
    [window cascadeTopLeftFromPoint:NSMakePoint (20, 20)];
    [window setTitle:app_name];
    [window makeKeyAndOrderFront:nil];
    [NSApp activateIgnoringOtherApps:YES];
    [NSApp run];
    [window release];
  }

  gum_stalker_unfollow_me (fixture->stalker);

  g_assert_cmpuint (fixture->sink->events->len, >, 0);
}
