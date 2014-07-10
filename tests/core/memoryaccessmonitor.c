/*
 * Copyright (C) 2010 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "memoryaccessmonitor-fixture.c"

TEST_LIST_BEGIN (memoryaccessmonitor)
  MAMONITOR_TESTENTRY (notify_on_read_access)
  MAMONITOR_TESTENTRY (notify_on_write_access)
  MAMONITOR_TESTENTRY (notify_on_execute_access)
  MAMONITOR_TESTENTRY (notify_should_include_progress)
  MAMONITOR_TESTENTRY (disable)
TEST_LIST_END ()

MAMONITOR_TESTCASE (notify_on_read_access)
{
  volatile guint8 * bytes = (guint8 *) fixture->range.base_address;
  guint8 val;
  volatile GumMemoryAccessDetails * d = &fixture->last_details;

  bytes[fixture->offset_in_first_page] = 0x13;
  bytes[fixture->offset_in_second_page] = 0x37;

  ENABLE_MONITOR ();

  val = bytes[fixture->offset_in_first_page];
  g_assert_cmpuint (fixture->number_of_notifies, ==, 1);
  g_assert_cmpint (d->operation, ==, GUM_MEMOP_READ);
  g_assert (d->from != NULL && d->from != d->address);
  g_assert (d->address == bytes + fixture->offset_in_first_page);
  g_assert_cmpuint (val, ==, 0x13);

  val = bytes[fixture->offset_in_first_page];
  g_assert_cmpuint (fixture->number_of_notifies, ==, 1);
  g_assert_cmpuint (val, ==, 0x13);

  val = bytes[fixture->offset_in_second_page];
  g_assert_cmpuint (fixture->number_of_notifies, ==, 2);
  g_assert_cmpint (d->operation, ==, GUM_MEMOP_READ);
  g_assert (d->from != NULL && d->from != d->address);
  g_assert (d->address == bytes + fixture->offset_in_second_page);
  g_assert_cmpuint (val, ==, 0x37);

  val = bytes[fixture->offset_in_second_page];
  g_assert_cmpuint (fixture->number_of_notifies, ==, 2);
  g_assert_cmpuint (val, ==, 0x37);
}

MAMONITOR_TESTCASE (notify_on_write_access)
{
  volatile guint8 * bytes = (guint8 *) fixture->range.base_address;
  guint8 val;
  volatile GumMemoryAccessDetails * d = &fixture->last_details;

  bytes[fixture->offset_in_first_page] = 0x13;

  ENABLE_MONITOR ();

  bytes[fixture->offset_in_first_page] = 0x14;
  g_assert_cmpuint (fixture->number_of_notifies, ==, 1);
  g_assert_cmpint (d->operation, ==, GUM_MEMOP_WRITE);
  g_assert (d->from != NULL && d->from != d->address);
  g_assert (d->address == bytes + fixture->offset_in_first_page);

  val = bytes[fixture->offset_in_first_page];
  g_assert_cmpuint (fixture->number_of_notifies, ==, 1);
  g_assert_cmpuint (val, ==, 0x14);
}

MAMONITOR_TESTCASE (notify_on_execute_access)
{
  volatile GumMemoryAccessDetails * d = &fixture->last_details;

  ENABLE_MONITOR ();

  fixture->nop_function_in_first_page ();
  g_assert_cmpuint (fixture->number_of_notifies, ==, 1);
  g_assert_cmpint (d->operation, ==, GUM_MEMOP_EXECUTE);
  g_assert (d->from != NULL && d->from == d->address);

  fixture->nop_function_in_first_page ();
  g_assert_cmpuint (fixture->number_of_notifies, ==, 1);
}

MAMONITOR_TESTCASE (notify_should_include_progress)
{
  volatile GumMemoryAccessDetails * d = &fixture->last_details;
  volatile guint8 * bytes = (guint8 *) fixture->range.base_address;

  g_assert_cmpuint (d->page_index, ==, 0);
  g_assert_cmpuint (d->pages_completed, ==, 0);
  g_assert_cmpuint (d->pages_remaining, ==, 0);

  ENABLE_MONITOR ();

  bytes[fixture->offset_in_second_page] = 0x37;
  g_assert_cmpuint (d->page_index, ==, 1);
  g_assert_cmpuint (d->pages_completed, ==, 1);
  g_assert_cmpuint (d->pages_remaining, ==, 1);

  bytes[fixture->offset_in_first_page] = 0x13;
  g_assert_cmpuint (d->page_index, ==, 0);
  g_assert_cmpuint (d->pages_completed, ==, 2);
  g_assert_cmpuint (d->pages_remaining, ==, 0);
}

MAMONITOR_TESTCASE (disable)
{
  volatile guint8 * bytes = (guint8 *) fixture->range.base_address;
  guint8 val;

  bytes[fixture->offset_in_first_page] = 0x13;
  bytes[fixture->offset_in_second_page] = 0x37;

  ENABLE_MONITOR ();
  DISABLE_MONITOR ();

  val = bytes[fixture->offset_in_first_page];
  g_assert_cmpuint (fixture->number_of_notifies, ==, 0);
  g_assert_cmpuint (val, ==, 0x13);

  val = bytes[fixture->offset_in_second_page];
  g_assert_cmpuint (fixture->number_of_notifies, ==, 0);
  g_assert_cmpuint (val, ==, 0x37);
}
