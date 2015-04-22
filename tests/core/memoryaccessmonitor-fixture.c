/*
 * Copyright (C) 2010, 2015 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gummemoryaccessmonitor.h"

#include "testutil.h"

#define MAMONITOR_TESTCASE(NAME) \
    void test_memory_access_monitor_ ## NAME (TestMAMonitorFixture * fixture, \
        gconstpointer data)
#define MAMONITOR_TESTENTRY(NAME) \
    TEST_ENTRY_WITH_FIXTURE ("Core/MemoryAccessMonitor", \
        test_memory_access_monitor, NAME, TestMAMonitorFixture)

typedef struct _TestMAMonitorFixture
{
  GumMemoryAccessMonitor * monitor;

  GumMemoryRange range;
  guint offset_in_first_page;
  guint offset_in_second_page;
  GCallback nop_function_in_first_page;

  volatile guint number_of_notifies;
  volatile GumMemoryAccessDetails last_details;
} TestMAMonitorFixture;

static void
test_memory_access_monitor_fixture_setup (TestMAMonitorFixture * fixture,
                                          gconstpointer data)
{
  fixture->range.base_address = GUM_ADDRESS (gum_alloc_n_pages (2, GUM_PAGE_RWX));
  fixture->range.size = 2 * gum_query_page_size ();
  fixture->offset_in_first_page = gum_query_page_size () / 2;
  fixture->offset_in_second_page =
      fixture->offset_in_first_page + gum_query_page_size ();
  *((guint8 *) fixture->range.base_address) = 0xc3; /* ret instruction */
  fixture->nop_function_in_first_page =
      GUM_POINTER_TO_FUNCPTR (GCallback, fixture->range.base_address);

  fixture->number_of_notifies = 0;

  fixture->monitor = NULL;
}

static void
test_memory_access_monitor_fixture_teardown (TestMAMonitorFixture * fixture,
                                             gconstpointer data)
{
  if (fixture->monitor != NULL)
    g_object_unref (fixture->monitor);

  gum_free_pages (GSIZE_TO_POINTER (fixture->range.base_address));
}

static void
memory_access_notify_cb (GumMemoryAccessMonitor * monitor,
                         const GumMemoryAccessDetails * details,
                         gpointer user_data)
{
  TestMAMonitorFixture * fixture = (TestMAMonitorFixture *) user_data;

  fixture->number_of_notifies++;
  fixture->last_details = *details;
}

#define ENABLE_MONITOR() \
    g_assert (fixture->monitor == NULL); \
    fixture->monitor = gum_memory_access_monitor_new (&fixture->range, 1, \
        memory_access_notify_cb, fixture, NULL); \
    g_assert (fixture->monitor != NULL); \
    g_assert (gum_memory_access_monitor_enable (fixture->monitor, NULL)); \
    g_assert_cmpuint (fixture->number_of_notifies, ==, 0)
#define DISABLE_MONITOR() \
    gum_memory_access_monitor_disable (fixture->monitor)
