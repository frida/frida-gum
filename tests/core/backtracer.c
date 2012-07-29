/*
 * Copyright (C) 2008-2010 Ole André Vadla Ravnås <ole.andre.ravnas@tandberg.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU Library General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 02111-1307, USA.
 */

#include "backtracer-fixture.c"

#define PRINT_BACKTRACES        0
#define ENABLE_PERFORMANCE_TEST 0

TEST_LIST_BEGIN (backtracer)
  BACKTRACER_TESTENTRY (basics)
#ifdef HAVE_LIBS
  BACKTRACER_TESTENTRY (full_cycle)
#endif
#if ENABLE_PERFORMANCE_TEST
  BACKTRACER_TESTENTRY (performance)
#endif
TEST_LIST_END ()

#if PRINT_BACKTRACES
static void print_backtrace (GumReturnAddressArray * ret_addrs);
#endif

BACKTRACER_TESTCASE (basics)
{
  GumReturnAddressArray ret_addrs = { 0, };
#ifdef HAVE_SYMBOL_BACKEND
  guint expected_line_number;
  GumReturnAddress first_address;
  GumReturnAddressDetails rad;

  expected_line_number = __LINE__ + 1;
#endif
  gum_backtracer_generate (fixture->backtracer, NULL, &ret_addrs);
  g_assert_cmpuint (ret_addrs.len, >=, 2);

#ifdef HAVE_SYMBOL_BACKEND
# if PRINT_BACKTRACES
  print_backtrace (&ret_addrs);
# endif

  first_address = ret_addrs.items[0];
  g_assert (first_address != NULL);

  g_assert (gum_return_address_details_from_address (first_address, &rad));
  g_assert (g_str_has_prefix (rad.module_name, "gum-tests"));
  g_assert_cmpstr (rad.function_name, ==, __FUNCTION__);
# ifndef HAVE_DARWIN
  g_assert (g_str_has_suffix (rad.file_name, "backtracer.c"));
  g_assert (rad.line_number == expected_line_number ||
      rad.line_number == expected_line_number + 1);
# endif
#endif
}

#ifdef HAVE_LIBS

BACKTRACER_TESTCASE (full_cycle)
{
  GumAllocatorProbe * probe;
  GumAllocationTracker * tracker;
  GumInterceptor * interceptor;
  guint expected_line_number, alternate_line_number;
  volatile gpointer a;
  GumList * blocks;
  GumAllocationBlock * block;
  GumReturnAddress first_address;

  tracker = gum_allocation_tracker_new_with_backtracer (fixture->backtracer);
  gum_allocation_tracker_begin (tracker);

  probe = gum_allocator_probe_new ();
  g_object_set (probe, "allocation-tracker", tracker, NULL);
  interceptor = gum_interceptor_obtain ();
  gum_interceptor_ignore_other_threads (interceptor);
  gum_allocator_probe_attach_to_apis (probe, test_util_heap_apis ());

  expected_line_number = __LINE__ + 1;
  a = malloc (1337);

  /* TODO: Remove this once reentrancy protection has been implemented to also
   *       cover AllocationTracker's methods */
  alternate_line_number = __LINE__ + 1;
  gum_allocator_probe_detach (probe);

  blocks = gum_allocation_tracker_peek_block_list (tracker);
  g_assert_cmpuint (gum_list_length (blocks), ==, 1);

  block = (GumAllocationBlock *) blocks->data;

#if PRINT_BACKTRACES
  print_backtrace (&block->return_addresses);
#endif

  g_assert_cmpuint (block->return_addresses.len, >=, 1);

  first_address = block->return_addresses.items[0];
  g_assert (first_address != NULL);

  {
#ifdef G_OS_WIN32
    GumReturnAddressDetails rad;

    g_assert (gum_return_address_details_from_address (first_address, &rad));
    g_assert (g_str_has_prefix (rad.module_name, "gum-tests"));
    g_assert_cmpstr (rad.function_name, ==, __FUNCTION__);
    g_assert (g_str_has_suffix (rad.file_name, "backtracer.c"));
    if (rad.line_number != alternate_line_number)
      g_assert_cmpuint (rad.line_number, ==, expected_line_number);
#else
    g_assert (first_address != NULL);
#endif
  }

  gum_allocation_block_list_free (blocks);

  free (a);
  gum_interceptor_unignore_other_threads (interceptor);
  g_object_unref (interceptor);
  g_object_unref (probe);
  g_object_unref (tracker);
}

#endif

#if ENABLE_PERFORMANCE_TEST

BACKTRACER_TESTCASE (performance)
{
  GumReturnAddressArray ret_addrs = { 0, };
  GTimer * timer;
  guint count = 0;

  timer = g_timer_new ();

  do
  {
    guint i;

    for (i = 0; i < 100; i++)
    {
      gum_backtracer_generate (fixture->backtracer, NULL, &ret_addrs);
      ret_addrs.len = 0;
    }

    count += 100;
  }
  while (g_timer_elapsed (timer, NULL) < 1.0);

  g_print ("(%d backtraces per second) ", count);

  g_timer_destroy (timer);
}

#endif

#if PRINT_BACKTRACES

static void
print_backtrace (GumReturnAddressArray * ret_addrs)
{
  guint i;

  g_print ("\n\nBacktrace (%d return addresses):\n", ret_addrs->len);

  for (i = 0; i != ret_addrs->len; i++)
  {
    GumReturnAddress * ra = ret_addrs->items[i];
    GumReturnAddressDetails rad;

    if (gum_return_address_details_from_address (ra, &rad))
    {
      g_print ("  %p %s!%s %s:%d\n", rad.address, rad.module_name,
          rad.function_name, rad.file_name, rad.line_number);
    }
    else
    {
      g_print ("  %p <unknown>\n", ra);
    }
  }

  g_print ("\n\n");
}

#endif
