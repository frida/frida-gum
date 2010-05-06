/*
 * Copyright (C) 2008 Ole André Vadla Ravnås <ole.andre.ravnas@tandberg.com>
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

#include <stdlib.h>
#include <gum/gum.h>

#define PRINT_BACKTRACES        0
#define ENABLE_PERFORMANCE_TEST 0

static GumBacktracer * make_backtracer (void);

#if PRINT_BACKTRACES
static void print_backtrace (GumReturnAddressArray * ret_addrs);
#endif

static void
test_basics (void)
{
  GumBacktracer * backtracer;
  GumReturnAddressArray ret_addrs = { 0, };
  GumReturnAddress * first_address;
  guint expected_line_number;

  backtracer = make_backtracer ();

  expected_line_number = __LINE__ + 1;
  gum_backtracer_generate (backtracer, NULL, &ret_addrs);
  g_assert_cmpuint (ret_addrs.len, >=, 2);

  gum_return_address_array_load_symbols (&ret_addrs);

#if PRINT_BACKTRACES
  print_backtrace (&ret_addrs);
#endif

  first_address = &ret_addrs.items[0];
  g_assert (first_address->address != NULL);

  g_assert (g_str_has_prefix (first_address->module_name, "gumtest"));
  g_assert_cmpstr (first_address->function_name, ==, __FUNCTION__);
  g_assert (g_str_has_suffix (first_address->file_name, "backtracer.c"));
  g_assert (first_address->line_number == expected_line_number
      || first_address->line_number == expected_line_number + 1);

  g_object_unref (backtracer);
}

static void
test_full_cycle (void)
{
  GumAllocatorProbe * probe;
  GumAllocationTracker * tracker;
  GumBacktracer * backtracer;
  guint expected_line_number;
  gpointer a;
  GumList * blocks;
  GumAllocationBlock * block;
  GumReturnAddress * first_address;

  backtracer = make_backtracer ();
  tracker = gum_allocation_tracker_new_with_backtracer (backtracer);
  gum_allocation_tracker_begin (tracker);

  probe = gum_allocator_probe_new ();
  g_object_set (probe, "allocation-tracker", tracker, NULL);
  gum_allocator_probe_attach (probe);

  expected_line_number = __LINE__ + 1;
  a = malloc (1337);

  /* TODO: Remove this once reentrancy protection has been implemented to also
   *       cover AllocationTracker's methods */
  gum_allocator_probe_detach (probe);

  blocks = gum_allocation_tracker_peek_block_list (tracker);
  g_assert_cmpuint (gum_list_length (blocks), ==, 1);

  block = blocks->data;

#if PRINT_BACKTRACES
  print_backtrace (&block->return_addresses);
#endif

  g_assert_cmpuint (block->return_addresses.len, >=, 1);

  first_address = &block->return_addresses.items[0];
  g_assert (first_address->address != NULL);

  g_assert (g_str_has_prefix (first_address->module_name, "gumtest"));
  g_assert_cmpstr (first_address->function_name, ==, __FUNCTION__);
  g_assert (g_str_has_suffix (first_address->file_name, "backtracer.c"));
  g_assert_cmpuint (first_address->line_number, ==, expected_line_number);

  gum_allocation_block_list_free (blocks);

  free (a);
  g_object_unref (probe);
  g_object_unref (tracker);
  g_object_unref (backtracer);
}

#if ENABLE_PERFORMANCE_TEST
static void
test_performance (void)
{
  GumBacktracer * backtracer;
  GumReturnAddressArray ret_addrs = { 0, };
  GTimer * timer;
  guint count = 0;

  backtracer = make_backtracer ();

  timer = g_timer_new ();

  do
  {
    guint i;

    for (i = 0; i < 100; i++)
    {
      gum_backtracer_generate (backtracer, NULL, &ret_addrs);
      ret_addrs.len = 0;
    }

    count += 100;
  }
  while (g_timer_elapsed (timer, NULL) < 1.0);

  g_print ("(%d backtraces per second) ", count);

  g_timer_destroy (timer);

  g_object_unref (backtracer);
}
#endif

static GumBacktracer *
make_backtracer (void)
{
#ifdef G_OS_WIN32
  return gum_windows_backtracer_new ();
#else
  return gum_gnu_backtracer_new ();
#endif
}

#if PRINT_BACKTRACES
static void
print_backtrace (GumReturnAddressArray * ret_addrs)
{
  guint i;

  g_print ("\n\nBacktrace (%d return addresses):\n", ret_addrs->len);

  for (i = 0; i < ret_addrs->len; i++)
  {
    GumReturnAddress * ra = &ret_addrs->items[i];

    g_print ("  %p %s!%s %s:%d\n", ra->address, ra->module_name,
        ra->function_name, ra->file_name, ra->line_number);
  }

  g_print ("\n\n");
}
#endif

void
gum_test_register_backtracer_tests (void)
{
  g_test_add_func ("/Gum/Backtracer/test-basics", &test_basics);
  g_test_add_func ("/Gum/Backtracer/test-full-cycle", &test_full_cycle);
#if ENABLE_PERFORMANCE_TEST
  g_test_add_func ("/Gum/Backtracer/test-performance", &test_performance);
#endif
}

