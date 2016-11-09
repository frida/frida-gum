/*
 * Copyright (C) 2016 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "testutil.h"

#include <mach/mach.h>

#define EXCEPTOR_TESTCASE(NAME) \
    void test_exceptor_ ## NAME (void)
#define EXCEPTOR_TESTENTRY(NAME) \
    TEST_ENTRY_SIMPLE ("Core/Exceptor/Darwin", test_exceptor, NAME)

TEST_LIST_BEGIN (exceptor_darwin)
  EXCEPTOR_TESTENTRY (task_get_exception_ports_should_hide_our_handler)
TEST_LIST_END ()

EXCEPTOR_TESTCASE (task_get_exception_ports_should_hide_our_handler)
{
  mach_port_t self_task;
  mach_msg_type_number_t old_count, new_count, i;
  exception_mask_t old_masks[EXC_TYPES_COUNT];
  exception_mask_t new_masks[EXC_TYPES_COUNT];
  mach_port_t old_handlers[EXC_TYPES_COUNT];
  mach_port_t new_handlers[EXC_TYPES_COUNT];
  exception_behavior_t old_behaviors[EXC_TYPES_COUNT];
  exception_behavior_t new_behaviors[EXC_TYPES_COUNT];
  thread_state_flavor_t old_flavors[EXC_TYPES_COUNT];
  thread_state_flavor_t new_flavors[EXC_TYPES_COUNT];
  kern_return_t kr;
  GumExceptor * exceptor;

  self_task = mach_task_self ();

  old_count = G_N_ELEMENTS (old_masks);
  kr = task_get_exception_ports (self_task, EXC_MASK_ALL, old_masks,
      &old_count, old_handlers, old_behaviors, old_flavors);
  g_assert_cmpint (kr, ==, KERN_SUCCESS);

  if (g_test_verbose ())
  {
    g_print ("\n\n[OLD] %u handlers:\n", old_count);
    for (i = 0; i != old_count; i++)
    {
      g_print ("\tports[%u]: mask=0x%08x handler=0x%08x behavior=0x%08x "
          "flavor=0x%08x\n", i, old_masks[i], old_handlers[i], old_behaviors[i],
          old_flavors[i]);
    }
  }

  exceptor = gum_exceptor_obtain ();

  new_count = G_N_ELEMENTS (new_masks);
  kr = task_get_exception_ports (self_task, EXC_MASK_ALL, new_masks,
      &new_count, new_handlers, new_behaviors, new_flavors);
  g_assert_cmpint (kr, ==, KERN_SUCCESS);

  if (g_test_verbose ())
  {
    g_print ("\n[NEW] %u handlers:\n", new_count);
    for (i = 0; i != new_count; i++)
    {
      g_print ("\tports[%u]: mask=0x%08x handler=0x%08x behavior=0x%08x "
          "flavor=0x%08x\n", i, new_masks[i], new_handlers[i], new_behaviors[i],
          new_flavors[i]);
    }
  }

  g_assert_cmpuint (new_count, ==, old_count);
  for (i = 0; i != new_count; i++)
  {
    g_assert_cmpuint (new_masks[i], ==, old_masks[i]);
    g_assert_cmpuint (new_handlers[i], ==, old_handlers[i]);
    g_assert_cmpuint (new_behaviors[i], ==, old_behaviors[i]);
    g_assert_cmpuint (new_flavors[i], ==, old_flavors[i]);
  }

  g_object_unref (exceptor);
}
