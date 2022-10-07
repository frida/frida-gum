/*
 * Copyright (C) 2016-2022 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumexceptor.h"

#include "backend-darwin/gumdarwin.h"
#include "testutil.h"

#include <mach/mach.h>

#define TESTCASE(NAME) \
    void test_exceptor_ ## NAME (void)
#define TESTENTRY(NAME) \
    TESTENTRY_SIMPLE ("Core/Exceptor/Darwin", test_exceptor, NAME)

#if defined (HAVE_MACOS) || defined (HAVE_IOS)

TESTLIST_BEGIN (exceptor_darwin)
  TESTENTRY (task_get_exception_ports_should_hide_our_handler)
  TESTENTRY (task_swap_exception_ports_should_not_obstruct_us)
TESTLIST_END ()

TESTCASE (task_get_exception_ports_should_hide_our_handler)
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

  old_count = EXC_TYPES_COUNT;
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

  new_count = EXC_TYPES_COUNT;
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

  for (i = 0; i != new_count; i++)
  {
    mach_port_mod_refs (self_task, new_handlers[i], MACH_PORT_RIGHT_SEND, -2);
  }

  g_object_unref (exceptor);
}

TESTCASE (task_swap_exception_ports_should_not_obstruct_us)
{
  GumExceptor * exceptor;
  mach_port_t self_task, server_port;
  kern_return_t kr;
  mach_msg_type_number_t count, i;
  exception_mask_t masks[EXC_TYPES_COUNT];
  mach_port_t handlers[EXC_TYPES_COUNT];
  exception_behavior_t behaviors[EXC_TYPES_COUNT];
  thread_state_flavor_t flavors[EXC_TYPES_COUNT];
  GumExceptorScope scope;
  gboolean caught = FALSE;

#ifdef HAVE_ASAN
  if (!g_test_slow ())
  {
    g_print ("<skipping on ASan, run in slow mode> ");
    return;
  }
#endif

  exceptor = gum_exceptor_obtain ();

  self_task = mach_task_self ();

  kr = mach_port_allocate (self_task, MACH_PORT_RIGHT_RECEIVE, &server_port);
  g_assert_cmpint (kr, ==, KERN_SUCCESS);

  kr = mach_port_insert_right (self_task, server_port, server_port,
      MACH_MSG_TYPE_MAKE_SEND);
  g_assert_cmpint (kr, ==, KERN_SUCCESS);

  count = EXC_TYPES_COUNT;
  kr = task_swap_exception_ports (self_task, EXC_MASK_BAD_ACCESS, server_port,
      EXCEPTION_STATE_IDENTITY | MACH_EXCEPTION_CODES,
      GUM_DARWIN_THREAD_STATE_FLAVOR, masks, &count, handlers, behaviors,
      flavors);
  g_assert_cmpint (kr, ==, KERN_SUCCESS);

  if (gum_exceptor_try (exceptor, &scope))
  {
    *((int *) 1) = 42;
  }

  if (gum_exceptor_catch (exceptor, &scope))
  {
    gchar * message;

    caught = TRUE;

    message = gum_exception_details_to_string (&scope.exception);
    g_assert_cmpstr (message, ==, "access violation accessing 0x1");
    g_free (message);
  }

  g_assert_true (caught);

  for (i = 0; i != count; i++)
  {
    mach_port_t handler = handlers[i];

    kr = task_set_exception_ports (self_task, masks[i], handler,
        behaviors[i], flavors[i]);
    g_assert_cmpint (kr, ==, KERN_SUCCESS);

    if (handler != MACH_PORT_NULL)
    {
      kr = mach_port_mod_refs (self_task, handler, MACH_PORT_RIGHT_SEND, -1);
      g_assert_cmpint (kr, ==, KERN_SUCCESS);
    }
  }

  kr = mach_port_mod_refs (self_task, server_port, MACH_PORT_RIGHT_SEND, -1);
  g_assert_cmpint (kr, ==, KERN_SUCCESS);
  kr = mach_port_mod_refs (self_task, server_port, MACH_PORT_RIGHT_RECEIVE, -1);
  g_assert_cmpint (kr, ==, KERN_SUCCESS);

  g_object_unref (exceptor);
}

#else

TESTLIST_BEGIN (exceptor_darwin)
TESTLIST_END ()

#endif
