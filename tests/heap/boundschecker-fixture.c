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

#include "gumboundschecker.h"

#include "gummemory.h"
#include "testutil.h"

#include <stdlib.h>
#include <string.h>
#ifdef G_OS_WIN32
#include <excpt.h>
#else
#include <setjmp.h>
#include <signal.h>
#endif

#define BOUNDSCHECKER_TESTCASE(NAME) \
    void test_bounds_checker_ ## NAME ( \
        TestBoundsCheckerFixture * fixture, gconstpointer data)
#define BOUNDSCHECKER_TESTENTRY(NAME) \
    TEST_ENTRY_WITH_FIXTURE ("Heap/BoundsChecker", \
        test_bounds_checker, NAME, TestBoundsCheckerFixture)

typedef struct _TestBoundsCheckerFixture
{
  GumBoundsChecker * checker;
} TestBoundsCheckerFixture;

static void
test_bounds_checker_fixture_setup (TestBoundsCheckerFixture * fixture,
                                   gconstpointer data)
{
  fixture->checker = gum_bounds_checker_new ();
}

static void
test_bounds_checker_fixture_teardown (TestBoundsCheckerFixture * fixture,
                                      gconstpointer data)
{
  g_object_unref (fixture->checker);
}

#ifdef G_OS_WIN32

static guint8
try_read_and_write_at (guint8 * a,
                       guint i,
                       gboolean * exception_raised_on_read,
                       gboolean * exception_raised_on_write)
{
  guint8 dummy_value_to_trick_optimizer = 0;
  *exception_raised_on_read = FALSE;
  *exception_raised_on_write = FALSE;

  __try
  {
    dummy_value_to_trick_optimizer = a[i];
  }
  __except (EXCEPTION_EXECUTE_HANDLER)
  {
    *exception_raised_on_read = TRUE;
  }

  __try
  {
    a[i] = 42;
  }
  __except (EXCEPTION_EXECUTE_HANDLER)
  {
    *exception_raised_on_write = TRUE;
  }

  return dummy_value_to_trick_optimizer;
}

#else

static sigjmp_buf try_read_and_write_context;

static void
on_sigsegv (int arg)
{
  siglongjmp (try_read_and_write_context, 1337);
}

static guint8
try_read_and_write_at (guint8 * a,
                       guint i,
                       gboolean * exception_raised_on_read,
                       gboolean * exception_raised_on_write)
{
  guint8 dummy_value_to_trick_optimizer = 0;

  *exception_raised_on_read = FALSE;
  *exception_raised_on_write = FALSE;

  signal (SIGSEGV, on_sigsegv);

  if (sigsetjmp (try_read_and_write_context, 1) == 0)
  {
    dummy_value_to_trick_optimizer = a[i];
  }
  else
  {
    *exception_raised_on_read = TRUE;
  }

  if (sigsetjmp (try_read_and_write_context, 1) == 0)
  {
    a[i] = 42;
  }
  else
  {
    *exception_raised_on_write = TRUE;
  }

  signal (SIGSEGV, SIG_DFL);

  return dummy_value_to_trick_optimizer;
}

#endif
