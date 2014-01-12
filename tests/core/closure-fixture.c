/*
 * Copyright (C) 2011 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
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

#include "gumclosure.h"

#include "testutil.h"

#define CLOSURE_TESTCASE(NAME) \
    void test_closure_ ## NAME (TestClosureFixture * fixture, \
        gconstpointer data)
#define CLOSURE_TESTENTRY(NAME) \
    TEST_ENTRY_WITH_FIXTURE ("Core/Closure", test_closure, NAME, \
        TestClosureFixture)

typedef struct _TestClosureFixture
{
  GumClosure * closure;
} TestClosureFixture;

static void
test_closure_fixture_setup (TestClosureFixture * fixture,
                            gconstpointer data)
{
}

static void
test_closure_fixture_teardown (TestClosureFixture * fixture,
                               gconstpointer data)
{
  gum_closure_free (fixture->closure);
}

static void can_invoke_capi_function_accepting_string_and_int (
    const gchar * str, gint i);
