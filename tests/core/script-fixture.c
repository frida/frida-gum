/*
 * Copyright (C) 2010 Ole André Vadla Ravnås <ole.andre.ravnas@tandberg.com>
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

#include "gumscript.h"

#include "testutil.h"

#include <string.h>
#ifdef G_OS_WIN32
#define VC_EXTRALEAN
#include <windows.h>
#endif

#define SCRIPT_TESTCASE(NAME) \
    void test_script_ ## NAME (TestScriptFixture * fixture, gconstpointer data)
#define SCRIPT_TESTENTRY(NAME) \
    TEST_ENTRY_WITH_FIXTURE ("Core/Script", test_script, NAME, \
        TestScriptFixture)

typedef struct _TestScriptFixture
{
  gpointer argument_list;
  GumInvocationContext invocation_context;
  GumInvocationBackend invocation_backend;
  GumCpuContext cpu_context;
} TestScriptFixture;

static gpointer
test_script_fixture_get_nth_argument (GumInvocationContext * context,
                                      guint n)
{
  TestScriptFixture * fixture = (TestScriptFixture *)
      context->backend->user_data;
  return ((gpointer *) fixture->argument_list)[n];
}

static void
test_script_fixture_replace_nth_argument (GumInvocationContext * context,
                                          guint n,
                                          gpointer value)
{
  TestScriptFixture * fixture = (TestScriptFixture *)
      context->backend->user_data;
  ((gpointer *) fixture->argument_list)[n] = value;
}

static void
test_script_fixture_setup (TestScriptFixture * fixture,
                           gconstpointer data)
{
  GumInvocationContext * ctx = &fixture->invocation_context;
  GumInvocationBackend * backend = &fixture->invocation_backend;

  ctx->cpu_context = &fixture->cpu_context;
  ctx->backend = backend;

  backend->get_nth_argument = test_script_fixture_get_nth_argument;
  backend->replace_nth_argument = test_script_fixture_replace_nth_argument;
  backend->user_data = fixture;

  memset (&fixture->cpu_context, 0, sizeof (GumCpuContext));
}

static void
test_script_fixture_teardown (TestScriptFixture * fixture,
                              gconstpointer data)
{
}
