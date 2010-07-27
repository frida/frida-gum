/*
 * Copyright (C) 2009 Ole André Vadla Ravnås <ole.andre.ravnas@tandberg.com>
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

#include "gumtracer.h"

#include "gummemory.h"
#include "testutil.h"

#include <stdio.h>
#include <string.h>

#define TRACER_TESTCASE(NAME) \
    void test_tracer_ ## NAME ( \
        TestTracerFixture * fixture, gconstpointer data)
#define TRACER_TESTENTRY(NAME) \
    TEST_ENTRY_WITH_FIXTURE ("Core/Tracer", test_tracer, NAME, \
        TestTracerFixture)

typedef struct _TestTracerFixture
{
  GumTracer * tracer;

  guint8 * code;
} TestTracerFixture;

static void
test_tracer_fixture_setup (TestTracerFixture * fixture,
                           gconstpointer data)
{
  fixture->tracer = gum_tracer_new ();
}

static void
test_tracer_fixture_teardown (TestTracerFixture * fixture,
                              gconstpointer data)
{
  g_object_unref (fixture->tracer);

  if (fixture->code != NULL)
    gum_free_pages (fixture->code);
}

static guint8 *
test_tracer_fixture_dup_code (TestTracerFixture * fixture,
                              const guint8 * tpl_code,
                              guint tpl_size)
{
  g_assert (fixture->code == NULL);
  fixture->code = (guint8 *) gum_alloc_n_pages (1, GUM_PAGE_RWX);
  memcpy (fixture->code, tpl_code, tpl_size);
  return fixture->code;
}

#define gum_assert_cmp_type_of(e, cmp, t) \
    g_assert_cmpint (GUM_TRACE_ENTRY_TYPE (e), cmp, t)

#define gum_assert_cmp_name_of(e, cmp, s) \
    g_assert_cmpstr (gum_tracer_name_id_to_string (fixture->tracer,\
        GUM_TRACE_ENTRY_NAME_ID (e)), cmp, s)

#define gum_assert_cmp_thread_id_of(e, cmp, n) \
    g_assert_cmpuint (GUM_TRACE_ENTRY_THREAD_ID (e), cmp, n)
#define gum_assert_cmp_thread_ids_of(a, cmp, b) \
    g_assert_cmpuint (GUM_TRACE_ENTRY_THREAD_ID (a), cmp,\
        GUM_TRACE_ENTRY_THREAD_ID (b))

#define gum_assert_cmp_depth_of(e, cmp, n) \
    g_assert_cmpuint (GUM_TRACE_ENTRY_DEPTH (e), cmp, n)

#define gum_assert_cmp_timestamp_of(e, cmp, n) \
    g_assert_cmpuint (GUM_TRACE_ENTRY_TIMESTAMP (e), cmp, n)
#define gum_assert_cmp_timestamps_of(a, cmp, b) \
    g_assert_cmpuint (GUM_TRACE_ENTRY_TIMESTAMP (a), cmp,\
        GUM_TRACE_ENTRY_TIMESTAMP (b))

#define gum_assert_cmp_arglist_size_of(e, cmp, n) \
    g_assert_cmpuint (GUM_TRACE_ENTRY_ARGLIST_SIZE (e), cmp, n)
