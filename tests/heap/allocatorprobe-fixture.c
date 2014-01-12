/*
 * Copyright (C) 2008-2010 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
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

#include "gumallocatorprobe.h"

#ifdef G_OS_WIN32

#include "dummyclasses.h"
#include "testutil.h"

#include <stdlib.h>

#define ALLOCPROBE_TESTCASE(NAME) \
    void test_allocator_probe_ ## NAME (TestAllocatorProbeFixture * fixture, \
        gconstpointer data)
#define ALLOCPROBE_TESTENTRY(NAME) \
    TEST_ENTRY_WITH_FIXTURE ("Heap/AllocatorProbe", test_allocator_probe, \
        NAME, TestAllocatorProbeFixture)

typedef struct _TestAllocatorProbeFixture
{
  GumAllocatorProbe * ap;
  GumInterceptor * interceptor;
} TestAllocatorProbeFixture;

static void
test_allocator_probe_fixture_setup (TestAllocatorProbeFixture * fixture,
                                    gconstpointer data)
{
  fixture->ap = gum_allocator_probe_new ();

  fixture->interceptor = gum_interceptor_obtain ();
  gum_interceptor_ignore_other_threads (fixture->interceptor);
}

static void
test_allocator_probe_fixture_teardown (TestAllocatorProbeFixture * fixture,
                                       gconstpointer data)
{
  gum_interceptor_unignore_other_threads (fixture->interceptor);
  g_object_unref (fixture->interceptor);

  g_object_unref (fixture->ap);
}

#define ATTACH_PROBE()                  \
  gum_allocator_probe_attach_to_apis (fixture->ap, test_util_heap_apis ())
#define DETACH_PROBE()                  \
  gum_allocator_probe_detach (fixture->ap)
#define READ_PROBE_COUNTERS()           \
    g_object_get (fixture->ap,            \
        "malloc-count", &malloc_count,    \
        "realloc-count", &realloc_count,  \
        "free-count", &free_count,        \
        (void *) NULL);

G_BEGIN_DECLS

#if defined (G_OS_WIN32) && defined (_DEBUG)
static void do_nonstandard_heap_calls (TestAllocatorProbeFixture * fixture,
    gint block_type, gint factor);
#endif

G_END_DECLS

#endif /* G_OS_WIN32 */
