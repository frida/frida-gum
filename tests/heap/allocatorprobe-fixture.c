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

#include "gumallocatorprobe.h"

#include "dummyclasses.h"
#include "testutil.h"

#if defined (G_OS_WIN32) && defined (_DEBUG)
#include <crtdbg.h>
#endif
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
  GumHeapApiList * apis;
} TestAllocatorProbeFixture;

static void
test_allocator_probe_fixture_setup (TestAllocatorProbeFixture * fixture,
                                    gconstpointer data)
{
  GumHeapApi api = { 0, };

  fixture->ap = gum_allocator_probe_new ();

  api.malloc = malloc;
  api.calloc = calloc;
  api.realloc = realloc;
  api.free = free;
#if defined (G_OS_WIN32) && defined (_DEBUG)
  api._malloc_dbg = _malloc_dbg;
  api._calloc_dbg = _calloc_dbg;
  api._realloc_dbg = _realloc_dbg;
  api._free_dbg = _free_dbg;
#endif

  fixture->apis = gum_heap_api_list_new ();
  gum_heap_api_list_add (fixture->apis, &api);
}

static void
test_allocator_probe_fixture_teardown (TestAllocatorProbeFixture * fixture,
                                       gconstpointer data)
{
  gum_heap_api_list_free (fixture->apis);

  g_object_unref (fixture->ap);
}

#define ATTACH_PROBE()                  \
  gum_allocator_probe_attach_to_apis (fixture->ap, fixture->apis)
#define DETACH_PROBE()                  \
  gum_allocator_probe_detach (fixture->ap)
#define READ_PROBE_COUNTERS()           \
    g_object_get (fixture->ap,            \
        "malloc-count", &malloc_count,    \
        "realloc-count", &realloc_count,  \
        "free-count", &free_count,        \
        NULL);

#if defined (G_OS_WIN32) && defined (_DEBUG)
static void do_nonstandard_heap_calls (TestAllocatorProbeFixture * fixture,
    gint block_type, gint factor);
#endif