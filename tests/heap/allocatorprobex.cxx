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

#ifdef G_OS_WIN32

#include "allocatorprobe-fixture.c"

G_BEGIN_DECLS

TEST_LIST_BEGIN (allocator_probe_cxx)
  ALLOCPROBE_TESTENTRY (new_delete)
  ALLOCPROBE_TESTENTRY (concurrency)
TEST_LIST_END ()

static gpointer concurrency_torture_helper (gpointer data);

ALLOCPROBE_TESTCASE (new_delete)
{
  guint malloc_count, realloc_count, free_count;
  int * a;

  g_object_set (fixture->ap, "enable-counters", TRUE, (void *) NULL);

  READ_PROBE_COUNTERS ();
  g_assert_cmpuint (malloc_count, ==, 0);
  g_assert_cmpuint (realloc_count, ==, 0);
  g_assert_cmpuint (free_count, ==, 0);

  a = new int;
  READ_PROBE_COUNTERS ();
  g_assert_cmpuint (malloc_count, ==, 0);
  g_assert_cmpuint (realloc_count, ==, 0);
  g_assert_cmpuint (free_count, ==, 0);

  delete a;

  ATTACH_PROBE ();

  a = new int;
  READ_PROBE_COUNTERS ();
  g_assert_cmpuint (malloc_count, ==, 1);
  g_assert_cmpuint (realloc_count, ==, 0);
  g_assert_cmpuint (free_count, ==, 0);

  delete a;
  READ_PROBE_COUNTERS ();
  g_assert_cmpuint (malloc_count, ==, 1);
  g_assert_cmpuint (realloc_count, ==, 0);
  g_assert_cmpuint (free_count, ==, 1);

  DETACH_PROBE ();

  READ_PROBE_COUNTERS ();
  g_assert_cmpuint (malloc_count, ==, 0);
  g_assert_cmpuint (realloc_count, ==, 0);
  g_assert_cmpuint (free_count, ==, 0);
}

ALLOCPROBE_TESTCASE (concurrency)
{
  gum_interceptor_unignore_other_threads (fixture->interceptor);

  gum_allocator_probe_attach (fixture->ap);

  GThread * thread = g_thread_create (concurrency_torture_helper, NULL, TRUE,
      NULL);

  g_thread_yield ();

  for (int i = 0; i < 2000; i++)
  {
    int * a = new int;
    delete a;
  }

  g_thread_join (thread);

  gum_interceptor_ignore_other_threads (fixture->interceptor);
}

static gpointer
concurrency_torture_helper (gpointer data)
{
  for (int i = 0; i < 2000; i++)
  {
    void * b = malloc (1);
    free (b);
  }

  return NULL;
}

G_END_DECLS

#endif /* G_OS_WIN32 */
