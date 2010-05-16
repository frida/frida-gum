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

#include <gum/gum.h>
#include <stdlib.h>
#include <string.h>
#ifdef G_OS_WIN32
#include <excpt.h>
#else
#include <setjmp.h>
#include <signal.h>
#endif

#include "../gum/gummemory.h"

static gpointer detach_worker (gpointer data);
static guint8 try_read_and_write_at (guint8 * a, guint i,
    gboolean * exception_raised_on_read, gboolean * exception_raised_on_write);

static void
test_tail_checking_malloc (void)
{
  GumBoundsChecker * checker;
  guint8 * a;
  gboolean exception_on_read, exception_on_write;

  checker = gum_bounds_checker_new ();

  gum_bounds_checker_attach (checker);
  a = malloc (1);
  a[0] = 1;
  try_read_and_write_at (a, 16, &exception_on_read, &exception_on_write);
  free (a);
  gum_bounds_checker_detach (checker);

  g_assert (exception_on_read && exception_on_write);

  g_object_unref (checker);
}

static void
test_tail_checking_calloc (void)
{
  GumBoundsChecker * checker;
  guint8 * a;
  gboolean exception_on_read, exception_on_write;

  checker = gum_bounds_checker_new ();

  gum_bounds_checker_attach (checker);
  a = calloc (1, 1);
  a[0] = 1;
  try_read_and_write_at (a, 16, &exception_on_read, &exception_on_write);
  free (a);
  gum_bounds_checker_detach (checker);

  g_assert (exception_on_read && exception_on_write);

  g_object_unref (checker);
}

static void
test_tail_checking_realloc (void)
{
  GumBoundsChecker * checker;
  guint8 * a;
  gboolean exception_on_read, exception_on_write;

  checker = gum_bounds_checker_new ();

  gum_bounds_checker_attach (checker);
  a = malloc (1);
  a = realloc (a, 2);
  a[0] = 1;
  try_read_and_write_at (a, 16, &exception_on_read, &exception_on_write);
  free (a);
  gum_bounds_checker_detach (checker);

  g_assert (exception_on_read && exception_on_write);

  g_object_unref (checker);
}

static void
test_realloc_shrink (void)
{
  GumBoundsChecker * checker;
  guint8 * a;

  checker = gum_bounds_checker_new ();

  gum_bounds_checker_attach (checker);
  a = malloc (4096);
  a = realloc (a, 1);
  free (a);
  gum_bounds_checker_detach (checker);

  g_object_unref (checker);
}

static void
test_tail_checking_realloc_null (void)
{
  GumBoundsChecker * checker;
  guint8 * a;
  gboolean exception_on_read, exception_on_write;

  checker = gum_bounds_checker_new ();

  gum_bounds_checker_attach (checker);
  a = realloc (NULL, 1);
  a[0] = 1;
  try_read_and_write_at (a, 16, &exception_on_read, &exception_on_write);
  free (a);
  gum_bounds_checker_detach (checker);

  g_assert (exception_on_read && exception_on_write);

  g_object_unref (checker);
}

static void
test_realloc_migration_pool_to_pool (void)
{
  GumBoundsChecker * checker;
  guint32 * p;
  guint32 value_after_migration;

  checker = gum_bounds_checker_new ();

  gum_bounds_checker_attach (checker);
  p = malloc (4);
  *p = 0x1234face;
  p = realloc (p, 8);
  value_after_migration = *p;
  free (p);
  gum_bounds_checker_detach (checker);

  g_assert_cmphex (value_after_migration, ==, 0x1234face);

  g_object_unref (checker);
}

static void
test_realloc_migration_pool_to_heap (void)
{
  GumBoundsChecker * checker;
  guint32 * a;
  guint32 value_after_migration;

  checker = gum_bounds_checker_new ();
  g_object_set (checker, "pool-size", 2, NULL);

  gum_bounds_checker_attach (checker);
  a = malloc (4);
  *a = 0x1234face;
  a = realloc (a, gum_query_page_size () + 1);
  value_after_migration = *a;
  free (a);
  gum_bounds_checker_detach (checker);

  g_assert_cmphex (value_after_migration, ==, 0x1234face);

  g_object_unref (checker);
}

static void
test_protected_after_free (void)
{
  GumBoundsChecker * checker;
  guint8 * a;
  gboolean exception_on_read, exception_on_write;

  checker = gum_bounds_checker_new ();

  gum_bounds_checker_attach (checker);
  a = malloc (1);
  a[0] = 1;
  free (a);
  try_read_and_write_at (a, 0, &exception_on_read, &exception_on_write);
  gum_bounds_checker_detach (checker);

  g_assert (exception_on_read && exception_on_write);

  g_object_unref (checker);
}

static void
test_calloc_initializes_to_zero (void)
{
  GumBoundsChecker * checker;
  guint8 * p;
  guint8 expected[1024] = { 0, };

  checker = gum_bounds_checker_new ();
  g_object_set (checker, "pool-size", 2, NULL);

  gum_bounds_checker_attach (checker);
  p = calloc (1, sizeof (expected));
  memset (p, 0xcc, sizeof (expected));
  free (p);
  p = calloc (1, sizeof (expected));
  g_assert_cmpint (memcmp (p, expected, sizeof (expected)), ==, 0);
  free (p);
  gum_bounds_checker_detach (checker);

  g_object_unref (checker);
}

typedef struct _DetachWorkerContext DetachWorkerContext;

struct _DetachWorkerContext
{
  GumBoundsChecker * checker;
  volatile gboolean detach_now;
  GThread * thread;
};

static void
test_detach_before_free (void)
{
  GumBoundsChecker * checker;
  guint32 * p;
  guint32 value;
  DetachWorkerContext ctx;

  checker = gum_bounds_checker_new ();

  ctx.checker = checker;
  ctx.detach_now = FALSE;
  ctx.thread = g_thread_create (detach_worker, &ctx, TRUE, NULL);

  g_usleep (G_USEC_PER_SEC / 5);

  gum_bounds_checker_attach (checker);
  p = malloc (1);
  *p = 0x4321f00d;
  ctx.detach_now = TRUE;
  g_usleep (G_USEC_PER_SEC / 5);
  value = *p;
  free (p);

  g_usleep (G_USEC_PER_SEC / 5);
  g_thread_join (ctx.thread);

  g_assert_cmphex (value, ==, 0x4321f00d);

  g_object_unref (checker);
}

static void
test_custom_front_alignment (void)
{
  GumBoundsChecker * checker;
  guint8 * a;
  gboolean exception_on_read, exception_on_write;

  checker = gum_bounds_checker_new ();
  g_object_set (checker, "front-alignment", 1, NULL);
  gum_bounds_checker_attach (checker);
  a = malloc (1);
  a[0] = 1;
  try_read_and_write_at (a, 1, &exception_on_read, &exception_on_write);
  free (a);
  gum_bounds_checker_detach (checker);

  g_assert (exception_on_read && exception_on_write);

  g_object_unref (checker);
}

static gpointer
detach_worker (gpointer data)
{
  DetachWorkerContext * ctx = data;
  while (!ctx->detach_now)
    g_usleep (G_USEC_PER_SEC / 20);
  gum_bounds_checker_detach (ctx->checker);
  return NULL;
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

void
gum_test_register_bounds_checker_tests (void)
{
  g_test_add_func ("/Gum/BoundsChecker/test-tail-checking-malloc",
      &test_tail_checking_malloc);
  g_test_add_func ("/Gum/BoundsChecker/test-tail-checking-calloc",
      &test_tail_checking_calloc);
  g_test_add_func ("/Gum/BoundsChecker/test-tail-checking-realloc",
      &test_tail_checking_realloc);
  g_test_add_func ("/Gum/BoundsChecker/test-tail-checking-realloc-null",
      &test_tail_checking_realloc_null);
  g_test_add_func ("/Gum/BoundsChecker/test-realloc-shrink",
      &test_realloc_shrink);
  g_test_add_func ("/Gum/BoundsChecker/test-realloc-migration-pool-to-pool",
      &test_realloc_migration_pool_to_pool);
  g_test_add_func ("/Gum/BoundsChecker/test-realloc-migration-pool-to-heap",
      &test_realloc_migration_pool_to_heap);
  g_test_add_func ("/Gum/BoundsChecker/test-protected-after-free",
      &test_protected_after_free);
  g_test_add_func ("/Gum/BoundsChecker/test-calloc-initializes-to-zero",
      &test_calloc_initializes_to_zero);
  g_test_add_func ("/Gum/BoundsChecker/test-detach-before-free",
      &test_detach_before_free);
  g_test_add_func ("/Gum/BoundsChecker/test-custom-front-alignment",
      &test_custom_front_alignment);
}
