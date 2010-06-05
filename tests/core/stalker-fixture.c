/*
 * Copyright (C) 2009-2010 Ole André Vadla Ravnås <ole.andre.ravnas@tandberg.com>
 * Copyright (C)      2010 Karl Trygve Kalleberg <karltk@boblycat.org>
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

#include "fakeeventsink.h"
#include "gumcodewriter.h"
#include "gummemory.h"
#include "testutil.h"

#include <string.h>

#define STALKER_TESTCASE(NAME) \
    void test_stalker_ ## NAME ( \
        TestStalkerFixture * fixture, gconstpointer data)
#define STALKER_TESTENTRY(NAME) \
    TEST_ENTRY_WITH_FIXTURE (Stalker, test_stalker, NAME, \
        TestStalkerFixture)

#define NTH_EVENT_AS_CALL(N) \
    (gum_fake_event_sink_get_nth_event_as_call (fixture->sink, N))
#define NTH_EVENT_AS_RET(N) \
    (gum_fake_event_sink_get_nth_event_as_ret (fixture->sink, N))
#define NTH_EXEC_EVENT_LOCATION(N) \
    (gum_fake_event_sink_get_nth_event_as_exec (fixture->sink, N)->location)

typedef struct _TestStalkerFixture
{
  GumStalker * stalker;
  GumFakeEventSink * sink;

  guint8 * code;
  guint8 * last_invoke_calladdr;
  guint8 * last_invoke_retaddr;
} TestStalkerFixture;

typedef gint (* StalkerTestFunc) (gint arg);

static void
test_stalker_fixture_setup (TestStalkerFixture * fixture,
                            gconstpointer data)
{
  fixture->stalker = gum_stalker_new ();
  fixture->sink = GUM_FAKE_EVENT_SINK (gum_fake_event_sink_new ());
}

static void
test_stalker_fixture_teardown (TestStalkerFixture * fixture,
                               gconstpointer data)
{
  g_object_unref (fixture->sink);
  g_object_unref (fixture->stalker);

  if (fixture->code != NULL)
    gum_free_pages (fixture->code);
}

static guint8 *
test_stalker_fixture_dup_code (TestStalkerFixture * fixture,
                               const guint8 * tpl_code,
                               guint tpl_size)
{
  if (fixture->code != NULL)
    gum_free_pages (fixture->code);
  fixture->code = (guint8 *) gum_alloc_n_pages (
      (tpl_size / gum_query_page_size ()) + 1, GUM_PAGE_RWX);
  memcpy (fixture->code, tpl_code, tpl_size);
  return fixture->code;
}

#define INVOKER_INSN_COUNT  6
#define INVOKER_IMPL_OFFSET 2

/* custom invoke code as we want to stalk a deterministic code sequence */
static gint
test_stalker_fixture_follow_and_invoke (TestStalkerFixture * fixture,
                                        StalkerTestFunc func,
                                        gint arg)
{
  gint ret;
  guint8 * code;
  GumCodeWriter cw;
  GCallback invoke_func;

  code = gum_alloc_n_pages (1, GUM_PAGE_RWX);

  gum_code_writer_init (&cw, code);

  gum_code_writer_put_pushad (&cw);

  gum_code_writer_put_push (&cw, (guint32) fixture->sink);
  gum_code_writer_put_push (&cw, (guint32) fixture->stalker);
  gum_code_writer_put_call (&cw, gum_stalker_follow_me);

  gum_code_writer_put_push (&cw, arg);
  fixture->last_invoke_calladdr = gum_code_writer_cur (&cw);
  gum_code_writer_put_call (&cw, func);
  fixture->last_invoke_retaddr = gum_code_writer_cur (&cw);
  gum_code_writer_put_mov_ecx (&cw, (guint32) &ret);
  gum_code_writer_put_mov_ecx_ptr_eax (&cw);

  gum_code_writer_put_push (&cw, (guint32) fixture->stalker);
  gum_code_writer_put_call (&cw, gum_stalker_unfollow_me);
  gum_code_writer_put_add_esp_u32 (&cw, 4 * sizeof (GumStalker *));

  gum_code_writer_put_popad (&cw);

  gum_code_writer_put_ret (&cw);

  gum_code_writer_free (&cw);

  invoke_func = (GCallback) code;
  invoke_func ();

  gum_free_pages (code);

  return ret;
}
