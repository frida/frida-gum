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

#include "testutil.h"
#include "fakeeventsink.h"

#include "gumcodewriter.h"
#include "gummemory.h"

#include <string.h>

#ifdef G_OS_WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#endif

#define STALKER_TESTCASE(NAME) \
    void test_stalker_ ## NAME ( \
        TestStalkerFixture * fixture, gconstpointer data)
#define STALKER_TESTENTRY(NAME) \
    TEST_ENTRY_WITH_FIXTURE (Stalker, test_stalker, NAME, \
        TestStalkerFixture)

#define NTH_CALL_EVENT(N, M) \
    (g_array_index (fixture->sink->events, GumEvent, N).call.M)
#define NTH_EXEC_EVENT_LOCATION(N) \
    (g_array_index (fixture->sink->events, GumEvent, N).exec.location)

typedef struct _TestStalkerFixture
{
  GumStalker * stalker;
  GumFakeEventSink * sink;

  guint8 * code;
  guint8 * last_invoke_calladdr;
  guint8 * last_invoke_retaddr;
} TestStalkerFixture;

typedef gint (* StalkerTestFunc) (gint arg);

static void invoke_follow_return_code (TestStalkerFixture * fixture);
static void invoke_unfollow_deep_code (TestStalkerFixture * fixture);

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
  fixture->code = gum_alloc_n_pages (1, GUM_PAGE_RWX);
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

  gum_code_writer_put_ret (&cw);

  gum_code_writer_free (&cw);

  invoke_func = (GCallback) code;
  invoke_func ();

  gum_free_pages (code);

  return ret;
}

TEST_LIST_BEGIN (stalker)
  STALKER_TESTENTRY (call)
  STALKER_TESTENTRY (ret)
  STALKER_TESTENTRY (exec)
  STALKER_TESTENTRY (unconditional_jumps)
  STALKER_TESTENTRY (conditional_jump_true)
  STALKER_TESTENTRY (conditional_jump_false)
  STALKER_TESTENTRY (follow_return)
  STALKER_TESTENTRY (follow_stdcall)
  STALKER_TESTENTRY (unfollow_deep)
  STALKER_TESTENTRY (indirect_call_with_immediate)
  STALKER_TESTENTRY (indirect_call_with_register_and_immediate)
  STALKER_TESTENTRY (indirect_jump_with_immediate)
  STALKER_TESTENTRY (direct_call_with_register)
  STALKER_TESTENTRY (no_clobber)

  STALKER_TESTENTRY (heap_api)

#ifdef G_OS_WIN32
  STALKER_TESTENTRY (win32_indirect_call_seg)
  STALKER_TESTENTRY (win32_api)
#endif
TEST_LIST_END ()

static const guint8 flat_code[] = {
    0x33, 0xc0, /* xor eax, eax */
    0x40,       /* inc eax      */
    0x40,       /* inc eax      */
    0xc3        /* retn         */
};

static StalkerTestFunc
invoke_flat (TestStalkerFixture * fixture,
             GumEventType mask)
{
  StalkerTestFunc func;
  gint ret;

  func = (StalkerTestFunc) test_stalker_fixture_dup_code (fixture,
      flat_code, sizeof (flat_code));

  fixture->sink->mask = mask;
  ret = test_stalker_fixture_follow_and_invoke (fixture, func, -1);
  g_assert_cmpint (ret, ==, 2);

  return func;
}

STALKER_TESTCASE (call)
{
  StalkerTestFunc func;
  GumCallEvent * ev;

  func = invoke_flat (fixture, GUM_CALL);

  g_assert_cmpuint (fixture->sink->events->len, ==, 1);
  g_assert_cmpint (g_array_index (fixture->sink->events, GumEvent, 0).type,
      ==, GUM_CALL);
  ev = &g_array_index (fixture->sink->events, GumEvent, 0).call;
  g_assert_cmphex ((guint64) ev->location,
      ==, (guint64) fixture->last_invoke_calladdr);
  g_assert_cmphex ((guint64) ev->target, ==, (guint64) func);
}

STALKER_TESTCASE (ret)
{
  StalkerTestFunc func;
  GumRetEvent * ev;

  func = invoke_flat (fixture, GUM_RET);

  g_assert_cmpuint (fixture->sink->events->len, ==, 1);
  g_assert_cmpint (g_array_index (fixture->sink->events, GumEvent, 0).type,
      ==, GUM_RET);
  ev = &g_array_index (fixture->sink->events, GumEvent, 0).ret;
  g_assert_cmphex ((guint64) ev->location,
      ==, (guint64) (((guint8 *) GSIZE_TO_POINTER (func)) + 4));
  g_assert_cmphex ((guint64) ev->target,
      ==, (guint64) fixture->last_invoke_retaddr);
}

STALKER_TESTCASE (exec)
{
  StalkerTestFunc func;
  GumRetEvent * ev;

  func = invoke_flat (fixture, GUM_EXEC);

  g_assert_cmpuint (fixture->sink->events->len, ==, INVOKER_INSN_COUNT + 4);
  g_assert_cmpint (g_array_index (fixture->sink->events, GumEvent,
      INVOKER_IMPL_OFFSET).type, ==, GUM_EXEC);
  ev = &g_array_index (fixture->sink->events, GumEvent,
      INVOKER_IMPL_OFFSET).ret;
  g_assert_cmphex ((guint64) ev->location, ==, (guint64) func);
}

static const guint8 jumpy_code[] = {
    0x31, 0xc0,                   /* xor eax,eax  */
    0xeb, 0x01,                   /* jmp short +1 */
    0xcc,                         /* int3         */
    0x40,                         /* inc eax      */
    0xe9, 0x02, 0x00, 0x00, 0x00, /* jmp near +2  */
    0xcc,                         /* int3         */
    0xcc,                         /* int3         */
    0xc3                          /* ret          */
};

static StalkerTestFunc
invoke_jumpy (TestStalkerFixture * fixture,
              GumEventType mask)
{
  StalkerTestFunc func;
  gint ret;

  func = (StalkerTestFunc) test_stalker_fixture_dup_code (fixture,
      jumpy_code, sizeof (jumpy_code));

  fixture->sink->mask = mask;
  ret = test_stalker_fixture_follow_and_invoke (fixture, func, -1);
  g_assert_cmpint (ret, ==, 1);

  return func;
}

STALKER_TESTCASE (unconditional_jumps)
{
  invoke_jumpy (fixture, GUM_EXEC);

  g_assert_cmpuint (fixture->sink->events->len, ==, INVOKER_INSN_COUNT + 5);
  g_assert_cmphex ((guint64) NTH_EXEC_EVENT_LOCATION (INVOKER_IMPL_OFFSET + 0),
      ==, (guint64) (fixture->code + 0));
  g_assert_cmphex ((guint64) NTH_EXEC_EVENT_LOCATION (INVOKER_IMPL_OFFSET + 1),
      ==, (guint64) (fixture->code + 2));
  g_assert_cmphex ((guint64) NTH_EXEC_EVENT_LOCATION (INVOKER_IMPL_OFFSET + 2),
      ==, (guint64) (fixture->code + 5));
  g_assert_cmphex ((guint64) NTH_EXEC_EVENT_LOCATION (INVOKER_IMPL_OFFSET + 3),
      ==, (guint64) (fixture->code + 6));
  g_assert_cmphex ((guint64) NTH_EXEC_EVENT_LOCATION (INVOKER_IMPL_OFFSET + 4),
      ==, (guint64) (fixture->code + 13));
}

static const guint8 condy_code[] = {
    0x81, 0x7c, 0x24, 0x04, 0x2a, 0x00, 0x00, 0x00, /* cmp dword [esp+0x4], 42  */
    0x74, 0x05,                                     /* jz +5                    */
    0xe9, 0x06, 0x00, 0x00, 0x00,                   /* jmp dword +6             */

    0xb8, 0x39, 0x05, 0x00, 0x00,                   /* mov eax, 1337            */
    0xc3,                                           /* ret                      */

    0xb8, 0xcb, 0x04, 0x00, 0x00,                   /* mov eax, 1227            */
    0xc3,                                           /* ret                      */
};

static StalkerTestFunc
invoke_condy (TestStalkerFixture * fixture,
              GumEventType mask,
              gint arg)
{
  StalkerTestFunc func;
  gint ret;

  func = (StalkerTestFunc) test_stalker_fixture_dup_code (fixture,
      condy_code, sizeof (condy_code));

  fixture->sink->mask = mask;
  ret = test_stalker_fixture_follow_and_invoke (fixture, func, arg);

  g_assert_cmpint (ret, ==, (arg == 42) ? 1337 : 1227);

  return func;
}

STALKER_TESTCASE (conditional_jump_true)
{
  invoke_condy (fixture, GUM_EXEC, 42);

  g_assert_cmpuint (fixture->sink->events->len, ==, INVOKER_INSN_COUNT + 4);
  g_assert_cmphex ((guint64) NTH_EXEC_EVENT_LOCATION (INVOKER_IMPL_OFFSET + 0),
      ==, (guint64) (fixture->code + 0));
  g_assert_cmphex ((guint64) NTH_EXEC_EVENT_LOCATION (INVOKER_IMPL_OFFSET + 1),
      ==, (guint64) (fixture->code + 8));
  g_assert_cmphex ((guint64) NTH_EXEC_EVENT_LOCATION (INVOKER_IMPL_OFFSET + 2),
      ==, (guint64) (fixture->code + 15));
  g_assert_cmphex ((guint64) NTH_EXEC_EVENT_LOCATION (INVOKER_IMPL_OFFSET + 3),
      ==, (guint64) (fixture->code + 20));
}

STALKER_TESTCASE (conditional_jump_false)
{
  invoke_condy (fixture, GUM_EXEC, 43);

  g_assert_cmpuint (fixture->sink->events->len, ==, INVOKER_INSN_COUNT + 5);
  g_assert_cmphex ((guint64) NTH_EXEC_EVENT_LOCATION (INVOKER_IMPL_OFFSET + 0),
      ==, (guint64) (fixture->code + 0));
  g_assert_cmphex ((guint64) NTH_EXEC_EVENT_LOCATION (INVOKER_IMPL_OFFSET + 1),
      ==, (guint64) (fixture->code + 8));
  g_assert_cmphex ((guint64) NTH_EXEC_EVENT_LOCATION (INVOKER_IMPL_OFFSET + 2),
      ==, (guint64) (fixture->code + 10));
  g_assert_cmphex ((guint64) NTH_EXEC_EVENT_LOCATION (INVOKER_IMPL_OFFSET + 3),
      ==, (guint64) (fixture->code + 21));
  g_assert_cmphex ((guint64) NTH_EXEC_EVENT_LOCATION (INVOKER_IMPL_OFFSET + 4),
      ==, (guint64) (fixture->code + 26));
}

STALKER_TESTCASE (follow_return)
{
  fixture->sink->mask = GUM_EXEC;

  invoke_follow_return_code (fixture);

  g_assert_cmpuint (fixture->sink->events->len, ==, 5);
}

static void
invoke_follow_return_code (TestStalkerFixture * fixture)
{
  guint8 * code;
  GumCodeWriter cw;
  const gchar * start_following_lbl = "start_following";
  GCallback invoke_func;

  code = gum_alloc_n_pages (1, GUM_PAGE_RWX);

  gum_code_writer_init (&cw, code);

  gum_code_writer_put_call_near_label (&cw, start_following_lbl);

  gum_code_writer_put_nop (&cw);

  gum_code_writer_put_push (&cw, (guint32) fixture->stalker);
  gum_code_writer_put_call (&cw, gum_stalker_unfollow_me);
  gum_code_writer_put_add_esp_u32 (&cw, sizeof (GumStalker *));

  gum_code_writer_put_ret (&cw);

  gum_code_writer_put_label (&cw, start_following_lbl);
  gum_code_writer_put_push (&cw, (guint32) fixture->sink);
  gum_code_writer_put_push (&cw, (guint32) fixture->stalker);
  gum_code_writer_put_call (&cw, gum_stalker_follow_me);
  gum_code_writer_put_add_esp_u32 (&cw, 2 * sizeof (gpointer));
  gum_code_writer_put_ret (&cw);

  gum_code_writer_free (&cw);

  invoke_func = (GCallback) code;
  invoke_func ();

  gum_free_pages (code);
}

STALKER_TESTCASE (follow_stdcall)
{
  const guint8 stdcall_code[] =
  {
    0x68, 0xef, 0xbe, 0x00, 0x00, /* push dword 0xbeef */
    0xe8, 0x02, 0x00, 0x00, 0x00, /* call func         */
    0xc3,                         /* ret               */
    0xcc,                         /* int3              */

  /* func: */
    0x8b, 0x44, 0x24, 0x04,       /* mov eax,[esp+0x4] */
    0xc2, 0x04, 0x00              /* ret  4            */
  };
  StalkerTestFunc func;
  gint ret;

  func = (StalkerTestFunc) test_stalker_fixture_dup_code (fixture,
      stdcall_code, sizeof (stdcall_code));

  ret = test_stalker_fixture_follow_and_invoke (fixture, func, 0);

  g_assert_cmpint (ret, ==, 0xbeef);
}

STALKER_TESTCASE (unfollow_deep)
{
  fixture->sink->mask = GUM_EXEC;

  invoke_unfollow_deep_code (fixture);

  g_assert_cmpuint (fixture->sink->events->len, ==, 6);
}

static void
invoke_unfollow_deep_code (TestStalkerFixture * fixture)
{
  guint8 * code;
  GumCodeWriter cw;
  const gchar * func_a_lbl = "func_a";
  const gchar * func_b_lbl = "func_b";
  const gchar * func_c_lbl = "func_c";
  GCallback invoke_func;

  code = gum_alloc_n_pages (1, GUM_PAGE_RWX);

  gum_code_writer_init (&cw, code);

  gum_code_writer_put_push (&cw, (guint32) fixture->sink);
  gum_code_writer_put_push (&cw, (guint32) fixture->stalker);
  gum_code_writer_put_call (&cw, gum_stalker_follow_me);
  gum_code_writer_put_add_esp_u32 (&cw, 2 * sizeof (gpointer));

  gum_code_writer_put_call_near_label (&cw, func_a_lbl);
  gum_code_writer_put_ret (&cw);

  gum_code_writer_put_label (&cw, func_a_lbl);
  gum_code_writer_put_call_near_label (&cw, func_b_lbl);
  gum_code_writer_put_ret (&cw);

  gum_code_writer_put_label (&cw, func_b_lbl);
  gum_code_writer_put_call_near_label (&cw, func_c_lbl);
  gum_code_writer_put_ret (&cw);

  gum_code_writer_put_label (&cw, func_c_lbl);
  gum_code_writer_put_push (&cw, (guint32) fixture->stalker);
  gum_code_writer_put_call (&cw, gum_stalker_unfollow_me);
  gum_code_writer_put_add_esp_u32 (&cw, sizeof (GumStalker *));
  gum_code_writer_put_ret (&cw);

  gum_code_writer_free (&cw);

  invoke_func = (GCallback) code;
  invoke_func ();

  gum_free_pages (code);
}

static const guint8 indirect_call_with_immediate_code[] = {
    0xff, 0x15, 0x00, 0x00, 0x00, 0x00, /* call <indirect> */
    0xc3,                               /* ret             */

    0xb8, 0x39, 0x05, 0x00, 0x00,       /* mov eax, 1337   */
    0xc3,                               /* ret             */
};

static StalkerTestFunc
invoke_indirect_call_with_immediate (TestStalkerFixture * fixture,
                                     GumEventType mask,
                                     gpointer * call_location,
                                     gpointer * call_target)
{
  guint8 * code;
  StalkerTestFunc func;
  gpointer subfunc_addr;
  gint ret;

  code = test_stalker_fixture_dup_code (fixture,
      indirect_call_with_immediate_code,
      sizeof (indirect_call_with_immediate_code));
  func = (StalkerTestFunc) code;

  subfunc_addr = code + 6 + 1;
  *((gpointer *) (code + 2)) = &subfunc_addr;

  if (call_location != NULL)
    *call_location = code + 0;
  if (call_target != NULL)
    *call_target = subfunc_addr;

  fixture->sink->mask = mask;
  ret = test_stalker_fixture_follow_and_invoke (fixture, func, 0);

  g_assert_cmpint (ret, ==, 1337);

  return func;
}

STALKER_TESTCASE (indirect_call_with_immediate)
{
  gpointer location, target;

  invoke_indirect_call_with_immediate (fixture, GUM_EXEC, NULL, NULL);
  g_assert_cmpuint (fixture->sink->events->len,
      ==, INVOKER_INSN_COUNT + 4);

  gum_fake_event_sink_reset (fixture->sink);

  invoke_indirect_call_with_immediate (fixture, GUM_CALL, &location, &target);
  g_assert_cmpuint (fixture->sink->events->len, ==, 2);

  g_assert_cmphex ((guint64) NTH_CALL_EVENT (1, location),
      ==, (guint64) location);
  g_assert_cmphex ((guint64) NTH_CALL_EVENT (1, target), ==, (guint64) target);
}

static const guint8 indirect_call_with_register_and_immediate_code[] = {
    0xb8, 0x78, 0x56, 0x34, 0x12,       /* mov eax, 0x12345678  */
    0xff, 0x50, 0x54,                   /* call [eax + 0x54]    */
    0xb8, 0x78, 0x56, 0x34, 0x12,       /* mov eax, 0x12345678  */
    0xff, 0x90, 0x54, 0x00, 0x00, 0x00, /* call [eax + 0x54]    */
    0xc3,                               /* ret                  */

    0xb8, 0xe9, 0x03, 0x00, 0x00,       /* mov eax, 1001        */
    0xc3,                               /* ret                  */
};

static StalkerTestFunc
invoke_indirect_call_with_register_and_immediate (TestStalkerFixture * fixture,
                                                  GumEventType mask,
                                                  gpointer * last_call_location,
                                                  gpointer * last_call_target)
{
  guint8 * code;
  StalkerTestFunc func;
  gpointer subfunc_addr;
  gint ret;

  code = test_stalker_fixture_dup_code (fixture,
      indirect_call_with_register_and_immediate_code,
      sizeof (indirect_call_with_register_and_immediate_code));
  func = (StalkerTestFunc) code;

  subfunc_addr = code + 20;
  *((gpointer *) (code + 1)) =
      GSIZE_TO_POINTER (GPOINTER_TO_SIZE (&subfunc_addr) - 0x54);
  *((gpointer *) (code + 9)) =
      GSIZE_TO_POINTER (GPOINTER_TO_SIZE (&subfunc_addr) - 0x54);

  if (last_call_location != NULL)
    *last_call_location = code + 13;
  if (last_call_target != NULL)
    *last_call_target = subfunc_addr;

  fixture->sink->mask = mask;
  ret = test_stalker_fixture_follow_and_invoke (fixture, func, 0);

  g_assert_cmpint (ret, ==, 1001);

  return func;
}

STALKER_TESTCASE (indirect_call_with_register_and_immediate)
{
  gpointer location, target;

  invoke_indirect_call_with_register_and_immediate (fixture, GUM_EXEC,
      NULL, NULL);
  g_assert_cmpuint (fixture->sink->events->len,
      ==, INVOKER_INSN_COUNT + 9);

  gum_fake_event_sink_reset (fixture->sink);

  invoke_indirect_call_with_register_and_immediate (fixture, GUM_CALL,
      &location, &target);
  g_assert_cmpuint (fixture->sink->events->len, ==, 3);

  g_assert_cmphex ((guint64) NTH_CALL_EVENT (2, location),
      ==, (guint64) location);
  g_assert_cmphex ((guint64) NTH_CALL_EVENT (2, target), ==, (guint64) target);
}

static const guint8 indirect_jump_with_immediate_code[] = {
    0xff, 0x25, 0x00, 0x00, 0x00, 0x00, /* jmp <indirect> */
    0xcc,                               /* int3           */

    0xb8, 0x39, 0x05, 0x00, 0x00,       /* mov eax, 1337  */
    0xc3,                               /* ret            */
};

static StalkerTestFunc
invoke_indirect_jump_with_immediate (TestStalkerFixture * fixture,
                                     GumEventType mask)
{
  guint8 * code;
  StalkerTestFunc func;
  gpointer realfunc_addr;
  gint ret;

  code = test_stalker_fixture_dup_code (fixture, indirect_jump_with_immediate_code,
      sizeof (indirect_jump_with_immediate_code));
  func = (StalkerTestFunc) code;

  realfunc_addr = code + 6 + 1;
  *((gpointer *) (code + 2)) = &realfunc_addr;

  fixture->sink->mask = mask;
  ret = test_stalker_fixture_follow_and_invoke (fixture, func, 0);

  g_assert_cmpint (ret, ==, 1337);

  return func;
}

STALKER_TESTCASE (indirect_jump_with_immediate)
{
  invoke_indirect_jump_with_immediate (fixture, GUM_EXEC);

  g_assert_cmpuint (fixture->sink->events->len,
      ==, INVOKER_INSN_COUNT + 3);
}

static const guint8 direct_call_with_register_code[] = {
    0xb8, 0x78, 0x56, 0x34, 0x12,       /* mov eax, 0x12345678  */
    0xff, 0xd0,                         /* call eax             */
    0xc3,                               /* ret                  */

    0xb8, 0xcb, 0x04, 0x00, 0x00,       /* mov eax, 1227        */
    0xc3                                /* ret                  */
};

static StalkerTestFunc
invoke_direct_call_with_register (TestStalkerFixture * fixture,
                                  GumEventType mask,
                                  gpointer * call_location,
                                  gpointer * call_target)
{
  guint8 * code;
  StalkerTestFunc func;
  gpointer subfunc_addr;
  gint ret;

  code = test_stalker_fixture_dup_code (fixture,
      direct_call_with_register_code,
      sizeof (direct_call_with_register_code));
  func = (StalkerTestFunc) code;

  subfunc_addr = code + 8;
  *((gpointer *) (code + 1)) = subfunc_addr;

  if (call_location != NULL)
    *call_location = code + 5;
  if (call_target != NULL)
    *call_target = subfunc_addr;

  fixture->sink->mask = mask;
  ret = test_stalker_fixture_follow_and_invoke (fixture, func, 0);

  g_assert_cmpint (ret, ==, 1227);

  return func;
}

STALKER_TESTCASE (direct_call_with_register)
{
  gpointer location, target;

  invoke_direct_call_with_register (fixture, GUM_EXEC, NULL, NULL);
  g_assert_cmpuint (fixture->sink->events->len,
      ==, INVOKER_INSN_COUNT + 5);

  gum_fake_event_sink_reset (fixture->sink);

  invoke_direct_call_with_register (fixture, GUM_CALL, &location, &target);
  g_assert_cmpuint (fixture->sink->events->len, ==, 2);

  g_assert_cmphex ((guint64) NTH_CALL_EVENT (1, location),
      ==, (guint64) location);
  g_assert_cmphex ((guint64) NTH_CALL_EVENT (1, target), ==, (guint64) target);
}

typedef void (* ClobberFunc) (GumCpuContext * ctx);

STALKER_TESTCASE (no_clobber)
{
  guint8 * code;
  GumCodeWriter cw;
  const gchar * my_func_lbl = "my_func";
  const gchar * my_beach_lbl = "my_beach";
  ClobberFunc func;
  GumCpuContext ctx;

  code = gum_alloc_n_pages (1, GUM_PAGE_RWX);
  gum_code_writer_init (&cw, code);

  gum_code_writer_put_pushad (&cw);

  gum_code_writer_put_pushad (&cw);
  gum_code_writer_put_push (&cw, (guint32) fixture->sink);
  gum_code_writer_put_push (&cw, (guint32) fixture->stalker);
  gum_code_writer_put_call (&cw, gum_stalker_follow_me);
  gum_code_writer_put_add_esp_u32 (&cw, 2 * sizeof (gpointer));
  gum_code_writer_put_popad (&cw);

  gum_code_writer_put_mov_eax (&cw, 0xcafebabe);
  gum_code_writer_put_mov_ecx (&cw, 0xbeefbabe);
  gum_code_writer_put_mov_edx (&cw, 0xb00bbabe);
  gum_code_writer_put_mov_ebx (&cw, 0xf001babe);
  gum_code_writer_put_mov_ebp (&cw, 0xababe);
  gum_code_writer_put_mov_esi (&cw, 0x1337);
  gum_code_writer_put_mov_edi (&cw, 0x1227);

  gum_code_writer_put_call_near_label (&cw, my_func_lbl);

  gum_code_writer_put_pushad (&cw);
  gum_code_writer_put_push (&cw, (guint32) fixture->stalker);
  gum_code_writer_put_call (&cw, gum_stalker_unfollow_me);
  gum_code_writer_put_add_esp_u32 (&cw, 1 * sizeof (gpointer));
  gum_code_writer_put_popad (&cw);

  gum_code_writer_put_push_ecx (&cw);
  gum_code_writer_put_mov_ecx_esp_offset_ptr (&cw, sizeof (gpointer)
      + (8 * sizeof (gpointer)) + sizeof (gpointer));
  gum_code_writer_put_mov_reg_offset_ptr_reg (&cw,
      GUM_REG_ECX, G_STRUCT_OFFSET (GumCpuContext, eax), GUM_REG_EAX);
  gum_code_writer_put_mov_reg_offset_ptr_reg (&cw,
      GUM_REG_ECX, G_STRUCT_OFFSET (GumCpuContext, edx), GUM_REG_EDX);
  gum_code_writer_put_mov_reg_offset_ptr_reg (&cw,
      GUM_REG_ECX, G_STRUCT_OFFSET (GumCpuContext, ebx), GUM_REG_EBX);
  gum_code_writer_put_mov_reg_offset_ptr_reg (&cw,
      GUM_REG_ECX, G_STRUCT_OFFSET (GumCpuContext, ebp), GUM_REG_EBP);
  gum_code_writer_put_mov_reg_offset_ptr_reg (&cw,
      GUM_REG_ECX, G_STRUCT_OFFSET (GumCpuContext, esi), GUM_REG_ESI);
  gum_code_writer_put_mov_reg_offset_ptr_reg (&cw,
      GUM_REG_ECX, G_STRUCT_OFFSET (GumCpuContext, edi), GUM_REG_EDI);
  gum_code_writer_put_pop_eax (&cw);
  gum_code_writer_put_mov_reg_offset_ptr_reg (&cw,
      GUM_REG_ECX, G_STRUCT_OFFSET (GumCpuContext, ecx), GUM_REG_EAX);

  gum_code_writer_put_popad (&cw);

  gum_code_writer_put_ret (&cw);

  gum_code_writer_put_label (&cw, my_func_lbl);
  gum_code_writer_put_nop (&cw);
  gum_code_writer_put_jmp_short_label (&cw, my_beach_lbl);
  gum_code_writer_put_int3 (&cw);

  gum_code_writer_put_label (&cw, my_beach_lbl);
  gum_code_writer_put_nop (&cw);
  gum_code_writer_put_nop (&cw);
  gum_code_writer_put_ret (&cw);

  gum_code_writer_free (&cw);

  fixture->sink->mask = GUM_CALL | GUM_RET | GUM_EXEC;
  func = (ClobberFunc) code;
  func (&ctx);

  g_assert_cmphex (ctx.eax, ==, 0xcafebabe);
  g_assert_cmphex (ctx.ecx, ==, 0xbeefbabe);
  g_assert_cmphex (ctx.edx, ==, 0xb00bbabe);
  g_assert_cmphex (ctx.ebx, ==, 0xf001babe);
  g_assert_cmphex (ctx.ebp, ==, 0xababe);
  g_assert_cmphex (ctx.esi, ==, 0x1337);
  g_assert_cmphex (ctx.edi, ==, 0x1227);

  gum_free_pages (code);
}

STALKER_TESTCASE (heap_api)
{
  gpointer p;

  fixture->sink->mask = GUM_EXEC | GUM_CALL | GUM_RET;

  gum_stalker_follow_me (fixture->stalker, GUM_EVENT_SINK (fixture->sink));
  p = malloc (1);
  free (p);
  gum_stalker_unfollow_me (fixture->stalker);

  /*gum_fake_event_sink_dump (fixture->sink);*/
}

#ifdef G_OS_WIN32

static const guint8 indirect_call_seg_code[] = {
    0x64, 0xff, 0x35, 0x00, 0x07, 0x00, 0x00, /* push dword [dword fs:0x700] */
                                              /* mov dword [dword fs:0x700], <addr> */
    0x64, 0xc7, 0x05, 0x00, 0x07, 0x00, 0x00, 0xaa, 0xbb, 0xcc, 0xdd,

    0x64, 0xff, 0x15, 0x00, 0x07, 0x00, 0x00, /* call fs:700h                */

    0x50,                                     /* push eax                    */
    0x8b, 0x44, 0x24, 0x04,                   /* mov eax, [esp+0x4]          */
    0x64, 0xa3, 0x00, 0x07, 0x00, 0x00,       /* mov [fs:0x700],eax          */
    0x58,                                     /* pop eax                     */
    0x81, 0xc4, 0x04, 0x00, 0x00, 0x00,       /* add esp, 0x4                */

    0xc3,                                     /* ret                         */

    0xb8, 0xbe, 0xba, 0xfe, 0xca,             /* mov eax, 0xcafebabe         */
    0xc3,                                     /* ret                         */
};

static StalkerTestFunc
invoke_indirect_call_seg (TestStalkerFixture * fixture,
                          GumEventType mask)
{
  guint8 * code;
  StalkerTestFunc func;
  guint ret;

  code = test_stalker_fixture_dup_code (fixture, indirect_call_seg_code,
      sizeof (indirect_call_seg_code));
  func = (StalkerTestFunc) code;

  *((gpointer *) (code + 14)) = code + sizeof (indirect_call_seg_code) - 1 - 5;

  fixture->sink->mask = mask;
  ret = test_stalker_fixture_follow_and_invoke (fixture, func, 0);

  g_assert_cmphex (ret, ==, 0xcafebabe);

  return func;
}

STALKER_TESTCASE (win32_indirect_call_seg)
{
  invoke_indirect_call_seg (fixture, GUM_EXEC);

  g_assert_cmpuint (fixture->sink->events->len,
      ==, INVOKER_INSN_COUNT + 11);
}

STALKER_TESTCASE (win32_api)
{
  fixture->sink->mask = GUM_EXEC | GUM_CALL | GUM_RET;

  gum_stalker_follow_me (fixture->stalker, GUM_EVENT_SINK (fixture->sink));
  MessageBeep (MB_ICONINFORMATION);
  gum_stalker_unfollow_me (fixture->stalker);
}

#endif
