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

#include <glib.h>
#ifdef G_OS_WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#endif

#include "stalker-fixture.c"

static void invoke_follow_return_code (TestStalkerFixture * fixture);
static void invoke_unfollow_deep_code (TestStalkerFixture * fixture);

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
  STALKER_TESTENTRY (indirect_call_with_register_and_byte_immediate)
  STALKER_TESTENTRY (indirect_call_with_register_and_dword_immediate)
  STALKER_TESTENTRY (indirect_call_with_esp_and_byte_immediate)
  STALKER_TESTENTRY (indirect_call_with_esp_and_dword_immediate)
  STALKER_TESTENTRY (indirect_jump_with_immediate)
  STALKER_TESTENTRY (direct_call_with_register)
  STALKER_TESTENTRY (no_clobber)

  STALKER_TESTENTRY (heap_api)

#ifdef G_OS_WIN32
  STALKER_TESTENTRY (win32_indirect_call_seg)
  STALKER_TESTENTRY (win32_api)
#endif
TEST_LIST_END ()

STALKER_TESTCASE (heap_api)
{
  gpointer p;

  fixture->sink->mask = GUM_EXEC | GUM_CALL | GUM_RET;

  gum_stalker_follow_me (fixture->stalker, GUM_EVENT_SINK (fixture->sink));
  p = malloc (1);
  free (p);
  gum_stalker_unfollow_me (fixture->stalker);

  g_assert_cmpuint (fixture->sink->events->len, >, 0);

  /*gum_fake_event_sink_dump (fixture->sink);*/
}

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

typedef struct _CallTemplate CallTemplate;

struct _CallTemplate
{
  const guint8 * code_template;
  guint code_size;
  guint call_site_offset;
  guint target_address_offset;
  gboolean target_address_offset_points_directly_to_function;
  guint target_func_offset;
  gint target_func_immediate_fixup;
  guint instruction_count;
};

static StalkerTestFunc
invoke_call_from_template (TestStalkerFixture * fixture,
                           CallTemplate * call_template)
{
  guint8 * code;
  StalkerTestFunc func;
  gsize target_actual_address;
  gpointer target_func_address;
  gint ret;

  code = test_stalker_fixture_dup_code (fixture,
      call_template->code_template, call_template->code_size);
  func = (StalkerTestFunc) code;

  target_func_address = code + call_template->target_func_offset;
  if (call_template->target_address_offset_points_directly_to_function)
    target_actual_address = GPOINTER_TO_SIZE (target_func_address);
  else
    target_actual_address = GPOINTER_TO_SIZE (&target_func_address);
  *((gsize *) (code + call_template->target_address_offset)) =
      target_actual_address + call_template->target_func_immediate_fixup;

  fixture->sink->mask = GUM_EXEC;
  ret = test_stalker_fixture_follow_and_invoke (fixture, func, 0);
  g_assert_cmpint (ret, ==, 1337);
  g_assert_cmpuint (fixture->sink->events->len,
      ==, INVOKER_INSN_COUNT + call_template->instruction_count);

  gum_fake_event_sink_reset (fixture->sink);

  fixture->sink->mask = GUM_CALL;
  ret = test_stalker_fixture_follow_and_invoke (fixture, func, 0);
  g_assert_cmpint (ret, ==, 1337);
  g_assert_cmpuint (fixture->sink->events->len, ==, 2);
  g_assert_cmphex ((guint64) NTH_CALL_EVENT (1, location),
      ==, (guint64) (code + call_template->call_site_offset));
  g_assert_cmphex ((guint64) NTH_CALL_EVENT (1, target),
      ==, (guint64) (code + call_template->target_func_offset));

  return func;
}

STALKER_TESTCASE (indirect_call_with_immediate)
{
  const guint8 code[] = {
      0xff, 0x15, 0x00, 0x00, 0x00, 0x00, /* call <indirect> */
      0xc3,                               /* ret             */

      0xb8, 0x39, 0x05, 0x00, 0x00,       /* mov eax, 1337   */
      0xc3,                               /* ret             */
  };
  CallTemplate call_template = { 0, };

  call_template.code_template = code;
  call_template.code_size = sizeof (code);
  call_template.call_site_offset = 0;
  call_template.target_address_offset = 2;
  call_template.target_func_offset = 7;
  call_template.instruction_count = 4;

  invoke_call_from_template (fixture, &call_template);
}

STALKER_TESTCASE (indirect_call_with_register_and_byte_immediate)
{
  const guint8 code[] = {
      0xb8, 0x78, 0x56, 0x34, 0x12,       /* mov eax, 0x12345678  */
      0xff, 0x50, 0x54,                   /* call [eax + 0x54]    */
      0xc3,                               /* ret                  */

      0xb8, 0x39, 0x05, 0x00, 0x00,       /* mov eax, 1337        */
      0xc3,                               /* ret                  */
  };
  CallTemplate call_template = { 0, };

  call_template.code_template = code;
  call_template.code_size = sizeof (code);
  call_template.call_site_offset = 5;
  call_template.target_address_offset = 1;
  call_template.target_func_offset = 9;
  call_template.target_func_immediate_fixup = -0x54;
  call_template.instruction_count = 5;

  invoke_call_from_template (fixture, &call_template);
}

STALKER_TESTCASE (indirect_call_with_register_and_dword_immediate)
{
  const guint8 code[] = {
      0xb8, 0x78, 0x56, 0x34, 0x12,       /* mov eax, 0x12345678  */
      0xff, 0x90, 0x54, 0x00, 0x00, 0x00, /* call [eax + 0x54]    */
      0xc3,                               /* ret                  */

      0xb8, 0x39, 0x05, 0x00, 0x00,       /* mov eax, 1337        */
      0xc3,                               /* ret                  */
  };
  CallTemplate call_template = { 0, };

  call_template.code_template = code;
  call_template.code_size = sizeof (code);
  call_template.call_site_offset = 5;
  call_template.target_address_offset = 1;
  call_template.target_func_offset = 12;
  call_template.target_func_immediate_fixup = -0x54;
  call_template.instruction_count = 5;

  invoke_call_from_template (fixture, &call_template);
}

STALKER_TESTCASE (indirect_call_with_esp_and_byte_immediate)
{
  const guint8 code[] = {
      0xb8, 0x78, 0x56, 0x34, 0x12,       /* mov eax, 0x12345678 */
      0x50,                               /* push eax            */
      0x56,                               /* push esi            */
      0x57,                               /* push edi            */
      0xff, 0x54, 0x24, 0x08,             /* call [esp + 8]      */
      0x5F,                               /* pop edi             */
      0x5E,                               /* pop esi             */
      0x59,                               /* pop ecx             */
      0xc3,                               /* ret                 */

      0xb8, 0x39, 0x05, 0x00, 0x00,       /* mov eax, 1337       */
      0xc3,                               /* ret                 */
  };
  CallTemplate call_template = { 0, };

  call_template.code_template = code;
  call_template.code_size = sizeof (code);
  call_template.call_site_offset = 8;
  call_template.target_address_offset = 1;
  call_template.target_address_offset_points_directly_to_function = TRUE;
  call_template.target_func_offset = 16;
  call_template.instruction_count = 11;

  invoke_call_from_template (fixture, &call_template);
}

STALKER_TESTCASE (indirect_call_with_esp_and_dword_immediate)
{
  const guint8 code[] = {
      0xb8, 0x78, 0x56, 0x34, 0x12,               /* mov eax, 0x12345678 */
      0x50,                                       /* push eax            */
      0x56,                                       /* push esi            */
      0x57,                                       /* push edi            */
      0xff, 0x94, 0x24, 0x08, 0x00, 0x00, 0x00,   /* call [esp + 8]      */
      0x5F,                                       /* pop edi             */
      0x5E,                                       /* pop esi             */
      0x59,                                       /* pop ecx             */
      0xc3,                                       /* ret                 */

      0xb8, 0x39, 0x05, 0x00, 0x00,               /* mov eax, 1337       */
      0xc3,                                       /* ret                 */
  };
  CallTemplate call_template = { 0, };

  call_template.code_template = code;
  call_template.code_size = sizeof (code);
  call_template.call_site_offset = 8;
  call_template.target_address_offset = 1;
  call_template.target_address_offset_points_directly_to_function = TRUE;
  call_template.target_func_offset = 19;
  call_template.instruction_count = 11;

  invoke_call_from_template (fixture, &call_template);
}

STALKER_TESTCASE (direct_call_with_register)
{
  const guint8 code[] = {
      0xb8, 0x78, 0x56, 0x34, 0x12,       /* mov eax, 0x12345678  */
      0xff, 0xd0,                         /* call eax             */
      0xc3,                               /* ret                  */

      0xb8, 0x39, 0x05, 0x00, 0x00,       /* mov eax, 1337        */
      0xc3                                /* ret                  */
  };
  CallTemplate call_template = { 0, };

  call_template.code_template = code;
  call_template.code_size = sizeof (code);
  call_template.call_site_offset = 5;
  call_template.target_address_offset = 1;
  call_template.target_address_offset_points_directly_to_function = TRUE;
  call_template.target_func_offset = 8;
  call_template.instruction_count = 5;

  invoke_call_from_template (fixture, &call_template);
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
