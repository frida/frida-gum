/*
 * Copyright (C) 2009-2020 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 * Copyright (C) 2017 Antonio Ken Iannillo <ak.iannillo@gmail.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumstalker.h"

#include "fakeeventsink.h"
#include "gumarmwriter.h"
#include "gummemory.h"
#include "stalkerdummychannel.h"
#include "testutil.h"

#include <lzma.h>
#include <stdlib.h>
#include <string.h>
#ifdef HAVE_LINUX
# include <sys/prctl.h>
#endif

#define TESTCASE(NAME) \
    void test_arm_stalker_ ## NAME (                                      \
    TestArmStalkerFixture * fixture, gconstpointer data)
#define TESTENTRY(NAME) \
    TESTENTRY_WITH_FIXTURE ("Core/Stalker", test_arm_stalker, NAME,       \
    TestArmStalkerFixture)

#define NTH_EVENT_AS_CALL(N) \
    (gum_fake_event_sink_get_nth_event_as_call (fixture->sink, N))
#define NTH_EVENT_AS_RET(N) \
    (gum_fake_event_sink_get_nth_event_as_ret (fixture->sink, N))
#define NTH_EXEC_EVENT_LOCATION(N) \
    (gum_fake_event_sink_get_nth_event_as_exec (fixture->sink, N)->location)

#define TESTCODE(NAME, ...) static const guint8 NAME[] = { __VA_ARGS__ }
#define CODE_START(NAME) ((gconstpointer) NAME)
#define CODE_SIZE(NAME) sizeof (NAME)

#define GUM_EVENT_TYPE_exec GumExecEvent
#define GUM_EVENT_TYPE_NAME_exec GUM_EXEC

#define GUM_EVENT_TYPE_call GumCallEvent
#define GUM_EVENT_TYPE_NAME_call GUM_CALL

#define GUM_EVENT_TYPE_block GumBlockEvent
#define GUM_EVENT_TYPE_NAME_block GUM_BLOCK

#define GUM_EVENT_TYPE_ret GumRetEvent
#define GUM_EVENT_TYPE_NAME_ret GUM_RET

#define GUM_ASSERT_EVENT_ADDR(TYPE, INDEX, FIELD, VALUE)                  \
    {                                                                     \
      GUM_EVENT_TYPE_ ## TYPE * ev;                                       \
                                                                          \
      g_assert_cmpuint (fixture->sink->events->len, >, INDEX);            \
      g_assert_cmpint (g_array_index (fixture->sink->events,              \
          GumEvent, INDEX).type, ==, GUM_EVENT_TYPE_NAME_ ## TYPE);       \
                                                                          \
      ev = &g_array_index (fixture->sink->events, GumEvent, INDEX).TYPE;  \
      GUM_ASSERT_CMPADDR (ev->FIELD, ==, VALUE);                          \
    }

/*
 * Total number of instructions in the invoker built by follow_and_invoke().
 * This is counted from the first instruction after the call to follow_me()
 * up to and including the call to unfollow_me().
 */
#define INVOKER_INSN_COUNT 6

/*
 * Total number of call instructions in the invoker built by
 * follow_and_invoke().
 */
#define INVOKER_CALL_INSN_COUNT 2

/*
 * Total number of blocks in the invoker built by follow_and_invoke().
 */
#define INVOKER_BLOCK_COUNT 0

/*
 * Offset of the first instruction within the invoker which should be stalked in
 * bytes.
 */
#define INVOKER_IMPL_OFFSET 20

typedef struct _TestArmStalkerFixture TestArmStalkerFixture;
typedef struct _UnfollowTransformContext UnfollowTransformContext;

struct _TestArmStalkerFixture
{
  GumStalker * stalker;
  GumStalkerTransformer * transformer;
  GumFakeEventSink * sink;

  guint8 * code;
  guint8 * stalked_invoker;
  guint8 * unstalked_invoker;
  guint32 stalked_ret;
  guint32 unstalked_ret;
};

struct _UnfollowTransformContext
{
  GumStalker * stalker;
  guint num_blocks_transformed;
  guint target_block;
  gint max_instructions;
};

static void test_arm_stalker_fixture_setup (TestArmStalkerFixture * fixture,
    gconstpointer data);
static void test_arm_stalker_fixture_teardown (TestArmStalkerFixture * fixture,
    gconstpointer data);
static GumAddress test_arm_stalker_fixture_dup_code (
    TestArmStalkerFixture * fixture, const guint32 * tpl_code, guint tpl_size);

static GumAddress invoke_arm_expecting_return_value (
    TestArmStalkerFixture * fixture, GumEventType mask, const guint32 * code,
    guint32 len, guint32 expected_return_value);
static GumAddress invoke_thumb_expecting_return_value (
    TestArmStalkerFixture * fixture, GumEventType mask, const guint32 * code,
    guint32 len, guint32 expected_return_value);
static gint test_arm_stalker_fixture_follow_and_invoke (
    TestArmStalkerFixture * fixture, GumAddress addr);
static void test_arm_stalker_fixture_unstalked (TestArmStalkerFixture * fixture,
    GumAddress addr);
static void test_arm_stalker_fixture_stalked (TestArmStalkerFixture * fixture,
    GumAddress addr);

TESTCODE (arm_flat_code,
  0x00, 0x00, 0x40, 0xe0, /* sub r0, r0, r0  */
  0x01, 0x00, 0x80, 0xe2, /* add r0, r0, 1   */
  0x01, 0x00, 0x80, 0xe2, /* add r0, r0, 1   */
  0x0e, 0xf0, 0xa0, 0xe1  /* mov pc, lr      */
);

TESTCODE (thumb_flat_code,
  0x00, 0xb5,             /* push {lr}       */
  0x00, 0x1a,             /* subs r0, r0, r0 */
  0x01, 0x30,             /* adds r0, 1      */
  0x01, 0x30,             /* adds r0, 1      */
  0x00, 0xbd              /* pop {pc}        */
);

static void
test_arm_stalker_fixture_setup (TestArmStalkerFixture * fixture,
                                gconstpointer data)
{
  fixture->stalker = gum_stalker_new ();
  fixture->transformer = NULL;
  fixture->sink = GUM_FAKE_EVENT_SINK (gum_fake_event_sink_new ());
  fixture->sink->mask = 0;
}

static void
test_arm_stalker_fixture_teardown (TestArmStalkerFixture * fixture,
                                   gconstpointer data)
{
  while (gum_stalker_garbage_collect (fixture->stalker))
    g_usleep (10000);

  g_object_unref (fixture->sink);
  g_clear_object (&fixture->transformer);
  g_object_unref (fixture->stalker);

  if (fixture->code != NULL)
    gum_free_pages (fixture->code);
}

static GumAddress
test_arm_stalker_fixture_dup_code (TestArmStalkerFixture * fixture,
                                   const guint32 * tpl_code,
                                   guint tpl_size)
{
  GumAddressSpec spec;

  spec.near_address = gum_stalker_follow_me;
  spec.max_distance = G_MAXINT32 / 2;

  if (fixture->code != NULL)
    gum_free_pages (fixture->code);
  fixture->code = gum_alloc_n_pages_near (
      (tpl_size / gum_query_page_size ()) + 1, GUM_PAGE_RW, &spec);
  memcpy (fixture->code, tpl_code, tpl_size);
  gum_memory_mark_code (fixture->code, tpl_size);

  return GUM_ADDRESS (fixture->code);
}

static GumAddress
invoke_arm_flat_expecting_return_value (TestArmStalkerFixture * fixture,
                                        GumEventType mask,
                                        guint expected_return_value)
{
  return invoke_arm_expecting_return_value (fixture, mask,
      CODE_START (arm_flat_code), CODE_SIZE (arm_flat_code),
      expected_return_value);
}

static GumAddress
invoke_thumb_flat_expecting_return_value (TestArmStalkerFixture * fixture,
                                          GumEventType mask,
                                          guint expected_return_value)
{
  return invoke_thumb_expecting_return_value (fixture, mask,
      CODE_START (thumb_flat_code), CODE_SIZE (thumb_flat_code),
      expected_return_value);
}

static GumAddress
stalk_arm_flat_expecting_return_value (TestArmStalkerFixture * fixture,
                                       GumEventType mask,
                                       guint expected_return_value)
{
  GumAddress addr;

  addr = test_arm_stalker_fixture_dup_code (fixture,
      CODE_START (arm_flat_code), CODE_SIZE (arm_flat_code));

  fixture->sink->mask = mask;
  test_arm_stalker_fixture_stalked (fixture, addr);

  g_assert_cmpuint (expected_return_value, ==, fixture->stalked_ret);

  return addr;
}

static GumAddress
invoke_arm_expecting_return_value (TestArmStalkerFixture * fixture,
                                   GumEventType mask,
                                   const guint32 * code,
                                   guint32 len,
                                   guint32 expected_return_value)
{
  GumAddress addr;
  guint32 ret;

  addr = test_arm_stalker_fixture_dup_code (fixture, code, len);

  fixture->sink->mask = mask;
  ret = test_arm_stalker_fixture_follow_and_invoke (fixture, addr);
  g_assert_cmpuint (ret, ==, expected_return_value);

  return addr;
}

static GumAddress
invoke_thumb_expecting_return_value (TestArmStalkerFixture * fixture,
                                     GumEventType mask,
                                     const guint32 * code,
                                     guint32 len,
                                     guint32 expected_return_value)
{
  GumAddress addr;
  guint32 ret;

  addr = test_arm_stalker_fixture_dup_code (fixture, code, len);

  fixture->sink->mask = mask;
  ret = test_arm_stalker_fixture_follow_and_invoke (fixture, addr + 1);
  g_assert_cmpuint (ret, ==, expected_return_value);

  return addr;
}

static gint
test_arm_stalker_fixture_follow_and_invoke (TestArmStalkerFixture * fixture,
                                            GumAddress addr)
{
  test_arm_stalker_fixture_unstalked (fixture, addr);
  test_arm_stalker_fixture_stalked (fixture, addr);

  g_assert_cmpuint (fixture->unstalked_ret, ==, fixture->stalked_ret);

  return fixture->stalked_ret;
}

static void
test_arm_stalker_fixture_unstalked (TestArmStalkerFixture * fixture,
                                    GumAddress addr)
{
  GumArmWriter cw;
  GCallback unstalked_func;

  fixture->unstalked_invoker = gum_alloc_n_pages (1, GUM_PAGE_RW);

  gum_arm_writer_init (&cw, fixture->unstalked_invoker);

  gum_arm_writer_put_push_registers (&cw, 1, ARM_REG_LR);

  gum_arm_writer_put_ldr_reg_u32 (&cw, ARM_REG_R0, addr);
  gum_arm_writer_put_blx_reg (&cw, ARM_REG_R0);

  gum_arm_writer_put_ldr_reg_address (&cw, ARM_REG_R1,
      GUM_ADDRESS (&fixture->unstalked_ret));
  gum_arm_writer_put_str_reg_reg_offset (&cw, ARM_REG_R0, ARM_REG_R1, 0);

  gum_arm_writer_put_pop_registers (&cw, 1, ARM_REG_LR);
  gum_arm_writer_put_ret (&cw);

  gum_arm_writer_flush (&cw);
  gum_memory_mark_code (cw.base, gum_arm_writer_offset (&cw));
  gum_arm_writer_clear (&cw);

  unstalked_func =
      GUM_POINTER_TO_FUNCPTR (GCallback, fixture->unstalked_invoker);
  unstalked_func ();

  gum_free_pages (fixture->unstalked_invoker);
}

static void
test_arm_stalker_fixture_stalked (TestArmStalkerFixture * fixture,
                                  GumAddress addr)
{
  GumAddressSpec spec;
  GumArmWriter cw;
  GCallback stalked_func;

  spec.near_address = gum_stalker_follow_me;
  spec.max_distance = G_MAXINT32 / 2;
  fixture->stalked_invoker = gum_alloc_n_pages_near (1, GUM_PAGE_RW, &spec);

  gum_arm_writer_init (&cw, fixture->stalked_invoker);

  gum_arm_writer_put_push_registers (&cw, 2, ARM_REG_R0, ARM_REG_LR);

  gum_arm_writer_put_call_address_with_arguments (&cw,
      GUM_ADDRESS (gum_stalker_follow_me), 3,
      GUM_ARG_ADDRESS, GUM_ADDRESS (fixture->stalker),
      GUM_ARG_ADDRESS, GUM_ADDRESS (fixture->transformer),
      GUM_ARG_ADDRESS, GUM_ADDRESS (fixture->sink));

  gum_arm_writer_put_ldr_reg_u32 (&cw, ARM_REG_R0, GUM_ADDRESS (addr));
  gum_arm_writer_put_blx_reg (&cw, ARM_REG_R0);

  gum_arm_writer_put_ldr_reg_address (&cw, ARM_REG_R1,
      GUM_ADDRESS (&fixture->stalked_ret));
  gum_arm_writer_put_str_reg_reg_offset (&cw, ARM_REG_R0, ARM_REG_R1, 0);

  gum_arm_writer_put_call_address_with_arguments (&cw,
      GUM_ADDRESS (gum_stalker_unfollow_me), 1,
      GUM_ARG_ADDRESS, GUM_ADDRESS (fixture->stalker));

  gum_arm_writer_put_pop_registers (&cw, 2, ARM_REG_R0, ARM_REG_LR);
  gum_arm_writer_put_ret (&cw);

  gum_arm_writer_flush (&cw);
  gum_memory_mark_code (cw.base, gum_arm_writer_offset (&cw));
  gum_arm_writer_clear (&cw);

  stalked_func = GUM_POINTER_TO_FUNCPTR (GCallback, fixture->stalked_invoker);
  stalked_func ();

  gum_free_pages (fixture->stalked_invoker);
}

static void
dummy_call_probe (GumCallSite * site,
                  gpointer user_data)
{
}
