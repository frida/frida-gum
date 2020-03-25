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

#include <stdlib.h>
#include <string.h>

#define TESTCASE(NAME) \
    void test_arm_stalker_ ## NAME ( \
    TestArmStalkerFixture * fixture, gconstpointer data)
#define TESTENTRY(NAME) \
    TESTENTRY_WITH_FIXTURE ("Core/Stalker", test_arm_stalker, NAME, \
    TestArmStalkerFixture)

#define NTH_EVENT_AS_CALL(N) \
    (gum_fake_event_sink_get_nth_event_as_call (fixture->sink, N))
#define NTH_EVENT_AS_RET(N) \
    (gum_fake_event_sink_get_nth_event_as_ret (fixture->sink, N))
#define NTH_EXEC_EVENT_LOCATION(N) \
    (gum_fake_event_sink_get_nth_event_as_exec (fixture->sink, N)->location)

typedef struct _TestArmStalkerFixture
{
  GumStalker * stalker;
  GumStalkerTransformer * transformer;
  GumFakeEventSink * sink;

  guint8 * code;
  guint8 * invoker;
  guint8 * last_invoke_calladdr;
  guint8 * last_invoke_retaddr;
} TestArmStalkerFixture;

typedef gint (* StalkerTestFunc) (gint arg);

static void silence_warnings (void);

static void
debug_hello (gpointer pointer)
{
  g_print ("* pointer: %p *\n", pointer);
}

static void
put_debug_print_pointer (GumArmWriter * cw,
                         gpointer pointer)
{
  gum_arm_writer_put_push_all_r_registers (cw, 1);
  gum_arm_writer_put_call_address_with_arguments (cw,
      GUM_ADDRESS (debug_hello), 1,
      GUM_ARG_ADDRESS, GUM_ADDRESS (pointer));
  gum_arm_writer_put_pop_all_r_registers (cw, 1);
}

static void
put_debug_print_reg (GumArmWriter * cw,
                     arm_reg reg)
{
  gum_arm_writer_put_push_all_r_registers (cw, 1);
  gum_arm_writer_put_call_address_with_arguments (cw,
      GUM_ADDRESS (debug_hello), 1,
      GUM_ARG_REGISTER, reg);
  gum_arm_writer_put_pop_all_r_registers (cw, 1);
}

static void
test_arm_stalker_fixture_setup (TestArmStalkerFixture * fixture,
                                  gconstpointer data)
{
  fixture->stalker = gum_stalker_new ();
  fixture->transformer = NULL;
  fixture->sink = GUM_FAKE_EVENT_SINK (gum_fake_event_sink_new ());
  fixture->sink->mask = 0;

  silence_warnings ();
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

static GCallback
test_arm_stalker_fixture_dup_code (TestArmStalkerFixture * fixture,
                                     const guint32 * tpl_code,
                                     guint tpl_size)
{
  GumAddressSpec spec;

  spec.near_address = gum_strip_code_pointer (gum_stalker_follow_me);
  spec.max_distance = G_MAXINT32 / 2;

  if (fixture->code != NULL)
    gum_free_pages (fixture->code);
  fixture->code = gum_alloc_n_pages_near (
      (tpl_size / gum_query_page_size ()) + 1, GUM_PAGE_RW, &spec);
  memcpy (fixture->code, tpl_code, tpl_size);
  gum_memory_mark_code (fixture->code, tpl_size);

  return GUM_POINTER_TO_FUNCPTR (GCallback,
      gum_sign_code_pointer (fixture->code));
}
/* Total number of instructions in the invoker built by test_arm_stalker_fixture_follow_and_invoke */
#define INVOKER_INSN_COUNT 8

/* Total number of call instructions in the invoker built by test_arm_stalker_fixture_follow_and_invoke */
#define INVOKER_CALL_INSN_COUNT 2

/* Total number of blocks in the invoker built by test_arm_stalker_fixture_follow_and_invoke */
#define INVOKER_BLOCK_COUNT 0

/* Offset of the first instruction within the invoker which
should be stalked in bytes */
#define INVOKER_IMPL_OFFSET 20

/* custom invoke code as we want to stalk a deterministic code sequence */
static gint
test_arm_stalker_fixture_follow_and_invoke (TestArmStalkerFixture * fixture,
                                              StalkerTestFunc func,
                                              gint arg)
{
  GumAddressSpec spec;
  GumArmWriter cw;
  gint ret;
  GCallback invoke_func;

  spec.near_address = gum_strip_code_pointer (gum_stalker_follow_me);
  spec.max_distance = G_MAXINT32 / 2;
  fixture->invoker = gum_alloc_n_pages_near (1, GUM_PAGE_RW, &spec);

  gum_arm_writer_init (&cw, fixture->invoker);

  gum_arm_writer_put_push_registers (&cw, 1, ARM_REG_LR);

  gum_arm_writer_put_call_address_with_arguments (&cw,
      GUM_ADDRESS (gum_stalker_follow_me), 3,
      GUM_ARG_ADDRESS, GUM_ADDRESS (fixture->stalker),
      GUM_ARG_ADDRESS, GUM_ADDRESS (fixture->transformer),
      GUM_ARG_ADDRESS, GUM_ADDRESS (fixture->sink));

  /* call function -int func(int x)- and save address before and after call */
  gum_arm_writer_put_ldr_reg_address (&cw, ARM_REG_R0, GUM_ADDRESS (arg));
  fixture->last_invoke_calladdr = gum_arm_writer_cur (&cw);
  gum_arm_writer_put_call_address_with_arguments (&cw, GUM_ADDRESS (func), 0);
  fixture->last_invoke_retaddr = gum_arm_writer_cur (&cw);
  gum_arm_writer_put_ldr_reg_address (&cw, ARM_REG_R1, GUM_ADDRESS (&ret));
  gum_arm_writer_put_str_reg_reg_offset (&cw, ARM_REG_R0, ARM_REG_R1, 0);

  gum_arm_writer_put_call_address_with_arguments (&cw,
      GUM_ADDRESS (gum_stalker_unfollow_me), 1,
      GUM_ARG_ADDRESS, GUM_ADDRESS (fixture->stalker));

  gum_arm_writer_put_pop_registers (&cw, 1, ARM_REG_LR);
  gum_arm_writer_put_ret (&cw);

  gum_arm_writer_flush (&cw);
  gum_memory_mark_code (cw.base, gum_arm_writer_offset (&cw));
  gum_arm_writer_clear (&cw);

  invoke_func =
    GUM_POINTER_TO_FUNCPTR (GCallback,
                            gum_sign_code_pointer (fixture->invoker));
  invoke_func ();

  gum_free_pages (fixture->invoker);

  return ret;
}

static void
silence_warnings (void)
{
  (void) put_debug_print_pointer;
  (void) put_debug_print_reg;
  (void) test_arm_stalker_fixture_dup_code;
  (void) test_arm_stalker_fixture_follow_and_invoke;
}

typedef struct _UnfollowTransformContext UnfollowTransformContext;

struct _UnfollowTransformContext
{
  GumStalker * stalker;
  guint num_blocks_transformed;
  guint target_block;
  gint max_instructions;
};
