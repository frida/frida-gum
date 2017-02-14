/*
 * Copyright (C) 2009-2013 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
 * Copyright (C) 2017 Antonio Ken Iannillo <ak.iannillo@gmail.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumstalker.h"

#include "fakeeventsink.h"
#include "gumarm64writer.h"
#include "gummemory.h"
#include "testutil.h"

#include <stdlib.h>
#include <string.h>

#define STALKER_TESTCASE(NAME) \
    void test_arm64_stalker_ ## NAME ( \
    TestArm64StalkerFixture * fixture, gconstpointer data)
#define STALKER_TESTENTRY(NAME) \
    TEST_ENTRY_WITH_FIXTURE ("Core/Arm64Stalker", test_arm64_stalker, NAME, \
    TestArm64StalkerFixture)

#define NTH_EVENT_AS_CALL(N) \
    (gum_fake_event_sink_get_nth_event_as_call (fixture->sink, N))
#define NTH_EVENT_AS_RET(N) \
    (gum_fake_event_sink_get_nth_event_as_ret (fixture->sink, N))
#define NTH_EXEC_EVENT_LOCATION(N) \
    (gum_fake_event_sink_get_nth_event_as_exec (fixture->sink, N)->location)

typedef struct _TestArm64StalkerFixture
{
  GumStalker * stalker;
  GumFakeEventSink * sink;

  guint8 * code;
  guint8 * last_invoke_calladdr;
  guint8 * last_invoke_retaddr;
} TestArm64StalkerFixture;

typedef gint (* StalkerTestFunc) (gint arg);

static void silence_warnings (void);

static void
debug_hello (gpointer pointer)
{
  g_print ("* pointer: %p *\n", pointer);
}

static void
put_debug_print_pointer (GumArm64Writer * cw,
                         gpointer pointer)
{
  gum_arm64_writer_put_push_all_x_registers (cw);
  gum_arm64_writer_put_call_address_with_arguments (cw,
      GUM_ADDRESS (debug_hello), 1,
      GUM_ARG_ADDRESS, GUM_ADDRESS (pointer));
  gum_arm64_writer_put_pop_all_x_registers (cw);
}

static void
put_debug_print_reg (GumArm64Writer * cw,
                     arm64_reg reg)
{
  gum_arm64_writer_put_push_all_x_registers (cw);
  gum_arm64_writer_put_call_address_with_arguments (cw,
      GUM_ADDRESS (debug_hello), 1,
      GUM_ARG_REGISTER, reg);
  gum_arm64_writer_put_pop_all_x_registers (cw);
}

static void
test_arm64_stalker_fixture_setup (TestArm64StalkerFixture * fixture,
                                  gconstpointer data)
{
  fixture->stalker = gum_stalker_new ();
  fixture->sink = GUM_FAKE_EVENT_SINK (gum_fake_event_sink_new ());

  silence_warnings ();
}

static void
test_arm64_stalker_fixture_teardown (TestArm64StalkerFixture * fixture,
                                     gconstpointer data)
{
  g_object_unref (fixture->sink);
  g_object_unref (fixture->stalker);

  if (fixture->code != NULL)
    gum_free_pages (fixture->code);
}

static guint8 *
test_arm64_stalker_fixture_dup_code (TestArm64StalkerFixture * fixture,
                                     const guint32 * tpl_code,
                                     guint tpl_size)
{
  GumAddressSpec spec;

  spec.near_address = gum_stalker_follow_me;
  spec.max_distance = G_MAXINT32 / 2;

  if (fixture->code != NULL)
    gum_free_pages (fixture->code);
  fixture->code = gum_alloc_n_pages_near (
      (tpl_size / gum_query_page_size ()) + 1, GUM_PAGE_RWX, &spec);
  memcpy (fixture->code, tpl_code, tpl_size);

  return fixture->code;
}

#define INVOKER_INSN_COUNT 6
#define INVOKER_IMPL_OFFSET 2

/* custom invoke code as we want to stalk a deterministic code sequence */
static gint
test_arm64_stalker_fixture_follow_and_invoke (TestArm64StalkerFixture * fixture,
                                              StalkerTestFunc func,
                                              gint arg)
{
  GumAddressSpec spec;
  guint8 * code;
  GumArm64Writer cw;
  gint ret;
  GCallback invoke_func;

  spec.near_address = gum_stalker_follow_me;
  spec.max_distance = G_MAXINT32 / 2;
  code = gum_alloc_n_pages_near (1, GUM_PAGE_RWX, &spec);

  gum_arm64_writer_init (&cw, code);

  gum_arm64_writer_put_push_reg_reg (&cw, ARM64_REG_X29, ARM64_REG_X30);
  gum_arm64_writer_put_mov_reg_reg (&cw, ARM64_REG_X29, ARM64_REG_SP);

  gum_arm64_writer_put_call_address_with_arguments (&cw,
      GUM_ADDRESS (gum_stalker_follow_me), 2,
      GUM_ARG_ADDRESS, fixture->stalker,
      GUM_ARG_ADDRESS, fixture->sink);

  /* call function -int func(int x)- and save address before and after call */
  gum_arm64_writer_put_ldr_reg_address (&cw, ARM64_REG_X0, GUM_ADDRESS (arg));
  fixture->last_invoke_calladdr = gum_arm64_writer_cur (&cw);
  gum_arm64_writer_put_call_address_with_arguments (&cw, GUM_ADDRESS (func), 0);
  fixture->last_invoke_retaddr = gum_arm64_writer_cur (&cw);
  gum_arm64_writer_put_ldr_reg_address (&cw, ARM64_REG_X1, GUM_ADDRESS (&ret));
  gum_arm64_writer_put_str_reg_reg_offset (&cw, ARM64_REG_X0, ARM64_REG_X1, 0);

  gum_arm64_writer_put_call_address_with_arguments (&cw,
      GUM_ADDRESS (gum_stalker_unfollow_me), 1,
      GUM_ARG_ADDRESS, fixture->stalker);

  gum_arm64_writer_put_pop_reg_reg (&cw, ARM64_REG_X29, ARM64_REG_X30);
  gum_arm64_writer_put_ret (&cw);

  gum_arm64_writer_free (&cw);

  invoke_func = GUM_POINTER_TO_FUNCPTR (GCallback, code);
  invoke_func ();

  gum_free_pages (code);

  return ret;
}

static void
silence_warnings (void)
{
  (void) put_debug_print_pointer;
  (void) put_debug_print_reg;
  (void) test_arm64_stalker_fixture_dup_code;
  (void) test_arm64_stalker_fixture_follow_and_invoke;
}

typedef struct _StalkerVictimContext StalkerVictimContext;
typedef guint StalkerVictimState;

struct _StalkerVictimContext
{
  volatile StalkerVictimState state;
  GumThreadId thread_id;
  GMutex mutex;
  GCond cond;
};

enum _StalkerVictimState
{
  STALKER_VICTIM_CREATED = 1,
  STALKER_VICTIM_READY_FOR_FOLLOW,
  STALKER_VICTIM_IS_FOLLOWED,
  STALKER_VICTIM_READY_FOR_UNFOLLOW,
  STALKER_VICTIM_IS_UNFOLLOWED,
  STALKER_VICTIM_READY_FOR_SHUTDOWN,
  STALKER_VICTIM_IS_SHUTDOWN
};
