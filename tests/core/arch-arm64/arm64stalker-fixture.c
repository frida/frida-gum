/*
 * Copyright (C) 2009-2013 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
 * Copyright (C) 2010-2013 Karl Trygve Kalleberg <karltk@boblycat.org>
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
#ifdef G_OS_WIN32
#define VC_EXTRALEAN
#include <windows.h>
#include <tchar.h>
#endif

#define STALKER_ARM64_TESTCASE(NAME) \
    void test_arm64_stalker_ ## NAME ( \
        TestArm64StalkerFixture * fixture, gconstpointer data)
#define STALKER_ARM64_TESTENTRY(NAME) \
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
  fixture->code = (guint32 *) gum_alloc_n_pages_near (
      (tpl_size / gum_query_page_size ()) + 1, GUM_PAGE_RWX, &spec);
  memcpy (fixture->code, tpl_code, tpl_size);
  return fixture->code;
}

#if GLIB_SIZEOF_VOID_P == 4
# define INVOKER_INSN_COUNT 11
# define INVOKER_IMPL_OFFSET 5
#elif GLIB_SIZEOF_VOID_P == 8
# if GUM_NATIVE_ABI_IS_WINDOWS
#  define INVOKER_INSN_COUNT 12
#  define INVOKER_IMPL_OFFSET 5
# else
#  define INVOKER_INSN_COUNT 10
#  define INVOKER_IMPL_OFFSET 4
# endif
#endif

/* custom invoke code as we want to stalk a deterministic code sequence */
static gint
test_arm64_stalker_fixture_follow_and_invoke (TestArm64StalkerFixture * fixture,
                                        StalkerTestFunc func,
                                        gint arg)
{
    GumAddressSpec spec;
    gint ret;
    guint8 * code;
    GumArm64Writer cw;
    GCallback invoke_func;

    spec.near_address = gum_stalker_follow_me;
    spec.max_distance = G_MAXINT32 / 2;
    code = (guint8 *) gum_alloc_n_pages_near (1, GUM_PAGE_RWX, &spec);

    // init writer
    gum_arm64_writer_init (&cw, code);

    // call gum_stalker_follow_me
    gum_arm64_writer_put_instruction(&cw, 0xa9bf7bfd);  //gum_x86_writer_put_pushax (&cw);
    gum_arm64_writer_put_instruction(&cw, 0x910003fd); //gum_x86_writer_put_sub_reg_imm (&cw, GUM_REG_XSP, align_correction_follow);
    gum_arm64_writer_put_call_address_with_arguments(&cw,
                                                     gum_stalker_follow_me, 2,
                                                     GUM_ARG_ADDRESS, fixture->stalker,
                                                     GUM_ARG_ADDRESS, fixture->sink);
    /*gum_x86_writer_put_call_with_arguments (&cw,
      gum_stalker_follow_me, 2,
      GUM_ARG_POINTER, fixture->stalker,
      GUM_ARG_POINTER, fixture->sink);*/
    //gum_x86_writer_put_add_reg_imm (&cw, GUM_REG_XSP, align_correction_follow);

    // call function -int func(int x)- and save address before and after call
    //gum_x86_writer_put_sub_reg_imm (&cw, GUM_REG_XSP, align_correction_call);
    gum_arm64_writer_put_ldr_reg_address(&cw, ARM64_REG_X0, GUM_ADDRESS (arg));//gum_x86_writer_put_mov_reg_address (&cw, GUM_REG_XCX, GUM_ADDRESS (arg));

    fixture->last_invoke_calladdr = (guint8 *) gum_arm64_writer_cur(&cw);//gum_x86_writer_cur (&cw);

    //gum_arm64_writer_put_bl_imm(&cw, func);//gum_x86_writer_put_call (&cw, func);
    gum_arm64_writer_put_call_address_with_arguments(&cw, func, 0);

    fixture->last_invoke_retaddr = (guint8 *) gum_arm64_writer_cur(&cw);//gum_x86_writer_cur (&cw);
    //gum_arm64_writer_put_str_reg_reg_offset(&cw, ARM64_REG_X0, ARM64_REG_SP, GUM_ADDRESS (&ret));
    gum_arm64_writer_put_ldr_reg_address(&cw, ARM64_REG_X1, GUM_ADDRESS (&ret));//gum_x86_writer_put_mov_reg_address (&cw, GUM_REG_XCX, GUM_ADDRESS (&ret));
    gum_arm64_writer_put_str_reg_reg_offset(&cw, ARM64_REG_X0, ARM64_REG_X1, 0);
    //gum_x86_writer_put_mov_reg_ptr_reg (&cw, GUM_REG_XCX, GUM_REG_EAX);
    //gum_x86_writer_put_add_reg_imm (&cw, GUM_REG_XSP, align_correction_call);

    // call gum_stalker_unfollow_me
    //gum_x86_writer_put_sub_reg_imm (&cw, GUM_REG_XSP, align_correction_unfollow);
    gum_arm64_writer_put_call_address_with_arguments(&cw,
                                                     gum_stalker_unfollow_me, 1,
                                                     GUM_ARG_ADDRESS, fixture->stalker);
    /*gum_x86_writer_put_call_with_arguments (&cw,
      gum_stalker_unfollow_me, 1,
      GUM_ARG_POINTER, fixture->stalker);*/
    //gum_x86_writer_put_add_reg_imm (&cw, GUM_REG_XSP, align_correction_unfollow);

    gum_arm64_writer_put_instruction(&cw, 0xa8c17bfd);//gum_x86_writer_put_popax (&cw);

    gum_arm64_writer_put_instruction(&cw, 0xd65f03c0);//gum_x86_writer_put_ret (&cw);

    gum_arm64_writer_free (&cw);

    invoke_func = GUM_POINTER_TO_FUNCPTR (GCallback, code);
    invoke_func ();

    gum_free_pages (code);

  return ret;
}

static void
silence_warnings (void)
{
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