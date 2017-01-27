/*
 * Copyright (C) 2009-2014 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
 * Copyright (C) 2010-2013 Karl Trygve Kalleberg <karltk@boblycat.org>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "arm64stalker-fixture.c"

TEST_LIST_BEGIN (arm64stalker)
/*STALKER_ARM64_TESTENTRY (no_events)
STALKER_ARM64_TESTENTRY (call)
STALKER_ARM64_TESTENTRY (ret)
STALKER_ARM64_TESTENTRY (exec)*/
STALKER_ARM64_TESTENTRY (no_register_clobber)
TEST_LIST_END()


static const guint32 flat_code[] = {
        0xCB000000, /* sub w0,w0,w0 */
        0x91000400, /* inc w0       */
        0x91000400, /* inc w0       */
        0xd65f03c0  /* ret          */
};

static StalkerTestFunc invoke_flat(TestArm64StalkerFixture *fixture,
                                   GumEventType mask) {
    StalkerTestFunc func;
    gint ret;

    func = GUM_POINTER_TO_FUNCPTR(StalkerTestFunc,
                                  test_arm64_stalker_fixture_dup_code(fixture, flat_code, sizeof(flat_code)));

    fixture->sink->mask = mask;
    ret = test_arm64_stalker_fixture_follow_and_invoke(fixture, func, -1);
    g_assert_cmpint(ret, == , 2);

    return func;
}

STALKER_ARM64_TESTCASE (no_events) {
    invoke_flat(fixture, GUM_NOTHING);
    g_assert_cmpuint(fixture->sink->events->len, == , 0);
}

STALKER_ARM64_TESTCASE (call) {
    StalkerTestFunc func;
    GumCallEvent *ev;

    func = invoke_flat(fixture, GUM_CALL);

    g_assert_cmpuint(fixture->sink->events->len, == , 2);
    g_assert_cmpint(g_array_index(fixture->sink->events, GumEvent, 0).type, == , GUM_CALL);
    ev = &g_array_index(fixture->sink->events, GumEvent, 0).call;
    GUM_ASSERT_CMPADDR(ev->location, == , fixture->last_invoke_calladdr);
    GUM_ASSERT_CMPADDR(ev->target, == , func);
}

STALKER_ARM64_TESTCASE (ret) {
    StalkerTestFunc func;
    GumRetEvent *ev;

    func = invoke_flat(fixture, GUM_RET);

    g_assert_cmpuint(fixture->sink->events->len, == , 1);
    g_assert_cmpint(g_array_index(fixture->sink->events, GumEvent, 0).type, == , GUM_RET);

    ev = &g_array_index(fixture->sink->events, GumEvent, 0).ret;

    GUM_ASSERT_CMPADDR(ev->location, == , ((guint8 *) GSIZE_TO_POINTER(func)) + 3 * 4);
    GUM_ASSERT_CMPADDR(ev->target, == , fixture->last_invoke_retaddr);
}

STALKER_ARM64_TESTCASE (exec) {
    StalkerTestFunc func;
    GumRetEvent *ev;

    func = invoke_flat(fixture, GUM_EXEC);

    g_assert_cmpuint(fixture->sink->events->len, == , INVOKER_INSN_COUNT + 4);
    g_assert_cmpint(g_array_index(fixture->sink->events, GumEvent, INVOKER_IMPL_OFFSET).type, == , GUM_EXEC);
    ev = &g_array_index(fixture->sink->events, GumEvent, INVOKER_IMPL_OFFSET).ret;
    GUM_ASSERT_CMPADDR(ev->location, == , func);
}

typedef void (*ClobberFunc)(GumCpuContext *ctx);

STALKER_ARM64_TESTCASE (no_register_clobber)
{

    guint8 * code;
    GumArm64Writer cw;
    const gchar * my_func_lbl = "my_func";
    const gchar * my_beach_lbl = "my_beach";
    const gchar * my_ken_lbl = "my_ken";
    ClobberFunc func;
    GumCpuContext ctx;

    code = gum_alloc_n_pages (1, GUM_PAGE_RWX);
    gum_arm64_writer_init (&cw, code);

    // +++
    gum_arm64_writer_put_push_all_registers(&cw); // 16 push of 16

    // +++
    gum_arm64_writer_put_push_all_registers(&cw);
    gum_arm64_writer_put_call_address_with_arguments(&cw,
                                                     gum_stalker_follow_me, 2,
                                                     GUM_ARG_ADDRESS, fixture->stalker,
                                                     GUM_ARG_ADDRESS, fixture->sink);

    // ---
    gum_arm64_writer_put_pop_all_registers(&cw);

    for (int i=ARM64_REG_X0; i<=ARM64_REG_X28;i++){
        gum_arm64_writer_put_ldr_reg_u64(&cw, i, i);
    }

    //gum_arm64_writer_put_b_label(&cw, my_func_lbl);
    //gum_arm64_writer_put_label (&cw, my_ken_lbl);

    // +++
    gum_arm64_writer_put_push_all_registers(&cw);
    gum_arm64_writer_put_call_address_with_arguments(&cw,
                                                     gum_stalker_unfollow_me, 1,
                                                     GUM_ARG_ADDRESS, fixture->stalker);
    // ---
    gum_arm64_writer_put_pop_all_registers(&cw);

    int offset = (4* sizeof(gpointer))+(32 * sizeof (gpointer));

    for (int i=ARM64_REG_X0; i<=ARM64_REG_X28;i++){
        gum_arm64_writer_put_str_reg_reg_offset(&cw, i, ARM64_REG_SP,
                                                offset+G_STRUCT_OFFSET (GumCpuContext, x[i-ARM64_REG_X0]));
    }

    // ---
    gum_arm64_writer_put_pop_all_registers(&cw);

    gum_arm64_writer_put_ret (&cw);

    /*
    gum_arm64_writer_put_label (&cw, my_func_lbl);
    gum_arm64_writer_put_nop (&cw);
    gum_arm64_writer_put_b_label (&cw, my_beach_lbl);
    gum_arm64_writer_put_brk_imm (&cw, 0x14);

    gum_arm64_writer_put_label (&cw, my_beach_lbl);
    gum_arm64_writer_put_nop (&cw);
    gum_arm64_writer_put_nop (&cw);
    gum_arm64_writer_put_nop (&cw);
    gum_arm64_writer_put_b_label (&cw, my_ken_lbl);*/


    gum_arm64_writer_free (&cw);

    fixture->sink->mask = GUM_CALL | GUM_RET | GUM_EXEC;
    func = GUM_POINTER_TO_FUNCPTR (ClobberFunc, code);
    func (&ctx);

    for (int i=ARM64_REG_X0; i<=ARM64_REG_X28;i++){
        g_assert_cmphex (ctx.x[i-ARM64_REG_X0], ==, i);
    }

    gum_free_pages (code);

}
