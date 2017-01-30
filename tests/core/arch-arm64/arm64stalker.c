/*
 * Copyright (C) 2009-2014 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
 * Copyright (C) 2010-2013 Karl Trygve Kalleberg <karltk@boblycat.org>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "arm64stalker-fixture.c"

TEST_LIST_BEGIN (arm64stalker)

//EVENTS
STALKER_ARM64_TESTENTRY (no_events)
STALKER_ARM64_TESTENTRY (call)
STALKER_ARM64_TESTENTRY (ret)
STALKER_ARM64_TESTENTRY (exec)

//BRANCH
/*
STALKER_ARM64_TESTENTRY(unconditional_branch)
STALKER_ARM64_TESTENTRY(unconditional_branch_reg)
STALKER_ARM64_TESTENTRY(conditional_branch)
STALKER_ARM64_TESTENTRY(compare_and_branch)
STALKER_ARM64_TESTENTRY(test_bit_and_branch)*/

//FOLLOWS
/*
STALKER_ARM64_TESTENTRY(follow_std_call)
STALKER_ARM64_TESTENTRY(follow_return)
STALKER_ARM64_TESTENTRY(follow_syscall)
 */


//STALKER_ARM64_TESTENTRY(follow_thread)

STALKER_ARM64_TESTENTRY (heap_api)

//STALKER_ARM64_TESTENTRY (no_register_clobber)
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

STALKER_ARM64_TESTCASE (unconditional_branch) {

    guint8 *code;
    GumArm64Writer cw;
    gpointer address;
    const gchar *my_ken_lbl = "my_ken";
    StalkerTestFunc func;

    code = gum_alloc_n_pages(1, GUM_PAGE_RWX);
    gum_arm64_writer_init(&cw, code);

    // +++
    gum_arm64_writer_put_push_all_registers(&cw);
    gum_arm64_writer_put_call_address_with_arguments(&cw,
                                                     gum_stalker_follow_me, 2,
                                                     GUM_ARG_ADDRESS, fixture->stalker,
                                                     GUM_ARG_ADDRESS, fixture->sink);

    // ---
    gum_arm64_writer_put_pop_all_registers(&cw);

    gum_arm64_writer_put_nop(&cw);
    gum_arm64_writer_put_nop(&cw);
    gum_arm64_writer_put_b_label(&cw, my_ken_lbl);

    address = gum_arm64_writer_cur(&cw);
    gum_arm64_writer_put_add_reg_reg_imm(&cw, ARM64_REG_X0, ARM64_REG_X0, 10);

    // +++
    gum_arm64_writer_put_push_all_registers(&cw);
    gum_arm64_writer_put_call_address_with_arguments(&cw,
                                                     gum_stalker_unfollow_me, 1,
                                                     GUM_ARG_ADDRESS, fixture->stalker);
    // ---
    gum_arm64_writer_put_pop_all_registers(&cw);

    gum_arm64_writer_put_ret(&cw);

    gum_arm64_writer_put_label(&cw, my_ken_lbl);
    gum_arm64_writer_put_add_reg_reg_imm(&cw, ARM64_REG_X0, ARM64_REG_X0, 1);
    gum_arm64_writer_put_b_imm(&cw, address);

    gum_arm64_writer_free(&cw);

    fixture->sink->mask = GUM_CALL | GUM_RET | GUM_EXEC;
    func = GUM_POINTER_TO_FUNCPTR(StalkerTestFunc, code);
    int r = func(2);

    g_assert(13 == r);

    gum_free_pages(code);


}

STALKER_ARM64_TESTCASE (unconditional_branch_reg) {

    guint8 *code;
    GumArm64Writer cw;
    gpointer address;
    const gchar *my_ken_lbl = "my_ken";
    StalkerTestFunc func;

    code = gum_alloc_n_pages(1, GUM_PAGE_RWX);
    gum_arm64_writer_init(&cw, code);

    // +++
    gum_arm64_writer_put_push_all_registers(&cw);
    gum_arm64_writer_put_call_address_with_arguments(&cw,
                                                     gum_stalker_follow_me, 2,
                                                     GUM_ARG_ADDRESS, fixture->stalker,
                                                     GUM_ARG_ADDRESS, fixture->sink);

    // ---
    gum_arm64_writer_put_pop_all_registers(&cw);

    gum_arm64_writer_put_nop(&cw);
    gum_arm64_writer_put_nop(&cw);
    gum_arm64_writer_put_b_label(&cw, my_ken_lbl);

    address = gum_arm64_writer_cur(&cw);
    gum_arm64_writer_put_add_reg_reg_imm(&cw, ARM64_REG_X0, ARM64_REG_X0, 10);

    // +++
    gum_arm64_writer_put_push_all_registers(&cw);
    gum_arm64_writer_put_call_address_with_arguments(&cw,
                                                     gum_stalker_unfollow_me, 1,
                                                     GUM_ARG_ADDRESS, fixture->stalker);
    // ---
    gum_arm64_writer_put_pop_all_registers(&cw);

    gum_arm64_writer_put_ret(&cw);

    gum_arm64_writer_put_label(&cw, my_ken_lbl);
    gum_arm64_writer_put_add_reg_reg_imm(&cw, ARM64_REG_X0, ARM64_REG_X0, 1);
    gum_arm64_writer_put_ldr_reg_address(&cw, ARM64_REG_X15, address);
    gum_arm64_writer_put_br_reg(&cw, ARM64_REG_X15);

    gum_arm64_writer_free(&cw);

    fixture->sink->mask = GUM_CALL | GUM_RET | GUM_EXEC;
    func = GUM_POINTER_TO_FUNCPTR(StalkerTestFunc, code);
    int r = func(2);

    g_assert(13 == r);

    gum_free_pages(code);


}

STALKER_ARM64_TESTCASE (conditional_branch) {

    guint8 *code;
    GumArm64Writer cw;
    gpointer address;
    arm64_cc cc = ARM64_CC_EQ;
    const gchar *my_ken_lbl = "my_ken";
    StalkerTestFunc func;

    code = gum_alloc_n_pages(1, GUM_PAGE_RWX);
    gum_arm64_writer_init(&cw, code);

    gum_arm64_writer_put_push_all_registers(&cw);
    gum_arm64_writer_put_call_address_with_arguments(&cw,
                                                     gum_stalker_follow_me, 2,
                                                     GUM_ARG_ADDRESS, fixture->stalker,
                                                     GUM_ARG_ADDRESS, fixture->sink);
    gum_arm64_writer_put_pop_all_registers(&cw);

    gum_arm64_writer_put_nop(&cw);
    gum_arm64_writer_put_nop(&cw);
    //gum_arm64_writer_put_sub_reg_reg_imm(&cw, ARM64_REG_X0, ARM64_REG_X0, 2);
    gum_arm64_writer_put_instruction(&cw, 0xF1000800); //subs x0,x0,#2
    gum_arm64_writer_put_b_cond_label(&cw, cc, my_ken_lbl);

    address = gum_arm64_writer_cur(&cw);
    gum_arm64_writer_put_nop(&cw);

    // +++
    gum_arm64_writer_put_push_all_registers(&cw);
    gum_arm64_writer_put_call_address_with_arguments(&cw,
                                                     gum_stalker_unfollow_me, 1,
                                                     GUM_ARG_ADDRESS, fixture->stalker);
    // ---
    gum_arm64_writer_put_pop_all_registers(&cw);

    gum_arm64_writer_put_ret(&cw);

    gum_arm64_writer_put_label(&cw, my_ken_lbl);
    gum_arm64_writer_put_add_reg_reg_imm(&cw, ARM64_REG_X0, ARM64_REG_X0, 1);
    gum_arm64_writer_put_b_imm(&cw, address);

    gum_arm64_writer_free(&cw);

    fixture->sink->mask = GUM_CALL | GUM_RET | GUM_EXEC;
    func = GUM_POINTER_TO_FUNCPTR(StalkerTestFunc, code);
    int r = func(2);

    g_assert(r == 1);

    gum_free_pages(code);


}

STALKER_ARM64_TESTCASE (compare_and_branch) {

    guint8 *code;
    GumArm64Writer cw;
    const gchar *my_ken_lbl = "my_ken";
    const gchar *my_nken_lbl = "my_nken";
    StalkerTestFunc func;

    code = gum_alloc_n_pages(1, GUM_PAGE_RWX);
    gum_arm64_writer_init(&cw, code);

    gum_arm64_writer_put_push_all_registers(&cw);
    gum_arm64_writer_put_call_address_with_arguments(&cw,
                                                     gum_stalker_follow_me, 2,
                                                     GUM_ARG_ADDRESS, fixture->stalker,
                                                     GUM_ARG_ADDRESS, fixture->sink);
    gum_arm64_writer_put_pop_all_registers(&cw);

    gum_arm64_writer_put_nop(&cw);
    gum_arm64_writer_put_nop(&cw);
    gum_arm64_writer_put_sub_reg_reg_imm(&cw, ARM64_REG_X0, ARM64_REG_X0, 2);
    gum_arm64_writer_put_cbz_reg_label(&cw, ARM64_REG_X0, my_ken_lbl);

    gum_arm64_writer_put_label(&cw, my_nken_lbl);
    gum_arm64_writer_put_nop(&cw);

    // +++
    gum_arm64_writer_put_push_all_registers(&cw);
    gum_arm64_writer_put_call_address_with_arguments(&cw,
                                                     gum_stalker_unfollow_me, 1,
                                                     GUM_ARG_ADDRESS, fixture->stalker);
    // ---
    gum_arm64_writer_put_pop_all_registers(&cw);

    gum_arm64_writer_put_ret(&cw);

    gum_arm64_writer_put_label(&cw, my_ken_lbl);
    gum_arm64_writer_put_add_reg_reg_imm(&cw, ARM64_REG_X0, ARM64_REG_X0, 1);
    gum_arm64_writer_put_cbnz_reg_label(&cw, ARM64_REG_X0, my_nken_lbl);

    gum_arm64_writer_free(&cw);

    fixture->sink->mask = GUM_CALL | GUM_RET | GUM_EXEC;
    func = GUM_POINTER_TO_FUNCPTR(StalkerTestFunc, code);
    int r = func(2);

    g_assert(r == 1);

    gum_free_pages(code);


}

STALKER_ARM64_TESTCASE (test_bit_and_branch) {

    guint8 *code;
    GumArm64Writer cw;
    const gchar *my_ken_lbl = "my_ken";
    const gchar *my_nken_lbl = "my_nken";
    StalkerTestFunc func;

    code = gum_alloc_n_pages(1, GUM_PAGE_RWX);
    gum_arm64_writer_init(&cw, code);

    gum_arm64_writer_put_push_all_registers(&cw);
    gum_arm64_writer_put_call_address_with_arguments(&cw,
                                                     gum_stalker_follow_me, 2,
                                                     GUM_ARG_ADDRESS, fixture->stalker,
                                                     GUM_ARG_ADDRESS, fixture->sink);
    gum_arm64_writer_put_pop_all_registers(&cw);

    gum_arm64_writer_put_nop(&cw);
    gum_arm64_writer_put_nop(&cw);
    gum_arm64_writer_put_sub_reg_reg_imm(&cw, ARM64_REG_X0, ARM64_REG_X0, 2);
    gum_arm64_writer_put_tbz_reg_imm_label(&cw, ARM64_REG_W0, 0, my_ken_lbl);

    gum_arm64_writer_put_label(&cw, my_nken_lbl);
    gum_arm64_writer_put_nop(&cw);

    // +++
    gum_arm64_writer_put_push_all_registers(&cw);
    gum_arm64_writer_put_call_address_with_arguments(&cw,
                                                     gum_stalker_unfollow_me, 1,
                                                     GUM_ARG_ADDRESS, fixture->stalker);
    // ---
    gum_arm64_writer_put_pop_all_registers(&cw);

    gum_arm64_writer_put_ret(&cw);

    gum_arm64_writer_put_label(&cw, my_ken_lbl);
    gum_arm64_writer_put_add_reg_reg_imm(&cw, ARM64_REG_X0, ARM64_REG_X0, 1);
    gum_arm64_writer_put_tbnz_reg_imm_label(&cw, ARM64_REG_W0, 0, my_nken_lbl);

    gum_arm64_writer_free(&cw);

    fixture->sink->mask = GUM_CALL | GUM_RET | GUM_EXEC;
    func = GUM_POINTER_TO_FUNCPTR(StalkerTestFunc, code);
    int r = func(2);

    g_assert(r == 1);

    gum_free_pages(code);


}

STALKER_ARM64_TESTCASE (follow_std_call) {

    guint8 *code;
    GumArm64Writer cw;
    gpointer address;
    const gchar *my_ken_lbl = "my_ken";
    StalkerTestFunc func;

    code = gum_alloc_n_pages(1, GUM_PAGE_RWX);
    gum_arm64_writer_init(&cw, code);

    gum_arm64_writer_put_push_reg_reg(&cw, ARM64_REG_X30, ARM64_REG_X29);
    gum_arm64_writer_put_mov_reg_reg(&cw, ARM64_REG_X29, ARM64_REG_SP);

    gum_arm64_writer_put_b_label(&cw, my_ken_lbl);

    address = gum_arm64_writer_cur(&cw);
    gum_arm64_writer_put_add_reg_reg_imm(&cw, ARM64_REG_X0, ARM64_REG_X0, 1);
    gum_arm64_writer_put_ret(&cw);

    gum_arm64_writer_put_label(&cw, my_ken_lbl);
    gum_arm64_writer_put_push_all_registers(&cw);
    gum_arm64_writer_put_call_address_with_arguments(&cw,
                                                     gum_stalker_follow_me, 2,
                                                     GUM_ARG_ADDRESS, fixture->stalker,
                                                     GUM_ARG_ADDRESS, fixture->sink);
    gum_arm64_writer_put_pop_all_registers(&cw);
    gum_arm64_writer_put_add_reg_reg_imm(&cw, ARM64_REG_X0, ARM64_REG_X0, 1);
    gum_arm64_writer_put_bl_imm(&cw, address);

    gum_arm64_writer_put_push_all_registers(&cw);
    gum_arm64_writer_put_call_address_with_arguments(&cw,
                                                     gum_stalker_unfollow_me, 1,
                                                     GUM_ARG_ADDRESS, fixture->stalker);
    gum_arm64_writer_put_pop_all_registers(&cw);

    gum_arm64_writer_put_pop_reg_reg(&cw, ARM64_REG_X30, ARM64_REG_X29);
    gum_arm64_writer_put_ret(&cw);

    gum_arm64_writer_free(&cw);

    fixture->sink->mask = GUM_CALL | GUM_RET | GUM_EXEC;
    func = GUM_POINTER_TO_FUNCPTR(StalkerTestFunc, code);
    int r = func(2);

    g_assert(r == 4);

    gum_free_pages(code);


}

STALKER_ARM64_TESTCASE (follow_return) {

    guint8 *code;
    GumArm64Writer cw;
    gpointer address;
    const gchar *my_ken_lbl = "my_ken";
    StalkerTestFunc func;

    code = gum_alloc_n_pages(1, GUM_PAGE_RWX);
    gum_arm64_writer_init(&cw, code);

    gum_arm64_writer_put_push_reg_reg(&cw, ARM64_REG_X30, ARM64_REG_X29);
    gum_arm64_writer_put_mov_reg_reg(&cw, ARM64_REG_X29, ARM64_REG_SP);

    gum_arm64_writer_put_b_label(&cw, my_ken_lbl);

    address = gum_arm64_writer_cur(&cw);
    gum_arm64_writer_put_push_all_registers(&cw);
    gum_arm64_writer_put_call_address_with_arguments(&cw,
                                                     gum_stalker_follow_me, 2,
                                                     GUM_ARG_ADDRESS, fixture->stalker,
                                                     GUM_ARG_ADDRESS, fixture->sink);
    gum_arm64_writer_put_pop_all_registers(&cw);
    gum_arm64_writer_put_ret(&cw);

    gum_arm64_writer_put_label(&cw, my_ken_lbl);
    gum_arm64_writer_put_nop(&cw);
    gum_arm64_writer_put_add_reg_reg_imm(&cw, ARM64_REG_X0, ARM64_REG_X0, 1);
    gum_arm64_writer_put_bl_imm(&cw, address);
    gum_arm64_writer_put_add_reg_reg_imm(&cw, ARM64_REG_X0, ARM64_REG_X0, 1);

    // +++
    gum_arm64_writer_put_push_all_registers(&cw);
    gum_arm64_writer_put_call_address_with_arguments(&cw,
                                                     gum_stalker_unfollow_me, 1,
                                                     GUM_ARG_ADDRESS, fixture->stalker);
    // ---
    gum_arm64_writer_put_pop_all_registers(&cw);

    gum_arm64_writer_put_pop_reg_reg(&cw, ARM64_REG_X30, ARM64_REG_X29);
    gum_arm64_writer_put_ret(&cw);

    gum_arm64_writer_free(&cw);

    fixture->sink->mask = GUM_CALL | GUM_RET | GUM_EXEC;
    func = GUM_POINTER_TO_FUNCPTR(StalkerTestFunc, code);
    int r = func(2);

    g_assert(r == 4);

    gum_free_pages(code);


}

STALKER_ARM64_TESTCASE (follow_syscall) {

    fixture->sink->mask = (GumEventType)(GUM_EXEC | GUM_CALL | GUM_RET);

    gum_stalker_follow_me(fixture->stalker, GUM_EVENT_SINK(fixture->sink));
    g_usleep(1);
    gum_stalker_unfollow_me(fixture->stalker);

    g_assert_cmpuint(fixture->sink->events->len, > , 0);

}

static gpointer
stalker_victim(gpointer data) {
    StalkerVictimContext *ctx = (StalkerVictimContext *) data;

    g_mutex_lock(&ctx->mutex);

    /* 2: Signal readyness, giving our thread id */
    g_print("2:Signal readyness, giving our thread id\n");
    ctx->state = STALKER_VICTIM_READY_FOR_FOLLOW;
    ctx->thread_id = gum_process_get_current_thread_id();
    g_cond_signal(&ctx->cond);

    /* 3: Wait for master to tell us we're being followed */
    g_print("3:Wait for master to tell us we're being followed\n");
    while (ctx->state != STALKER_VICTIM_IS_FOLLOWED)
        g_cond_wait(&ctx->cond, &ctx->mutex);

    /* 6: Signal that we're ready to be unfollowed */
    g_print("6:Signal that we're ready to be unfollowed\n");
    ctx->state = STALKER_VICTIM_READY_FOR_UNFOLLOW;
    g_cond_signal(&ctx->cond);

    /* 7: Wait for master to tell us we're no longer followed */
    g_print("7:Wait for master to tell us we're no longer followed\n");
    while (ctx->state != STALKER_VICTIM_IS_UNFOLLOWED)
        g_cond_wait(&ctx->cond, &ctx->mutex);

    /* 10: Signal that we're ready for a reset */
    g_print("10:Signal that we're ready for a reset\n");
    ctx->state = STALKER_VICTIM_READY_FOR_SHUTDOWN;
    g_cond_signal(&ctx->cond);

    /* 11: Wait for master to tell us we can call it a day */
    g_print("11:Wait for master to tell us we can call it a day\n");
    while (ctx->state != STALKER_VICTIM_IS_SHUTDOWN)
        g_cond_wait(&ctx->cond, &ctx->mutex);

    g_mutex_unlock(&ctx->mutex);

    return NULL;
}

STALKER_ARM64_TESTCASE (follow_thread) {
    StalkerVictimContext ctx;
    GumThreadId thread_id;
    GThread *thread;

    ctx.state = STALKER_VICTIM_CREATED;
    g_mutex_init(&ctx.mutex);
    g_cond_init(&ctx.cond);

    thread = g_thread_new("stalker-test-victim", stalker_victim, &ctx);

    /* 1: Wait for victim to tell us it's ready, giving its thread id */
    g_print("1:Wait for victim to tell us it's ready, giving its thread id\n");
    g_mutex_lock(&ctx.mutex);
    while (ctx.state != STALKER_VICTIM_READY_FOR_FOLLOW)
        g_cond_wait(&ctx.cond, &ctx.mutex);
    thread_id = ctx.thread_id;
    g_mutex_unlock(&ctx.mutex);

    /* 4: Follow and notify victim about it */
    g_print("4:Follow and notify victim about it\n");
    fixture->sink->mask = (GumEventType)(GUM_EXEC | GUM_CALL | GUM_RET);
    gum_stalker_follow(fixture->stalker, thread_id,
                       GUM_EVENT_SINK(fixture->sink));
    g_mutex_lock(&ctx.mutex);
    ctx.state = STALKER_VICTIM_IS_FOLLOWED;
    g_cond_signal(&ctx.cond);
    g_mutex_unlock(&ctx.mutex);

    /* 5: Wait for victim to tell us to unfollow */
    g_print("5:Wait for victim to tell us to unfollow\n");
    g_mutex_lock(&ctx.mutex);
    while (ctx.state != STALKER_VICTIM_READY_FOR_UNFOLLOW)
        g_cond_wait(&ctx.cond, &ctx.mutex);
    g_mutex_unlock(&ctx.mutex);

    g_assert_cmpuint(fixture->sink->events->len, > , 0);

    /* 8: Unfollow and notify victim about it */
    g_print("8:Unfollow and notify victim about it\n");
    gum_stalker_unfollow(fixture->stalker, thread_id);
    g_mutex_lock(&ctx.mutex);
    ctx.state = STALKER_VICTIM_IS_UNFOLLOWED;
    g_cond_signal(&ctx.cond);
    g_mutex_unlock(&ctx.mutex);

    /* 9: Wait for victim to tell us it's ready for us to reset the sink */
    g_print("9:Wait for victim to tell us it's ready for us to reset the sink\n");
    g_mutex_lock(&ctx.mutex);
    while (ctx.state != STALKER_VICTIM_READY_FOR_SHUTDOWN)
        g_cond_wait(&ctx.cond, &ctx.mutex);
    g_mutex_unlock(&ctx.mutex);

    gum_fake_event_sink_reset(fixture->sink);

    /* 12: Tell victim to it' */
    g_print("12:Tell victim to it\n");
    g_mutex_lock(&ctx.mutex);
    ctx.state = STALKER_VICTIM_IS_SHUTDOWN;
    g_cond_signal(&ctx.cond);
    g_mutex_unlock(&ctx.mutex);

    g_thread_join(thread);

    g_assert_cmpuint(fixture->sink->events->len, == , 0);

    g_mutex_clear(&ctx.mutex);
    g_cond_clear(&ctx.cond);
}

STALKER_ARM64_TESTCASE (heap_api) {
    gpointer p;

    fixture->sink->mask = (GumEventType)(GUM_EXEC | GUM_CALL | GUM_RET);

    gum_stalker_follow_me(fixture->stalker, GUM_EVENT_SINK(fixture->sink));
    p = malloc(1);
    free(p);
    gum_stalker_unfollow_me(fixture->stalker);

    g_assert_cmpuint(fixture->sink->events->len, > , 0);

}

typedef void (*ClobberFunc)(GumCpuContext *ctx);

STALKER_ARM64_TESTCASE (no_register_clobber) {

    guint8 *code;
    GumArm64Writer cw;
    const gchar *my_func_lbl = "my_func";
    const gchar *my_beach_lbl = "my_beach";
    const gchar *my_ken_lbl = "my_ken";
    ClobberFunc func;
    GumCpuContext ctx;

    code = gum_alloc_n_pages(1, GUM_PAGE_RWX);
    gum_arm64_writer_init(&cw, code);

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

    for (int i = ARM64_REG_X0; i <= ARM64_REG_X28; i++) {
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

    int offset = (4 * sizeof(gpointer)) + (32 * sizeof(gpointer));

    for (int i = ARM64_REG_X0; i <= ARM64_REG_X28; i++) {
        gum_arm64_writer_put_str_reg_reg_offset(&cw, i, ARM64_REG_SP,
                                                offset + G_STRUCT_OFFSET(GumCpuContext, x[i - ARM64_REG_X0]));
    }

    // ---
    gum_arm64_writer_put_pop_all_registers(&cw);

    gum_arm64_writer_put_ret(&cw);

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


    gum_arm64_writer_free(&cw);

    fixture->sink->mask = GUM_CALL | GUM_RET | GUM_EXEC;
    func = GUM_POINTER_TO_FUNCPTR(ClobberFunc, code);
    func(&ctx);

    for (int i = ARM64_REG_X0; i <= ARM64_REG_X28; i++) {
        g_assert_cmphex(ctx.x[i - ARM64_REG_X0], == , i);
    }

    gum_free_pages(code);

}
