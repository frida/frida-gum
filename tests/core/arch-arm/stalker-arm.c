/*
 * Copyright (C) 2009-2020 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 * Copyright (C) 2017 Antonio Ken Iannillo <ak.iannillo@gmail.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "stalker-arm-fixture.c"

TESTLIST_BEGIN (stalker)
  TESTENTRY (trust_should_be_one_by_default)
  TESTENTRY (add_call_probe_unsupported)
  TESTENTRY (remove_call_probe_unsupported)

  TESTENTRY (arm_no_events)
  TESTENTRY (thumb_no_events)
  TESTENTRY (arm_exec_events_generated)
  TESTENTRY (thumb_exec_events_generated)
  TESTENTRY (arm_call_events_generated)
  TESTENTRY (thumb_call_events_generated)
  TESTENTRY (arm_block_events_generated)
  TESTENTRY (thumb_block_events_generated)
  TESTENTRY (arm_nested_call_events_generated)
  TESTENTRY (thumb_nested_call_events_generated)
  TESTENTRY (arm_nested_ret_events_generated)
  TESTENTRY (thumb_nested_ret_events_generated)
  TESTENTRY (arm_unmodified_lr)
  TESTENTRY (thumb_unmodified_lr)
  TESTENTRY (arm_excluded_range)
  TESTENTRY (thumb_excluded_range)
  TESTENTRY (arm_excluded_range_call_events)
  TESTENTRY (thumb_excluded_range_call_events)
  TESTENTRY (arm_excluded_range_ret_events)
  TESTENTRY (thumb_excluded_range_ret_events)
  TESTENTRY (arm_pop_pc_ret_events_generated)
  TESTENTRY (thumb_pop_pc_ret_events_generated)
  TESTENTRY (arm_pop_just_pc_ret_events_generated)
  TESTENTRY (thumb_pop_just_pc_ret_events_generated)
  TESTENTRY (thumb_pop_just_pc2_ret_events_generated)
  TESTENTRY (arm_ldm_pc_ret_events_generated)
  TESTENTRY (thumb_ldm_pc_ret_events_generated)
  TESTENTRY (arm_branch_cc_block_events_generated)
  TESTENTRY (thumb_branch_cc_block_events_generated)

  TESTENTRY (thumb_cbz_cbnz_block_events_generated)

  TESTENTRY (thumb2_mov_pc_reg_exec_events_generated)
  TESTENTRY (thumb2_mov_pc_reg_without_thumb_bit_set)
  TESTENTRY (thumb2_mov_pc_reg_no_clobber_reg)

  /*
   * The following tests have no Thumb equivalent as Thumb does not support
   * conditional instructions nor is PC allowed as the destination register
   * for some opcodes.
   */
  TESTENTRY (arm_branch_link_cc_block_events_generated)
  TESTENTRY (arm_cc_excluded_range)
  TESTENTRY (arm_ldr_pc)
  TESTENTRY (arm_ldr_pc_pre_index_imm)
  TESTENTRY (arm_ldr_pc_post_index_imm)
  TESTENTRY (arm_ldr_pc_pre_index_imm_negative)
  TESTENTRY (arm_ldr_pc_post_index_imm_negative)
  TESTENTRY (arm_sub_pc)
  TESTENTRY (arm_add_pc)

  TESTENTRY (thumb_it_eq)
  TESTENTRY (thumb_it_eq_branch)
  TESTENTRY (thumb_itt_eq_branch)
  TESTENTRY (thumb_ite_eq_branch)
  TESTENTRY (thumb_it_eq_branch_link)
  TESTENTRY (thumb_it_eq_branch_link_excluded)
  TESTENTRY (thumb_it_eq_pop)
  TESTENTRY (thumb_itttt_eq_blx_reg)
  TESTENTRY (thumb_it_flags)
  TESTENTRY (thumb_tbb)
  TESTENTRY (thumb_tbh)
  TESTENTRY (thumb_strex_no_exec_events)

  TESTENTRY (self_modifying_code_should_be_detected_with_threshold_minus_one)
  TESTENTRY (self_modifying_code_should_not_be_detected_with_threshold_zero)
  TESTENTRY (self_modifying_code_should_be_detected_with_threshold_one)

  TESTENTRY (call_thumb)
  TESTENTRY (branch_thumb)
  TESTENTRY (can_follow_workload)
  TESTENTRY (performance)

  TESTENTRY (custom_transformer)
  TESTENTRY (arm_callout)
  TESTENTRY (thumb_callout)
  TESTENTRY (unfollow_should_be_allowed_before_first_transform)
  TESTENTRY (unfollow_should_be_allowed_mid_first_transform)
  TESTENTRY (unfollow_should_be_allowed_after_first_transform)
  TESTENTRY (unfollow_should_be_allowed_before_second_transform)
  TESTENTRY (unfollow_should_be_allowed_mid_second_transform)
  TESTENTRY (unfollow_should_be_allowed_after_second_transform)
  TESTENTRY (follow_me_should_support_nullable_event_sink)

  TESTENTRY (follow_syscall)
  TESTENTRY (follow_thread)
  TESTENTRY (unfollow_should_handle_terminated_thread)
  TESTENTRY (pthread_create)
  TESTENTRY (heap_api)
TESTLIST_END ()

static void dummy_call_probe (GumCallSite * site, gpointer user_data);
static gboolean store_range_of_test_runner (const GumModuleDetails * details,
    gpointer user_data);
static void pretend_workload (GumMemoryRange * runner_range);
static gboolean test_log_fatal_func (const gchar * log_domain,
    GLogLevelFlags log_level, const gchar * message, gpointer user_data);
static GLogWriterOutput test_log_writer_func (GLogLevelFlags log_level,
    const GLogField * fields, gsize n_fields, gpointer user_data);
static void duplicate_adds (GumStalkerIterator * iterator,
    GumStalkerOutput * output, gpointer user_data);
static void transform_arm_return_value (GumStalkerIterator * iterator,
    GumStalkerOutput * output, gpointer user_data);
static void on_arm_ret (GumCpuContext * cpu_context, gpointer user_data);
static gboolean is_arm_mov_pc_lr (const guint8 * bytes, gsize size);
static void transform_thumb_return_value (GumStalkerIterator * iterator,
    GumStalkerOutput * output, gpointer user_data);
static void on_thumb_ret (GumCpuContext * cpu_context,
    gpointer user_data);
static gboolean is_thumb_pop_pc (const guint8 * bytes, gsize size);
static void unfollow_during_transform (GumStalkerIterator * iterator,
    GumStalkerOutput * output, gpointer user_data);
static gpointer run_stalked_briefly (gpointer data);
static gpointer run_stalked_into_termination (gpointer data);
static gpointer increment_integer (gpointer data);
static void patch_code_pointer (GumAddress code, guint offset,
    GumAddress value);
static void patch_code_pointer_slot (gpointer mem, gpointer user_data);

TESTCASE (trust_should_be_one_by_default)
{
  g_assert_cmpuint (gum_stalker_get_trust_threshold (fixture->stalker), ==, 1);
}

TESTCASE (deactivate_unsupported)
{
  g_test_expect_message (G_LOG_DOMAIN, G_LOG_LEVEL_WARNING,
      "Activate/deactivate unsupported");
  gum_stalker_deactivate (fixture->stalker);
  g_test_assert_expected_messages ();
}

TESTCASE (activate_unsupported)
{
  g_test_expect_message (G_LOG_DOMAIN, G_LOG_LEVEL_WARNING,
      "Activate/deactivate unsupported");
  gum_stalker_activate (fixture->stalker, NULL);
  g_test_assert_expected_messages ();
}

TESTCASE (add_call_probe_unsupported)
{
  GumProbeId id;

  g_test_expect_message (G_LOG_DOMAIN, G_LOG_LEVEL_WARNING,
      "Call probes unsupported");
  id = gum_stalker_add_call_probe (fixture->stalker, NULL, dummy_call_probe,
      NULL, NULL);
  g_test_assert_expected_messages ();
  g_assert_cmpuint (id, ==, 0);
}

static void
dummy_call_probe (GumCallSite * site,
                  gpointer user_data)
{
}

TESTCASE (remove_call_probe_unsupported)
{
  g_test_expect_message (G_LOG_DOMAIN, G_LOG_LEVEL_WARNING,
      "Call probes unsupported");
  gum_stalker_remove_call_probe (fixture->stalker, 10);
  g_test_assert_expected_messages ();
}

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

TESTCASE (arm_no_events)
{
  INVOKE_ARM_EXPECTING (GUM_NOTHING, arm_flat_code, 2);

  g_assert_cmpuint (fixture->sink->events->len, ==, 0);
}

TESTCASE (thumb_no_events)
{
  INVOKE_THUMB_EXPECTING (GUM_NOTHING, thumb_flat_code, 2);

  g_assert_cmpuint (fixture->sink->events->len, ==, 0);
}

TESTCASE (arm_exec_events_generated)
{
  GumAddress func;

  func = INVOKE_ARM_EXPECTING (GUM_EXEC, arm_flat_code, 2);

  g_assert_cmpuint (fixture->sink->events->len, ==,
      INVOKER_INSN_COUNT + (CODE_SIZE (arm_flat_code) / 4));

  GUM_ASSERT_EVENT_ADDR (exec, 0, location,
      fixture->invoker + INVOKER_IMPL_OFFSET);
  GUM_ASSERT_EVENT_ADDR (exec, 1, location,
      fixture->invoker + INVOKER_IMPL_OFFSET + 4);

  GUM_ASSERT_EVENT_ADDR (exec, 2, location, func);
  GUM_ASSERT_EVENT_ADDR (exec, 3, location, func + 4);
  GUM_ASSERT_EVENT_ADDR (exec, 4, location, func + 8);
  GUM_ASSERT_EVENT_ADDR (exec, 5, location, func + 12);

  GUM_ASSERT_EVENT_ADDR (exec, 6, location,
      fixture->invoker + INVOKER_IMPL_OFFSET + 8);
  GUM_ASSERT_EVENT_ADDR (exec, 7, location,
      fixture->invoker + INVOKER_IMPL_OFFSET + 12);
  GUM_ASSERT_EVENT_ADDR (exec, 8, location,
      fixture->invoker + INVOKER_IMPL_OFFSET + 16);
  GUM_ASSERT_EVENT_ADDR (exec, 9, location,
      fixture->invoker + INVOKER_IMPL_OFFSET + 20);
}

TESTCASE (thumb_exec_events_generated)
{
  GumAddress func;

  func = INVOKE_THUMB_EXPECTING (GUM_EXEC, thumb_flat_code, 2);

  g_assert_cmpuint (fixture->sink->events->len, ==,
      INVOKER_INSN_COUNT + (CODE_SIZE (thumb_flat_code) / 2));

  GUM_ASSERT_EVENT_ADDR (exec, 0, location,
      fixture->invoker + INVOKER_IMPL_OFFSET);
  GUM_ASSERT_EVENT_ADDR (exec, 1, location,
      fixture->invoker + INVOKER_IMPL_OFFSET + 4);

  GUM_ASSERT_EVENT_ADDR (exec, 2, location, func);
  GUM_ASSERT_EVENT_ADDR (exec, 3, location, func + 2);
  GUM_ASSERT_EVENT_ADDR (exec, 4, location, func + 4);
  GUM_ASSERT_EVENT_ADDR (exec, 5, location, func + 6);
  GUM_ASSERT_EVENT_ADDR (exec, 6, location, func + 8);

  GUM_ASSERT_EVENT_ADDR (exec, 7, location,
      fixture->invoker + INVOKER_IMPL_OFFSET + 8);
  GUM_ASSERT_EVENT_ADDR (exec, 8, location,
      fixture->invoker + INVOKER_IMPL_OFFSET + 12);
  GUM_ASSERT_EVENT_ADDR (exec, 9, location,
      fixture->invoker + INVOKER_IMPL_OFFSET + 16);
  GUM_ASSERT_EVENT_ADDR (exec, 10, location,
      fixture->invoker + INVOKER_IMPL_OFFSET + 20);
}

TESTCASE (arm_call_events_generated)
{
  GumAddress func;

  func = INVOKE_ARM_EXPECTING (GUM_CALL, arm_flat_code, 2);

  g_assert_cmpuint (fixture->sink->events->len, ==, INVOKER_CALL_INSN_COUNT);

  GUM_ASSERT_EVENT_ADDR (call, 0, target, func);
  GUM_ASSERT_EVENT_ADDR (call, 0, depth, 0);
}

TESTCASE (thumb_call_events_generated)
{
  GumAddress func;

  func = INVOKE_THUMB_EXPECTING (GUM_CALL, thumb_flat_code, 2);

  g_assert_cmpuint (fixture->sink->events->len, ==, INVOKER_CALL_INSN_COUNT);

  GUM_ASSERT_EVENT_ADDR (call, 0, target, func + 1);
  GUM_ASSERT_EVENT_ADDR (call, 0, depth, 0);
}

TESTCODE (arm_block_events,
  0x00, 0x00, 0x40, 0xe0, /* sub r0, r0, r0 */
  0x01, 0x00, 0x80, 0xe2, /* add r0, r0, 1  */
  0x00, 0x00, 0x00, 0xea, /* b beach        */

  0xf0, 0x00, 0xf0, 0xe7, /* udf 0          */

  /* beach:                                 */
  0x01, 0x00, 0x80, 0xe2, /* add r0, r0, 1  */
  0x0e, 0xf0, 0xa0, 0xe1  /* mov pc, lr     */
);

TESTCASE (arm_block_events_generated)
{
  GumAddress func;

  func = INVOKE_ARM_EXPECTING (GUM_BLOCK, arm_block_events, 2);

  g_assert_cmpuint (fixture->sink->events->len, ==, INVOKER_BLOCK_COUNT + 1);

  GUM_ASSERT_EVENT_ADDR (block, 0, begin, func);
  GUM_ASSERT_EVENT_ADDR (block, 0, end, func + (3 * 4));
}

TESTCODE (thumb_block_events,
  0x00, 0xb5, /* push {lr}       */
  0x00, 0x1a, /* subs r0, r0, r0 */
  0x01, 0x30, /* adds r0, 1      */
  0x00, 0xe0, /* b beach         */

  0x00, 0xde, /* udf 0           */

  /* beach:                      */
  0x01, 0x30, /* adds r0, 1      */
  0x00, 0xbd  /* pop {pc}        */
);

TESTCASE (thumb_block_events_generated)
{
  GumAddress func;

  func = INVOKE_THUMB_EXPECTING (GUM_BLOCK, thumb_block_events, 2);

  g_assert_cmpuint (fixture->sink->events->len, ==, INVOKER_BLOCK_COUNT + 1);

  GUM_ASSERT_EVENT_ADDR (block, 0, begin, func);
  GUM_ASSERT_EVENT_ADDR (block, 0, end, func + (4 * 2));
}

TESTCODE (arm_nested_call,
  0x00, 0x40, 0x2d, 0xe9, /* stmdb sp!, {lr} */
  0x00, 0x00, 0x40, 0xe0, /* sub r0, r0, r0  */
  0x01, 0x00, 0x80, 0xe2, /* add r0, r0, 1   */
  0x02, 0x00, 0x00, 0xeb, /* bl func_a       */
  0x06, 0x00, 0x00, 0xeb, /* bl func_b       */
  0x00, 0x40, 0xbd, 0xe8, /* ldm sp!, {lr}   */
  0x0e, 0xf0, 0xa0, 0xe1, /* mov pc, lr      */

  /* func_a:                                 */
  0x00, 0x40, 0x2d, 0xe9, /* stmdb sp!, {lr} */
  0x01, 0x00, 0x80, 0xe2, /* add r0, r0, 1   */
  0x01, 0x00, 0x00, 0xeb, /* bl func_b       */
  0x00, 0x40, 0xbd, 0xe8, /* ldm sp!, {lr}   */
  0x0e, 0xf0, 0xa0, 0xe1, /* mov pc, lr      */

  /* func_b:                                 */
  0x01, 0x00, 0x80, 0xe2, /* add r0, r0, 1   */
  0x0e, 0xf0, 0xa0, 0xe1  /* mov pc, lr      */
);

TESTCASE (arm_nested_call_events_generated)
{
  GumAddress func;

  func = INVOKE_ARM_EXPECTING (GUM_CALL, arm_nested_call, 4);

  g_assert_cmpuint (fixture->sink->events->len, ==,
      INVOKER_CALL_INSN_COUNT + 3);

  GUM_ASSERT_EVENT_ADDR (call, 0, target, func);
  GUM_ASSERT_EVENT_ADDR (call, 0, depth, 0);

  GUM_ASSERT_EVENT_ADDR (call, 1, location, func + (3 * 4));
  GUM_ASSERT_EVENT_ADDR (call, 1, target, func + (7 * 4));
  GUM_ASSERT_EVENT_ADDR (call, 1, depth, 1);

  GUM_ASSERT_EVENT_ADDR (call, 2, location, func + (9 * 4));
  GUM_ASSERT_EVENT_ADDR (call, 2, target, func + (12 * 4));
  GUM_ASSERT_EVENT_ADDR (call, 2, depth, 2);

  GUM_ASSERT_EVENT_ADDR (call, 3, location, func + (4 * 4));
  GUM_ASSERT_EVENT_ADDR (call, 3, target, func + (12 * 4));
  GUM_ASSERT_EVENT_ADDR (call, 3, depth, 1);
}

TESTCODE (thumb_nested_call,
  0x00, 0xb5,             /* push {lr}       */
  0x00, 0x1a,             /* subs r0, r0, r0 */
  0x01, 0x30,             /* adds r0, 1      */
  0x00, 0xf0, 0x03, 0xf8, /* bl func_a       */
  0x00, 0xf0, 0x06, 0xf8, /* bl func_b       */
  0x00, 0xbd,             /* pop {pc}        */

  /* func_a:                                 */
  0x00, 0xb5,             /* push {lr}       */
  0x01, 0x30,             /* adds r0, 1      */
  0x00, 0xf0, 0x01, 0xf8, /* bl func_b       */
  0x00, 0xbd,             /* pop {pc}        */

  /* func_b:                                 */
  0x00, 0xb5,             /* push {lr}       */
  0x01, 0x30,             /* adds r0, 1      */
  0x00, 0xbd              /* pop {pc}        */
);

TESTCASE (thumb_nested_call_events_generated)
{
  GumAddress func;

  func = INVOKE_THUMB_EXPECTING (GUM_CALL, thumb_nested_call, 4);

  g_assert_cmpuint (fixture->sink->events->len, ==,
      INVOKER_CALL_INSN_COUNT + 3);

  GUM_ASSERT_EVENT_ADDR (call, 0, target, func + 1);
  GUM_ASSERT_EVENT_ADDR (call, 0, depth, 0);

  GUM_ASSERT_EVENT_ADDR (call, 1, location, func + 6);
  GUM_ASSERT_EVENT_ADDR (call, 1, target, func + 17);
  GUM_ASSERT_EVENT_ADDR (call, 1, depth, 1);

  GUM_ASSERT_EVENT_ADDR (call, 2, location, func + 20);
  GUM_ASSERT_EVENT_ADDR (call, 2, target, func + 27);
  GUM_ASSERT_EVENT_ADDR (call, 2, depth, 2);

  GUM_ASSERT_EVENT_ADDR (call, 3, location, func + 10);
  GUM_ASSERT_EVENT_ADDR (call, 3, target, func + 27);
  GUM_ASSERT_EVENT_ADDR (call, 3, depth, 1);
}

TESTCASE (arm_nested_ret_events_generated)
{
  GumAddress func;

  func = INVOKE_ARM_EXPECTING (GUM_RET, arm_nested_call, 4);

  g_assert_cmpuint (fixture->sink->events->len, ==, 4);

  GUM_ASSERT_EVENT_ADDR (ret, 0, location, func + (13 * 4));
  GUM_ASSERT_EVENT_ADDR (ret, 0, target, func + (10 * 4));
  GUM_ASSERT_EVENT_ADDR (ret, 0, depth, 2);

  GUM_ASSERT_EVENT_ADDR (ret, 1, location, func + (11 * 4));
  GUM_ASSERT_EVENT_ADDR (ret, 1, target, func + (4 * 4));
  GUM_ASSERT_EVENT_ADDR (ret, 1, depth, 1);

  GUM_ASSERT_EVENT_ADDR (ret, 2, location, func + (13 * 4));
  GUM_ASSERT_EVENT_ADDR (ret, 2, target, func + (5 * 4));
  GUM_ASSERT_EVENT_ADDR (ret, 2, depth, 1);

  GUM_ASSERT_EVENT_ADDR (ret, 3, location, func + (6 * 4));
  GUM_ASSERT_EVENT_ADDR (ret, 3, depth, 0);
}

TESTCASE (thumb_nested_ret_events_generated)
{
  GumAddress func;

  func = INVOKE_THUMB_EXPECTING (GUM_RET, thumb_nested_call, 4);

  g_assert_cmpuint (fixture->sink->events->len, ==, 4);

  GUM_ASSERT_EVENT_ADDR (ret, 0, location, func + 30);
  GUM_ASSERT_EVENT_ADDR (ret, 0, target, func + 25);
  GUM_ASSERT_EVENT_ADDR (ret, 0, depth, 2);

  GUM_ASSERT_EVENT_ADDR (ret, 1, location, func + 24);
  GUM_ASSERT_EVENT_ADDR (ret, 1, target, func + 11);
  GUM_ASSERT_EVENT_ADDR (ret, 1, depth, 1);

  GUM_ASSERT_EVENT_ADDR (ret, 2, location, func + 30);
  GUM_ASSERT_EVENT_ADDR (ret, 2, target, func + 15);
  GUM_ASSERT_EVENT_ADDR (ret, 2, depth, 1);

  GUM_ASSERT_EVENT_ADDR (ret, 3, location, func + 14);
  GUM_ASSERT_EVENT_ADDR (ret, 3, depth, 0);
}

TESTCODE (arm_unmodified_lr,
  0x00, 0x40, 0x2d, 0xe9, /* stmdb sp!, {lr} */
  0x00, 0x00, 0x00, 0xeb, /* bl part_two     */

  0xec, 0xec, 0xec, 0xec,

  /* part_two:                               */
  0x00, 0x00, 0x9e, 0xe5, /* ldr r0, [lr]    */
  0x00, 0x40, 0xbd, 0xe8, /* ldm sp!, {lr}   */
  0x0e, 0xf0, 0xa0, 0xe1, /* mov pc, lr      */
);

TESTCASE (arm_unmodified_lr)
{
  INVOKE_ARM_EXPECTING (0, arm_unmodified_lr, 0xecececec);
}

TESTCODE (thumb_unmodified_lr,
  0x00, 0xb5,             /* push {lr}       */
  0x00, 0xf0, 0x02, 0xf8, /* bl part_two     */

  0xec, 0xec, 0xec, 0xec,

  /* part_two:                               */
  0x49, 0x1a,             /* subs r1, r1, r1 */
  0x01, 0x31,             /* adds r1, 1      */
  0x70, 0x46,             /* mov r0, lr      */
  0x88, 0x43,             /* bics r0, r1     */
  0x00, 0x68,             /* ldr r0, [r0]    */
  0x00, 0xbd              /* pop {pc}        */
);

TESTCASE (thumb_unmodified_lr)
{
  INVOKE_THUMB_EXPECTING (0, thumb_unmodified_lr, 0xecececec);
}

TESTCODE (arm_excluded_range,
  0x00, 0x40, 0x2d, 0xe9, /* stmdb sp!, {lr}  */
  0x00, 0x00, 0x40, 0xe0, /* sub r0, r0, r0   */
  0x01, 0x00, 0x80, 0xe2, /* add r0, r0, 1    */
  0x01, 0x00, 0x00, 0xeb, /* bl excluded_func */
  0x00, 0x40, 0xbd, 0xe8, /* ldm sp!, {lr}    */
  0x0e, 0xf0, 0xa0, 0xe1, /* mov pc, lr       */

  /* excluded_func:                           */
  0x01, 0x00, 0x80, 0xe2, /* add r0, r0, 1    */
  0x0e, 0xf0, 0xa0, 0xe1  /* mov pc, lr       */
);

TESTCASE (arm_excluded_range)
{
  GumAddress func;

  func = DUP_TESTCODE (arm_excluded_range);

  {
    GumMemoryRange r = {
      .base_address = GUM_ADDRESS (func) + 24,
      .size = 8
    };

    gum_stalker_exclude (fixture->stalker, &r);
  }

  {
    fixture->sink->mask = GUM_EXEC;
    g_assert_cmpuint (FOLLOW_AND_INVOKE (func), ==, 2);

    g_assert_cmpuint (fixture->sink->events->len, ==, INVOKER_INSN_COUNT + 6);

    GUM_ASSERT_EVENT_ADDR (exec, 2, location, func);
    GUM_ASSERT_EVENT_ADDR (exec, 3, location, func + 4);
    GUM_ASSERT_EVENT_ADDR (exec, 4, location, func + 8);
    GUM_ASSERT_EVENT_ADDR (exec, 5, location, func + 12);
    GUM_ASSERT_EVENT_ADDR (exec, 6, location, func + 16);
    GUM_ASSERT_EVENT_ADDR (exec, 7, location, func + 20);
  }
}

TESTCODE (thumb_excluded_range,
  0x00, 0xb5,             /* push {lr}        */
  0x00, 0x1a,             /* subs r0, r0, r0  */
  0x01, 0x30,             /* adds r0, 1       */
  0x00, 0xf0, 0x01, 0xf8, /* bl excluded_func */
  0x00, 0xbd,             /* pop {pc}         */

  /* excluded_func:                           */
  0x00, 0xb5,             /* push {lr}        */
  0x01, 0x30,             /* adds r0, 1       */
  0x00, 0xbd              /* pop {pc}         */
);

TESTCASE (thumb_excluded_range)
{
  GumAddress func;

  func = DUP_TESTCODE (thumb_excluded_range);

  {
    GumMemoryRange r = {
      .base_address = GUM_ADDRESS (func) + 12,
      .size = 6
    };

    gum_stalker_exclude (fixture->stalker, &r);
  }

  {
    fixture->sink->mask = GUM_EXEC;
    g_assert_cmpuint (FOLLOW_AND_INVOKE (func + 1), ==, 2);

    g_assert_cmpuint (fixture->sink->events->len, ==, INVOKER_INSN_COUNT + 5);

    GUM_ASSERT_EVENT_ADDR (exec, 2, location, func);
    GUM_ASSERT_EVENT_ADDR (exec, 3, location, func + 2);
    GUM_ASSERT_EVENT_ADDR (exec, 4, location, func + 4);
    GUM_ASSERT_EVENT_ADDR (exec, 5, location, func + 6);
    GUM_ASSERT_EVENT_ADDR (exec, 6, location, func + 10);
  }
}

TESTCODE (arm_excluded_range_call,
  0x04, 0xe0, 0x2d, 0xe5, /* push {lr}         */
  0x00, 0x00, 0x40, 0xe0, /* sub r0, r0, r0    */
  0x01, 0x00, 0x80, 0xe2, /* add r0, r0, 1     */
  0x05, 0x00, 0x00, 0xeb, /* bl func_c         */
  0x00, 0x00, 0x00, 0xeb, /* bl func_a         */
  0x04, 0xf0, 0x9d, 0xe4, /* pop {pc}          */

  /* func_a:                                   */
  0x01, 0x00, 0x80, 0xe2, /* add r0, r0, 1     */
  0x0e, 0xf0, 0xa0, 0xe1, /* mov pc, lr        */

  /* func_b:                                   */
  0x01, 0x00, 0x80, 0xe2, /* add r0, r0, 1     */
  0x0e, 0xf0, 0xa0, 0xe1, /* mov pc, lr        */

  /* func_c:                                   */
  0x04, 0xe0, 0x2d, 0xe5, /* push {lr}         */
  0x01, 0x00, 0x80, 0xe2, /* add r0, r0, 1     */
  0xfa, 0xff, 0xff, 0xeb, /* bl func_b         */
  0x04, 0xf0, 0x9d, 0xe4  /* pop {pc}          */
);

TESTCASE (arm_excluded_range_call_events)
{
  GumAddress func;

  func = DUP_TESTCODE (arm_excluded_range_call);

  {
    GumMemoryRange r = {
      .base_address = GUM_ADDRESS (func) + 40,
      .size = 16
    };

    gum_stalker_exclude (fixture->stalker, &r);
  }

  {
    fixture->sink->mask = GUM_CALL;
    g_assert_cmpuint (FOLLOW_AND_INVOKE (func), ==, 4);

    g_assert_cmpuint (fixture->sink->events->len, ==,
        INVOKER_CALL_INSN_COUNT + 2);

    GUM_ASSERT_EVENT_ADDR (call, 1, location, func + 12);
    GUM_ASSERT_EVENT_ADDR (call, 1, target, func + 40);
    GUM_ASSERT_EVENT_ADDR (call, 1, depth, 1);

    GUM_ASSERT_EVENT_ADDR (call, 2, location, func + 16);
    GUM_ASSERT_EVENT_ADDR (call, 2, target, func + 24);
    GUM_ASSERT_EVENT_ADDR (call, 2, depth, 1);
  }
}

TESTCODE (thumb_excluded_range_call,
  0x00, 0xb5,             /* push {lr}       */
  0x00, 0x1a,             /* subs r0, r0, r0 */
  0x01, 0x30,             /* adds r0, 1      */
  0x00, 0xf0, 0x09, 0xf8, /* bl func_c       */
  0x00, 0xf0, 0x01, 0xf8, /* bl func_a       */
  0x00, 0xbd,             /* pop {pc}        */

  /* func_a:                                 */
  0x00, 0xb5,             /* push {lr}       */
  0x01, 0x30,             /* adds r0, 1      */
  0x00, 0xbd,             /* pop {pc}        */

  /* func_b:                                 */
  0x00, 0xb5,             /* push {lr}       */
  0x01, 0x30,             /* adds r0, 1      */
  0x00, 0xbd,             /* pop {pc}        */

  /* func_c:                                 */
  0x00, 0xb5,             /* push {lr}       */
  0x01, 0x30,             /* adds r0, 1      */
  0xff, 0xf7, 0xf9, 0xff, /* bl func_b       */
  0x00, 0xbd              /* pop {pc}        */
);

TESTCASE (thumb_excluded_range_call_events)
{
  GumAddress func;

  func = DUP_TESTCODE (thumb_excluded_range_call);

  {
    GumMemoryRange r = {
      .base_address = GUM_ADDRESS (func) + 28,
      .size = 10
    };

    gum_stalker_exclude (fixture->stalker, &r);
  }

  {
    fixture->sink->mask = GUM_CALL;
    g_assert_cmpuint (FOLLOW_AND_INVOKE (func + 1), ==, 4);

    g_assert_cmpuint (fixture->sink->events->len, ==,
        INVOKER_CALL_INSN_COUNT + 2);

    GUM_ASSERT_EVENT_ADDR (call, 1, location, func + 6);
    GUM_ASSERT_EVENT_ADDR (call, 1, target, func + 29);
    GUM_ASSERT_EVENT_ADDR (call, 1, depth, 1);

    GUM_ASSERT_EVENT_ADDR (call, 2, location, func + 10);
    GUM_ASSERT_EVENT_ADDR (call, 2, target, func + 17);
    GUM_ASSERT_EVENT_ADDR (call, 2, depth, 1);
  }
}

TESTCASE (arm_excluded_range_ret_events)
{
  GumAddress func;

  func = DUP_TESTCODE (arm_excluded_range_call);

  {
    GumMemoryRange r = {
      .base_address = GUM_ADDRESS (func) + 40,
      .size = 16
    };

    gum_stalker_exclude (fixture->stalker, &r);
  }

  {
    fixture->sink->mask = GUM_RET;
    g_assert_cmpuint (FOLLOW_AND_INVOKE (func), ==, 4);

    g_assert_cmpuint (fixture->sink->events->len, ==, 2);

    GUM_ASSERT_EVENT_ADDR (ret, 0, location, func + 28);
    GUM_ASSERT_EVENT_ADDR (ret, 0, target, func + 20);
    GUM_ASSERT_EVENT_ADDR (ret, 0, depth, 1);

    GUM_ASSERT_EVENT_ADDR (ret, 1, location, func + 20);
    GUM_ASSERT_EVENT_ADDR (ret, 1, depth, 0);
  }
}

TESTCASE (thumb_excluded_range_ret_events)
{
  GumAddress func;

  func = DUP_TESTCODE (thumb_excluded_range_call);

  {
    GumMemoryRange r = {
      .base_address = GUM_ADDRESS (func) + 28,
      .size = 10
    };

    gum_stalker_exclude (fixture->stalker, &r);
  }

  {
    fixture->sink->mask = GUM_RET;
    g_assert_cmpuint (FOLLOW_AND_INVOKE (func + 1), ==, 4);

    g_assert_cmpuint (fixture->sink->events->len, ==, 2);

    GUM_ASSERT_EVENT_ADDR (ret, 0, location, func + 20);
    GUM_ASSERT_EVENT_ADDR (ret, 0, target, func + 15);
    GUM_ASSERT_EVENT_ADDR (ret, 0, depth, 1);

    GUM_ASSERT_EVENT_ADDR (ret, 1, location, func + 14);
    GUM_ASSERT_EVENT_ADDR (ret, 1, depth, 0);
  }
}

TESTCODE (arm_pop_pc,
  0xf0, 0x41, 0x2d, 0xe9, /* push {r4-r8, lr} */
  0x00, 0x00, 0x40, 0xe0, /* sub r0, r0, r0   */
  0x01, 0x00, 0x80, 0xe2, /* add r0, r0, 1    */
  0x00, 0x00, 0x00, 0xeb, /* bl inner         */
  0xf0, 0x81, 0xbd, 0xe8, /* pop {r4-r8, pc}  */

  /* inner:                                   */
  0x0e, 0x40, 0x2d, 0xe9, /* push {r1-r3, lr} */
  0x01, 0x00, 0x80, 0xe2, /* add r0, r0, 1    */
  0x0e, 0x80, 0xbd, 0xe8  /* pop {r1-r3, pc}  */
);

TESTCASE (arm_pop_pc_ret_events_generated)
{
  GumAddress func;

  func = INVOKE_ARM_EXPECTING (GUM_RET, arm_pop_pc, 2);

  g_assert_cmpuint (fixture->sink->events->len, ==, 2);

  g_assert_cmpint (
      g_array_index (fixture->sink->events, GumEvent, 0).type, ==, GUM_RET);

  GUM_ASSERT_EVENT_ADDR (ret, 0, location, func + 28);
  GUM_ASSERT_EVENT_ADDR (ret, 0, target, func + 16);
  GUM_ASSERT_EVENT_ADDR (ret, 0, depth, 1);

  GUM_ASSERT_EVENT_ADDR (ret, 1, location, func + 16);
  GUM_ASSERT_EVENT_ADDR (ret, 1, depth, 0);
}

TESTCODE (thumb_pop_pc,
  0xf0, 0xb5,             /* push {r4-r7, lr} */
  0x00, 0x1a,             /* subs r0, r0, r0  */
  0x01, 0x30,             /* adds r0, 1       */
  0x00, 0xf0, 0x01, 0xf8, /* bl inner         */
  0xf0, 0xbd,             /* pop {r4-r7, pc}  */

  /* inner:                                   */
  0x0e, 0xb5,             /* push {r1-r3, lr} */
  0x01, 0x30,             /* adds r0, 1       */
  0x0e, 0xbd              /* pop {r1-r3, pc}  */
);

TESTCASE (thumb_pop_pc_ret_events_generated)
{
  GumAddress func;

  func = INVOKE_THUMB_EXPECTING (GUM_RET, thumb_pop_pc, 2);

  g_assert_cmpuint (fixture->sink->events->len, ==, 2);

  g_assert_cmpint (
      g_array_index (fixture->sink->events, GumEvent, 0).type, ==, GUM_RET);

  GUM_ASSERT_EVENT_ADDR (ret, 0, location, func + 16);
  GUM_ASSERT_EVENT_ADDR (ret, 0, target, func + 11);
  GUM_ASSERT_EVENT_ADDR (ret, 0, depth, 1);

  GUM_ASSERT_EVENT_ADDR (ret, 1, location, func + 10);
  GUM_ASSERT_EVENT_ADDR (ret, 1, depth, 0);
}

TESTCODE (arm_pop_just_pc,
  0xf0, 0x41, 0x2d, 0xe9, /* push {r4-r8, lr} */
  0x00, 0x00, 0x40, 0xe0, /* sub r0, r0, r0   */
  0x01, 0x00, 0x80, 0xe2, /* add r0, r0, 1    */
  0x00, 0x00, 0x00, 0xeb, /* bl inner         */
  0xf0, 0x81, 0xbd, 0xe8, /* pop {r4-r8, pc}  */

  /* inner:                                   */
  0x00, 0x40, 0x2d, 0xe9, /* stmdb sp!, {lr}  */
  0x01, 0x00, 0x80, 0xe2, /* add r0, r0, 1    */
  0x00, 0x80, 0xbd, 0xe8  /* ldm sp!, {pc}    */
);

TESTCASE (arm_pop_just_pc_ret_events_generated)
{
  GumAddress func;

  func = INVOKE_ARM_EXPECTING (GUM_RET, arm_pop_just_pc, 2);

  g_assert_cmpuint (fixture->sink->events->len, ==, 2);

  g_assert_cmpint (
      g_array_index (fixture->sink->events, GumEvent, 0).type, ==, GUM_RET);

  GUM_ASSERT_EVENT_ADDR (ret, 0, location, func + 28);
  GUM_ASSERT_EVENT_ADDR (ret, 0, target, func + 16);
  GUM_ASSERT_EVENT_ADDR (ret, 0, depth, 1);

  GUM_ASSERT_EVENT_ADDR (ret, 1, location, func + 16);
  GUM_ASSERT_EVENT_ADDR (ret, 1, depth, 0);
}

TESTCODE (thumb_pop_just_pc,
  0xf0, 0xb5,             /* push {r4-r7, lr} */
  0x00, 0x1a,             /* subs r0, r0, r0  */
  0x01, 0x30,             /* adds r0, 1       */
  0x00, 0xf0, 0x01, 0xf8, /* bl inner         */
  0xf0, 0xbd,             /* pop {r4-r7, pc}  */

  /* inner:                                   */
  0x00, 0xb5,             /* push {lr}        */
  0x01, 0x30,             /* adds r0, 1       */
  0x00, 0xbd              /* pop {pc}         */
);

TESTCASE (thumb_pop_just_pc_ret_events_generated)
{
  GumAddress func;

  func = INVOKE_THUMB_EXPECTING (GUM_RET, thumb_pop_just_pc, 2);

  g_assert_cmpuint (fixture->sink->events->len, ==, 2);

  g_assert_cmpint (
      g_array_index (fixture->sink->events, GumEvent, 0).type, ==, GUM_RET);

  GUM_ASSERT_EVENT_ADDR (ret, 0, location, func + 16);
  GUM_ASSERT_EVENT_ADDR (ret, 0, target, func + 11);
  GUM_ASSERT_EVENT_ADDR (ret, 0, depth, 1);

  GUM_ASSERT_EVENT_ADDR (ret, 1, location, func + 10);
  GUM_ASSERT_EVENT_ADDR (ret, 1, depth, 0);
}

TESTCODE (thumb_pop_just_pc2,
  0xf0, 0xb5,             /* push {r4-r7, lr} */
  0x00, 0x1a,             /* subs r0, r0, r0  */
  0x01, 0x30,             /* adds r0, 1       */
  0x00, 0xf0, 0x01, 0xf8, /* bl inner         */
  0xf0, 0xbd,             /* pop {r4-r7, pc}  */

  /* inner:                                   */
  0x00, 0xb5,             /* push {lr}        */
  0x01, 0x30,             /* adds r0, 1       */
  0x5d, 0xf8, 0x04, 0xfb, /* ldr pc, [sp], #4 */
);

TESTCASE (thumb_pop_just_pc2_ret_events_generated)
{
  GumAddress func;

  func = INVOKE_THUMB_EXPECTING (GUM_RET, thumb_pop_just_pc2, 2);

  g_assert_cmpuint (fixture->sink->events->len, ==, 1);

  g_assert_cmpint (
      g_array_index (fixture->sink->events, GumEvent, 0).type, ==, GUM_RET);

  GUM_ASSERT_EVENT_ADDR (ret, 0, location, func + 10);
  GUM_ASSERT_EVENT_ADDR (ret, 0, depth, 0);
}

TESTCODE (arm_ldm_pc,
  0xf0, 0x41, 0x2d, 0xe9, /* push {r4-r8, lr}       */
  0x00, 0x00, 0x40, 0xe0, /* sub r0, r0, r0         */
  0x01, 0x00, 0x80, 0xe2, /* add r0, r0, 1          */
  0x00, 0x00, 0x00, 0xeb, /* bl inner               */
  0xf0, 0x81, 0xbd, 0xe8, /* pop {r4-r8, pc}        */

  /* inner:                                         */
  0x00, 0x30, 0x8d, 0xe2, /* add r3, sp, 0          */
  0xf0, 0x41, 0x23, 0xe9, /* stmdb r3!, {r4-r8, lr} */
  0x01, 0x00, 0x80, 0xe2, /* add r0, r0, 1          */
  0xf0, 0x81, 0xb3, 0xe8  /* ldm r3!, {r4-r8, pc}   */
);

TESTCASE (arm_ldm_pc_ret_events_generated)
{
  GumAddress func;

  func = INVOKE_ARM_EXPECTING (GUM_RET, arm_ldm_pc, 2);

  g_assert_cmpuint (fixture->sink->events->len, ==, 2);

  g_assert_cmpint (
      g_array_index (fixture->sink->events, GumEvent, 0).type, ==, GUM_RET);

  GUM_ASSERT_EVENT_ADDR (ret, 0, location, func + 32);
  GUM_ASSERT_EVENT_ADDR (ret, 0, target, func + 16);
  GUM_ASSERT_EVENT_ADDR (ret, 0, depth, 1);

  GUM_ASSERT_EVENT_ADDR (ret, 1, location, func + 16);
  GUM_ASSERT_EVENT_ADDR (ret, 1, depth, 0);
}

TESTCODE (thumb_ldm_pc,
  0xf0, 0xb5,             /* push {r4-r7, lr}        */
  0x00, 0x1a,             /* subs r0, r0, r0         */
  0x01, 0x30,             /* adds r0, 1              */
  0x00, 0xf0, 0x01, 0xf8, /* bl inner                */
  0xf0, 0xbd,             /* pop {r4-r7, pc}         */

  /* inner:                                          */
  0x00, 0xab,             /* add r3, sp, 0           */
  0x23, 0xe9, 0x06, 0x40, /* stmdb r3!, {r1, r2, lr} */
  0x01, 0x30,             /* adds r0, 1              */
  0xb3, 0xe8, 0x06, 0x80  /* ldm.w r3!, {r1, r2, pc} */
);

TESTCASE (thumb_ldm_pc_ret_events_generated)
{
  GumAddress func;

  func = INVOKE_THUMB_EXPECTING (GUM_RET, thumb_ldm_pc, 2);

  g_assert_cmpuint (fixture->sink->events->len, ==, 2);

  g_assert_cmpint (
      g_array_index (fixture->sink->events, GumEvent, 0).type, ==, GUM_RET);

  GUM_ASSERT_EVENT_ADDR (ret, 0, location, func + 20);
  GUM_ASSERT_EVENT_ADDR (ret, 0, target, func + 11);
  GUM_ASSERT_EVENT_ADDR (ret, 0, depth, 1);

  GUM_ASSERT_EVENT_ADDR (ret, 1, location, func + 10);
  GUM_ASSERT_EVENT_ADDR (ret, 1, depth, 0);
}

TESTCODE (arm_b_cc,
  0x00, 0x00, 0x40, 0xe0, /* sub r0, r0, r0 */
  0x01, 0x10, 0x41, 0xe0, /* sub r1, r1, r1 */

  0x00, 0x00, 0x51, 0xe3, /* cmp r1, 0      */
  0x00, 0x00, 0x00, 0x0a, /* beq after_a    */
  0x01, 0x00, 0x80, 0xe2, /* add r0, r0, 1  */
  /* after_a:                               */

  0x01, 0x00, 0x51, 0xe3, /* cmp r1, 1      */
  0x00, 0x00, 0x00, 0x0a, /* beq after_b    */
  0x02, 0x00, 0x80, 0xe2, /* add r0, r0, 2  */
  /* after_b:                               */

  0x00, 0x00, 0x51, 0xe3, /* cmp r1, 0      */
  0x00, 0x00, 0x00, 0xaa, /* bge after_c    */
  0x04, 0x00, 0x80, 0xe2, /* add r0, r0, 4  */
  /* after_c:                               */

  0x00, 0x00, 0x51, 0xe3, /* cmp r1, 0      */
  0x00, 0x00, 0x00, 0xba, /* blt after_d    */
  0x08, 0x00, 0x80, 0xe2, /* add r0, r0, 8  */
  /* after_d:                               */

  0x0e, 0xf0, 0xa0, 0xe1  /* mov pc, lr     */
);

TESTCASE (arm_branch_cc_block_events_generated)
{
  GumAddress func;

  func = INVOKE_ARM_EXPECTING (GUM_BLOCK, arm_b_cc, 10);

  g_assert_cmpuint (fixture->sink->events->len, ==, 4);

  GUM_ASSERT_EVENT_ADDR (block, 0, begin, func);
  GUM_ASSERT_EVENT_ADDR (block, 0, end, func + 16);

  GUM_ASSERT_EVENT_ADDR (block, 1, begin, func + 20);
  GUM_ASSERT_EVENT_ADDR (block, 1, end, func + 28);

  GUM_ASSERT_EVENT_ADDR (block, 2, begin, func + 28);
  GUM_ASSERT_EVENT_ADDR (block, 2, end, func + 40);

  GUM_ASSERT_EVENT_ADDR (block, 3, begin, func + 44);
  GUM_ASSERT_EVENT_ADDR (block, 3, end, func + 52);
}

TESTCODE (thumb_b_cc,
  0x00, 0xb5, /* push {lr}       */
  0x00, 0x1a, /* subs r0, r0, r0 */
  0x49, 0x1a, /* subs r1, r1, r1 */

  0x00, 0x29, /* cmp r1, 0       */
  0x00, 0xd0, /* beq after_a     */
  0x01, 0x30, /* adds r0, 1      */
  /* after_a:                    */

  0x01, 0x29, /* cmp r1, 1       */
  0x00, 0xd0, /* beq after_b     */
  0x02, 0x30, /* adds r0, 2      */
  /* after_b:                    */

  0x00, 0x29, /* cmp r1, 0       */
  0x00, 0xda, /* bge after_c     */
  0x04, 0x30, /* adds r0, 4      */
  /* after_c:                    */

  0x00, 0x29, /* cmp r1, 0       */
  0x00, 0xdb, /* blt after_d     */
  0x08, 0x30, /* adds r0, 8      */
  /* after_d:                    */

  0x00, 0xbd  /* pop {pc}        */
);

TESTCASE (thumb_branch_cc_block_events_generated)
{
  GumAddress func;

  func = INVOKE_THUMB_EXPECTING (GUM_BLOCK, thumb_b_cc, 10);

  g_assert_cmpuint (fixture->sink->events->len, ==, 4);

  GUM_ASSERT_EVENT_ADDR (block, 0, begin, func);
  GUM_ASSERT_EVENT_ADDR (block, 0, end, func + 10);

  GUM_ASSERT_EVENT_ADDR (block, 1, begin, func + 12);
  GUM_ASSERT_EVENT_ADDR (block, 1, end, func + 16);

  GUM_ASSERT_EVENT_ADDR (block, 2, begin, func + 16);
  GUM_ASSERT_EVENT_ADDR (block, 2, end, func + 22);

  GUM_ASSERT_EVENT_ADDR (block, 3, begin, func + 24);
  GUM_ASSERT_EVENT_ADDR (block, 3, end, func + 28);
}

TESTCODE (thumb_cbz_cbnz,
  0x00, 0xb5, /* push {lr}        */
  0x00, 0x1a, /* subs r0, r0, r0  */
  0x49, 0x1a, /* subs r1, r1, r1  */
  0x92, 0x1a, /* subs r2, r2, r2  */
  0x01, 0x32, /* adds r2, 1       */

  0x01, 0xb1, /* cbz r1, after_a  */
  0x01, 0x30, /* adds r0, 1       */
  /* after_a:                     */

  0x01, 0xb9, /* cbnz r1, after_b */
  0x02, 0x30, /* adds r0, 2       */
  /* after_b:                     */

  0x02, 0xb1, /* cbz r2, after_c  */
  0x04, 0x30, /* adds r0, 4       */
  /* after_c:                     */

  0x02, 0xb9, /* cbnz r2, after_d */
  0x08, 0x30, /* adds r0, 8       */
  /* after_d:                     */

  0x00, 0xbd  /* pop {pc}         */
);

TESTCASE (thumb_cbz_cbnz_block_events_generated)
{
  GumAddress func;

  func = INVOKE_THUMB_EXPECTING (GUM_BLOCK, thumb_cbz_cbnz, 6);

  g_assert_cmpuint (fixture->sink->events->len, ==, 4);

  GUM_ASSERT_EVENT_ADDR (block, 0, begin, func);
  GUM_ASSERT_EVENT_ADDR (block, 0, end, func + 12);

  GUM_ASSERT_EVENT_ADDR (block, 1, begin, func + 14);
  GUM_ASSERT_EVENT_ADDR (block, 1, end, func + 16);

  GUM_ASSERT_EVENT_ADDR (block, 2, begin, func + 16);
  GUM_ASSERT_EVENT_ADDR (block, 2, end, func + 20);

  GUM_ASSERT_EVENT_ADDR (block, 3, begin, func + 20);
  GUM_ASSERT_EVENT_ADDR (block, 3, end, func + 24);
}

TESTCODE (thumb2_mov_pc_reg,
  0x40, 0xb5, /* push {r6, lr}    */
  0x00, 0x1a, /* subs r0, r0, r0  */
  0x01, 0x4e, /* ldr r6, [pc, #4] */
  0xb7, 0x46, /* mov pc, r6       */

  0x0a, 0xde, /* udf 0x10         */
  0x0a, 0xde, /* udf 0x10         */
  /* inner_addr:                  */
  0xaa, 0xbb, 0xcc, 0xdd,

  /* inner:                       */
  0x01, 0x30, /* adds r0, #1      */
  0x40, 0xbd  /* pop {r6, pc}     */
);

TESTCASE (thumb2_mov_pc_reg_exec_events_generated)
{
  GumAddress func;

  func = DUP_TESTCODE (thumb2_mov_pc_reg);
  patch_code_pointer (func, 6 * 2, func + (8 * 2) + 1);

  fixture->sink->mask = GUM_EXEC;
  g_assert_cmpuint (FOLLOW_AND_INVOKE (func + 1), ==, 1);

  g_assert_cmpuint (fixture->sink->events->len, ==, INVOKER_INSN_COUNT + 6);

  GUM_ASSERT_EVENT_ADDR (exec, 2, location, func);
  GUM_ASSERT_EVENT_ADDR (exec, 3, location, func + 2);
  GUM_ASSERT_EVENT_ADDR (exec, 4, location, func + 4);
  GUM_ASSERT_EVENT_ADDR (exec, 5, location, func + 6);
  GUM_ASSERT_EVENT_ADDR (exec, 6, location, func + 16);
  GUM_ASSERT_EVENT_ADDR (exec, 7, location, func + 18);
}

TESTCASE (thumb2_mov_pc_reg_without_thumb_bit_set)
{
  GumAddress func;

  func = DUP_TESTCODE (thumb2_mov_pc_reg);
  patch_code_pointer (func, 6 * 2, func + (8 * 2) + 0);

  fixture->sink->mask = GUM_EXEC;
  g_assert_cmpuint (FOLLOW_AND_INVOKE (func + 1), ==, 1);

  g_assert_cmpuint (fixture->sink->events->len, ==, INVOKER_INSN_COUNT + 6);

  GUM_ASSERT_EVENT_ADDR (exec, 2, location, func);
  GUM_ASSERT_EVENT_ADDR (exec, 3, location, func + 2);
  GUM_ASSERT_EVENT_ADDR (exec, 4, location, func + 4);
  GUM_ASSERT_EVENT_ADDR (exec, 5, location, func + 6);
  GUM_ASSERT_EVENT_ADDR (exec, 6, location, func + 16);
  GUM_ASSERT_EVENT_ADDR (exec, 7, location, func + 18);
}

TESTCODE (thumb2_mov_pc_reg_no_clobber_reg,
  0x60, 0xb5, /* push {r5, r6, lr} */
  0x00, 0x1a, /* subs r0, r0, r0   */
  0x01, 0x4e, /* ldr r6, [pc, #4]  */
  0x35, 0x46, /* mov r5, r6        */
  0xb7, 0x46, /* mov pc, r6        */

  0x0a, 0xde, /* udf 0x10          */
  /* inner_addr:                   */
  0xaa, 0xbb, 0xcc, 0xdd,

  /* inner:                        */
  0xa8, 0x1b, /* subs r0, r5, r6   */
  0x60, 0xbd  /* pop {r5,r6, pc}   */
);

TESTCASE (thumb2_mov_pc_reg_no_clobber_reg)
{
  GumAddress func;

  func = DUP_TESTCODE (thumb2_mov_pc_reg_no_clobber_reg);
  patch_code_pointer (func, 6 * 2, func + (8 * 2) + 0);

  fixture->sink->mask = GUM_EXEC;
  g_assert_cmpuint (FOLLOW_AND_INVOKE (func + 1), ==, 0);

  g_assert_cmpuint (fixture->sink->events->len, ==, INVOKER_INSN_COUNT + 7);

  GUM_ASSERT_EVENT_ADDR (exec, 2, location, func);
  GUM_ASSERT_EVENT_ADDR (exec, 3, location, func + 2);
  GUM_ASSERT_EVENT_ADDR (exec, 4, location, func + 4);
  GUM_ASSERT_EVENT_ADDR (exec, 5, location, func + 6);
  GUM_ASSERT_EVENT_ADDR (exec, 6, location, func + 8);
  GUM_ASSERT_EVENT_ADDR (exec, 7, location, func + 16);
  GUM_ASSERT_EVENT_ADDR (exec, 8, location, func + 18);
}

TESTCODE (arm_bl_cc,
  0x04, 0xe0, 0x2d, 0xe5, /* push {lr}         */
  0x00, 0x00, 0x40, 0xe0, /* sub r0, r0, r0    */
  0x01, 0x10, 0x41, 0xe0, /* sub r1, r1, r1    */

  0x00, 0x00, 0x51, 0xe3, /* cmp r1, 0         */
  0x06, 0x00, 0x00, 0x0b, /* bleq func_a       */

  0x01, 0x00, 0x51, 0xe3, /* cmp r1, 1         */
  0x06, 0x00, 0x00, 0x0b, /* bleq func_b       */

  0x00, 0x00, 0x51, 0xe3, /* cmp r1, 0         */
  0x06, 0x00, 0x00, 0xab, /* blge func_c       */

  0x00, 0x00, 0x51, 0xe3, /* cmp r1, 0         */
  0x06, 0x00, 0x00, 0xbb, /* bllt func_d       */

  0x04, 0xf0, 0x9d, 0xe4, /* pop {pc}          */

  /* func_a:                                   */
  0x01, 0x00, 0x80, 0xe2, /* add r0, r0, 1     */
  0x0e, 0xf0, 0xa0, 0xe1, /* mov pc, lr        */

  /* func_b:                                   */
  0x02, 0x00, 0x80, 0xe2, /* add r0, r0, 2     */
  0x0e, 0xf0, 0xa0, 0xe1, /* mov pc, lr        */

  /* func_c:                                   */
  0x04, 0x00, 0x80, 0xe2, /* add r0, r0, 4     */
  0x0e, 0xf0, 0xa0, 0xe1, /* mov pc, lr        */

  /* func_d:                                   */
  0x08, 0x00, 0x80, 0xe2, /* add r0, r0, 8     */
  0x0e, 0xf0, 0xa0, 0xe1  /* mov pc, lr        */
);

TESTCASE (arm_branch_link_cc_block_events_generated)
{
  GumAddress func;

  func = INVOKE_ARM_EXPECTING (GUM_CALL, arm_bl_cc, 5);

  g_assert_cmpuint (fixture->sink->events->len, ==,
      INVOKER_CALL_INSN_COUNT + 2);

  GUM_ASSERT_EVENT_ADDR (call, 1, location, func + 16);
  GUM_ASSERT_EVENT_ADDR (call, 1, target, func + 48);

  GUM_ASSERT_EVENT_ADDR (call, 2, location, func + 32);
  GUM_ASSERT_EVENT_ADDR (call, 2, target, func + 64);
}

TESTCODE (arm_cc_excluded_range,
  0x00, 0x40, 0x2d, 0xe9, /* stmdb sp!, {lr}   */
  0x00, 0x00, 0x40, 0xe0, /* sub r0, r0, r0    */
  0x01, 0x10, 0x41, 0xe0, /* sub r1, r1, r1    */

  0x00, 0x00, 0x51, 0xe3, /* cmp r1, 0         */
  0x03, 0x00, 0x00, 0x0b, /* bleq func_a       */

  0x00, 0x00, 0x51, 0xe3, /* cmp r1, 0         */
  0x05, 0x00, 0x00, 0x1b, /* blne func_b       */

  0x00, 0x40, 0xbd, 0xe8, /* ldm sp!, {lr}     */
  0x0e, 0xf0, 0xa0, 0xe1, /* mov pc, lr        */

  /* func_a:                                   */
  0x04, 0xe0, 0x2d, 0xe5, /* push {lr}         */
  0x01, 0x00, 0x80, 0xe2, /* add r0, r0, 1     */
  0x04, 0x00, 0x00, 0xeb, /* bl func_c         */
  0x04, 0xf0, 0x9d, 0xe4, /* pop {pc}          */

  /* func_b:                                   */
  0x04, 0xe0, 0x2d, 0xe5, /* push {lr}         */
  0x02, 0x00, 0x80, 0xe2, /* add r0, r0, 2     */
  0x00, 0x00, 0x00, 0xeb, /* bl func_c         */
  0x04, 0xf0, 0x9d, 0xe4, /* pop {pc}          */

  /* func_c:                                   */
  0x0e, 0xf0, 0xa0, 0xe1  /* mov pc, lr        */
);

TESTCASE (arm_cc_excluded_range)
{
  GumAddress func;

  func = DUP_TESTCODE (arm_cc_excluded_range);

  {
    GumMemoryRange r = {
      .base_address = GUM_ADDRESS (func) + 36,
      .size = 36
    };

    gum_stalker_exclude (fixture->stalker, &r);
  }

  {
    fixture->sink->mask = GUM_CALL;
    g_assert_cmpuint (FOLLOW_AND_INVOKE (func), ==, 1);

    g_assert_cmpuint (fixture->sink->events->len, ==,
        INVOKER_CALL_INSN_COUNT + 1);

    GUM_ASSERT_EVENT_ADDR (call, 1, location, func + 16);
    GUM_ASSERT_EVENT_ADDR (call, 1, target, func + 36);
  }
}

TESTCODE (arm_ldr_pc,
  0x00, 0x00, 0x40, 0xe0, /* sub r0, r0, r0     */
  0x01, 0x00, 0x80, 0xe2, /* add r0, r0, 1      */
  0x04, 0xf0, 0x9f, 0xe5, /* ldr pc, inner_addr */
  0xf0, 0x01, 0xf0, 0xe7, /* udf 0x10           */

  0xec, 0xec, 0xec, 0xec,
  /* inner_addr:                                */
  0xaa, 0xbb, 0xcc, 0xdd,

  /* inner:                                     */
  0x01, 0x00, 0x80, 0xe2, /* add r0, r0, 1      */
  0x0e, 0xf0, 0xa0, 0xe1  /* mov pc, lr         */
);

TESTCASE (arm_ldr_pc)
{
  GumAddress func;

  func = DUP_TESTCODE (arm_ldr_pc);
  patch_code_pointer (func, 5 * 4, func + (6 * 4));

  fixture->sink->mask = GUM_BLOCK;
  g_assert_cmpuint (FOLLOW_AND_INVOKE (func), ==, 2);

  g_assert_cmpuint (fixture->sink->events->len, ==, 1);

  GUM_ASSERT_EVENT_ADDR (block, 0, begin, func);
  GUM_ASSERT_EVENT_ADDR (block, 0, end, func + 12);
}

TESTCODE (arm_ldr_pc_pre_index_imm,
  0x00, 0x00, 0x40, 0xe0, /* sub r0, r0, r0   */
  0x01, 0x00, 0x80, 0xe2, /* add r0, r0, 1    */
  0x04, 0x10, 0x8f, 0xe2, /* adr r1, imm_data */
  0x08, 0xf0, 0xb1, 0xe5, /* ldr pc, [r1, 8]! */
  0xf0, 0x01, 0xf0, 0xe7, /* udf 0x10         */

  /* imm_data:                                */
  0xec, 0xec, 0xec, 0xec,
  0xf0, 0xf0, 0xf0, 0xf0,
  /* inner_addr:                              */
  0xaa, 0xbb, 0xcc, 0xdd,
  0xba, 0xba, 0xba, 0xba,

  /* inner:                                   */
  0x04, 0x10, 0x91, 0xe5, /* ldr r1, [r1, 4]  */
  0x01, 0x00, 0x80, 0xe0, /* add r0, r0, r1   */
  0x0e, 0xf0, 0xa0, 0xe1  /* mov pc, lr       */
);

TESTCASE (arm_ldr_pc_pre_index_imm)
{
  GumAddress func;

  func = DUP_TESTCODE (arm_ldr_pc_pre_index_imm);
  patch_code_pointer (func, 7 * 4, func + (9 * 4));

  fixture->sink->mask = GUM_BLOCK;
  g_assert_cmpuint (FOLLOW_AND_INVOKE (func), ==, 0xbabababb);

  g_assert_cmpuint (fixture->sink->events->len, ==, 1);

  GUM_ASSERT_EVENT_ADDR (block, 0, begin, func);
  GUM_ASSERT_EVENT_ADDR (block, 0, end, func + 16);
}

TESTCODE (arm_ldr_pc_post_index_imm,
  0x00, 0x00, 0x40, 0xe0, /* sub r0, r0, r0     */
  0x01, 0x00, 0x80, 0xe2, /* add r0, r0, 1      */
  0x04, 0x10, 0x8f, 0xe2, /* adr r1, inner_addr */
  0x08, 0xf0, 0x91, 0xe4, /* ldr pc, [r1], 8    */
  0xf0, 0x01, 0xf0, 0xe7, /* udf 0x10           */

  /* inner_addr:                                */
  0xaa, 0xbb, 0xcc, 0xdd,
  0xf0, 0xf0, 0xf0, 0xf0,
  0xba, 0xba, 0xba, 0xba,

  /* inner:                                     */
  0x00, 0x10, 0x91, 0xe5, /* ldr r1, [r1]       */
  0x01, 0x00, 0x80, 0xe0, /* add r0, r0, r1     */
  0x0e, 0xf0, 0xa0, 0xe1  /* mov pc, lr         */
);

TESTCASE (arm_ldr_pc_post_index_imm)
{
  GumAddress func;

  func = DUP_TESTCODE (arm_ldr_pc_post_index_imm);
  patch_code_pointer (func, 5 * 4, func + (8 * 4));

  fixture->sink->mask = GUM_BLOCK;
  g_assert_cmpuint (FOLLOW_AND_INVOKE (func), ==, 0xbabababb);

  g_assert_cmpuint (fixture->sink->events->len, ==, 1);

  GUM_ASSERT_EVENT_ADDR (block, 0, begin, func);
  GUM_ASSERT_EVENT_ADDR (block, 0, end, func + 16);
}

TESTCODE (arm_ldr_pc_pre_index_imm_negative,
  0x00, 0x00, 0x40, 0xe0, /* sub r0, r0, r0        */
  0x01, 0x00, 0x80, 0xe2, /* add r0, r0, 1         */
  0x0c, 0x10, 0x8f, 0xe2, /* adr r1, negative_data */
  0x08, 0xf0, 0x31, 0xe5, /* ldr pc, [r1, -8]!     */
  0xf0, 0x01, 0xf0, 0xe7, /* udf 0x10              */

  /* inner_addr:                                   */
  0xaa, 0xbb, 0xcc, 0xdd,
  0xec, 0xec, 0xec, 0xec,
  /* negative_data:                                */
  0xf0, 0xf0, 0xf0, 0xf0,
  0xba, 0xba, 0xba, 0xba,

  /* inner:                                        */
  0x0c, 0x10, 0x91, 0xe5, /* ldr r1, [r1, 12]      */
  0x01, 0x00, 0x80, 0xe0, /* add r0, r0, r1        */
  0x0e, 0xf0, 0xa0, 0xe1  /* mov pc, lr            */
);

TESTCASE (arm_ldr_pc_pre_index_imm_negative)
{
  GumAddress func;

  func = DUP_TESTCODE (arm_ldr_pc_pre_index_imm_negative);
  patch_code_pointer (func, 5 * 4, func + (9 * 4));

  fixture->sink->mask = GUM_BLOCK;
  g_assert_cmpuint (FOLLOW_AND_INVOKE (func), ==, 0xbabababb);

  g_assert_cmpuint (fixture->sink->events->len, ==, 1);

  GUM_ASSERT_EVENT_ADDR (block, 0, begin, func);
  GUM_ASSERT_EVENT_ADDR (block, 0, end, func + 16);
}

TESTCODE (arm_ldr_pc_post_index_imm_negative,
  0x00, 0x00, 0x40, 0xe0, /* sub r0, r0, r0     */
  0x01, 0x00, 0x80, 0xe2, /* add r0, r0, 1      */
  0x0c, 0x10, 0x8f, 0xe2, /* adr r1, inner_addr */
  0x08, 0xf0, 0x11, 0xe4, /* ldr pc, [r1], -8   */
  0xf0, 0x01, 0xf0, 0xe7, /* udf 0x10           */

  0xba, 0xba, 0xba, 0xba,
  0xf0, 0xf0, 0xf0, 0xf0,
  /* inner_addr:                                */
  0xaa, 0xbb, 0xcc, 0xdd,

  /* inner:                                     */
  0x00, 0x10, 0x91, 0xe5, /* ldr r1, [r1]       */
  0x01, 0x00, 0x80, 0xe0, /* add r0, r0, r1     */
  0x0e, 0xf0, 0xa0, 0xe1  /* mov pc, lr         */
);

TESTCASE (arm_ldr_pc_post_index_imm_negative)
{
  GumAddress func;

  func = DUP_TESTCODE (arm_ldr_pc_post_index_imm_negative);
  patch_code_pointer (func, 7 * 4, func + (8 * 4));

  fixture->sink->mask = GUM_BLOCK;
  g_assert_cmpuint (FOLLOW_AND_INVOKE (func), ==, 0xbabababb);

  g_assert_cmpuint (fixture->sink->events->len, ==, 1);

  GUM_ASSERT_EVENT_ADDR (block, 0, begin, func);
  GUM_ASSERT_EVENT_ADDR (block, 0, end, func + 16);
}

TESTCODE (arm_sub_pc,
  0x00, 0x00, 0x40, 0xe0, /* sub r0, r0, r0 */
  0x01, 0x00, 0x00, 0xea, /* b part_two     */

  0x01, 0x00, 0x80, 0xe2, /* add r0, r0, 1  */
  0x0e, 0xf0, 0xa0, 0xe1, /* mov pc, lr     */

  /* part_two:                              */
  0x01, 0x00, 0x80, 0xe2, /* add r0, r0, 1  */
  0x14, 0xf0, 0x4f, 0xe2  /* sub pc, pc, 20 */
);

TESTCASE (arm_sub_pc)
{
  GumAddress func;

  func = INVOKE_ARM_EXPECTING (GUM_BLOCK, arm_sub_pc, 2);

  g_assert_cmpuint (fixture->sink->events->len, ==, 2);

  GUM_ASSERT_EVENT_ADDR (block, 0, begin, func);
  GUM_ASSERT_EVENT_ADDR (block, 0, end, func + 8);

  GUM_ASSERT_EVENT_ADDR (block, 1, begin, func + 16);
  GUM_ASSERT_EVENT_ADDR (block, 1, end, func + 24);
}

TESTCODE (arm_add_pc,
  0x00, 0x00, 0x40, 0xe0, /* sub r0, r0, r0 */
  0x04, 0xf0, 0x8f, 0xe2, /* add pc, pc, 4  */

  /* beach:                                 */
  0x01, 0x00, 0x80, 0xe2, /* add r0, r0, 1  */
  0x0e, 0xf0, 0xa0, 0xe1, /* mov pc, lr     */

  0x01, 0x00, 0x80, 0xe2, /* add r0, r0, 1  */
  0xfb, 0xff, 0xff, 0xea  /* b beach        */
);

TESTCASE (arm_add_pc)
{
  GumAddress func;

  func = INVOKE_ARM_EXPECTING (GUM_BLOCK, arm_add_pc, 2);

  g_assert_cmpuint (fixture->sink->events->len, ==, 2);

  GUM_ASSERT_EVENT_ADDR (block, 0, begin, func);
  GUM_ASSERT_EVENT_ADDR (block, 0, end, func + 8);

  GUM_ASSERT_EVENT_ADDR (block, 1, begin, func + 16);
  GUM_ASSERT_EVENT_ADDR (block, 1, end, func + 24);
}

TESTCODE (thumb_it_eq,
  0x00, 0xb5, /* push {lr}       */
  0x00, 0x1a, /* subs r0, r0, r0 */
  0x00, 0x28, /* cmp r0, #0      */
  0x08, 0xbf, /* it eq           */
  0x01, 0x30, /* adds r0, #1     */

  /* part_two:                   */
  0x00, 0x28, /* cmp r0, #0      */
  0x08, 0xbf, /* it eq           */
  0x02, 0x30, /* adds r0, #2     */
  0x00, 0xbd, /* pop {pc}        */
);

TESTCASE (thumb_it_eq)
{
  INVOKE_THUMB_EXPECTING (GUM_NOTHING, thumb_it_eq, 1);

  g_assert_cmpuint (fixture->sink->events->len, ==, 0);
}

TESTCODE (thumb_it_eq_branch,
  0x00, 0xb5, /* push {lr}       */
  0x00, 0x1a, /* subs r0, r0, r0 */
  0x00, 0x28, /* cmp r0, #0      */
  0x08, 0xbf, /* it eq           */
  0x00, 0xe0, /* b part_two      */
  0x00, 0xde, /* udf 0           */

  /* part_two:                   */
  0x01, 0x28, /* cmp r0, #1      */
  0x08, 0xbf, /* it eq           */
  0x00, 0xe0, /* b part_three    */
  0x00, 0xbd, /* pop {pc}        */

  /* part_three:                 */
  0x00, 0xde  /* udf 0           */
);

TESTCASE (thumb_it_eq_branch)
{
  GumAddress func;

  func = INVOKE_THUMB_EXPECTING (GUM_BLOCK, thumb_it_eq_branch, 0);

  g_assert_cmpuint (fixture->sink->events->len, ==, 1);

  GUM_ASSERT_EVENT_ADDR (block, 0, begin, func);
  GUM_ASSERT_EVENT_ADDR (block, 0, end, func + 10);
}

TESTCODE (thumb_itt_eq_branch,
  0x00, 0xb5, /* push {lr}       */
  0x00, 0x1a, /* subs r0, r0, r0 */
  0x49, 0x1a, /* subs r1, r1, r1 */
  0x00, 0x29, /* cmp r1, #0      */
  0x04, 0xbf, /* itt eq          */
  0x01, 0x30, /* add r0, #1      */
  0x00, 0xe0, /* b part_two      */
  0x00, 0xde, /* udf 0           */

  /* part_two:                   */
  0x01, 0x29, /* cmp r1, #1      */
  0x04, 0xbf, /* itt eq          */
  0x02, 0x30, /* add r0, #2      */
  0x00, 0xe0, /* b part_three    */
  0x00, 0xbd, /* pop {pc}        */

  /* part_three:                 */
  0x00, 0xde  /* udf 0           */
);

TESTCASE (thumb_itt_eq_branch)
{
  GumAddress func;

  func = INVOKE_THUMB_EXPECTING (GUM_BLOCK, thumb_itt_eq_branch, 1);

  g_assert_cmpuint (fixture->sink->events->len, ==, 1);

  GUM_ASSERT_EVENT_ADDR (block, 0, begin, func);
  GUM_ASSERT_EVENT_ADDR (block, 0, end, func + 14);
}

TESTCODE (thumb_ite_eq_branch,
  0x00, 0xb5, /* push {lr}       */
  0x00, 0x1a, /* subs r0, r0, r0 */
  0x49, 0x1a, /* subs r1, r1, r1 */
  0x01, 0x29, /* cmp r1, #1      */
  0x0c, 0xbf, /* ite eq          */
  0x01, 0x30, /* add r0, #1      */
  0x00, 0xe0, /* b part_two      */
  0x00, 0xde, /* udf 0           */

  /* part_two:                   */
  0x00, 0x29, /* cmp r1, #0      */
  0x0c, 0xbf, /* ite eq          */
  0x02, 0x30, /* add r0, #2      */
  0x00, 0xe0, /* b part_three    */
  0x00, 0xbd, /* pop {pc}        */

  /* part_three:                 */
  0x00, 0xde  /* udf 0           */
);

TESTCASE (thumb_ite_eq_branch)
{
  GumAddress func;

  func = INVOKE_THUMB_EXPECTING (GUM_BLOCK, thumb_ite_eq_branch, 2);

  g_assert_cmpuint (fixture->sink->events->len, ==, 1);

  GUM_ASSERT_EVENT_ADDR (block, 0, begin, func);
  GUM_ASSERT_EVENT_ADDR (block, 0, end, func + 14);
}

TESTCODE (thumb_it_eq_branch_link,
  0x00, 0xb5,             /* push {lr}       */
  0x00, 0x1a,             /* subs r0, r0, r0 */
  0x49, 0x1a,             /* subs r1, r1, r1 */
  0x01, 0x31,             /* adds r1, #1     */
  0x00, 0x28,             /* cmp r0, #0      */
  0x08, 0xbf,             /* it eq           */
  0x00, 0xf0, 0x06, 0xf8, /* bl part_three   */

  /* part_two:                               */
  0x01, 0x31,             /* adds r1, #1     */
  0x00, 0x28,             /* cmp r0, #0      */
  0x08, 0xbf,             /* it eq           */
  0x00, 0xf0, 0x01, 0xf8, /* bl part_three   */
  0x00, 0xbd,             /* pop {pc}        */

  /* part_three:                             */
  0x00, 0xb5,             /* push {lr}       */
  0x08, 0x44,             /* add r0, r1      */
  0x00, 0xbd,             /* pop {pc}        */
);

TESTCASE (thumb_it_eq_branch_link)
{
  GumAddress func;

  func = INVOKE_THUMB_EXPECTING (GUM_CALL, thumb_it_eq_branch_link, 1);

  g_assert_cmpuint (fixture->sink->events->len, ==,
      INVOKER_CALL_INSN_COUNT + 1);

  GUM_ASSERT_EVENT_ADDR (call, 1, location, func + 10);
  GUM_ASSERT_EVENT_ADDR (call, 1, target, func + 29);
}

TESTCASE (thumb_it_eq_branch_link_excluded)
{
  GumAddress func;

  func = DUP_TESTCODE (thumb_it_eq_branch_link);

  {
    GumMemoryRange r = {
      .base_address = GUM_ADDRESS (func) + 28,
      .size = 6
    };

    gum_stalker_exclude (fixture->stalker, &r);
  }

  {
    fixture->sink->mask = GUM_EXEC;
    g_assert_cmpuint (FOLLOW_AND_INVOKE (func + 1), ==, 1);

    g_assert_cmpuint (fixture->sink->events->len, ==, INVOKER_INSN_COUNT + 10);

    GUM_ASSERT_EVENT_ADDR (exec, 2, location, func);
    GUM_ASSERT_EVENT_ADDR (exec, 3, location, func + 2);
    GUM_ASSERT_EVENT_ADDR (exec, 4, location, func + 4);
    GUM_ASSERT_EVENT_ADDR (exec, 5, location, func + 6);
    GUM_ASSERT_EVENT_ADDR (exec, 6, location, func + 8);
    GUM_ASSERT_EVENT_ADDR (exec, 7, location, func + 10);
    GUM_ASSERT_EVENT_ADDR (exec, 8, location, func + 16);
    GUM_ASSERT_EVENT_ADDR (exec, 9, location, func + 18);
    GUM_ASSERT_EVENT_ADDR (exec, 10, location, func + 20);
    GUM_ASSERT_EVENT_ADDR (exec, 11, location, func + 26);
  }
}

TESTCODE (thumb_it_eq_pop,
  0x00, 0xb5,             /* push {lr}       */
  0x00, 0x1a,             /* subs r0, r0, r0 */
  0x01, 0x30,             /* adds r0, #1     */
  0x00, 0xf0, 0x03, 0xf8, /* bl part_two     */
  0x00, 0xf0, 0x01, 0xf8, /* bl part_two     */
  0x00, 0xbd,             /* pop {pc}        */

  /* part_two:                               */
  0x04, 0xb5,             /* push {r2, lr}   */
  0x02, 0x28,             /* cmp r0, #2      */
  0x08, 0xbf,             /* it eq           */
  0x04, 0xbd,             /* pop {r2, pc}    */
  0x01, 0x30,             /* adds r0, #1     */
  0x04, 0xbd,             /* pop {r2, pc}    */
);

TESTCASE (thumb_it_eq_pop)
{
  GumAddress func;

  func = INVOKE_THUMB_EXPECTING (GUM_RET, thumb_it_eq_pop, 2);

  g_assert_cmpuint (fixture->sink->events->len, ==, 3);

  GUM_ASSERT_EVENT_ADDR (ret, 0, location, func + 26);
  GUM_ASSERT_EVENT_ADDR (ret, 0, target, func + 11);

  GUM_ASSERT_EVENT_ADDR (ret, 1, location, func + 20);
  GUM_ASSERT_EVENT_ADDR (ret, 1, target, func + 15);

  GUM_ASSERT_EVENT_ADDR (ret, 2, location, func + 14);
}

TESTCODE (thumb_itttt_eq_blx_reg,
  0x00, 0xb5, /* push {lr}       */
  0x00, 0x1a, /* subs r0, r0, r0 */
  0x49, 0x1a, /* subs r1, r1, r1 */
  0x79, 0x44, /* add r1, pc      */
  0x1b, 0x31, /* adds r1, #27    */
  0x00, 0x28, /* cmp r0, #0      */
  0x01, 0xbf, /* itttt eq        */
  0x01, 0x30, /* adds r0, #1     */
  0x01, 0x30, /* adds r0, #1     */
  0x01, 0x30, /* adds r0, #1     */
  0x88, 0x47, /* blx r1          */

  /* part_two:                   */
  0x00, 0x28, /* cmp r0, #0      */
  0x01, 0xbf, /* itttt eq        */
  0x02, 0x30, /* adds r0, #2     */
  0x02, 0x30, /* adds r0, #2     */
  0x02, 0x30, /* adds r0, #2     */
  0x88, 0x47, /* blx r1          */
  0x00, 0xbd, /* pop {pc}        */

  /* part_three:                 */
  0x00, 0xb5, /* push {lr}       */
  0x01, 0x30, /* adds r0, #1     */
  0x00, 0xbd, /* pop {pc}        */
);

TESTCASE (thumb_itttt_eq_blx_reg)
{
  INVOKE_THUMB_EXPECTING (GUM_EXEC | GUM_CALL, thumb_itttt_eq_blx_reg, 4);
  g_assert_cmpuint (fixture->sink->events->len, ==, INVOKER_INSN_COUNT + 16);
}

TESTCODE (thumb_it_flags,
  0x00, 0xb5, /* push {lr}       */
  0x00, 0x1a, /* subs r0, r0, r0 */
  0x00, 0x28, /* cmp r0, #0      */
  0x08, 0xbf, /* ite eq          */
  0x01, 0x30, /* adds r0, #1     */

  /* part_two:                   */
  0x08, 0xbf, /* it eq           */
  0x02, 0x30, /* adds r0, #2     */
  0x00, 0xbd, /* pop {pc}        */
);

TESTCASE (thumb_it_flags)
{
  INVOKE_THUMB_EXPECTING (GUM_NOTHING, thumb_it_flags, 3);

  g_assert_cmpuint (fixture->sink->events->len, ==, 0);
}

TESTCODE (thumb_tbb,
  0x00, 0xb5,             /* push {lr}            */
  0x00, 0x20,             /* movs r0, 0           */

  0x01, 0x21,             /* movs r1, 1           */
  0xdf, 0xe8, 0x01, 0xf0, /* tbb [pc, r1]         */

  /* table1:                                      */
  0x02,                   /* (one - table1) / 2   */
  0x03,                   /* (two - table1) / 2   */
  0x04,                   /* (three - table1) / 2 */
  0xff,                   /* <alignment padding>  */

  /* one:                                         */
  0x40, 0x1c,             /* adds r0, r0, 1       */
  /* two:                                         */
  0x80, 0x1c,             /* adds r0, r0, 2       */
  /* three:                                       */
  0xc0, 0x1c,             /* adds r0, r0, 3       */

  0x00, 0xbd,             /* pop {pc}             */
);

TESTCASE (thumb_tbb)
{
  GumAddress func;

  func = INVOKE_THUMB_EXPECTING (GUM_RET, thumb_tbb, 5);

  g_assert_cmpuint (fixture->sink->events->len, ==, 1);

  GUM_ASSERT_EVENT_ADDR (ret, 0, location, func + 20);
}

TESTCODE (thumb_tbh,
  0x00, 0xb5,             /* push {lr}            */
  0x00, 0x20,             /* movs r0, 0           */

  0x5f, 0xf0, 0x02, 0x0c, /* movs.w ip, 2         */
  0xdf, 0xe8, 0x1c, 0xf0, /* tbh [pc, ip, lsl 1]  */

  /* table1:                                      */
  0x03, 0x00,             /* (one - table1) / 2   */
  0x04, 0x00,             /* (two - table1) / 2   */
  0x05, 0x00,             /* (three - table1) / 2 */

  /* one:                                         */
  0x40, 0x1c,             /* adds r0, r0, 1       */
  /* two:                                         */
  0x80, 0x1c,             /* adds r0, r0, 2       */
  /* three:                                       */
  0xc0, 0x1c,             /* adds r0, r0, 3       */

  0x00, 0xbd,             /* pop {pc}             */
);

TESTCASE (thumb_tbh)
{
  GumAddress func;

  func = INVOKE_THUMB_EXPECTING (GUM_RET, thumb_tbh, 3);

  g_assert_cmpuint (fixture->sink->events->len, ==, 1);

  GUM_ASSERT_EVENT_ADDR (ret, 0, location, func + 24);
}

TESTCODE (thumb_strex_no_exec_events,
  0x00, 0xb5,             /* push {lr}          */
  0x00, 0x20,             /* movs r0, 0         */

  0x02, 0xb4,             /* push {r1}          */

  0x5d, 0xe8, 0x00, 0x1f, /* ldrex r1, [sp]     */
  0x01, 0x31,             /* adds r1, #1        */
  0x01, 0x31,             /* adds r1, #1        */
  0x01, 0x31,             /* adds r1, #1        */
  0x01, 0x31,             /* adds r1, #1        */

  0x5d, 0xe8, 0x00, 0x1f, /* ldrex r1, [sp]     */
  0x01, 0x31,             /* adds r1, #1        */
  0x4d, 0xe8, 0x00, 0x12, /* strex r2, r1, [sp] */
  0x01, 0x31,             /* adds r1, #1        */

  0x02, 0xbc,             /* pop {r1}           */
  0x00, 0xbd,             /* pop {pc}           */
);

TESTCASE (thumb_strex_no_exec_events)
{
  GumAddress func;

  func = INVOKE_THUMB_EXPECTING (GUM_EXEC, thumb_strex_no_exec_events, 0);

  g_assert_cmpuint (fixture->sink->events->len, ==, INVOKER_INSN_COUNT + 7);

  GUM_ASSERT_EVENT_ADDR (exec, 2, location, func);
  GUM_ASSERT_EVENT_ADDR (exec, 3, location, func + 2);
  GUM_ASSERT_EVENT_ADDR (exec, 4, location, func + 4);
  GUM_ASSERT_EVENT_ADDR (exec, 5, location, func + 16);
  GUM_ASSERT_EVENT_ADDR (exec, 6, location, func + 28);
  GUM_ASSERT_EVENT_ADDR (exec, 7, location, func + 30);
  GUM_ASSERT_EVENT_ADDR (exec, 8, location, func + 32);
}

TESTCODE (self_modifying_code_should_be_detected,
  0x00, 0x00, 0x40, 0xe0, /* sub r0, r0, r0 */
  0x01, 0x00, 0x80, 0xe2, /* add r0, r0, 1  */
  0x0e, 0xf0, 0xa0, 0xe1, /* mov pc, lr     */
);

TESTCASE (self_modifying_code_should_be_detected_with_threshold_minus_one)
{
  GumAddress func;
  guint (* callback) (void);
  guint value;

  func = DUP_TESTCODE (self_modifying_code_should_be_detected);
  callback = GUM_POINTER_TO_FUNCPTR (guint (*) (void), func);

  fixture->sink->mask = GUM_EXEC | GUM_CALL | GUM_RET;

  gum_stalker_set_trust_threshold (fixture->stalker, -1);
  gum_stalker_follow_me (fixture->stalker, fixture->transformer,
      GUM_EVENT_SINK (fixture->sink));

  value = callback ();
  g_assert_cmpuint (value, ==, 1);

  patch_code_pointer (func, 4, 0xe2800002);
  value = callback ();
  g_assert_cmpuint (value, ==, 2);
  callback ();
  callback ();

  patch_code_pointer (func, 4, 0xe2800003);
  value = callback ();
  g_assert_cmpuint (value, ==, 3);

  gum_stalker_unfollow_me (fixture->stalker);

  g_assert_cmpuint (fixture->sink->events->len, >, 0);
}

TESTCASE (self_modifying_code_should_not_be_detected_with_threshold_zero)
{
  GumAddress func;
  guint (* callback) (void);
  guint value;

  func = DUP_TESTCODE (self_modifying_code_should_be_detected);
  callback = GUM_POINTER_TO_FUNCPTR (guint (*) (void), func);

  fixture->sink->mask = GUM_EXEC | GUM_CALL | GUM_RET;

  gum_stalker_set_trust_threshold (fixture->stalker, 0);
  gum_stalker_follow_me (fixture->stalker, fixture->transformer,
      GUM_EVENT_SINK (fixture->sink));

  value = callback ();
  g_assert_cmpuint (value, ==, 1);

  patch_code_pointer (func, 4, 0xe2800002);
  value = callback ();
  g_assert_cmpuint (value, ==, 1);

  gum_stalker_unfollow_me (fixture->stalker);

  g_assert_cmpuint (fixture->sink->events->len, >, 0);
}

TESTCASE (self_modifying_code_should_be_detected_with_threshold_one)
{
  GumAddress func;
  guint (* callback) (void);
  guint value;

  func = DUP_TESTCODE (self_modifying_code_should_be_detected);
  callback = GUM_POINTER_TO_FUNCPTR (guint (*) (void), func);

  fixture->sink->mask = GUM_EXEC | GUM_CALL | GUM_RET;

  gum_stalker_set_trust_threshold (fixture->stalker, 1);
  gum_stalker_follow_me (fixture->stalker, fixture->transformer,
      GUM_EVENT_SINK (fixture->sink));

  value = callback ();
  g_assert_cmpuint (value, ==, 1);

  patch_code_pointer (func, 4, 0xe2800002);
  value = callback ();
  g_assert_cmpuint (value, ==, 2);
  callback ();
  callback ();

  patch_code_pointer (func, 4, 0xe2800003);
  value = callback ();
  g_assert_cmpuint (value, ==, 2);

  gum_stalker_unfollow_me (fixture->stalker);

  g_assert_cmpuint (fixture->sink->events->len, >, 0);
}

TESTCODE (call_thumb,
  0x04, 0xe0, 0x2d, 0xe5, /* push {lr}      */
  0x00, 0x00, 0x40, 0xe0, /* sub r0, r0, r0 */
  0x01, 0x00, 0x80, 0xe2, /* add r0, r0, 1  */
  0x05, 0x00, 0x00, 0xfa, /* blx func_c     */
  0x00, 0x00, 0x00, 0xeb, /* bl func_a      */
  0x04, 0xf0, 0x9d, 0xe4, /* pop {pc}       */

  /* func_a:                                */
  0x01, 0x00, 0x80, 0xe2, /* add r0, r0, 1  */
  0x0e, 0xf0, 0xa0, 0xe1, /* mov pc, lr     */

  /* func_b:                                */
  0x01, 0x00, 0x80, 0xe2, /* add r0, r0, 1  */
  0x0e, 0xf0, 0xa0, 0xe1, /* mov pc, lr     */

  /* func_c:                                */
  0x00, 0xb5,             /* push {lr}      */
  0x01, 0x30,             /* adds r0, 1     */
  0xff, 0xf7, 0xf8, 0xef, /* blx func_b     */
  0x00, 0xbd,             /* pop {pc}       */
);

TESTCASE (call_thumb)
{
  GumAddress func;

  func = INVOKE_ARM_EXPECTING (GUM_CALL, call_thumb, 4);

  g_assert_cmpuint (fixture->sink->events->len, ==,
      INVOKER_CALL_INSN_COUNT + 3);

  GUM_ASSERT_EVENT_ADDR (call, 1, location, func + 12);
  GUM_ASSERT_EVENT_ADDR (call, 1, target, func + 41);
  GUM_ASSERT_EVENT_ADDR (call, 1, depth, 1);

  GUM_ASSERT_EVENT_ADDR (call, 2, location, func + 44);
  GUM_ASSERT_EVENT_ADDR (call, 2, target, func + 32);
  GUM_ASSERT_EVENT_ADDR (call, 2, depth, 2);

  GUM_ASSERT_EVENT_ADDR (call, 3, location, func + 16);
  GUM_ASSERT_EVENT_ADDR (call, 3, target, func + 24);
  GUM_ASSERT_EVENT_ADDR (call, 3, depth, 1);
}

TESTCODE (branch_thumb,
  0x00, 0x00, 0x40, 0xe0, /* sub r0, r0, r0 */
  0x01, 0x00, 0x80, 0xe2, /* add r0, r0, 1  */
  0x08, 0x10, 0x8f, 0xe2, /* adr r1, func_a */
  0x14, 0x20, 0x8f, 0xe2, /* adr r2, func_c */
  0x01, 0x20, 0x82, 0xe2, /* add r2, r2, 1  */
  0x12, 0xff, 0x2f, 0xe1, /* bx r2          */

  /* func_a:                                */
  0x00, 0x00, 0x00, 0xea, /* b func_b       */

  /* beach:                                 */
  0x0e, 0xf0, 0xa0, 0xe1, /* mov pc, lr     */

  /* func_b:                                */
  0x01, 0x00, 0x80, 0xe2, /* add r0, r0, 1  */
  0xfc, 0xff, 0xff, 0xea, /* b beach        */

  /* func_c:                                */
  0x01, 0x30,             /* adds r0, 1     */
  0x08, 0x47              /* bx r1          */
);

TESTCASE (branch_thumb)
{
  GumAddress func;

  func = INVOKE_ARM_EXPECTING (GUM_BLOCK, branch_thumb, 3);

  g_assert_cmpuint (fixture->sink->events->len, ==, INVOKER_BLOCK_COUNT + 4);

  GUM_ASSERT_EVENT_ADDR (block, 0, begin, func);
  GUM_ASSERT_EVENT_ADDR (block, 0, end, func + 24);

  GUM_ASSERT_EVENT_ADDR (block, 1, begin, func + 40);
  GUM_ASSERT_EVENT_ADDR (block, 1, end, func + 44);

  GUM_ASSERT_EVENT_ADDR (block, 2, begin, func + 24);
  GUM_ASSERT_EVENT_ADDR (block, 2, end, func + 28);

  GUM_ASSERT_EVENT_ADDR (block, 3, begin, func + 32);
  GUM_ASSERT_EVENT_ADDR (block, 3, end, func + 40);
}

TESTCODE (call_workload,
  0x02, 0x40, 0x2d, 0xe9, /* push {r1, lr}         */
  0x04, 0x10, 0x9f, 0xe5, /* ldr r1, workload_addr */
  0x31, 0xff, 0x2f, 0xe1, /* blx r1                */
  0x02, 0x80, 0xbd, 0xe8  /* pop {r1, pc}          */
);

TESTCASE (can_follow_workload)
{
  GumAddress func;
  void (* call_workload_impl) (GumMemoryRange * runner_range);
  GumMemoryRange runner_range;

#ifdef __ARM_PCS_VFP
  if (!g_test_slow ())
  {
    g_print ("<skipping, run in slow mode> ");
    return;
  }
#endif

  func = DUP_TESTCODE (call_workload);
  patch_code_pointer (func, 4 * 4, GUM_ADDRESS (pretend_workload));
  call_workload_impl = GSIZE_TO_POINTER (func);

  runner_range.base_address = 0;
  runner_range.size = 0;
  gum_process_enumerate_modules (store_range_of_test_runner, &runner_range);

  call_workload_impl (&runner_range);

  g_test_log_set_fatal_handler (test_log_fatal_func, NULL);
  g_log_set_writer_func (test_log_writer_func, NULL, NULL);

  fixture->sink->mask = GUM_RET;
  gum_stalker_follow_me (fixture->stalker, fixture->transformer,
      GUM_EVENT_SINK (fixture->sink));

  call_workload_impl (&runner_range);

  gum_stalker_unfollow_me (fixture->stalker);

  GUM_ASSERT_EVENT_ADDR (ret, fixture->sink->events->len - 1, location,
      func + 12);
}

TESTCASE (performance)
{
  GumMemoryRange runner_range;
  GTimer * timer;
  gdouble normal_cold, normal_hot;
  gdouble stalker_cold, stalker_hot;

#ifdef __ARM_PCS_VFP
  if (!g_test_slow ())
  {
    g_print ("<skipping, run in slow mode> ");
    return;
  }
#endif

  runner_range.base_address = 0;
  runner_range.size = 0;
  gum_process_enumerate_modules (store_range_of_test_runner, &runner_range);

  timer = g_timer_new ();
  pretend_workload (&runner_range);

  g_timer_reset (timer);
  pretend_workload (&runner_range);
  normal_cold = g_timer_elapsed (timer, NULL);

  g_timer_reset (timer);
  pretend_workload (&runner_range);
  normal_hot = g_timer_elapsed (timer, NULL);

  g_test_log_set_fatal_handler (test_log_fatal_func, NULL);
  g_log_set_writer_func (test_log_writer_func, NULL, NULL);

  fixture->sink->mask = GUM_NOTHING;
  gum_stalker_follow_me (fixture->stalker, fixture->transformer,
      GUM_EVENT_SINK (fixture->sink));

  g_timer_reset (timer);
  pretend_workload (&runner_range);
  stalker_cold = g_timer_elapsed (timer, NULL);

  g_timer_reset (timer);
  pretend_workload (&runner_range);
  stalker_hot = g_timer_elapsed (timer, NULL);

  gum_stalker_unfollow_me (fixture->stalker);

  g_timer_destroy (timer);

  g_print ("\n");
  g_print ("\t<normal_cold=%f>\n", normal_cold);
  g_print ("\t<normal_hot=%f>\n", normal_hot);
  g_print ("\t<stalker_cold=%f>\n", stalker_cold);
  g_print ("\t<stalker_hot=%f>\n", stalker_hot);
  g_print ("\t<ratio_cold=%f>\n", stalker_cold / normal_hot);
  g_print ("\t<ratio_hot=%f>\n", stalker_hot / normal_hot);
}

static gboolean
store_range_of_test_runner (const GumModuleDetails * details,
                            gpointer user_data)
{
  GumMemoryRange * runner_range = user_data;

  if (strstr (details->name, "gum-tests") != NULL)
  {
    *runner_range = *details->range;
    return FALSE;
  }

  return TRUE;
}

GUM_NOINLINE static void
pretend_workload (GumMemoryRange * runner_range)
{
  lzma_stream stream = LZMA_STREAM_INIT;
  const uint32_t preset = LZMA_PRESET_DEFAULT;
  lzma_ret ret;
  guint8 * outbuf;
  gsize outbuf_size;
  const gsize outbuf_size_increment = 1024 * 1024;

  ret = lzma_easy_encoder (&stream, preset, LZMA_CHECK_CRC64);
  g_assert_cmpint (ret, ==, LZMA_OK);

  outbuf_size = outbuf_size_increment;
  outbuf = malloc (outbuf_size);

  stream.next_in = GSIZE_TO_POINTER (runner_range->base_address);
  stream.avail_in = MIN (runner_range->size, 65536);
  stream.next_out = outbuf;
  stream.avail_out = outbuf_size;

  while (TRUE)
  {
    ret = lzma_code (&stream, LZMA_FINISH);

    if (stream.avail_out == 0)
    {
      gsize compressed_size;

      compressed_size = outbuf_size;

      outbuf_size += outbuf_size_increment;
      outbuf = realloc (outbuf, outbuf_size);

      stream.next_out = outbuf + compressed_size;
      stream.avail_out = outbuf_size - compressed_size;
    }

    if (ret != LZMA_OK)
    {
      g_assert_cmpint (ret, ==, LZMA_STREAM_END);
      break;
    }
  }

  lzma_end (&stream);

  free (outbuf);
}

static gboolean
test_log_fatal_func (const gchar * log_domain,
                     GLogLevelFlags log_level,
                     const gchar * message,
                     gpointer user_data)
{
  return FALSE;
}

static GLogWriterOutput
test_log_writer_func (GLogLevelFlags log_level,
                      const GLogField * fields,
                      gsize n_fields,
                      gpointer user_data)
{
  return G_LOG_WRITER_HANDLED;
}

TESTCASE (custom_transformer)
{
  fixture->transformer = gum_stalker_transformer_make_from_callback (
      duplicate_adds, NULL, NULL);

  INVOKE_ARM_EXPECTING (GUM_NOTHING, arm_flat_code, 4);
}

static void
duplicate_adds (GumStalkerIterator * iterator,
                GumStalkerOutput * output,
                gpointer user_data)
{
  const cs_insn * insn;

  while (gum_stalker_iterator_next (iterator, &insn))
  {
    gum_stalker_iterator_keep (iterator);

    if (insn->id == ARM_INS_ADD)
      gum_arm_writer_put_bytes (output->writer.arm, insn->bytes, insn->size);
  }
}

TESTCASE (arm_callout)
{
  gpointer magic = GSIZE_TO_POINTER (0xbaadface);

  fixture->transformer = gum_stalker_transformer_make_from_callback (
      transform_arm_return_value, magic, NULL);

  INVOKE_ARM_EXPECTING (GUM_NOTHING, arm_flat_code, 42);
}

static void
transform_arm_return_value (GumStalkerIterator * iterator,
                            GumStalkerOutput * output,
                            gpointer user_data)
{
  gpointer magic = user_data;
  const cs_insn * insn;

  while (gum_stalker_iterator_next (iterator, &insn))
  {
    if (is_arm_mov_pc_lr (insn->bytes, insn->size))
    {
      gum_stalker_iterator_put_callout (iterator, on_arm_ret, magic, NULL);
    }

    gum_stalker_iterator_keep (iterator);
  }
}

static void
on_arm_ret (GumCpuContext * cpu_context,
            gpointer user_data)
{
  gpointer magic = user_data;
  const guint8 * bytes = GSIZE_TO_POINTER (cpu_context->pc);

  g_assert_cmphex (GPOINTER_TO_SIZE (magic), ==, 0xbaadface);
  g_assert_cmpuint (cpu_context->r[0], ==, 2);
  g_assert_true (is_arm_mov_pc_lr (bytes, 4));

  cpu_context->r[0] = 42;
}

static gboolean
is_arm_mov_pc_lr (const guint8 * bytes,
                  gsize size)
{
  const guint8 mov_pc_lr[] = { 0x0e, 0xf0, 0xa0, 0xe1 };

  if (size != sizeof (mov_pc_lr))
    return FALSE;

  return memcmp (bytes, mov_pc_lr, size) == 0;
}

TESTCASE (thumb_callout)
{
  gpointer magic = GSIZE_TO_POINTER (0xfacef00d);

  fixture->transformer = gum_stalker_transformer_make_from_callback (
      transform_thumb_return_value, magic, NULL);

  INVOKE_THUMB_EXPECTING (GUM_NOTHING, thumb_flat_code, 24);
}

static void
transform_thumb_return_value (GumStalkerIterator * iterator,
                              GumStalkerOutput * output,
                              gpointer user_data)
{
  gpointer magic = user_data;
  const cs_insn * insn;

  while (gum_stalker_iterator_next (iterator, &insn))
  {
    if (is_thumb_pop_pc (insn->bytes, insn->size))
    {
      gum_stalker_iterator_put_callout (iterator, on_thumb_ret, magic, NULL);
    }

    gum_stalker_iterator_keep (iterator);
  }
}

static void
on_thumb_ret (GumCpuContext * cpu_context,
              gpointer user_data)
{
  gpointer magic = user_data;
  const guint8 * bytes = GSIZE_TO_POINTER (cpu_context->pc);

  g_assert_cmphex (GPOINTER_TO_SIZE (magic), ==, 0xfacef00d);
  g_assert_cmpuint (cpu_context->r[0], ==, 2);
  g_assert_true (is_thumb_pop_pc (bytes, 2));

  cpu_context->r[0] = 24;
}

static gboolean
is_thumb_pop_pc (const guint8 * bytes,
                 gsize size)
{
  guint8 pop_pc[] = { 0x00, 0xbd };

  if (size != sizeof (pop_pc))
    return FALSE;

  return memcmp (bytes, pop_pc, size) == 0;
}

TESTCASE (unfollow_should_be_allowed_before_first_transform)
{
  UnfollowTransformContext ctx;

  ctx.stalker = fixture->stalker;
  ctx.num_blocks_transformed = 0;
  ctx.target_block = 0;
  ctx.max_instructions = 0;

  fixture->transformer = gum_stalker_transformer_make_from_callback (
      unfollow_during_transform, &ctx, NULL);

  INVOKE_ARM_EXPECTING (GUM_NOTHING, arm_flat_code, 2);
}

TESTCASE (unfollow_should_be_allowed_mid_first_transform)
{
  UnfollowTransformContext ctx;

  ctx.stalker = fixture->stalker;
  ctx.num_blocks_transformed = 0;
  ctx.target_block = 0;
  ctx.max_instructions = 1;

  fixture->transformer = gum_stalker_transformer_make_from_callback (
      unfollow_during_transform, &ctx, NULL);

  INVOKE_ARM_EXPECTING (GUM_NOTHING, arm_flat_code, 2);
}

TESTCASE (unfollow_should_be_allowed_after_first_transform)
{
  UnfollowTransformContext ctx;

  ctx.stalker = fixture->stalker;
  ctx.num_blocks_transformed = 0;
  ctx.target_block = 0;
  ctx.max_instructions = -1;

  fixture->transformer = gum_stalker_transformer_make_from_callback (
      unfollow_during_transform, &ctx, NULL);

  INVOKE_ARM_EXPECTING (GUM_NOTHING, arm_flat_code, 2);
}

TESTCASE (unfollow_should_be_allowed_before_second_transform)
{
  UnfollowTransformContext ctx;

  ctx.stalker = fixture->stalker;
  ctx.num_blocks_transformed = 0;
  ctx.target_block = 1;
  ctx.max_instructions = 0;

  fixture->transformer = gum_stalker_transformer_make_from_callback (
      unfollow_during_transform, &ctx, NULL);

  INVOKE_ARM_EXPECTING (GUM_NOTHING, arm_flat_code, 2);
}

TESTCASE (unfollow_should_be_allowed_mid_second_transform)
{
  UnfollowTransformContext ctx;

  ctx.stalker = fixture->stalker;
  ctx.num_blocks_transformed = 0;
  ctx.target_block = 1;
  ctx.max_instructions = 1;

  fixture->transformer = gum_stalker_transformer_make_from_callback (
      unfollow_during_transform, &ctx, NULL);

  INVOKE_ARM_EXPECTING (GUM_NOTHING, arm_flat_code, 2);
}

TESTCASE (unfollow_should_be_allowed_after_second_transform)
{
  UnfollowTransformContext ctx;

  ctx.stalker = fixture->stalker;
  ctx.num_blocks_transformed = 0;
  ctx.target_block = 1;
  ctx.max_instructions = -1;

  fixture->transformer = gum_stalker_transformer_make_from_callback (
      unfollow_during_transform, &ctx, NULL);

  INVOKE_ARM_EXPECTING (GUM_NOTHING, arm_flat_code, 2);
}

static void
unfollow_during_transform (GumStalkerIterator * iterator,
                           GumStalkerOutput * output,
                           gpointer user_data)
{
  UnfollowTransformContext * ctx = user_data;
  const cs_insn * insn;

  if (ctx->num_blocks_transformed == ctx->target_block)
  {
    gint n;

    for (n = 0; n != ctx->max_instructions &&
        gum_stalker_iterator_next (iterator, &insn); n++)
    {
      gum_stalker_iterator_keep (iterator);
    }

    gum_stalker_unfollow_me (ctx->stalker);
  }
  else
  {
    while (gum_stalker_iterator_next (iterator, &insn))
      gum_stalker_iterator_keep (iterator);
  }

  ctx->num_blocks_transformed++;
}

TESTCASE (follow_me_should_support_nullable_event_sink)
{
  gpointer p;

  gum_stalker_follow_me (fixture->stalker, NULL, NULL);
  p = malloc (1);
  free (p);
  gum_stalker_unfollow_me (fixture->stalker);
}

TESTCASE (follow_syscall)
{
#ifdef __ARM_PCS_VFP
  if (!g_test_slow ())
  {
    g_print ("<skipping, run in slow mode> ");
    return;
  }
#endif

  fixture->sink->mask = GUM_EXEC | GUM_CALL | GUM_RET;

  gum_stalker_follow_me (fixture->stalker, fixture->transformer,
      GUM_EVENT_SINK (fixture->sink));
  g_usleep (1);
  gum_stalker_unfollow_me (fixture->stalker);

  g_assert_cmpuint (fixture->sink->events->len, >, 0);
}

TESTCASE (follow_thread)
{
  StalkerDummyChannel channel;
  GThread * thread;
  GumThreadId thread_id;
#ifdef HAVE_LINUX
  int prev_dumpable;

# ifdef __ARM_PCS_VFP
  if (!g_test_slow ())
  {
    g_print ("<skipping, run in slow mode> ");
    return;
  }
# endif

  /* Android spawns non-debuggable applications as not dumpable by default. */
  prev_dumpable = prctl (PR_GET_DUMPABLE);
  prctl (PR_SET_DUMPABLE, 0);
#endif

  sdc_init (&channel);

  thread = g_thread_new ("stalker-test-target", run_stalked_briefly, &channel);
  thread_id = sdc_await_thread_id (&channel);

  fixture->sink->mask = GUM_EXEC | GUM_CALL | GUM_RET;
  gum_stalker_follow (fixture->stalker, thread_id, NULL,
      GUM_EVENT_SINK (fixture->sink));
  sdc_put_follow_confirmation (&channel);

  sdc_await_run_confirmation (&channel);
  g_assert_cmpuint (fixture->sink->events->len, >, 0);

  gum_stalker_unfollow (fixture->stalker, thread_id);
  sdc_put_unfollow_confirmation (&channel);

  sdc_await_flush_confirmation (&channel);
  gum_fake_event_sink_reset (fixture->sink);

  sdc_put_finish_confirmation (&channel);

  g_thread_join (thread);

  g_assert_cmpuint (fixture->sink->events->len, ==, 0);

  sdc_finalize (&channel);

#ifdef HAVE_LINUX
  prctl (PR_SET_DUMPABLE, prev_dumpable);
#endif
}

static gpointer
run_stalked_briefly (gpointer data)
{
  StalkerDummyChannel * channel = data;

  sdc_put_thread_id (channel, gum_process_get_current_thread_id ());

  sdc_await_follow_confirmation (channel);

  sdc_put_run_confirmation (channel);

  sdc_await_unfollow_confirmation (channel);

  sdc_put_flush_confirmation (channel);

  sdc_await_finish_confirmation (channel);

  return NULL;
}

TESTCASE (unfollow_should_handle_terminated_thread)
{
  guint i;

#ifdef __ARM_PCS_VFP
  if (!g_test_slow ())
  {
    g_print ("<skipping, run in slow mode> ");
    return;
  }
#endif

  for (i = 0; i != 10; i++)
  {
    StalkerDummyChannel channel;
    GThread * thread;
    GumThreadId thread_id;

    sdc_init (&channel);

    thread = g_thread_new ("stalker-test-target", run_stalked_into_termination,
        &channel);
    thread_id = sdc_await_thread_id (&channel);

    fixture->sink->mask = GUM_CALL | GUM_RET;
    gum_stalker_follow (fixture->stalker, thread_id, NULL,
        GUM_EVENT_SINK (fixture->sink));
    sdc_put_follow_confirmation (&channel);

    g_thread_join (thread);

    if (i % 2 == 0)
      g_usleep (50000);

    gum_stalker_unfollow (fixture->stalker, thread_id);

    sdc_finalize (&channel);

    while (gum_stalker_garbage_collect (fixture->stalker))
      g_usleep (10000);
  }
}

static gpointer
run_stalked_into_termination (gpointer data)
{
  StalkerDummyChannel * channel = data;

  sdc_put_thread_id (channel, gum_process_get_current_thread_id ());

  sdc_await_follow_confirmation (channel);

  return NULL;
}

TESTCASE (pthread_create)
{
  int ret;
  pthread_t thread;
  int number = 0;

#ifdef __ARM_PCS_VFP
  if (!g_test_slow ())
  {
    g_print ("<skipping, run in slow mode> ");
    return;
  }
#endif

  fixture->sink->mask = GUM_NOTHING;

  gum_stalker_follow_me (fixture->stalker, fixture->transformer,
      GUM_EVENT_SINK (fixture->sink));

  ret = pthread_create (&thread, NULL, increment_integer, &number);
  g_assert_cmpint (ret, ==, 0);

  ret = pthread_join (thread, NULL);
  g_assert_cmpint (ret, ==, 0);

  g_assert_cmpint (number, ==, 1);

  gum_stalker_unfollow_me (fixture->stalker);
}

static gpointer
increment_integer (gpointer data)
{
  int * number = (int *) data;
  *number += 1;
  return NULL;
}

TESTCASE (heap_api)
{
  gpointer p;

  fixture->sink->mask = GUM_EXEC | GUM_CALL | GUM_RET;

  gum_stalker_follow_me (fixture->stalker, fixture->transformer,
      GUM_EVENT_SINK (fixture->sink));
  p = malloc (1);
  free (p);
  gum_stalker_unfollow_me (fixture->stalker);

  g_assert_cmpuint (fixture->sink->events->len, >, 0);
}

static void
patch_code_pointer (GumAddress code,
                    guint offset,
                    GumAddress value)
{
  gum_memory_patch_code (GSIZE_TO_POINTER (code + offset), sizeof (gpointer),
      patch_code_pointer_slot, GSIZE_TO_POINTER (value));
}

static void
patch_code_pointer_slot (gpointer mem,
                         gpointer user_data)
{
  gpointer * slot = mem;
  gpointer value = user_data;

  *slot = value;
}
