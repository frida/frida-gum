/*
 * Copyright (C) 2009-2020 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 * Copyright (C) 2010-2013 Karl Trygve Kalleberg <karltk@boblycat.org>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "stalker-x86-fixture.c"

#ifndef HAVE_WINDOWS
# include <lzma.h>
#endif

TESTLIST_BEGIN (stalker)
  TESTENTRY (no_events)
  TESTENTRY (call)
  TESTENTRY (ret)
  TESTENTRY (exec)
  TESTENTRY (call_depth)
  TESTENTRY (call_probe)
  TESTENTRY (custom_transformer)
  TESTENTRY (unfollow_should_be_allowed_before_first_transform)
  TESTENTRY (unfollow_should_be_allowed_mid_first_transform)
  TESTENTRY (unfollow_should_be_allowed_after_first_transform)
  TESTENTRY (unfollow_should_be_allowed_before_second_transform)
  TESTENTRY (unfollow_should_be_allowed_mid_second_transform)
  TESTENTRY (unfollow_should_be_allowed_after_second_transform)

  TESTENTRY (unconditional_jumps)
  TESTENTRY (short_conditional_jump_true)
  TESTENTRY (short_conditional_jump_false)
  TESTENTRY (short_conditional_jcxz_true)
  TESTENTRY (short_conditional_jcxz_false)
  TESTENTRY (long_conditional_jump)
  TESTENTRY (follow_return)
  TESTENTRY (follow_stdcall)
  TESTENTRY (follow_repne_ret)
  TESTENTRY (follow_repne_jb)
  TESTENTRY (unfollow_deep)
  TESTENTRY (call_followed_by_junk)
  TESTENTRY (indirect_call_with_immediate)
  TESTENTRY (indirect_call_with_register_and_no_immediate)
  TESTENTRY (indirect_call_with_register_and_positive_byte_immediate)
  TESTENTRY (indirect_call_with_register_and_negative_byte_immediate)
  TESTENTRY (indirect_call_with_register_and_positive_dword_immediate)
  TESTENTRY (indirect_call_with_register_and_negative_dword_immediate)
#if GLIB_SIZEOF_VOID_P == 8
  TESTENTRY (indirect_call_with_extended_registers_and_immediate)
#endif
  TESTENTRY (indirect_call_with_esp_and_byte_immediate)
  TESTENTRY (indirect_call_with_esp_and_dword_immediate)
  TESTENTRY (indirect_jump_with_immediate)
  TESTENTRY (indirect_jump_with_immediate_and_scaled_register)
  TESTENTRY (direct_call_with_register)
#if GLIB_SIZEOF_VOID_P == 8
  TESTENTRY (direct_call_with_extended_register)
#endif
  TESTENTRY (popcnt)
#if GLIB_SIZEOF_VOID_P == 4
  TESTENTRY (no_register_clobber)
#endif
  TESTENTRY (no_red_zone_clobber)
  TESTENTRY (big_block)

  TESTENTRY (heap_api)
  TESTENTRY (follow_syscall)
  TESTENTRY (follow_thread)
  TESTENTRY (unfollow_should_handle_terminated_thread)
#ifndef HAVE_WINDOWS
  TESTENTRY (performance)
#endif

#ifdef HAVE_WINDOWS
# if GLIB_SIZEOF_VOID_P == 4
  TESTENTRY (win32_indirect_call_seg)
# endif
  TESTENTRY (win32_messagebeep_api)
  TESTENTRY (win32_follow_user_to_kernel_to_callback)
  TESTENTRY (win32_follow_callback_to_kernel_to_user)
#endif
TESTLIST_END ()

static gpointer run_stalked_briefly (gpointer data);
static gpointer run_stalked_into_termination (gpointer data);
#ifndef HAVE_WINDOWS
static gboolean store_range_of_test_runner (const GumModuleDetails * details,
    gpointer user_data);
static void pretend_workload (GumMemoryRange * runner_range);
#endif
static void insert_extra_increment_after_xor (GumStalkerIterator * iterator,
    GumStalkerOutput * output, gpointer user_data);
static void store_xax (GumCpuContext * cpu_context, gpointer user_data);
static void unfollow_during_transform (GumStalkerIterator * iterator,
    GumStalkerOutput * output, gpointer user_data);
static void invoke_follow_return_code (TestStalkerFixture * fixture);
static void invoke_unfollow_deep_code (TestStalkerFixture * fixture);

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

  /*gum_fake_event_sink_dump (fixture->sink);*/
}

TESTCASE (follow_syscall)
{
  fixture->sink->mask = GUM_EXEC | GUM_CALL | GUM_RET;

  gum_stalker_follow_me (fixture->stalker, fixture->transformer,
      GUM_EVENT_SINK (fixture->sink));
  g_usleep (1);
  gum_stalker_unfollow_me (fixture->stalker);

  g_assert_cmpuint (fixture->sink->events->len, >, 0);

  /*gum_fake_event_sink_dump (fixture->sink);*/
}

TESTCASE (follow_thread)
{
  StalkerDummyChannel channel;
  GThread * thread;
  GumThreadId thread_id;

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

  for (i = 0; i != 10; i++)
  {
    StalkerDummyChannel channel;
    GThread * thread;
    GumThreadId thread_id;

    sdc_init (&channel);

    thread = g_thread_new ("stalker-test-target", run_stalked_into_termination,
        &channel);
    thread_id = sdc_await_thread_id (&channel);

    fixture->sink->mask = GUM_EXEC | GUM_CALL | GUM_RET;
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

#ifndef HAVE_WINDOWS

TESTCASE (performance)
{
  GumMemoryRange runner_range;
  GTimer * timer;
  gdouble duration_direct, duration_stalked;

  runner_range.base_address = 0;
  runner_range.size = 0;
  gum_process_enumerate_modules (store_range_of_test_runner, &runner_range);
  g_assert_cmpuint (runner_range.base_address, !=, 0);
  g_assert_cmpuint (runner_range.size, !=, 0);

  timer = g_timer_new ();
  pretend_workload (&runner_range);

  g_timer_reset (timer);
  pretend_workload (&runner_range);
  duration_direct = g_timer_elapsed (timer, NULL);

  fixture->sink->mask = GUM_NOTHING;

  gum_stalker_set_trust_threshold (fixture->stalker, 0);
  gum_stalker_follow_me (fixture->stalker, fixture->transformer,
      GUM_EVENT_SINK (fixture->sink));

  /* warm-up */
  g_timer_reset (timer);
  pretend_workload (&runner_range);
  g_timer_elapsed (timer, NULL);

  /* the real deal */
  gum_stalker_set_counters_enabled (TRUE);
  g_timer_reset (timer);
  pretend_workload (&runner_range);
  duration_stalked = g_timer_elapsed (timer, NULL);

  gum_stalker_unfollow_me (fixture->stalker);

  g_timer_destroy (timer);

  g_print ("<duration_direct=%f duration_stalked=%f ratio=%f> ",
      duration_direct, duration_stalked, duration_stalked / duration_direct);

  gum_stalker_dump_counters ();
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
  const uint32_t preset = 9 | LZMA_PRESET_EXTREME;
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

#endif

static const guint8 flat_code[] = {
    0x33, 0xc0, /* xor eax, eax */
    0xff, 0xc0, /* inc eax      */
    0xff, 0xc0, /* inc eax      */
    0xc3        /* retn         */
};

static StalkerTestFunc
invoke_flat_expecting_return_value (TestStalkerFixture * fixture,
                                    GumEventType mask,
                                    guint expected_return_value)
{
  StalkerTestFunc func;
  gint ret;

  func = GUM_POINTER_TO_FUNCPTR (StalkerTestFunc,
      test_stalker_fixture_dup_code (fixture, flat_code, sizeof (flat_code)));

  fixture->sink->mask = mask;
  ret = test_stalker_fixture_follow_and_invoke (fixture, func, -1);
  g_assert_cmpint (ret, ==, expected_return_value);

  return func;
}

static StalkerTestFunc
invoke_flat (TestStalkerFixture * fixture,
             GumEventType mask)
{
  return invoke_flat_expecting_return_value (fixture, mask, 2);
}

TESTCASE (no_events)
{
  invoke_flat (fixture, GUM_NOTHING);
  g_assert_cmpuint (fixture->sink->events->len, ==, 0);
}

TESTCASE (call)
{
  StalkerTestFunc func;
  GumCallEvent * ev;

  func = invoke_flat (fixture, GUM_CALL);

  g_assert_cmpuint (fixture->sink->events->len, ==, 2);
  g_assert_cmpint (g_array_index (fixture->sink->events, GumEvent, 0).type,
      ==, GUM_CALL);
  ev = &g_array_index (fixture->sink->events, GumEvent, 0).call;
  GUM_ASSERT_CMPADDR (ev->location, ==, fixture->last_invoke_calladdr);
  GUM_ASSERT_CMPADDR (ev->target, ==, func);
}

TESTCASE (ret)
{
  StalkerTestFunc func;
  GumRetEvent * ev;

  func = invoke_flat (fixture, GUM_RET);

  g_assert_cmpuint (fixture->sink->events->len, ==, 1);
  g_assert_cmpint (g_array_index (fixture->sink->events, GumEvent, 0).type,
      ==, GUM_RET);
  ev = &g_array_index (fixture->sink->events, GumEvent, 0).ret;
  GUM_ASSERT_CMPADDR (ev->location,
      ==, ((guint8 *) GSIZE_TO_POINTER (func)) + 6);
  GUM_ASSERT_CMPADDR (ev->target, ==, fixture->last_invoke_retaddr);
}

TESTCASE (exec)
{
  StalkerTestFunc func;
  GumRetEvent * ev;

  func = invoke_flat (fixture, GUM_EXEC);

  g_assert_cmpuint (fixture->sink->events->len, ==, INVOKER_INSN_COUNT + 4);
  g_assert_cmpint (g_array_index (fixture->sink->events, GumEvent,
      INVOKER_IMPL_OFFSET).type, ==, GUM_EXEC);
  ev = &g_array_index (fixture->sink->events, GumEvent,
      INVOKER_IMPL_OFFSET).ret;
  GUM_ASSERT_CMPADDR (ev->location, ==, func);
}

TESTCASE (call_depth)
{
  const guint8 code[] =
  {
    0xb8, 0x07, 0x00, 0x00, 0x00, /* mov eax, 7 */
    0xff, 0xc8,                   /* dec eax    */
    0x74, 0x05,                   /* jz +5      */
    0xe8, 0xf7, 0xff, 0xff, 0xff, /* call -9    */
    0xc3,                         /* ret        */
    0xcc,                         /* int3       */
  };
  StalkerTestFunc func;

  func = GUM_POINTER_TO_FUNCPTR (StalkerTestFunc,
      test_stalker_fixture_dup_code (fixture, code, sizeof (code)));

  fixture->sink->mask = GUM_CALL | GUM_RET;
  test_stalker_fixture_follow_and_invoke (fixture, func, 0);

  g_assert_cmpuint (fixture->sink->events->len, ==, 7 + 7 + 1);
  g_assert_cmpint (NTH_EVENT_AS_CALL (0)->depth, ==, 0);
  g_assert_cmpint (NTH_EVENT_AS_CALL (1)->depth, ==, 1);
  g_assert_cmpint (NTH_EVENT_AS_CALL (2)->depth, ==, 2);
  g_assert_cmpint (NTH_EVENT_AS_CALL (3)->depth, ==, 3);
  g_assert_cmpint (NTH_EVENT_AS_CALL (4)->depth, ==, 4);
  g_assert_cmpint (NTH_EVENT_AS_CALL (5)->depth, ==, 5);
  g_assert_cmpint (NTH_EVENT_AS_CALL (6)->depth, ==, 6);
  g_assert_cmpint (NTH_EVENT_AS_RET (7)->depth, ==, 7);
  g_assert_cmpint (NTH_EVENT_AS_RET (8)->depth, ==, 6);
  g_assert_cmpint (NTH_EVENT_AS_RET (9)->depth, ==, 5);
  g_assert_cmpint (NTH_EVENT_AS_RET (10)->depth, ==, 4);
  g_assert_cmpint (NTH_EVENT_AS_RET (11)->depth, ==, 3);
  g_assert_cmpint (NTH_EVENT_AS_RET (12)->depth, ==, 2);
  g_assert_cmpint (NTH_EVENT_AS_RET (13)->depth, ==, 1);
}

typedef struct _CallProbeContext CallProbeContext;

struct _CallProbeContext
{
  guint callback_count;
  guint8 * block_start;
  gpointer call_address;
  gpointer return_address;
};

static void probe_func_a_invocation (GumCallSite * site, gpointer user_data);

TESTCASE (call_probe)
{
  const guint8 code_template[] =
  {
    0x68, 0x44, 0x44, 0xaa, 0xaa, /* push 0xaaaa4444     */
    0x68, 0x33, 0x33, 0xaa, 0xaa, /* push 0xaaaa3333     */
    0xba, 0x22, 0x22, 0xaa, 0xaa, /* mov edx, 0xaaaa2222 */
    0xb9, 0x11, 0x11, 0xaa, 0xaa, /* mov ecx, 0xaaaa1111 */
    0xe8, 0x1b, 0x00, 0x00, 0x00, /* call func_a         */
    0x68, 0x44, 0x44, 0xaa, 0xaa, /* push 0xbbbb4444     */
    0x68, 0x33, 0x33, 0xaa, 0xaa, /* push 0xbbbb3333     */
    0xba, 0x22, 0x22, 0xaa, 0xaa, /* mov edx, 0xbbbb2222 */
    0xb9, 0x11, 0x11, 0xaa, 0xaa, /* mov ecx, 0xbbbb1111 */
    0xe8, 0x06, 0x00, 0x00, 0x00, /* call func_b         */
    0xc3,                         /* ret                 */

    0xcc,                         /* int 3               */

    /* func_a: */
    0xc2, 2 * sizeof (gpointer), 0x00, /* ret x          */

    0xcc,                         /* int 3               */

    /* func_b: */
    0xc2, 2 * sizeof (gpointer), 0x00, /* ret x          */
  };
  StalkerTestFunc func;
  guint8 * func_a_address;
  CallProbeContext probe_ctx, secondary_probe_ctx;
  GumProbeId probe_id;

  func = GUM_POINTER_TO_FUNCPTR (StalkerTestFunc,
      test_stalker_fixture_dup_code (fixture, code_template,
          sizeof (code_template)));

  func_a_address = fixture->code + 52;

  probe_ctx.callback_count = 0;
  probe_ctx.block_start = fixture->code;
  probe_ctx.call_address = fixture->code + 20;
  probe_ctx.return_address = fixture->code + 25;
  probe_id = gum_stalker_add_call_probe (fixture->stalker,
      func_a_address, probe_func_a_invocation, &probe_ctx, NULL);
  test_stalker_fixture_follow_and_invoke (fixture, func, 0);
  g_assert_cmpuint (probe_ctx.callback_count, ==, 1);

  secondary_probe_ctx.callback_count = 0;
  secondary_probe_ctx.block_start = fixture->code;
  secondary_probe_ctx.call_address = probe_ctx.call_address;
  secondary_probe_ctx.return_address = probe_ctx.return_address;
  gum_stalker_add_call_probe (fixture->stalker,
      func_a_address, probe_func_a_invocation, &secondary_probe_ctx, NULL);
  test_stalker_fixture_follow_and_invoke (fixture, func, 0);
  g_assert_cmpuint (probe_ctx.callback_count, ==, 2);
  g_assert_cmpuint (secondary_probe_ctx.callback_count, ==, 1);

  gum_stalker_remove_call_probe (fixture->stalker, probe_id);
  test_stalker_fixture_follow_and_invoke (fixture, func, 0);
  g_assert_cmpuint (probe_ctx.callback_count, ==, 2);
  g_assert_cmpuint (secondary_probe_ctx.callback_count, ==, 2);
}

static void
probe_func_a_invocation (GumCallSite * site,
                         gpointer user_data)
{
  CallProbeContext * ctx = (CallProbeContext *) user_data;

  ctx->callback_count++;

  GUM_ASSERT_CMPADDR (site->block_address, ==, ctx->block_start);
#if GLIB_SIZEOF_VOID_P == 4
  g_assert_cmphex (site->cpu_context->ecx, ==, 0xaaaa1111);
  g_assert_cmphex (site->cpu_context->edx, ==, 0xaaaa2222);
#else
  g_assert_cmphex (site->cpu_context->rcx & 0xffffffff, ==, 0xaaaa1111);
  g_assert_cmphex (site->cpu_context->rdx & 0xffffffff, ==, 0xaaaa2222);
#endif
  g_assert_cmphex (GUM_CPU_CONTEXT_XIP (site->cpu_context),
      ==, GPOINTER_TO_SIZE (ctx->call_address));
  g_assert_cmphex (((gsize *) site->stack_data)[0],
      ==, GPOINTER_TO_SIZE (ctx->return_address));
  g_assert_cmphex (((gsize *) site->stack_data)[1] & 0xffffffff,
      ==, 0xaaaa3333);
  g_assert_cmphex (((gsize *) site->stack_data)[2] & 0xffffffff,
      ==, 0xaaaa4444);

#if GLIB_SIZEOF_VOID_P == 4
  g_assert_cmphex (GPOINTER_TO_SIZE (
      gum_cpu_context_get_nth_argument (site->cpu_context, 0)),
      ==, 0xaaaa3333);
  g_assert_cmphex (GPOINTER_TO_SIZE (
      gum_cpu_context_get_nth_argument (site->cpu_context, 1)),
      ==, 0xaaaa4444);
#endif
}

static const guint8 jumpy_code[] = {
    0x31, 0xc0,                   /* xor eax, eax */
    0xeb, 0x01,                   /* jmp short +1 */
    0xcc,                         /* int3         */
    0xff, 0xc0,                   /* inc eax      */
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

  func = GUM_POINTER_TO_FUNCPTR (StalkerTestFunc,
      test_stalker_fixture_dup_code (fixture, jumpy_code, sizeof (jumpy_code)));

  fixture->sink->mask = mask;
  ret = test_stalker_fixture_follow_and_invoke (fixture, func, -1);
  g_assert_cmpint (ret, ==, 1);

  return func;
}

TESTCASE (custom_transformer)
{
  gsize last_xax = 0;

  fixture->transformer = gum_stalker_transformer_make_from_callback (
      insert_extra_increment_after_xor, &last_xax, NULL);

  g_assert_cmpuint (last_xax, ==, 0);

  invoke_flat_expecting_return_value (fixture, GUM_NOTHING, 3);

  g_assert_cmpuint (last_xax, ==, 3);
}

static void
insert_extra_increment_after_xor (GumStalkerIterator * iterator,
                                  GumStalkerOutput * output,
                                  gpointer user_data)
{
  gsize * last_xax = user_data;
  const cs_insn * insn;
  gboolean in_leaf_func;

  in_leaf_func = FALSE;

  while (gum_stalker_iterator_next (iterator, &insn))
  {
    if (in_leaf_func && insn->id == X86_INS_RET)
    {
      gum_stalker_iterator_put_callout (iterator, store_xax, last_xax, NULL);
    }

    gum_stalker_iterator_keep (iterator);

    if (insn->id == X86_INS_XOR)
    {
      in_leaf_func = TRUE;

      gum_x86_writer_put_inc_reg (output->writer.x86, GUM_REG_EAX);
    }
  }
}

static void
store_xax (GumCpuContext * cpu_context,
           gpointer user_data)
{
  gsize * last_xax = user_data;

  *last_xax = GUM_CPU_CONTEXT_XAX (cpu_context);
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

  invoke_flat_expecting_return_value (fixture, GUM_NOTHING, 2);
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

  invoke_flat_expecting_return_value (fixture, GUM_NOTHING, 2);
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

  invoke_flat_expecting_return_value (fixture, GUM_NOTHING, 2);
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

  invoke_flat_expecting_return_value (fixture, GUM_NOTHING, 2);
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

  invoke_flat_expecting_return_value (fixture, GUM_NOTHING, 2);
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

  invoke_flat_expecting_return_value (fixture, GUM_NOTHING, 2);
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

TESTCASE (unconditional_jumps)
{
  invoke_jumpy (fixture, GUM_EXEC);

  g_assert_cmpuint (fixture->sink->events->len, ==, INVOKER_INSN_COUNT + 5);
  GUM_ASSERT_CMPADDR (NTH_EXEC_EVENT_LOCATION (INVOKER_IMPL_OFFSET + 0),
      ==, fixture->code + 0);
  GUM_ASSERT_CMPADDR (NTH_EXEC_EVENT_LOCATION (INVOKER_IMPL_OFFSET + 1),
      ==, fixture->code + 2);
  GUM_ASSERT_CMPADDR (NTH_EXEC_EVENT_LOCATION (INVOKER_IMPL_OFFSET + 2),
      ==, fixture->code + 5);
  GUM_ASSERT_CMPADDR (NTH_EXEC_EVENT_LOCATION (INVOKER_IMPL_OFFSET + 3),
      ==, fixture->code + 7);
  GUM_ASSERT_CMPADDR (NTH_EXEC_EVENT_LOCATION (INVOKER_IMPL_OFFSET + 4),
      ==, fixture->code + 14);
}

static StalkerTestFunc
invoke_short_condy (TestStalkerFixture * fixture,
                    GumEventType mask,
                    gint arg)
{
  const guint8 code[] = {
      0x83, 0xf9, 0x2a,             /* cmp ecx, 42    */
      0x74, 0x05,                   /* jz +5          */
      0xe9, 0x06, 0x00, 0x00, 0x00, /* jmp dword +6   */

      0xb8, 0x39, 0x05, 0x00, 0x00, /* mov eax, 1337  */
      0xc3,                         /* ret            */

      0xb8, 0xcb, 0x04, 0x00, 0x00, /* mov eax, 1227  */
      0xc3,                         /* ret            */
  };
  StalkerTestFunc func;
  gint ret;

  func = GUM_POINTER_TO_FUNCPTR (StalkerTestFunc,
      test_stalker_fixture_dup_code (fixture, code, sizeof (code)));

  fixture->sink->mask = mask;
  ret = test_stalker_fixture_follow_and_invoke (fixture, func, arg);

  g_assert_cmpint (ret, ==, (arg == 42) ? 1337 : 1227);

  return func;
}

TESTCASE (short_conditional_jump_true)
{
  invoke_short_condy (fixture, GUM_EXEC, 42);

  g_assert_cmpuint (fixture->sink->events->len, ==, INVOKER_INSN_COUNT + 4);
  GUM_ASSERT_CMPADDR (NTH_EXEC_EVENT_LOCATION (INVOKER_IMPL_OFFSET + 0),
      ==, fixture->code + 0);
  GUM_ASSERT_CMPADDR (NTH_EXEC_EVENT_LOCATION (INVOKER_IMPL_OFFSET + 1),
      ==, fixture->code + 3);
  GUM_ASSERT_CMPADDR (NTH_EXEC_EVENT_LOCATION (INVOKER_IMPL_OFFSET + 2),
      ==, fixture->code + 10);
  GUM_ASSERT_CMPADDR (NTH_EXEC_EVENT_LOCATION (INVOKER_IMPL_OFFSET + 3),
      ==, fixture->code + 15);
}

TESTCASE (short_conditional_jump_false)
{
  invoke_short_condy (fixture, GUM_EXEC, 43);

  g_assert_cmpuint (fixture->sink->events->len, ==, INVOKER_INSN_COUNT + 5);
  GUM_ASSERT_CMPADDR (NTH_EXEC_EVENT_LOCATION (INVOKER_IMPL_OFFSET + 0),
      ==, fixture->code + 0);
  GUM_ASSERT_CMPADDR (NTH_EXEC_EVENT_LOCATION (INVOKER_IMPL_OFFSET + 1),
      ==, fixture->code + 3);
  GUM_ASSERT_CMPADDR (NTH_EXEC_EVENT_LOCATION (INVOKER_IMPL_OFFSET + 2),
      ==, fixture->code + 5);
  GUM_ASSERT_CMPADDR (NTH_EXEC_EVENT_LOCATION (INVOKER_IMPL_OFFSET + 3),
      ==, fixture->code + 16);
  GUM_ASSERT_CMPADDR (NTH_EXEC_EVENT_LOCATION (INVOKER_IMPL_OFFSET + 4),
      ==, fixture->code + 21);
}

static StalkerTestFunc
invoke_short_jcxz (TestStalkerFixture * fixture,
                   GumEventType mask,
                   gint arg)
{
  const guint8 code[] = {
    0xe3, 0x05,                   /* jecxz/jrcxz +5 */
    0xe9, 0x06, 0x00, 0x00, 0x00, /* jmp dword +6   */

    0xb8, 0x39, 0x05, 0x00, 0x00, /* mov eax, 1337  */
    0xc3,                         /* ret            */

    0xb8, 0xcb, 0x04, 0x00, 0x00, /* mov eax, 1227  */
    0xc3,                         /* ret            */
  };
  StalkerTestFunc func;
  gint ret;

  func = GUM_POINTER_TO_FUNCPTR (StalkerTestFunc,
      test_stalker_fixture_dup_code (fixture, code, sizeof (code)));

  fixture->sink->mask = mask;
  ret = test_stalker_fixture_follow_and_invoke (fixture, func, arg);

  g_assert_cmpint (ret, ==, (arg == 0) ? 1337 : 1227);

  return func;
}

TESTCASE (short_conditional_jcxz_true)
{
  invoke_short_jcxz (fixture, GUM_EXEC, 0);

  g_assert_cmpuint (fixture->sink->events->len, ==, INVOKER_INSN_COUNT + 3);
  GUM_ASSERT_CMPADDR (NTH_EXEC_EVENT_LOCATION (INVOKER_IMPL_OFFSET + 0),
      ==, fixture->code + 0);
  GUM_ASSERT_CMPADDR (NTH_EXEC_EVENT_LOCATION (INVOKER_IMPL_OFFSET + 1),
      ==, fixture->code + 7);
  GUM_ASSERT_CMPADDR (NTH_EXEC_EVENT_LOCATION (INVOKER_IMPL_OFFSET + 2),
      ==, fixture->code + 12);
}

TESTCASE (short_conditional_jcxz_false)
{
  invoke_short_jcxz (fixture, GUM_EXEC, 0x11223344);

  g_assert_cmpuint (fixture->sink->events->len, ==, INVOKER_INSN_COUNT + 4);
  GUM_ASSERT_CMPADDR (NTH_EXEC_EVENT_LOCATION (INVOKER_IMPL_OFFSET + 0),
      ==, fixture->code + 0);
  GUM_ASSERT_CMPADDR (NTH_EXEC_EVENT_LOCATION (INVOKER_IMPL_OFFSET + 1),
      ==, fixture->code + 2);
  GUM_ASSERT_CMPADDR (NTH_EXEC_EVENT_LOCATION (INVOKER_IMPL_OFFSET + 2),
      ==, fixture->code + 13);
  GUM_ASSERT_CMPADDR (NTH_EXEC_EVENT_LOCATION (INVOKER_IMPL_OFFSET + 3),
      ==, fixture->code + 18);
}

static StalkerTestFunc
invoke_long_condy (TestStalkerFixture * fixture,
                   GumEventType mask,
                   gint arg)
{
  const guint8 code[] = {
      0xe9, 0x0c, 0x01, 0x00, 0x00,         /* jmp +268             */

      0xb8, 0x39, 0x05, 0x00, 0x00,         /* mov eax, 1337        */
      0xc3,                                 /* ret                  */

      0xb8, 0xcb, 0x04, 0x00, 0x00,         /* mov eax, 1227        */
      0xc3,                                 /* ret                  */

      0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
      0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
      0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
      0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
      0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
      0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
      0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
      0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
      0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
      0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
      0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
      0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
      0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
      0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
      0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
      0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
      0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
      0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
      0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
      0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
      0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
      0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
      0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
      0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
      0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
      0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,

      0x81, 0xc1, 0xff, 0xff, 0xff, 0xff,   /* add ecx, G_MAXUINT32 */
      0x0f, 0x83, 0xee, 0xfe, 0xff, 0xff,   /* jnc dword -274       */
      0xe9, 0xe3, 0xfe, 0xff, 0xff,         /* jmp dword -285       */
  };
  StalkerTestFunc func;
  gint ret;

  g_assert_true (arg == FALSE || arg == TRUE);

  func = GUM_POINTER_TO_FUNCPTR (StalkerTestFunc,
      test_stalker_fixture_dup_code (fixture, code, sizeof (code)));

  fixture->sink->mask = mask;
  ret = test_stalker_fixture_follow_and_invoke (fixture, func, arg);

  g_assert_cmpint (ret, ==, (arg == TRUE) ? 1337 : 1227);

  return func;
}

TESTCASE (long_conditional_jump)
{
  invoke_long_condy (fixture, GUM_EXEC, TRUE);
  invoke_long_condy (fixture, GUM_EXEC, FALSE);
}

#if GLIB_SIZEOF_VOID_P == 4
# define FOLLOW_RETURN_EXTRA_INSN_COUNT 2
#elif GLIB_SIZEOF_VOID_P == 8
# if GUM_NATIVE_ABI_IS_WINDOWS
#  define FOLLOW_RETURN_EXTRA_INSN_COUNT 3
# else
#  define FOLLOW_RETURN_EXTRA_INSN_COUNT 1
# endif
#endif

TESTCASE (follow_return)
{
  fixture->sink->mask = GUM_EXEC;

  invoke_follow_return_code (fixture);

  g_assert_cmpuint (fixture->sink->events->len,
      ==, 5 + FOLLOW_RETURN_EXTRA_INSN_COUNT);
}

static void
invoke_follow_return_code (TestStalkerFixture * fixture)
{
  GumAddressSpec spec;
  guint8 * code;
  GumX86Writer cw;
#if GLIB_SIZEOF_VOID_P == 4
  guint align_correction_follow = 12;
  guint align_correction_unfollow = 8;
#else
  guint align_correction_follow = 0;
  guint align_correction_unfollow = 8;
#endif
  const gchar * start_following_lbl = "start_following";
  GCallback invoke_func;

  spec.near_address = gum_stalker_follow_me;
  spec.max_distance = G_MAXINT32 / 2;

  code = gum_alloc_n_pages_near (1, GUM_PAGE_RWX, &spec);

  gum_x86_writer_init (&cw, code);

  gum_x86_writer_put_call_near_label (&cw, start_following_lbl);
  gum_x86_writer_put_nop (&cw);
  gum_x86_writer_put_sub_reg_imm (&cw, GUM_REG_XSP, align_correction_unfollow);
  gum_x86_writer_put_call_address_with_arguments (&cw, GUM_CALL_CAPI,
      GUM_ADDRESS (gum_stalker_unfollow_me), 1,
      GUM_ARG_ADDRESS, GUM_ADDRESS (fixture->stalker));
  gum_x86_writer_put_add_reg_imm (&cw, GUM_REG_XSP, align_correction_unfollow);
  gum_x86_writer_put_ret (&cw);

  gum_x86_writer_put_label (&cw, start_following_lbl);
  gum_x86_writer_put_sub_reg_imm (&cw, GUM_REG_XSP, align_correction_follow);
  gum_x86_writer_put_call_address_with_arguments (&cw, GUM_CALL_CAPI,
      GUM_ADDRESS (gum_stalker_follow_me), 3,
      GUM_ARG_ADDRESS, GUM_ADDRESS (fixture->stalker),
      GUM_ARG_ADDRESS, GUM_ADDRESS (fixture->transformer),
      GUM_ARG_ADDRESS, GUM_ADDRESS (fixture->sink));
  gum_x86_writer_put_add_reg_imm (&cw, GUM_REG_XSP, align_correction_follow);
  gum_x86_writer_put_ret (&cw);

  gum_x86_writer_clear (&cw);

  invoke_func = GUM_POINTER_TO_FUNCPTR (GCallback, code);
  invoke_func ();

  gum_free_pages (code);
}

TESTCASE (follow_stdcall)
{
  const guint8 stdcall_code[] =
  {
    0x68, 0xef, 0xbe, 0x00, 0x00, /* push dword 0xbeef */
    0xe8, 0x02, 0x00, 0x00, 0x00, /* call func         */
    0xc3,                         /* ret               */
    0xcc,                         /* int3              */

  /* func: */
    0x8b, 0x44, 0x24,             /* mov eax, [esp+X]  */
          sizeof (gpointer),
    0xc2, sizeof (gpointer), 0x00 /* ret X             */
  };
  StalkerTestFunc func;
  gint ret;

  func = GUM_POINTER_TO_FUNCPTR (StalkerTestFunc,
      test_stalker_fixture_dup_code (fixture, stdcall_code,
          sizeof (stdcall_code)));

  fixture->sink->mask = GUM_EXEC;
  ret = test_stalker_fixture_follow_and_invoke (fixture, func, 0);

  g_assert_cmpuint (fixture->sink->events->len, ==, INVOKER_INSN_COUNT + 5);

  g_assert_cmpint (ret, ==, 0xbeef);
}

TESTCASE (follow_repne_ret)
{
  const guint8 repne_ret_code[] =
  {
    0xb8, 0xef, 0xbe, 0x00, 0x00, /* mov eax, 0xbeef     */
    0xf2, 0xc3,                   /* repne ret           */
    0xcc,                         /* int3                */
  };
  StalkerTestFunc func;
  gint ret;

  func = GUM_POINTER_TO_FUNCPTR (StalkerTestFunc,
      test_stalker_fixture_dup_code (fixture, repne_ret_code,
          sizeof (repne_ret_code)));

  fixture->sink->mask = GUM_EXEC;
  ret = test_stalker_fixture_follow_and_invoke (fixture, func, 0);

  g_assert_cmpuint (fixture->sink->events->len, ==, INVOKER_INSN_COUNT + 2);

  g_assert_cmpint (ret, ==, 0xbeef);
}

TESTCASE (follow_repne_jb)
{
  const guint8 repne_jb_code[] =
  {
    0x68, 0xef, 0xbe, 0x00, 0x00, /* push dword 0xbeef   */
    0xb8, 0xff, 0x00, 0x00, 0x00, /* mov eax, 0xff       */
    0xb9, 0xfe, 0x00, 0x00, 0x00, /* mov ecx, 0xfe       */
    0x3b, 0xc8,                   /* cmp ecx, eax        */
    0xf2, 0x72, 0x02,             /* repne jb short func */
    0xc3,                         /* ret                 */
    0xcc,                         /* int3                */

                                  /* func:               */
    0x58,                         /* pop eax             */
    0xc3,                         /* ret                 */
  };
  StalkerTestFunc func;
  gint ret;

  func = GUM_POINTER_TO_FUNCPTR (StalkerTestFunc,
      test_stalker_fixture_dup_code (fixture, repne_jb_code,
          sizeof (repne_jb_code)));

  g_assert_cmpint (func (0), ==, 0xbeef);

  fixture->sink->mask = GUM_EXEC;
  ret = test_stalker_fixture_follow_and_invoke (fixture, func, 0);

  g_assert_cmpuint (fixture->sink->events->len, ==, INVOKER_INSN_COUNT + 7);

  g_assert_cmpint (ret, ==, 0xbeef);
}

#if GLIB_SIZEOF_VOID_P == 4
#define UNFOLLOW_DEEP_EXTRA_INSN_COUNT 1
#elif GLIB_SIZEOF_VOID_P == 8
# if GUM_NATIVE_ABI_IS_WINDOWS
#  define UNFOLLOW_DEEP_EXTRA_INSN_COUNT 2
# else
#  define UNFOLLOW_DEEP_EXTRA_INSN_COUNT 0
# endif
#endif

TESTCASE (unfollow_deep)
{
  fixture->sink->mask = GUM_EXEC;

  invoke_unfollow_deep_code (fixture);

  g_assert_cmpuint (fixture->sink->events->len,
      ==, 7 + UNFOLLOW_DEEP_EXTRA_INSN_COUNT);
}

static void
invoke_unfollow_deep_code (TestStalkerFixture * fixture)
{
  GumAddressSpec spec;
  guint8 * code;
  GumX86Writer cw;
#if GLIB_SIZEOF_VOID_P == 4
  guint align_correction_follow = 0;
  guint align_correction_unfollow = 12;
#else
  guint align_correction_follow = 8;
  guint align_correction_unfollow = 0;
#endif
  const gchar * func_a_lbl = "func_a";
  const gchar * func_b_lbl = "func_b";
  const gchar * func_c_lbl = "func_c";
  GCallback invoke_func;

  spec.near_address = gum_stalker_follow_me;
  spec.max_distance = G_MAXINT32 / 2;

  code = (guint8 *) gum_alloc_n_pages_near (1, GUM_PAGE_RWX, &spec);

  gum_x86_writer_init (&cw, code);

  gum_x86_writer_put_sub_reg_imm (&cw, GUM_REG_XSP, align_correction_follow);
  gum_x86_writer_put_call_address_with_arguments (&cw, GUM_CALL_CAPI,
      GUM_ADDRESS (gum_stalker_follow_me), 3,
      GUM_ARG_ADDRESS, GUM_ADDRESS (fixture->stalker),
      GUM_ARG_ADDRESS, GUM_ADDRESS (fixture->transformer),
      GUM_ARG_ADDRESS, GUM_ADDRESS (fixture->sink));
  gum_x86_writer_put_add_reg_imm (&cw, GUM_REG_XSP, align_correction_follow);
  gum_x86_writer_put_call_near_label (&cw, func_a_lbl);
  gum_x86_writer_put_ret (&cw);

  gum_x86_writer_put_label (&cw, func_a_lbl);
  gum_x86_writer_put_call_near_label (&cw, func_b_lbl);
  gum_x86_writer_put_ret (&cw);

  gum_x86_writer_put_label (&cw, func_b_lbl);
  gum_x86_writer_put_call_near_label (&cw, func_c_lbl);
  gum_x86_writer_put_ret (&cw);

  gum_x86_writer_put_label (&cw, func_c_lbl);
  gum_x86_writer_put_sub_reg_imm (&cw, GUM_REG_XSP, align_correction_unfollow);
  gum_x86_writer_put_call_address_with_arguments (&cw, GUM_CALL_CAPI,
      GUM_ADDRESS (gum_stalker_unfollow_me), 1,
      GUM_ARG_ADDRESS, GUM_ADDRESS (fixture->stalker));
  gum_x86_writer_put_add_reg_imm (&cw, GUM_REG_XSP, align_correction_unfollow);
  gum_x86_writer_put_ret (&cw);

  gum_x86_writer_clear (&cw);

  invoke_func = GUM_POINTER_TO_FUNCPTR (GCallback, code);
  invoke_func ();

  gum_free_pages (code);
}

TESTCASE (call_followed_by_junk)
{
  const guint8 code[] =
  {
    0xe8, 0x05, 0x00, 0x00, 0x00, /* call func         */
    0xff, 0xff, 0xff, 0xff, 0xff, /* <junk>            */
    0x58,                         /* pop eax           */
    0x68, 0xef, 0xbe, 0x00, 0x00, /* push dword 0xbeef */
    0x58,                         /* pop eax           */
    0xc3                          /* ret               */
  };
  StalkerTestFunc func;
  gint ret;

  func = GUM_POINTER_TO_FUNCPTR (StalkerTestFunc,
      test_stalker_fixture_dup_code (fixture, code, sizeof (code)));

  fixture->sink->mask = GUM_EXEC;
  ret = test_stalker_fixture_follow_and_invoke (fixture, func, 0);

  g_assert_cmpuint (fixture->sink->events->len,
      ==, INVOKER_INSN_COUNT + 5);

  g_assert_cmpint (ret, ==, 0xbeef);
}

typedef struct _CallTemplate CallTemplate;

struct _CallTemplate
{
  const guint8 * code_template;
  guint code_size;
  guint call_site_offset;
  guint target_mov_offset;
  guint target_address_offset;
  gboolean target_address_offset_points_directly_to_function;
  guint target_func_offset;
  gint target_func_immediate_fixup;
  guint instruction_count;
  guint ia32_padding_instruction_count;
  gboolean enable_probe;
};

static void probe_template_func_invocation (GumCallSite * site,
    gpointer user_data);

static StalkerTestFunc
invoke_call_from_template (TestStalkerFixture * fixture,
                           const CallTemplate * call_template)
{
  guint8 * code;
  StalkerTestFunc func;
  gpointer target_func_address;
  gsize target_actual_address;
  guint expected_insn_count;
  gint ret;
  GumProbeId probe_id;

  code = test_stalker_fixture_dup_code (fixture,
      call_template->code_template, call_template->code_size);
  func = GUM_POINTER_TO_FUNCPTR (StalkerTestFunc, code);

  target_func_address = code + call_template->target_func_offset;
  if (call_template->target_address_offset_points_directly_to_function)
    target_actual_address = GPOINTER_TO_SIZE (target_func_address);
  else
    target_actual_address = GPOINTER_TO_SIZE (&target_func_address);
  *((gsize *) (code + call_template->target_address_offset)) =
      target_actual_address + call_template->target_func_immediate_fixup;

#if GLIB_SIZEOF_VOID_P == 8
  if (call_template->target_mov_offset != 0)
    *(code + call_template->target_mov_offset - 1) = 0x48;
#endif

  expected_insn_count = INVOKER_INSN_COUNT + call_template->instruction_count;
#if GLIB_SIZEOF_VOID_P == 4
  expected_insn_count += call_template->ia32_padding_instruction_count;
#endif

  fixture->sink->mask = GUM_EXEC;
  ret = test_stalker_fixture_follow_and_invoke (fixture, func, 0);
  g_assert_cmpint (ret, ==, 1337);
  g_assert_cmpuint (fixture->sink->events->len, ==, expected_insn_count);

  gum_fake_event_sink_reset (fixture->sink);

  fixture->sink->mask = GUM_CALL;
  ret = test_stalker_fixture_follow_and_invoke (fixture, func, 0);
  g_assert_cmpint (ret, ==, 1337);
  g_assert_cmpuint (fixture->sink->events->len, ==, 2 + 1);
  GUM_ASSERT_CMPADDR (NTH_EVENT_AS_CALL (1)->location,
      ==, code + call_template->call_site_offset);
  GUM_ASSERT_CMPADDR (NTH_EVENT_AS_CALL (1)->target,
      ==, code + call_template->target_func_offset);

  probe_id = gum_stalker_add_call_probe (fixture->stalker, target_func_address,
      probe_template_func_invocation, NULL, NULL);
  fixture->sink->mask = GUM_NOTHING;
  ret = test_stalker_fixture_follow_and_invoke (fixture, func, 0);
  g_assert_cmpint (ret, == , 1337);
  gum_stalker_remove_call_probe (fixture->stalker, probe_id);

  return func;
}

static void
probe_template_func_invocation (GumCallSite * site,
                                gpointer user_data)
{
}

TESTCASE (indirect_call_with_immediate)
{
  const guint8 code[] = {
      0xeb, 0x08,                         /* jmp +8          */

      0x00, 0x00, 0x00, 0x00,             /* address padding */
      0x00, 0x00, 0x00, 0x00,

      0xff, 0x15, 0xf2, 0xff, 0xff, 0xff, /* call            */
      0xc3,                               /* ret             */

      0xb8, 0x39, 0x05, 0x00, 0x00,       /* mov eax, 1337   */
      0xc3,                               /* ret             */
  };
  CallTemplate call_template = { 0, };

  call_template.code_template = code;
  call_template.code_size = sizeof (code);
  call_template.call_site_offset = 10;
  call_template.target_address_offset = 12;
  call_template.target_func_offset = 17;
  call_template.instruction_count = 5;

#if GLIB_SIZEOF_VOID_P == 8
  call_template.target_address_offset -= 10;
  call_template.target_address_offset_points_directly_to_function = TRUE;
#endif

  invoke_call_from_template (fixture, &call_template);
}

TESTCASE (indirect_call_with_register_and_no_immediate)
{
  const guint8 code[] = {
      0x90, 0xb8, 0x00, 0x00, 0x00, 0x00, /* mov xax, X           */
                  0x90, 0x90, 0x90, 0x90,
      0xff, 0x10,                         /* call [xax]           */
      0xc3,                               /* ret                  */

      0xb8, 0x39, 0x05, 0x00, 0x00,       /* mov eax, 1337        */
      0xc3,                               /* ret                  */
  };
  CallTemplate call_template = { 0, };

  call_template.code_template = code;
  call_template.code_size = sizeof (code);
  call_template.call_site_offset = 10;
  call_template.target_mov_offset = 1;
  call_template.target_address_offset = 2;
  call_template.target_func_offset = 13;
  call_template.instruction_count = 5;
  call_template.ia32_padding_instruction_count = 5;

  invoke_call_from_template (fixture, &call_template);
}

TESTCASE (indirect_call_with_register_and_positive_byte_immediate)
{
  const guint8 code[] = {
      0x90, 0xb8, 0x00, 0x00, 0x00, 0x00, /* mov xax, X           */
                  0x90, 0x90, 0x90, 0x90,
      0xff, 0x50, 0x54,                   /* call [xax + 0x54]    */
      0xc3,                               /* ret                  */

      0xb8, 0x39, 0x05, 0x00, 0x00,       /* mov eax, 1337        */
      0xc3,                               /* ret                  */
  };
  CallTemplate call_template = { 0, };

  call_template.code_template = code;
  call_template.code_size = sizeof (code);
  call_template.call_site_offset = 10;
  call_template.target_mov_offset = 1;
  call_template.target_address_offset = 2;
  call_template.target_func_offset = 14;
  call_template.target_func_immediate_fixup = -0x54;
  call_template.instruction_count = 5;
  call_template.ia32_padding_instruction_count = 5;

  invoke_call_from_template (fixture, &call_template);
}

TESTCASE (indirect_call_with_register_and_negative_byte_immediate)
{
  const guint8 code[] = {
      0x90, 0xbd, 0x00, 0x00, 0x00, 0x00, /* mov xbp, X           */
                  0x90, 0x90, 0x90, 0x90,
      0xff, 0x55, 0xe4,                   /* call [xbp - 0x1c]    */
      0xc3,                               /* ret                  */

      0xb8, 0x39, 0x05, 0x00, 0x00,       /* mov eax, 1337        */
      0xc3,                               /* ret                  */
  };
  CallTemplate call_template = { 0, };

  call_template.code_template = code;
  call_template.code_size = sizeof (code);
  call_template.call_site_offset = 10;
  call_template.target_mov_offset = 1;
  call_template.target_address_offset = 2;
  call_template.target_func_offset = 14;
  call_template.target_func_immediate_fixup = 0x1c;
  call_template.instruction_count = 5;
  call_template.ia32_padding_instruction_count = 5;

  invoke_call_from_template (fixture, &call_template);
}

TESTCASE (indirect_call_with_register_and_positive_dword_immediate)
{
  const guint8 code[] = {
      0x90, 0xb8, 0x00, 0x00, 0x00, 0x00, /* mov xax, X           */
                  0x90, 0x90, 0x90, 0x90,
      0xff, 0x90, 0x54, 0x00, 0x00, 0x00, /* call [xax + 0x54]    */
      0xc3,                               /* ret                  */

      0xb8, 0x39, 0x05, 0x00, 0x00,       /* mov eax, 1337        */
      0xc3,                               /* ret                  */
  };
  CallTemplate call_template = { 0, };

  call_template.code_template = code;
  call_template.code_size = sizeof (code);
  call_template.call_site_offset = 10;
  call_template.target_mov_offset = 1;
  call_template.target_address_offset = 2;
  call_template.target_func_offset = 17;
  call_template.target_func_immediate_fixup = -0x54;
  call_template.instruction_count = 5;
  call_template.ia32_padding_instruction_count = 5;

  invoke_call_from_template (fixture, &call_template);
}

TESTCASE (indirect_call_with_register_and_negative_dword_immediate)
{
  const guint8 code[] = {
      0x90, 0xb8, 0x00, 0x00, 0x00, 0x00, /* mov xax, X           */
                  0x90, 0x90, 0x90, 0x90,
      0xff, 0x90, 0xbe, 0xab, 0xff, 0xff, /* call [xax - 0x5442]  */
      0xc3,                               /* ret                  */

      0xb8, 0x39, 0x05, 0x00, 0x00,       /* mov eax, 1337        */
      0xc3,                               /* ret                  */
  };
  CallTemplate call_template = { 0, };

  call_template.code_template = code;
  call_template.code_size = sizeof (code);
  call_template.call_site_offset = 10;
  call_template.target_mov_offset = 1;
  call_template.target_address_offset = 2;
  call_template.target_func_offset = 17;
  call_template.target_func_immediate_fixup = 0x5442;
  call_template.instruction_count = 5;
  call_template.ia32_padding_instruction_count = 5;

  invoke_call_from_template (fixture, &call_template);
}

#if GLIB_SIZEOF_VOID_P == 8

TESTCASE (indirect_call_with_extended_registers_and_immediate)
{
  const guint8 code[] = {
      0x49, 0xbb, 0x00, 0x00, 0x00, 0x00, /* mov r11, X                   */
                  0x00, 0x00, 0x00, 0x00,
      0x49, 0xba, 0x39, 0x05, 0x00, 0x00, /* mov r10, 1337                */
                  0x00, 0x00, 0x00, 0x00,
      0x43, 0xff, 0x94, 0xd3,             /* call [r11 + r10*8 + 0x270e0] */
                  0xe0, 0x70, 0x02, 0x00,
      0xc3,                               /* ret                          */

      0xb8, 0x39, 0x05, 0x00, 0x00,       /* mov eax, 1337                */
      0xc3,                               /* ret                          */
  };
  CallTemplate call_template = { 0, };

  call_template.code_template = code;
  call_template.code_size = sizeof (code);
  call_template.call_site_offset = 20;
  call_template.target_address_offset = 2;
  call_template.target_func_offset = 29;
  call_template.target_func_immediate_fixup = -((1337 * 8) + 0x270e0);
  call_template.instruction_count = 6;

  invoke_call_from_template (fixture, &call_template);
}

#endif

TESTCASE (indirect_call_with_esp_and_byte_immediate)
{
  const guint8 code[] = {
      0x90, 0xb8, 0x00, 0x00, 0x00, 0x00, /* mov xax, X          */
                  0x90, 0x90, 0x90, 0x90,
      0x50,                               /* push xax            */
      0x56,                               /* push xsi            */
      0x57,                               /* push xdi            */
      0xff, 0x54, 0x24,                   /* call [xsp + Y]      */
            2 * sizeof (gpointer),
      0x5F,                               /* pop xdi             */
      0x5E,                               /* pop xsi             */
      0x59,                               /* pop xcx             */
      0xc3,                               /* ret                 */

      0xb8, 0x39, 0x05, 0x00, 0x00,       /* mov eax, 1337       */
      0xc3,                               /* ret                 */
  };
  CallTemplate call_template = { 0, };

  call_template.code_template = code;
  call_template.code_size = sizeof (code);
  call_template.call_site_offset = 13;
  call_template.target_mov_offset = 1;
  call_template.target_address_offset = 2;
  call_template.target_address_offset_points_directly_to_function = TRUE;
  call_template.target_func_offset = 21;
  call_template.instruction_count = 11;
  call_template.ia32_padding_instruction_count = 5;

  invoke_call_from_template (fixture, &call_template);
}

TESTCASE (indirect_call_with_esp_and_dword_immediate)
{
  const guint8 code[] = {
      0x90, 0xb8, 0x00, 0x00, 0x00, 0x00,         /* mov xax, X          */
                  0x90, 0x90, 0x90, 0x90,
      0x50,                                       /* push xax            */
      0x56,                                       /* push xsi            */
      0x57,                                       /* push xdi            */
      0xff, 0x94, 0x24,                           /* call [xsp + Y]      */
            2 * sizeof (gpointer), 0x00, 0x00, 0x00,
      0x5F,                                       /* pop xdi             */
      0x5E,                                       /* pop xsi             */
      0x59,                                       /* pop xcx             */
      0xc3,                                       /* ret                 */

      0xb8, 0x39, 0x05, 0x00, 0x00,               /* mov eax, 1337       */
      0xc3,                                       /* ret                 */
  };
  CallTemplate call_template = { 0, };

  call_template.code_template = code;
  call_template.code_size = sizeof (code);
  call_template.call_site_offset = 13;
  call_template.target_mov_offset = 1;
  call_template.target_address_offset = 2;
  call_template.target_address_offset_points_directly_to_function = TRUE;
  call_template.target_func_offset = 24;
  call_template.instruction_count = 11;
  call_template.ia32_padding_instruction_count = 5;

  invoke_call_from_template (fixture, &call_template);
}

TESTCASE (direct_call_with_register)
{
  const guint8 code[] = {
      0x90, 0xb8, 0x00, 0x00, 0x00, 0x00, /* mov xax, X          */
                  0x90, 0x90, 0x90, 0x90,
      0xff, 0xd0,                         /* call xax             */
      0xc3,                               /* ret                  */

      0xb8, 0x39, 0x05, 0x00, 0x00,       /* mov eax, 1337        */
      0xc3                                /* ret                  */
  };
  CallTemplate call_template = { 0, };

  call_template.code_template = code;
  call_template.code_size = sizeof (code);
  call_template.call_site_offset = 10;
  call_template.target_mov_offset = 1;
  call_template.target_address_offset = 2;
  call_template.target_address_offset_points_directly_to_function = TRUE;
  call_template.target_func_offset = 13;
  call_template.instruction_count = 5;
  call_template.ia32_padding_instruction_count = 5;

  invoke_call_from_template (fixture, &call_template);
}

#if GLIB_SIZEOF_VOID_P == 8

TESTCASE (direct_call_with_extended_register)
{
  const guint8 code[] = {
      0x49, 0xb9, 0x00, 0x00, 0x00, 0x00, /* mov r9, X            */
                  0x00, 0x00, 0x00, 0x00,
      0x41, 0xff, 0xd1,                   /* call r9              */
      0xc3,                               /* ret                  */

      0xb8, 0x39, 0x05, 0x00, 0x00,       /* mov eax, 1337        */
      0xc3,                               /* ret                  */
  };
  CallTemplate call_template = { 0, };

  call_template.code_template = code;
  call_template.code_size = sizeof (code);
  call_template.call_site_offset = 10;
  call_template.target_mov_offset = 0;
  call_template.target_address_offset = 2;
  call_template.target_address_offset_points_directly_to_function = TRUE;
  call_template.target_func_offset = 14;
  call_template.instruction_count = 5;
  call_template.ia32_padding_instruction_count = 0;

  invoke_call_from_template (fixture, &call_template);
}

#endif

TESTCASE (popcnt)
{
  const guint8 code[] =
  {
    0xf3, 0x0f, 0xb8, 0xcb, /* popcnt ecx, ebx */
    0xc3,                   /* ret             */
    0xcc,                   /* int3            */
  };
  StalkerTestFunc func;

  func = GUM_POINTER_TO_FUNCPTR (StalkerTestFunc,
      test_stalker_fixture_dup_code (fixture, code, sizeof (code)));

  fixture->sink->mask = GUM_NOTHING;
  test_stalker_fixture_follow_and_invoke (fixture, func, 0);
}

typedef struct _JumpTemplate JumpTemplate;

struct _JumpTemplate
{
  const guint8 * code_template;
  guint code_size;
  guint offset_of_target_pointer;
  gboolean offset_of_target_pointer_points_directly;
  guint offset_of_target;
  gint target_immediate_fixup;
  guint instruction_count;
  guint ia32_padding_instruction_count;
};

static StalkerTestFunc
invoke_jump (TestStalkerFixture * fixture,
             JumpTemplate * jump_template)
{
  guint8 * code;
  StalkerTestFunc func;
  gpointer target_address;
  gsize target_actual_address;
  guint expected_insn_count;
  gint ret;

  code = test_stalker_fixture_dup_code (fixture, jump_template->code_template,
      jump_template->code_size);
  func = GUM_POINTER_TO_FUNCPTR (StalkerTestFunc, code);

  target_address = code + jump_template->offset_of_target;
  if (jump_template->offset_of_target_pointer_points_directly)
    target_actual_address = GPOINTER_TO_SIZE (target_address);
  else
    target_actual_address = GPOINTER_TO_SIZE (&target_address);
  *((gsize *) (code + jump_template->offset_of_target_pointer)) =
      target_actual_address + jump_template->target_immediate_fixup;

  expected_insn_count = INVOKER_INSN_COUNT + jump_template->instruction_count;
#if GLIB_SIZEOF_VOID_P == 4
  expected_insn_count += jump_template->ia32_padding_instruction_count;
#endif

  fixture->sink->mask = GUM_EXEC;
  ret = test_stalker_fixture_follow_and_invoke (fixture, func, 0);
  g_assert_cmpint (ret, ==, 1337);
  g_assert_cmpuint (fixture->sink->events->len, ==, expected_insn_count);

  return func;
}

TESTCASE (indirect_jump_with_immediate)
{
  const guint8 code[] = {
      0xeb, 0x08,                         /* jmp +8          */

      0x00, 0x00, 0x00, 0x00,             /* address padding */
      0x00, 0x00, 0x00, 0x00,

      0xff, 0x25, 0xf2, 0xff, 0xff, 0xff, /* jmp             */
      0xcc,                               /* int3            */

      0xb8, 0x39, 0x05, 0x00, 0x00,       /* mov eax, 1337   */
      0xc3,                               /* ret             */
  };
  JumpTemplate jump_template = { 0, };

  jump_template.code_template = code;
  jump_template.code_size = sizeof (code);
  jump_template.offset_of_target_pointer = 12;
  jump_template.offset_of_target = 17;
  jump_template.instruction_count = 4;

#if GLIB_SIZEOF_VOID_P == 8
  jump_template.offset_of_target_pointer -= 10;
  jump_template.offset_of_target_pointer_points_directly = TRUE;
#endif

  invoke_jump (fixture, &jump_template);
}

TESTCASE (indirect_jump_with_immediate_and_scaled_register)
{
  guint8 code[] = {
      0x90, 0xbe, 0x00, 0x00, 0x00, 0x00,       /* mov xsi, addr                    */
                  0x90, 0x90, 0x90, 0x90,
      0x90, 0xb8, 0x03, 0x00, 0x00, 0x00,       /* mov xax, 3                       */
                  0x90, 0x90, 0x90, 0x90,
      0xff, 0x64, 0x86, 0xf9,                   /* jmp [xsi + xax * 4 - 7]          */
      0xcc,                                     /* int3                             */

      0xb8, 0x39, 0x05, 0x00, 0x00,             /* mov eax, 1337                    */
      0xc3,                                     /* ret                              */
  };
  JumpTemplate jump_template = { 0, };

  jump_template.code_template = code;
  jump_template.code_size = sizeof (code);
  jump_template.offset_of_target_pointer = 2;
  jump_template.offset_of_target = 25;
  jump_template.target_immediate_fixup = -5;
  jump_template.instruction_count = 5;
  jump_template.ia32_padding_instruction_count = 10;

#if GLIB_SIZEOF_VOID_P == 8
  code[0] = 0x48;

  code[10] = 0x48;
  memset (code + 10 + 6, 0, 4);

  jump_template.ia32_padding_instruction_count = 5;
#endif

  invoke_jump (fixture, &jump_template);
}

#if GLIB_SIZEOF_VOID_P == 4

typedef void (* ClobberFunc) (GumCpuContext * ctx);

TESTCASE (no_register_clobber)
{
  guint8 * code;
  GumX86Writer cw;
  const gchar * my_func_lbl = "my_func";
  const gchar * my_beach_lbl = "my_beach";
  ClobberFunc func;
  GumCpuContext ctx;

  code = gum_alloc_n_pages (1, GUM_PAGE_RWX);
  gum_x86_writer_init (&cw, code);

  gum_x86_writer_put_pushax (&cw);

  gum_x86_writer_put_pushax (&cw);
  gum_x86_writer_put_push_u32 (&cw, (guint32) fixture->sink);
  gum_x86_writer_put_push_u32 (&cw, (guint32) fixture->transformer);
  gum_x86_writer_put_push_u32 (&cw, (guint32) fixture->stalker);
  gum_x86_writer_put_call_address (&cw, GUM_ADDRESS (gum_stalker_follow_me));
  gum_x86_writer_put_add_reg_imm (&cw, GUM_REG_ESP, 3 * sizeof (gpointer));
  gum_x86_writer_put_popax (&cw);

  gum_x86_writer_put_mov_reg_u32 (&cw, GUM_REG_EAX, 0xcafebabe);
  gum_x86_writer_put_mov_reg_u32 (&cw, GUM_REG_ECX, 0xbeefbabe);
  gum_x86_writer_put_mov_reg_u32 (&cw, GUM_REG_EDX, 0xb00bbabe);
  gum_x86_writer_put_mov_reg_u32 (&cw, GUM_REG_EBX, 0xf001babe);
  gum_x86_writer_put_mov_reg_u32 (&cw, GUM_REG_EBP, 0xababe);
  gum_x86_writer_put_mov_reg_u32 (&cw, GUM_REG_ESI, 0x1337);
  gum_x86_writer_put_mov_reg_u32 (&cw, GUM_REG_EDI, 0x1227);

  gum_x86_writer_put_call_near_label (&cw, my_func_lbl);

  gum_x86_writer_put_pushax (&cw);
  gum_x86_writer_put_sub_reg_imm (&cw, GUM_REG_ESP, 2 * sizeof (gpointer));
  gum_x86_writer_put_push_u32 (&cw, (guint32) fixture->stalker);
  gum_x86_writer_put_call_address (&cw, GUM_ADDRESS (gum_stalker_unfollow_me));
  gum_x86_writer_put_add_reg_imm (&cw, GUM_REG_ESP, 3 * sizeof (gpointer));
  gum_x86_writer_put_popax (&cw);

  gum_x86_writer_put_push_reg (&cw, GUM_REG_ECX);
  gum_x86_writer_put_mov_reg_reg_offset_ptr (&cw, GUM_REG_ECX,
      GUM_REG_ESP, sizeof (gpointer) + (8 * sizeof (gpointer))
      + sizeof (gpointer));
  gum_x86_writer_put_mov_reg_offset_ptr_reg (&cw,
      GUM_REG_ECX, G_STRUCT_OFFSET (GumCpuContext, eax), GUM_REG_EAX);
  gum_x86_writer_put_mov_reg_offset_ptr_reg (&cw,
      GUM_REG_ECX, G_STRUCT_OFFSET (GumCpuContext, edx), GUM_REG_EDX);
  gum_x86_writer_put_mov_reg_offset_ptr_reg (&cw,
      GUM_REG_ECX, G_STRUCT_OFFSET (GumCpuContext, ebx), GUM_REG_EBX);
  gum_x86_writer_put_mov_reg_offset_ptr_reg (&cw,
      GUM_REG_ECX, G_STRUCT_OFFSET (GumCpuContext, ebp), GUM_REG_EBP);
  gum_x86_writer_put_mov_reg_offset_ptr_reg (&cw,
      GUM_REG_ECX, G_STRUCT_OFFSET (GumCpuContext, esi), GUM_REG_ESI);
  gum_x86_writer_put_mov_reg_offset_ptr_reg (&cw,
      GUM_REG_ECX, G_STRUCT_OFFSET (GumCpuContext, edi), GUM_REG_EDI);
  gum_x86_writer_put_pop_reg (&cw, GUM_REG_EAX);
  gum_x86_writer_put_mov_reg_offset_ptr_reg (&cw,
      GUM_REG_ECX, G_STRUCT_OFFSET (GumCpuContext, ecx), GUM_REG_EAX);

  gum_x86_writer_put_popax (&cw);

  gum_x86_writer_put_ret (&cw);

  gum_x86_writer_put_label (&cw, my_func_lbl);
  gum_x86_writer_put_nop (&cw);
  gum_x86_writer_put_jmp_short_label (&cw, my_beach_lbl);
  gum_x86_writer_put_breakpoint (&cw);

  gum_x86_writer_put_label (&cw, my_beach_lbl);
  gum_x86_writer_put_nop (&cw);
  gum_x86_writer_put_nop (&cw);
  gum_x86_writer_put_ret (&cw);

  gum_x86_writer_clear (&cw);

  fixture->sink->mask = GUM_CALL | GUM_RET | GUM_EXEC;
  func = GUM_POINTER_TO_FUNCPTR (ClobberFunc, code);
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

#endif

TESTCASE (no_red_zone_clobber)
{
  guint8 code_template[] =
  {
    0x90, 0xb8, 0x00, 0x00, 0x00, 0x00, /* mov xax, <addr>    */
                0x90, 0x90, 0x90, 0x90,
    0x90, 0x89, 0x44, 0x24, 0xf8,       /* mov [rsp - 8], xax */
    0x90, 0x8b, 0x44, 0x24, 0xf8,       /* mov xax, [rsp - 8] */
    0xff, 0xe0,                         /* jmp rax            */
    0xcc,                               /* int3               */
    0xb8, 0x39, 0x05, 0x00, 0x00,       /* mov rax, 1337      */
    0xc3                                /* ret                */
  };
  guint8 * code;
  StalkerTestFunc func;
  gint ret;

#if GLIB_SIZEOF_VOID_P == 8
  code_template[0] = 0x48;
  code_template[10] = 0x48;
  code_template[15] = 0x48;
#endif

  code = test_stalker_fixture_dup_code (fixture, code_template,
      sizeof (code_template));
  *((gpointer *) (code + 2)) = code + 23;

  func = GUM_POINTER_TO_FUNCPTR (StalkerTestFunc, code);
  ret = func (42);
  g_assert_cmpint (ret, ==, 1337);

  fixture->sink->mask = GUM_EXEC;
  ret = test_stalker_fixture_follow_and_invoke (fixture, func, 0);
#if GLIB_SIZEOF_VOID_P == 8
  g_assert_cmpuint (fixture->sink->events->len, ==, INVOKER_INSN_COUNT + 6);
#else
  g_assert_cmpuint (fixture->sink->events->len, ==, INVOKER_INSN_COUNT + 13);
#endif
  g_assert_cmpint (ret, ==, 1337);
}

TESTCASE (big_block)
{
  const guint nop_instruction_count = 1000000;
  guint8 * code;
  GumX86Writer cw;
  guint i;
  StalkerTestFunc func;

  code = gum_alloc_n_pages (
      (nop_instruction_count / gum_query_page_size ()) + 1,
      GUM_PAGE_RWX);
  gum_x86_writer_init (&cw, code);

  for (i = 0; i != nop_instruction_count; i++)
    gum_x86_writer_put_nop (&cw);
  gum_x86_writer_put_ret (&cw);

  gum_x86_writer_flush (&cw);

  func = GUM_POINTER_TO_FUNCPTR (StalkerTestFunc,
      test_stalker_fixture_dup_code (fixture, code,
          gum_x86_writer_offset (&cw)));

  gum_x86_writer_clear (&cw);
  gum_free_pages (code);

  test_stalker_fixture_follow_and_invoke (fixture, func, -1);
}

#ifdef HAVE_WINDOWS

typedef struct _TestWindow TestWindow;

typedef void (* TestWindowMessageHandler) (TestWindow * window, gpointer user_data);

struct _TestWindow
{
  LPTSTR klass;
  HWND handle;
  GumStalker * stalker;

  TestWindowMessageHandler handler;
  gpointer user_data;
};

static void do_follow (TestWindow * window, gpointer user_data);
static void do_unfollow (TestWindow * window, gpointer user_data);

static TestWindow * create_test_window (GumStalker * stalker);
static void destroy_test_window (TestWindow * window);
static void send_message_and_pump_messages_briefly (TestWindow * window,
    TestWindowMessageHandler handler, gpointer user_data);

static LRESULT CALLBACK test_window_proc (HWND hwnd, UINT msg,
    WPARAM wparam, LPARAM lparam);

#if GLIB_SIZEOF_VOID_P == 4

static StalkerTestFunc
invoke_indirect_call_seg (TestStalkerFixture * fixture,
                          GumEventType mask)
{
  const guint8 code_template[] = {
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
  guint8 * code;
  StalkerTestFunc func;
  guint ret;

  code = test_stalker_fixture_dup_code (fixture, code_template,
      sizeof (code_template));
  func = GUM_POINTER_TO_FUNCPTR (StalkerTestFunc, code);

  *((gpointer *) (code + 14)) = code + sizeof (code_template) - 1 - 5;

  fixture->sink->mask = mask;
  ret = test_stalker_fixture_follow_and_invoke (fixture, func, 0);

  g_assert_cmphex (ret, ==, 0xcafebabe);

  return func;
}

TESTCASE (win32_indirect_call_seg)
{
  invoke_indirect_call_seg (fixture, GUM_EXEC);

  g_assert_cmpuint (fixture->sink->events->len,
      ==, INVOKER_INSN_COUNT + 11);
}

#endif

TESTCASE (win32_messagebeep_api)
{
  fixture->sink->mask = GUM_EXEC | GUM_CALL | GUM_RET;

  gum_stalker_follow_me (fixture->stalker, fixture->transformer,
      GUM_EVENT_SINK (fixture->sink));
  MessageBeep (MB_ICONINFORMATION);
  gum_stalker_unfollow_me (fixture->stalker);
}

TESTCASE (win32_follow_user_to_kernel_to_callback)
{
  TestWindow * window;

  window = create_test_window (fixture->stalker);

  gum_stalker_follow_me (fixture->stalker, fixture->transformer,
      GUM_EVENT_SINK (fixture->sink));
  send_message_and_pump_messages_briefly (window, do_unfollow,
      fixture->stalker);
  g_assert_false (gum_stalker_is_following_me (fixture->stalker));

  destroy_test_window (window);
}

TESTCASE (win32_follow_callback_to_kernel_to_user)
{
  TestWindow * window;

  window = create_test_window (fixture->stalker);

  send_message_and_pump_messages_briefly (window, do_follow, fixture->sink);
  g_assert_true (gum_stalker_is_following_me (fixture->stalker));
  gum_stalker_unfollow_me (fixture->stalker);

  destroy_test_window (window);
}

static void
do_follow (TestWindow * window, gpointer user_data)
{
  gum_stalker_follow_me (window->stalker, NULL, GUM_EVENT_SINK (user_data));
}

static void
do_unfollow (TestWindow * window, gpointer user_data)
{
  gum_stalker_unfollow_me (window->stalker);
}

static TestWindow *
create_test_window (GumStalker * stalker)
{
  TestWindow * window;
  WNDCLASS wc = { 0, };

  window = g_slice_new (TestWindow);

  window->stalker = stalker;

  wc.lpfnWndProc = test_window_proc;
  wc.hInstance = GetModuleHandle (NULL);
  wc.lpszClassName = _T ("GumTestWindowClass");
  window->klass = (LPTSTR) GSIZE_TO_POINTER (RegisterClass (&wc));
  g_assert_nonnull (window->klass);

#pragma warning (push)
#pragma warning (disable: 4306)
  window->handle = CreateWindow (window->klass, _T ("GumTestWindow"),
      WS_CAPTION, 10, 10, 320, 240, HWND_MESSAGE, NULL,
      GetModuleHandle (NULL), NULL);
#pragma warning (pop)
  g_assert_nonnull (window->handle);

  SetWindowLongPtr (window->handle, GWLP_USERDATA, (LONG_PTR) window);
  ShowWindow (window->handle, SW_SHOWNORMAL);

  return window;
}

static void
destroy_test_window (TestWindow * window)
{
  g_assert_true (UnregisterClass (window->klass, GetModuleHandle (NULL)));

  g_slice_free (TestWindow, window);
}

static void
send_message_and_pump_messages_briefly (TestWindow * window,
    TestWindowMessageHandler handler, gpointer user_data)
{
  MSG msg;

  window->handler = handler;
  window->user_data = user_data;

  SendMessage (window->handle, WM_USER, 0, 0);

  while (GetMessage (&msg, NULL, 0, 0))
  {
    TranslateMessage (&msg);
    DispatchMessage (&msg);
  }
}

static LRESULT CALLBACK
test_window_proc (HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam)
{
  if (msg == WM_USER)
  {
    TestWindow * window;

    window = (TestWindow *) GetWindowLongPtr (hwnd, GWLP_USERDATA);
    window->handler (window, window->user_data);

    SetTimer (hwnd, 1, USER_TIMER_MINIMUM, NULL);

    return 0;
  }
  else if (msg == WM_TIMER)
  {
    KillTimer (hwnd, 1);
    DestroyWindow (hwnd);
  }
  else if (msg == WM_DESTROY)
  {
    PostQuitMessage (0);
    return 0;
  }

  return DefWindowProc (hwnd, msg, wparam, lparam);
}

#endif
