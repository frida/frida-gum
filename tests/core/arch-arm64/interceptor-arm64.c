/*
 * Copyright (C) 2019-2020 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "interceptor-arm64-fixture.c"

TESTLIST_BEGIN (interceptor_arm64)
  TESTENTRY (attach_to_thunk_reading_lr)
  TESTENTRY (attach_to_function_reading_lr)
TESTLIST_END ()

typedef struct _GumEmitLrThunkContext GumEmitLrThunkContext;
typedef struct _GumEmitLrFuncContext GumEmitLrFuncContext;

struct _GumEmitLrThunkContext
{
  gpointer code;
  gsize (* run) (void);
  gsize (* thunk) (void);
  gsize expected_lr;
};

struct _GumEmitLrFuncContext
{
  gpointer code;
  gsize (* run) (void);
  gsize (* func) (void);
  gsize caller_lr;
};

static void gum_emit_lr_thunk (gpointer mem, gpointer user_data);
static void gum_emit_lr_func (gpointer mem, gpointer user_data);

TESTCASE (attach_to_thunk_reading_lr)
{
  const gsize code_size_in_pages = 1;
  gsize code_size;
  GumEmitLrThunkContext ctx;

  code_size = code_size_in_pages * gum_query_page_size ();
  ctx.code = gum_alloc_n_pages (code_size_in_pages, GUM_PAGE_RW);
  ctx.run = NULL;
  ctx.thunk = NULL;
  ctx.expected_lr = 0;

  gum_memory_patch_code (ctx.code, code_size, gum_emit_lr_thunk, &ctx);

  g_assert_cmphex (ctx.run (), ==, ctx.expected_lr);

  interceptor_fixture_attach (fixture, 0, ctx.thunk, '>', '<');
  g_assert_cmphex (ctx.run (), ==, ctx.expected_lr);
  g_assert_cmpstr (fixture->result->str, ==, "><");

  interceptor_fixture_detach (fixture, 0);
  gum_free_pages (ctx.code);
}

static void
gum_emit_lr_thunk (gpointer mem,
                   gpointer user_data)
{
  GumEmitLrThunkContext * ctx = user_data;
  GumArm64Writer aw;
  const gchar * thunk_start = "thunk_start";
  const gchar * inner_start = "inner_start";

  gum_arm64_writer_init (&aw, mem);
  aw.pc = GUM_ADDRESS (ctx->code);

  ctx->run = gum_sign_code_pointer (GSIZE_TO_POINTER (aw.pc));
  gum_arm64_writer_put_push_reg_reg (&aw, ARM64_REG_X19, ARM64_REG_LR);
  gum_arm64_writer_put_bl_label (&aw, thunk_start);
  ctx->expected_lr = aw.pc;
  gum_arm64_writer_put_pop_reg_reg (&aw, ARM64_REG_X19, ARM64_REG_LR);
  gum_arm64_writer_put_ret (&aw);

  ctx->thunk = GSIZE_TO_POINTER (aw.pc);
  gum_arm64_writer_put_label (&aw, thunk_start);
  gum_arm64_writer_put_mov_reg_reg (&aw, ARM64_REG_X3, ARM64_REG_LR);
  gum_arm64_writer_put_b_label (&aw, inner_start);

  gum_arm64_writer_put_label (&aw, inner_start);
  gum_arm64_writer_put_mov_reg_reg (&aw, ARM64_REG_X0, ARM64_REG_X3);
  gum_arm64_writer_put_ret (&aw);

  gum_arm64_writer_clear (&aw);
}

TESTCASE (attach_to_function_reading_lr)
{
  const gsize code_size_in_pages = 1;
  gsize code_size;
  GumEmitLrFuncContext ctx;

  code_size = code_size_in_pages * gum_query_page_size ();
  ctx.code = gum_alloc_n_pages (code_size_in_pages, GUM_PAGE_RW);
  ctx.run = NULL;
  ctx.func = NULL;
  ctx.caller_lr = 0;

  gum_memory_patch_code (ctx.code, code_size, gum_emit_lr_func, &ctx);

  g_assert_cmphex (ctx.run (), ==, ctx.caller_lr);

  interceptor_fixture_attach (fixture, 0, ctx.func, '>', '<');
  g_assert_cmphex (ctx.run (), !=, ctx.caller_lr);
  g_assert_cmpstr (fixture->result->str, ==, "><");

  interceptor_fixture_detach (fixture, 0);
  gum_free_pages (ctx.code);
}

static void
gum_emit_lr_func (gpointer mem,
                  gpointer user_data)
{
  GumEmitLrFuncContext * ctx = user_data;
  GumArm64Writer aw;
  const gchar * func_start = "func_start";

  gum_arm64_writer_init (&aw, mem);
  aw.pc = GUM_ADDRESS (ctx->code);

  ctx->run = gum_sign_code_pointer (GSIZE_TO_POINTER (aw.pc));
  gum_arm64_writer_put_push_reg_reg (&aw, ARM64_REG_X19, ARM64_REG_LR);
  gum_arm64_writer_put_bl_label (&aw, func_start);
  ctx->caller_lr = aw.pc;
  gum_arm64_writer_put_pop_reg_reg (&aw, ARM64_REG_X19, ARM64_REG_LR);
  gum_arm64_writer_put_ret (&aw);

  ctx->func = GSIZE_TO_POINTER (aw.pc);
  gum_arm64_writer_put_label (&aw, func_start);
  gum_arm64_writer_put_push_reg_reg (&aw, ARM64_REG_X19, ARM64_REG_X20);
  gum_arm64_writer_put_nop (&aw);
  gum_arm64_writer_put_nop (&aw);
  gum_arm64_writer_put_mov_reg_reg (&aw, ARM64_REG_X0, ARM64_REG_LR);
  gum_arm64_writer_put_pop_reg_reg (&aw, ARM64_REG_X19, ARM64_REG_X20);
  gum_arm64_writer_put_ret (&aw);

  gum_arm64_writer_clear (&aw);
}
