/*
 * Copyright (C) 2010 Ole André Vadla Ravnås <ole.andre.ravnas@tandberg.com>
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

#include "guminterceptor-priv.h"

#include "gummemory.h"
#include "gumthumbwriter.h"

#include <string.h>
#include <unistd.h>

#define GUM_INTERCEPTOR_REDIRECT_CODE_SIZE (8 + 4)
#define FUNCTION_CONTEXT_ADDRESS(ctx) (GSIZE_TO_POINTER ( \
    GPOINTER_TO_SIZE (ctx->function_address) & ~0x1))

static void gum_function_context_clear_cache (FunctionContext * ctx);
extern void __clear_cache (guint8 * begin, guint8 * end);

static void dump_bytes (guint8 * address, guint size);
static void dump_thumb_code (guint8 * address, guint size);

void
_gum_function_context_make_monitor_trampoline (FunctionContext * ctx)
{
  gpointer function_address;
  GumThumbWriter tw;

  g_assert_cmpuint (GPOINTER_TO_SIZE (ctx->function_address) & 0x1, ==, 0x1);
  function_address = FUNCTION_CONTEXT_ADDRESS (ctx);
  g_assert ((GPOINTER_TO_SIZE (function_address) & 0x2) == 0);

  g_print ("\n\nbuilding trampoline for function_ctx=%p\n\n", ctx);
  dump_bytes (function_address, 32);
  dump_thumb_code (function_address, 32);

  ctx->overwritten_prologue_len = GUM_INTERCEPTOR_REDIRECT_CODE_SIZE;
  memcpy (ctx->overwritten_prologue, function_address,
      ctx->overwritten_prologue_len);

  ctx->trampoline_slice = gum_code_allocator_new_slice_near (ctx->allocator,
      function_address);

  gum_thumb_writer_init (&tw, ctx->trampoline_slice->data);

  /*
   * Generate on_enter trampoline
   */
  ctx->on_enter_trampoline = gum_thumb_writer_cur (&tw);

  /* build low part of GumCpuContext */
  gum_thumb_writer_put_add_reg_reg_imm (&tw, GUM_TREG_R1, GUM_TREG_SP, 9 * 4);
  gum_thumb_writer_put_push_regs (&tw, 2, GUM_TREG_R0, GUM_TREG_R1);

  gum_thumb_writer_put_ldr_address (&tw, GUM_TREG_R0, GUM_ADDRESS (ctx));
  gum_thumb_writer_put_mov_reg_reg (&tw, GUM_TREG_R1, GUM_TREG_SP);
  gum_thumb_writer_put_mov_reg_u8 (&tw, GUM_TREG_R2, 4 + 4 + (8 * 4));
  gum_thumb_writer_put_add_reg_reg (&tw, GUM_TREG_R2, GUM_TREG_R1);
  gum_thumb_writer_put_ldr_address (&tw, GUM_TREG_R3,
      GUM_ADDRESS (_gum_function_context_on_enter));
  gum_thumb_writer_put_blx_reg (&tw, GUM_TREG_R3);

  gum_thumb_writer_free (&tw);

#if defined (HAVE_DARWIN) && defined (HAVE_ARM)
  gum_mprotect (ctx->trampoline_slice->data, ctx->trampoline_slice->size,
      GUM_PAGE_READ | GUM_PAGE_EXECUTE);
#endif
}

void
_gum_function_context_make_replace_trampoline (FunctionContext * ctx,
                                               gpointer replacement_address,
                                               gpointer user_data)
{
  g_assert_not_reached ();
}

void
_gum_function_context_destroy_trampoline (FunctionContext * ctx)
{
#if defined (HAVE_DARWIN) && defined (HAVE_ARM)
  gum_mprotect (ctx->trampoline_slice->data, ctx->trampoline_slice->size,
      GUM_PAGE_READ | GUM_PAGE_WRITE);
#endif

  gum_code_allocator_free_slice (ctx->allocator, ctx->trampoline_slice);
  ctx->trampoline_slice = NULL;
}

void
_gum_function_context_activate_trampoline (FunctionContext * ctx)
{
  GumThumbWriter tw;

  gum_thumb_writer_init (&tw, FUNCTION_CONTEXT_ADDRESS (ctx));

  /* build high part of GumCpuContext */
  gum_thumb_writer_put_push_regs (&tw, 8 + 1,
      GUM_TREG_R0, GUM_TREG_R1, GUM_TREG_R2, GUM_TREG_R3,
      GUM_TREG_R4, GUM_TREG_R5, GUM_TREG_R6, GUM_TREG_R7,
      GUM_TREG_LR);

  /* jump to stage2 */
  gum_thumb_writer_put_ldr_address (&tw, GUM_TREG_R0,
      GUM_ADDRESS (ctx->on_enter_trampoline + 1));
  gum_thumb_writer_put_bx_reg (&tw, GUM_TREG_R0);
  gum_thumb_writer_free (&tw);

  gum_function_context_clear_cache (ctx);
}

void
_gum_function_context_deactivate_trampoline (FunctionContext * ctx)
{
  guint8 * function_address = FUNCTION_CONTEXT_ADDRESS (ctx);

  memcpy (function_address, ctx->overwritten_prologue,
      ctx->overwritten_prologue_len);
  gum_function_context_clear_cache (ctx);
}

static void
gum_function_context_clear_cache (FunctionContext * ctx)
{
  guint8 * function_address = FUNCTION_CONTEXT_ADDRESS (ctx);

  __clear_cache (function_address, function_address +
      GUM_INTERCEPTOR_REDIRECT_CODE_SIZE);
}

gpointer
_gum_interceptor_resolve_redirect (gpointer address)
{
  return NULL;
}

gboolean
_gum_interceptor_can_intercept (gpointer function_address)
{
  return (GPOINTER_TO_SIZE (function_address) & 0x1) == 0x1; /* thumb */
}

gpointer
_gum_interceptor_invocation_get_nth_argument (GumInvocationContext * context,
                                              guint n)
{
  g_assert_cmpuint (n, <=, 3); /* FIXME */

  return (gpointer) context->cpu_context->r[n];
}

void
_gum_interceptor_invocation_replace_nth_argument (
    GumInvocationContext * context,
    guint n,
    gpointer value)
{
  g_assert_cmpuint (n, <=, 3); /* FIXME */

  context->cpu_context->r[n] = (guint32) value;
}

gpointer
_gum_interceptor_invocation_get_return_value (GumInvocationContext * context)
{
  return (gpointer) context->cpu_context->r[0];
}

static void
dump_bytes (guint8 * address,
            guint size)
{
  GString * s;
  guint total_offset, line_offset;

  s = g_string_sized_new (1024);

  g_string_append (s, "Bytes:\n");

  for (total_offset = 0, line_offset = 0; total_offset != size; total_offset++)
  {
    if (line_offset == 0)
    {
      g_string_append_printf (s, "%08x ",
          GPOINTER_TO_UINT (address + total_offset));
    }
    else if (line_offset == 8)
    {
      g_string_append_c (s, ' ');
    }

    g_string_append_printf (s, " %02x", address[total_offset]);

    line_offset++;
    if (line_offset == 16)
    {
      g_string_append_c (s, '\n');
      line_offset = 0;
    }
  }

  g_string_append_c (s, '\n');

  write (1, s->str, s->len);
  g_string_free (s, TRUE);
}

static void
dump_thumb_code (guint8 * address,
                 guint size)
{
  GString * s;
  guint total_offset;

  g_assert_cmpuint (size % 2, ==, 0);

  s = g_string_sized_new (1024);

  g_string_append (s, "Thumb code:\n");

  for (total_offset = 0; total_offset != size; total_offset += 2)
  {
    guint16 insn = *((guint16 *) (address + total_offset));

    g_string_append_printf (s, "%08x  %04x\n",
        GPOINTER_TO_UINT (address + total_offset), (guint) insn);
  }

  g_string_append_c (s, '\n');

  write (1, s->str, s->len);
  g_string_free (s, TRUE);
}

