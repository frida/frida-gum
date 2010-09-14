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

#include <string.h>
#include <unistd.h>

#define FUNCTION_CONTEXT_ADDRESS(ctx) (GSIZE_TO_POINTER ( \
    GPOINTER_TO_SIZE (ctx->function_address) & ~0x1))

static void gum_function_context_clear_cache (FunctionContext * ctx);
extern void __clear_cache (guint8 * begin, guint8 * end);

static void dump_bytes (guint8 * address, guint size);
static void dump_thumb_code (guint8 * address, guint size);

static const guint16 thumb_enter_stage1_code[] =
{
  /* build high part of GumCpuContext */
  0xb5ff, /* push {r0, r1, r2, r3, r4, r5, r6, r7, lr} */

  /* jump to stage2 */
  0x4801, /* ldr r0, [pc, #4] */
  0x4700, /* bx r0 */
  0x46c0, /* nop (alignment padding) */
};

static const guint16 thumb_enter_stage2_code[] =
{
  /* build low part of GumCpuContext */
  0xa909, /* add r1, sp, #(9 * 4) */
  0xb403, /* push {r0, r1} */

  0x4803, /* ldr r0, [pc, #12] */
  0x4669, /* mov r1, sp */
  0x2228, /* movs r2, #(4 + 4 + (8 * 4)) */
  0x1852, /* adds r2, r2, r1 */
  0x4b00, /* ldr r3, [pc, #0] */
  0x4798, /* blx r3 */

  /* TODO */
};

void
_gum_function_context_make_monitor_trampoline (FunctionContext * ctx)
{
  gpointer function_address;
  gpointer * data;

  g_assert_cmpuint (GPOINTER_TO_SIZE (ctx->function_address) & 0x1, ==, 0x1);
  function_address = FUNCTION_CONTEXT_ADDRESS (ctx);
  g_assert ((GPOINTER_TO_SIZE (function_address) & 0x2) == 0);

  g_print ("\n\nbuilding trampoline for function_ctx=%p\n\n", ctx);
  dump_bytes (function_address, 32);
  dump_thumb_code (function_address, 32);

  ctx->overwritten_prologue_len = sizeof (thumb_enter_stage1_code) +
      sizeof (gpointer);
  memcpy (ctx->overwritten_prologue, function_address,
      ctx->overwritten_prologue_len);

  ctx->trampoline_slice = gum_code_allocator_new_slice_near (ctx->allocator,
      function_address);

  ctx->on_enter_trampoline = ctx->trampoline_slice->data;
  memcpy (ctx->on_enter_trampoline, thumb_enter_stage2_code,
      sizeof (thumb_enter_stage2_code));
  data = (gpointer *) ((guint8 *) ctx->on_enter_trampoline +
      sizeof (thumb_enter_stage2_code));
  data[0] = _gum_function_context_on_enter;
  data[1] = ctx;

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
  guint8 * function_address = FUNCTION_CONTEXT_ADDRESS (ctx);

  memcpy (function_address, thumb_enter_stage1_code,
      sizeof (thumb_enter_stage1_code));
  *((gpointer *) (function_address + sizeof (thumb_enter_stage1_code))) =
      ctx->on_enter_trampoline + 1;
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
      sizeof (thumb_enter_stage1_code) + sizeof (gpointer));
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

