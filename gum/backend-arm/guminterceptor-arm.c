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

#include <unistd.h>

static void dump_bytes (guint8 * address, guint size);
static void dump_thumb_code (guint8 * address, guint size);

void
_gum_function_context_make_monitor_trampoline (FunctionContext * ctx)
{
  gpointer function_address;

  g_assert_cmpuint (GPOINTER_TO_SIZE (ctx->function_address) & 0x1, ==, 0x1);
  function_address = GSIZE_TO_POINTER (
      GPOINTER_TO_SIZE (ctx->function_address) & ~0x1);

  g_print ("\n\n");
  dump_bytes (function_address, 32);
  dump_thumb_code (function_address, 32);

  g_assert_not_reached ();
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
  gum_code_allocator_free_slice (ctx->allocator, ctx->trampoline_slice);
  ctx->trampoline_slice = NULL;
}

void
_gum_function_context_activate_trampoline (FunctionContext * ctx)
{
  g_assert_not_reached ();
}

void
_gum_function_context_deactivate_trampoline (FunctionContext * ctx)
{
  g_assert_not_reached ();
}

gpointer
_gum_interceptor_resolve_redirect (gpointer address)
{
  return NULL;
}

gboolean
_gum_interceptor_can_intercept (gpointer function_address)
{
  return TRUE;
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

    g_string_append_printf (s, "%08x  %02x %02x\n",
        GPOINTER_TO_UINT (address + total_offset),
        (guint) ((insn & 0xff00) >> 8),
        (guint) ((insn & 0x00ff) >> 0));
  }

  g_string_append_c (s, '\n');

  write (1, s->str, s->len);
  g_string_free (s, TRUE);
}

