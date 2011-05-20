/*
 * Copyright (C) 2011 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
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

#include "gumclosure.h"

#include "gummemory.h"
#include "gumthumbwriter.h"

struct _GumClosure
{
  GVariant * args;
  gpointer code;
  GCallback entrypoint;
};

GumClosure *
gum_closure_new (GumCallingConvention conv,
                 GumClosureTarget target,
                 GVariant * args)
{
  GumClosure * closure;
  GumThumbWriter cw;
  gsize arg_count;
  gint arg_index;
  guint code_size;

  g_assert_cmpint (conv, ==, GUM_CALL_CAPI);

  closure = g_slice_new (GumClosure);
  closure->args = g_variant_ref_sink (args);
  closure->code = gum_alloc_n_pages (1, GUM_PAGE_RW);
  closure->entrypoint = GUM_POINTER_TO_FUNCPTR (GCallback, closure->code + 1);

  gum_thumb_writer_init (&cw, closure->code);

  arg_count = g_variant_n_children (args);
  g_assert_cmpuint (arg_count, <=, 4);

  for (arg_index = 0; arg_index != arg_count; arg_index++)
  {
    GVariant * arg;
    GumAddress arg_value;

    arg = g_variant_get_child_value (args, arg_index);

    if (g_variant_is_of_type (arg, G_VARIANT_TYPE_STRING))
    {
      arg_value = GUM_ADDRESS (g_variant_get_string (arg, NULL));
    }
    else if (g_variant_is_of_type (arg, G_VARIANT_TYPE_INT32))
    {
      arg_value = GUM_ADDRESS (g_variant_get_int32 (arg));
    }
    else
    {
      arg_value = 0;
      g_assert_not_reached ();
    }

    gum_thumb_writer_put_ldr_reg_address (&cw, GUM_AREG_R0 + arg_index,
        arg_value);

    g_variant_unref (arg);
  }

  gum_thumb_writer_put_push_regs (&cw, 2, GUM_AREG_R4, GUM_AREG_LR);

  gum_thumb_writer_put_ldr_reg_address (&cw, GUM_AREG_R4,
      GUM_ADDRESS (target));
  gum_thumb_writer_put_blx_reg (&cw, GUM_AREG_R4);

  gum_thumb_writer_put_pop_regs (&cw, 2, GUM_AREG_R4, GUM_AREG_PC);

  gum_thumb_writer_free (&cw);

  code_size = gum_query_page_size ();
  gum_mprotect (closure->code, code_size, GUM_PAGE_RX);
  gum_clear_cache (closure->code, code_size);

  return closure;
}

void
gum_closure_free (GumClosure * closure)
{
  g_variant_unref (closure->args);
  gum_free_pages (closure->code);

  g_slice_free (GumClosure, closure);
}

void
gum_closure_invoke (GumClosure * closure)
{
  closure->entrypoint ();
}
