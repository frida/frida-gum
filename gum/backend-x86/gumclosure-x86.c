/*
 * Copyright (C) 2011 Ole André Vadla Ravnås <ole.andre.ravnas@tandberg.com>
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
#include "gumx86writer.h"

#include <string.h>

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
  GumX86Writer cw;
  gsize arg_count;
  gint arg_index;
  gsize args_stack_alloc;

  g_assert_cmpint (conv, ==, GUM_CALL_CAPI);

  closure = g_slice_new (GumClosure);
  closure->args = g_variant_ref_sink (args);
  closure->code = gum_alloc_n_pages (1, GUM_PAGE_RWX);
  closure->entrypoint = GUM_POINTER_TO_FUNCPTR (GCallback, closure->code);

  gum_x86_writer_init (&cw, closure->code);

  arg_count = g_variant_n_children (args);
  g_assert_cmpuint (arg_count, <=, 4);

  for (arg_index = arg_count - 1; arg_index >= 0; arg_index--)
  {
    GVariant * arg;
    GumCpuReg arg_reg;
    GumAddress arg_value;

    arg = g_variant_get_child_value (args, arg_index);

#if GLIB_SIZEOF_VOID_P == 4
    arg_reg = GUM_REG_XAX;
#else
    arg_reg = gum_x86_writer_get_cpu_register_for_nth_argument (&cw,
        arg_index);
#endif

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

    gum_x86_writer_put_mov_reg_address (&cw, arg_reg, arg_value);
#if GLIB_SIZEOF_VOID_P == 4
    gum_x86_writer_put_push_reg (&cw, arg_reg);
#endif

    g_variant_unref (arg);
  }

#if GLIB_SIZEOF_VOID_P == 8
  args_stack_alloc = 4 * sizeof (gpointer);
  gum_x86_writer_put_sub_reg_imm (&cw, GUM_REG_XSP, args_stack_alloc);
#else
  args_stack_alloc = arg_count * sizeof (gpointer);
#endif

  gum_x86_writer_put_call (&cw, GUM_FUNCPTR_TO_POINTER (target));

  if (args_stack_alloc != 0)
    gum_x86_writer_put_add_reg_imm (&cw, GUM_REG_XSP, args_stack_alloc);

  gum_x86_writer_put_ret (&cw);

  gum_x86_writer_free (&cw);

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