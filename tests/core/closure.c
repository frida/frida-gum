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

#include "closure-fixture.c"

TEST_LIST_BEGIN (closure)
  CLOSURE_TESTENTRY (can_invoke_capi_function_accepting_string_and_int)
TEST_LIST_END ()

static gboolean gum_target_function_has_been_called = FALSE;

CLOSURE_TESTCASE (can_invoke_capi_function_accepting_string_and_int)
{
  fixture->closure = gum_closure_new (GUM_CALL_CAPI,
      GUM_CLOSURE_TARGET (can_invoke_capi_function_accepting_string_and_int),
      g_variant_new ("(si)", "Hello Gum", -42));
  gum_closure_invoke (fixture->closure);
  g_assert (gum_target_function_has_been_called);
}

static void
can_invoke_capi_function_accepting_string_and_int (const gchar * str,
                                                   gint i)
{
  gum_target_function_has_been_called = TRUE;

  g_assert_cmpstr (str, ==, "Hello Gum");
  g_assert_cmpint (i, ==, -42);
}