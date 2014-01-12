/*
 * Copyright (C) 2008-2010 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
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

#include "guminvocationcontext.h"

GumPointCut
gum_invocation_context_get_point_cut (GumInvocationContext * context)
{
  return context->backend->get_point_cut (context);
}

gpointer
gum_invocation_context_get_nth_argument (GumInvocationContext * context,
                                         guint n)
{
  return context->backend->get_nth_argument (context, n);
}

void
gum_invocation_context_replace_nth_argument (GumInvocationContext * context,
                                             guint n,
                                             gpointer value)
{
  context->backend->replace_nth_argument (context, n, value);
}

gpointer
gum_invocation_context_get_return_value (GumInvocationContext * context)
{
  return context->backend->get_return_value (context);
}

guint
gum_invocation_context_get_thread_id (GumInvocationContext * context)
{
  return context->backend->get_thread_id (context);
}

gpointer
gum_invocation_context_get_listener_thread_data (
    GumInvocationContext * context,
    gsize required_size)
{
  return context->backend->get_listener_thread_data (context, required_size);
}

gpointer
gum_invocation_context_get_listener_function_data (
    GumInvocationContext * context)
{
  return context->backend->get_listener_function_data (context);
}

gpointer
gum_invocation_context_get_listener_function_invocation_data (
    GumInvocationContext * context,
    gsize required_size)
{
  return context->backend->get_listener_function_invocation_data (context,
      required_size);
}

gpointer
gum_invocation_context_get_replacement_function_data (
    GumInvocationContext * context)
{
  return context->backend->get_replacement_function_data (context);
}
