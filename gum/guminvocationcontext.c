/*
 * Copyright (C) 2008-2010 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
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

void
gum_invocation_context_replace_return_value (GumInvocationContext * context,
                                             gpointer value)
{
  context->backend->replace_return_value (context, value);
}

gpointer
gum_invocation_context_get_return_address (GumInvocationContext * context)
{
  GumCpuContext * c = context->cpu_context;

#if defined (HAVE_I386)
# if GLIB_SIZEOF_VOID_P == 4
  return GSIZE_TO_POINTER (c->eip);
# else
  return GSIZE_TO_POINTER (c->rip);
# endif
#elif defined (HAVE_ARM)
  return GSIZE_TO_POINTER (c->pc);
#elif defined (HAVE_ARM64)
  return GSIZE_TO_POINTER (c->pc);
#else
# error Unsupported architecture
#endif
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
