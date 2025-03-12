/*
 * Copyright (C) 2014-2015 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumdefs.h"

gpointer
gum_cpu_context_get_nth_argument (GumCpuContext * self,
                                  guint n)
{
  if (n < 8)
  {
    return GSIZE_TO_POINTER (self->x[n]);
  }
  else
  {
    gpointer * stack_argument = GSIZE_TO_POINTER (self->sp);

    return stack_argument[n - 8];
  }
}

void
gum_cpu_context_replace_nth_argument (GumCpuContext * self,
                                      guint n,
                                      gpointer value)
{
  if (n < 8)
  {
    self->x[n] = GPOINTER_TO_SIZE (value);
  }
  else
  {
    gpointer * stack_argument = GSIZE_TO_POINTER (self->sp);

    stack_argument[n - 8] = value;
  }
}

gpointer
gum_cpu_context_get_return_value (GumCpuContext * self)
{
  return GSIZE_TO_POINTER (self->x[0]);
}

void
gum_cpu_context_replace_return_value (GumCpuContext * self,
                                      gpointer value)
{
  self->x[0] = GPOINTER_TO_SIZE (value);
}
