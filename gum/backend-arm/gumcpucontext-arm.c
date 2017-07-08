/*
 * Copyright (C) 2010 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumdefs.h"

gpointer
gum_cpu_context_get_nth_argument (GumCpuContext * self,
                                  guint n)
{
  if (n < 4)
  {
    return (gpointer) self->r[n];
  }
  else
  {
    gpointer * stack_argument = (gpointer *) self->sp;

    return stack_argument[n - 4];
  }
}

void
gum_cpu_context_replace_nth_argument (GumCpuContext * self,
                                      guint n,
                                      gpointer value)
{
  if (n < 4)
  {
    self->r[n] = (guint32) value;
  }
  else
  {
    gpointer * stack_argument = (gpointer *) self->sp;

    stack_argument[n - 4] = value;
  }
}

gpointer
gum_cpu_context_get_return_value (GumCpuContext * self)
{
  return (gpointer) self->r[0];
}

void
gum_cpu_context_replace_return_value (GumCpuContext * self,
                                      gpointer value)
{
  self->r[0] = (guint32) value;
}
