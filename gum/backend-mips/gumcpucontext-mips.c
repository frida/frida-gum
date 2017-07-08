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
  if (n < 4)
  {
    switch (n)
    {
      case 0:
        return (gpointer) self->a0;
      case 1:
        return (gpointer) self->a1;
      case 2:
        return (gpointer) self->a2;
      case 3:
        return (gpointer) self->a3;
    }
  }
  else
  {
    gpointer * stack_argument = (gpointer *) (self->sp + 0x14);

    return stack_argument[n - 4];
  }

  return NULL;
}

void
gum_cpu_context_replace_nth_argument (GumCpuContext * self,
                                      guint n,
                                      gpointer value)
{
  if (n < 4)
  {
    switch (n)
    {
      case 0:
        self->a0 = (guint32) value;
        break;
      case 1:
        self->a1 = (guint32) value;
        break;
      case 2:
        self->a2 = (guint32) value;
        break;
      case 3:
        self->a3 = (guint32) value;
        break;
    }
  }
  else
  {
    gpointer * stack_argument = (gpointer *) (self->sp + 0x14);

    stack_argument[n - 4] = value;
  }
}

gpointer
gum_cpu_context_get_return_value (GumCpuContext * self)
{
  return (gpointer) self->v0;
}

void
gum_cpu_context_replace_return_value (GumCpuContext * self,
                                      gpointer value)
{
  self->v0 = (guint32) value;
}
