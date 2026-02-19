/*
 * Copyright (C) 2014-2015 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 * Copyright (C) 2025 Francesco Tamagni <mrmacete@protonmail.ch>
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
      case 4:
        return (gpointer) self->a4;
      case 5:
        return (gpointer) self->a5;
      case 6:
        return (gpointer) self->a6;
      case 7:
        return (gpointer) self->a7;
    }
  }
  else
  {
    gpointer * stack_argument = (gpointer *) self->sp;

    return stack_argument[n - 8];
  }

  return NULL;
}

void
gum_cpu_context_replace_nth_argument (GumCpuContext * self,
                                      guint n,
                                      gpointer value)
{
  if (n < 8)
  {
    switch (n)
    {
      case 0:
        self->a0 = (guint64) GPOINTER_TO_SIZE (value);
        break;
      case 1:
        self->a1 = (guint64) GPOINTER_TO_SIZE (value);
        break;
      case 2:
        self->a2 = (guint64) GPOINTER_TO_SIZE (value);
        break;
      case 3:
        self->a3 = (guint64) GPOINTER_TO_SIZE (value);
        break;
      case 4:
        self->a4 = (guint64) GPOINTER_TO_SIZE (value);
        break;
      case 5:
        self->a5 = (guint64) GPOINTER_TO_SIZE (value);
        break;
      case 6:
        self->a6 = (guint64) GPOINTER_TO_SIZE (value);
        break;
      case 7:
        self->a7 = (guint64) GPOINTER_TO_SIZE (value);
        break;
    }
  }
  else
  {
    gpointer * stack_argument = (gpointer *) self->sp;

    stack_argument[n - 8] = value;
  }
}

gpointer
gum_cpu_context_get_return_value (GumCpuContext * self)
{
  return (gpointer) self->a0;
}

void
gum_cpu_context_replace_return_value (GumCpuContext * self,
                                      gpointer value)
{
  self->a0 = (guint64) GPOINTER_TO_SIZE (value);
}

