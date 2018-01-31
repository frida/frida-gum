/*
 * Copyright (C) 2010-2018 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumspinlock.h"

typedef struct _GumSpinlockImpl GumSpinlockImpl;

struct _GumSpinlockImpl
{
  volatile gint is_held;
};

void
gum_spinlock_init (GumSpinlock * spinlock)
{
  GumSpinlockImpl * self = (GumSpinlockImpl *) spinlock;

  self->is_held = FALSE;
}

void
gum_spinlock_free (GumSpinlock * spinlock)
{
}

void
gum_spinlock_acquire (GumSpinlock * spinlock)
{
  GumSpinlockImpl * self = (GumSpinlockImpl *) spinlock;

  while (!g_atomic_int_compare_and_exchange (&self->is_held, FALSE, TRUE))
    ;
}

void
gum_spinlock_release (GumSpinlock * spinlock)
{
  GumSpinlockImpl * self = (GumSpinlockImpl *) spinlock;

  g_atomic_int_set (&self->is_held, FALSE);
}
