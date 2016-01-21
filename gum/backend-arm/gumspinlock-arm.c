/*
 * Copyright (C) 2010 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumspinlock.h"

#include "gumlibc.h"

typedef struct _GumSpinlockImpl GumSpinlockImpl;

struct _GumSpinlockImpl
{
  volatile int is_held;
};

void
gum_spinlock_init (GumSpinlock * spinlock)
{
  gum_memset (spinlock, 0, sizeof (GumSpinlock));
}

void
gum_spinlock_free (GumSpinlock * spinlock)
{
}

void
gum_spinlock_acquire (GumSpinlock * spinlock)
{
  GumSpinlockImpl * self = (GumSpinlockImpl *) spinlock;

  while (__sync_lock_test_and_set (&self->is_held, 1))
    ;
}

void
gum_spinlock_release (GumSpinlock * spinlock)
{
  GumSpinlockImpl * self = (GumSpinlockImpl *) spinlock;

  __sync_lock_release (&self->is_held);
}
