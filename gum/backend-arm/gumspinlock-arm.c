/*
 * Copyright (C) 2010-2021 Ole André Vadla Ravnås <oleavr@nowsecure.com>
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
gum_spinlock_acquire (GumSpinlock * spinlock)
{
  GumSpinlockImpl * self = (GumSpinlockImpl *) spinlock;

#ifdef HAVE_SYNC_LOCK
  while (__sync_lock_test_and_set (&self->is_held, 1))
    ;
#else
  while (!g_atomic_int_compare_and_exchange (&self->is_held, FALSE, TRUE))
    ;
#endif
}

void
gum_spinlock_release (GumSpinlock * spinlock)
{
  GumSpinlockImpl * self = (GumSpinlockImpl *) spinlock;

#ifdef HAVE_SYNC_LOCK
  __sync_lock_release (&self->is_held);
#else
  g_atomic_int_set (&self->is_held, FALSE);
#endif
}
