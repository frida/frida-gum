/*
 * Copyright (C) 2010 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
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

#include "gumspinlock.h"

#include <string.h>

typedef struct _GumSpinlockImpl GumSpinlockImpl;

struct _GumSpinlockImpl
{
  volatile int is_held;
};

void
gum_spinlock_init (GumSpinlock * spinlock)
{
  memset (spinlock, 0, sizeof (GumSpinlock));
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
