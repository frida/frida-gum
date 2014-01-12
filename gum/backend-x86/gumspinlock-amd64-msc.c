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

#include "gumx86writer.h"
#include "gummemory.h"

typedef struct _GumSpinlockImpl GumSpinlockImpl;

typedef void (* GumSpinlockAcquireFunc) (GumSpinlock * spinlock);

struct _GumSpinlockImpl
{
  volatile guint32 is_held;

  gpointer code;
  GumSpinlockAcquireFunc acquire_impl;
};

void
gum_spinlock_init (GumSpinlock * spinlock)
{
  GumSpinlockImpl * self = (GumSpinlockImpl *) spinlock;
  GumX86Writer cw;
  gpointer try_again_label = "gum_spinlock_try_again";
  gpointer beach_label = "gum_spinlock_beach";

  self->is_held = FALSE;

  self->code = gum_alloc_n_pages (1, GUM_PAGE_RWX);

  gum_x86_writer_init (&cw, self->code);

  self->acquire_impl = GUM_POINTER_TO_FUNCPTR (GumSpinlockAcquireFunc,
      gum_x86_writer_cur (&cw));
  gum_x86_writer_put_mov_reg_u32 (&cw, GUM_REG_EDX, 1);

  gum_x86_writer_put_label (&cw, try_again_label);
  gum_x86_writer_put_mov_reg_u32 (&cw, GUM_REG_EAX, 0);
  gum_x86_writer_put_lock_cmpxchg_reg_ptr_reg (&cw, GUM_REG_RCX, GUM_REG_EDX);
  gum_x86_writer_put_jcc_short_label (&cw, GUM_X86_JZ, beach_label,
      GUM_NO_HINT);

  gum_x86_writer_put_pause (&cw);
  gum_x86_writer_put_jmp_short_label (&cw, try_again_label);

  gum_x86_writer_put_label (&cw, beach_label);
  gum_x86_writer_put_ret (&cw);

  gum_x86_writer_free (&cw);
}

void
gum_spinlock_free (GumSpinlock * spinlock)
{
  GumSpinlockImpl * self = (GumSpinlockImpl *) spinlock;

  gum_free_pages (self->code);
}

void
gum_spinlock_acquire (GumSpinlock * spinlock)
{
  ((GumSpinlockImpl *) spinlock)->acquire_impl (spinlock);
}

void
gum_spinlock_release (GumSpinlock * spinlock)
{
  ((GumSpinlockImpl *) spinlock)->is_held = FALSE;
}
