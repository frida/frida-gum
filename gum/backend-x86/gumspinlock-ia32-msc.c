/*
 * Copyright (C) 2010 Ole André Vadla Ravnås <ole.andre.ravnas@tandberg.com>
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

void
gum_spinlock_init (GumSpinlock * spinlock)
{
  memset (spinlock, 0, sizeof (GumSpinlock));
}

void
gum_spinlock_free (GumSpinlock * spinlock)
{
}

__declspec (naked) void
gum_spinlock_acquire (GumSpinlock * spinlock)
{
  __asm
  {
    mov ecx, [esp + 4];
    mov edx, 1;

try_again:
    xor eax, eax;
    lock cmpxchg [ecx], edx;
    jz beach;

    pause;
    jmp try_again;

beach:
    ret;
  }
}

__declspec (naked) void
gum_spinlock_release (GumSpinlock * spinlock)
{
  __asm
  {
    mov ecx, [esp + 4];
    mov [ecx], 0;
    ret;
  }
}
