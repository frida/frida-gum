/*
 * Copyright (C) 2010-2019 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumspinlock.h"

#include "gumlibc.h"

void
gum_spinlock_init (GumSpinlock * spinlock)
{
  gum_memset (spinlock, 0, sizeof (GumSpinlock));
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
