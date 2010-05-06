/*
 * Copyright (C) 2008 Ole André Vadla Ravnås <ole.andre.ravnas@tandberg.com>
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

#include "interceptor-lowlevel.h"

typedef struct _CpuContext CpuContext;

struct _CpuContext
{
  gsize edi;
  gsize esi;
  gsize ebp;
  gsize esp;
  gsize ebx;
  gsize edx;
  gsize ecx;
  gsize eax;
};

#pragma warning (push)
#pragma warning (disable: 4731) /* yes, we're intentionally changing EBP */

void
invoke_clobber_test_function_with_cpu_context (const GumCpuContext * input,
                                               GumCpuContext * output)
{
  __asm
  {
    pushad;

    mov eax, [input];
    mov edi, [eax + GumCpuContext.edi];
    mov esi, [eax + GumCpuContext.esi];
    mov ebx, [eax + GumCpuContext.ebx];
    mov edx, [eax + GumCpuContext.edx];
    mov ecx, [eax + GumCpuContext.ecx];
    mov eax, [eax + GumCpuContext.eax];

    mov ebp, [input];
    mov ebp, [ebp + GumCpuContext.ebp];

    call clobber_test_function;

    push eax;
    mov eax, ebp;
    mov ebp, [esp + 4 + CpuContext.ebp];
    mov ebp, [output];
    mov [ebp + GumCpuContext.ebp], eax;
    pop eax;

    mov [ebp + GumCpuContext.edi], edi;
    mov [ebp + GumCpuContext.esi], esi;
    mov [ebp + GumCpuContext.ebx], ebx;
    mov [ebp + GumCpuContext.edx], edx;
    mov [ebp + GumCpuContext.ecx], ecx;
    mov [ebp + GumCpuContext.eax], eax;

    popad;
  }
}

#pragma warning (pop)

void
invoke_clobber_test_function_with_carry_set (gsize * flags_input,
                                             gsize * flags_output)
{
  __asm
  {
    pushad;

    stc; /* enable carry flag, very likely to get clobbered */

    pushfd;
    pop eax;
    mov ecx, [flags_input];
    mov [ecx], eax;

    call clobber_test_function;

    pushfd;
    pop eax;
    mov ecx, [flags_output];
    mov [ecx], eax;

    popad;
  }
}

gpointer __declspec (naked)
clobber_test_function (gpointer data)
{
  __asm
  {
    /* 5 byte padding */
    nop;
    nop;
    nop;
    nop;
    nop;

    ret;
  }
}

