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

#include "guminterceptor-priv.h"

#define SAVED_REGISTERS_SIZE         40

#define GUARD_MAGIC_TIB_OFFSET      704h
#define GUARD_MAGIC_VALUE      47756D21h

__declspec(naked) void
_gum_interceptor_function_context_on_enter_thunk ()
{
  guint32 prev_guard_value;
  FunctionContext * function_ctx;
  GumCpuContext * cpu_context;
  gpointer * caller_ret_addr;
  gpointer function_arguments;

  __asm
  {
    /* save flags and registers, but bail if we're recursing */
    pushfd;

    cmp fs:[GUARD_MAGIC_TIB_OFFSET], GUARD_MAGIC_VALUE;
    jnz proceed;
    popfd;
    ret 4;

proceed:
    pushad;
    push ebp; /* placeholder for GumCpuContext.eip */

    /* standard prologue */
    push ebp;
    mov ebp, esp;
    sub esp, __LOCAL_SIZE;

    /* start guarding against recursion */
    mov ecx, fs:[GUARD_MAGIC_TIB_OFFSET];
    mov [prev_guard_value], ecx;
    mov fs:[GUARD_MAGIC_TIB_OFFSET], GUARD_MAGIC_VALUE;

    /* fetch input data */
    mov ecx, [ebp + 4 + SAVED_REGISTERS_SIZE + 4 + 0];
    mov [function_ctx], ecx;
    lea ecx, [ebp + 4];
    mov [cpu_context], ecx;
    lea ecx, [ebp + 4 + SAVED_REGISTERS_SIZE + 4 + 4];
    mov [caller_ret_addr], ecx;
    lea ecx, [ebp + 4 + SAVED_REGISTERS_SIZE + 4 + 4 + 4];
    mov [function_arguments], ecx;
  }

  _gum_interceptor_function_context_on_enter (function_ctx, cpu_context,
      caller_ret_addr, function_arguments);

  __asm
  {
    /* stop guarding against recursion */
    mov ecx, [prev_guard_value];
    mov fs:[GUARD_MAGIC_TIB_OFFSET], ecx;

    /* standard epilogue */
    mov esp, ebp;
    pop ebp;

    /* restore flags and registers */
    add esp, 4; /* clear off placeholder for GumCpuContext.eip */
    popad;
    popfd;

    ret 4;
  }
}

__declspec(naked) void
_gum_interceptor_function_context_on_leave_thunk ()
{
  gpointer function_return_value, caller_ret_addr;

  __asm
  {
    push ebp; /* placeholder for caller's return address */

    /* save flags and registers */
    pushfd;
    pushad;
    push ebp; /* placeholder for GumCpuContext.eip */

    /* standard prologue */
    push ebp;
    mov ebp, esp;
    sub esp, __LOCAL_SIZE;

    mov ecx, [ebp + 4 + GumCpuContext.eax];
    mov [function_return_value], ecx;
  }

  caller_ret_addr =
      _gum_interceptor_function_context_on_leave (function_return_value);

  __asm
  {
    /* fill in caller's return address */
    mov eax, [caller_ret_addr];
    mov [ebp + 4 + SAVED_REGISTERS_SIZE], eax;

    /* epilogue */
    mov esp, ebp;
    pop ebp;

    /* restore flags and registers */
    add esp, 4; /* clear off placeholder for GumCpuContext.eip */
    popad;
    popfd;

    ret;
  }
}