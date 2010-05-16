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

.intel_syntax noprefix

.section .text

.set SAVED_REGISTERS_SIZE,       40
.set GUM_CPU_CONTEXT_OFFSET_EAX, 32

.global _gum_interceptor_function_context_on_enter_thunk
  .type _gum_interceptor_function_context_on_enter_thunk, @function
  .balign 16, 0x90
_gum_interceptor_function_context_on_enter_thunk:
  // save flags and registers, but bail if we're recursing
  pushfd;

  //cmp fs:[GUARD_MAGIC_TIB_OFFSET], GUARD_MAGIC_VALUE;
  //jnz proceed;
  //popfd;
  //ret 4;

proceed:
  pushad;
  push ebp; // placeholder for GumCpuContext.eip

  // standard prologue
  push ebp;
  mov ebp, esp;

  // start guarding against recursion
  //mov ecx, fs:[GUARD_MAGIC_TIB_OFFSET];
  //mov [prev_guard_value], ecx;
  //mov fs:[GUARD_MAGIC_TIB_OFFSET], GUARD_MAGIC_VALUE;

  // argument 4: function_arguments
  lea ecx, [ebp + 4 + SAVED_REGISTERS_SIZE + 4 + 4 + 4];
  push ecx;

  // argument 3: caller_ret_addr
  lea ecx, [ebp + 4 + SAVED_REGISTERS_SIZE + 4 + 4];
  push ecx;

  // argument 2: cpu_context
  lea ecx, [ebp + 4];
  push ecx;

  // argument 1: function_ctx
  mov ecx, [ebp + 4 + SAVED_REGISTERS_SIZE + 4 + 0];
  push ecx;

  call _gum_interceptor_function_context_on_enter;
  add esp, 16;

  // stop guarding against recursion
  //mov ecx, [prev_guard_value];
  //mov fs:[GUARD_MAGIC_TIB_OFFSET], ecx;

  // standard epilogue
  mov esp, ebp;
  pop ebp;

  // restore flags and registers
  add esp, 4; // clear off placeholder for GumCpuContext.eip
  popad;
  popfd;

  ret 4;

.global _gum_interceptor_function_context_on_leave_thunk
  .type _gum_interceptor_function_context_on_leave_thunk, @function
  .balign 16, 0x90
_gum_interceptor_function_context_on_leave_thunk:
  push eax; // placeholder for caller's return address

  // save flags and registers
  pushfd;
  pushad;
  push eax; // placeholder for GumCpuContext.eip

  // standard prologue
  push ebp;
  mov ebp, esp;

  // argument 1: function_return_value
  mov ecx, [ebp + 4 + GUM_CPU_CONTEXT_OFFSET_EAX];
  push ecx

  call _gum_interceptor_function_context_on_leave;
  add esp, 4;

  // fill in caller's return address
  mov [ebp + 4 + SAVED_REGISTERS_SIZE], eax;

  // epilogue
  mov esp, ebp;
  pop ebp;

  // restore flags and registers
  add esp, 4; // clear off placeholder for GumCpuContext.eip
  popad;
  popfd;

  ret;

