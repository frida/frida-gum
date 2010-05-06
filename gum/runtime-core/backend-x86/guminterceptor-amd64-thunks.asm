;
; Copyright (C) 2009 Ole André Vadla Ravnås <ole.andre.ravnas@tandberg.com>
;
; This library is free software; you can redistribute it and/or
; modify it under the terms of the GNU Library General Public
; License as published by the Free Software Foundation; either
; version 2 of the License, or (at your option) any later version.
;
; This library is distributed in the hope that it will be useful,
; but WITHOUT ANY WARRANTY; without even the implied warranty of
; MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
; Library General Public License for more details.
;
; You should have received a copy of the GNU Library General Public
; License along with this library; if not, write to the
; Free Software Foundation, Inc., 59 Temple Place - Suite 330,
; Boston, MA 02111-1307, USA.
;

TITLE GUM Interceptor AMD64 thunks (guminterceptor-amd64-thunks.asm)

EXTERNDEF _gum_interceptor_function_context_on_enter: NEAR
EXTERNDEF _gum_interceptor_function_context_on_leave: NEAR

.code
_gum_interceptor_function_context_on_enter_thunk PROC
  ; save flags
  pushfq

  ; store calculated rip
  push qword ptr [rsp + 8]

  ; save GPR
  push r15
  push r14
  push r13
  push r12
  push r11
  push r10
  push r9
  push r8

  push rbp
  push rdi
  push rsi
  push rdx
  push rcx
  push rbx
  push rax

  ; calculate rsp
  push rsp
  add qword ptr [rsp], (7 + 8 + 1 + 1 + 1) * 8 ; adjust

  ; notify function context
  sub rsp, 4 * 8
  lea r9, [rsp + (25 * 8)] ; function_arguments: FIXME
  lea r8, [rsp + (24 * 8)] ; caller_ret_addr
  lea rdx, [rsp + (4 * 8)] ; cpu_context
  mov rcx, qword ptr [rsp + (23 * 8)] ; function_ctx
  call _gum_interceptor_function_context_on_enter
  add rsp, 4 * 8

  ; skip rsp
  add rsp, 8

  ; restore GPR
  pop rax
  pop rbx
  pop rcx
  pop rdx
  pop rsi
  pop rdi
  pop rbp

  pop r8
  pop r9
  pop r10
  pop r11
  pop r12
  pop r13
  pop r14
  pop r15

  ; discard calculated rip
  add rsp, 8

  popfq
  ret 8
_gum_interceptor_function_context_on_enter_thunk ENDP

_gum_interceptor_function_context_on_leave_thunk PROC
  ; placeholder for caller's return address
  push rbp

  ; save flags
  pushfq

  ; save registers clobbered by calling convention
  push rax
  push rcx
  push rdx
  push r8
  push r9
  push r10
  push r11

  ; notify function context
  sub rsp, 1 * 8
  mov rcx, rax
  call _gum_interceptor_function_context_on_leave
  add rsp, 1 * 8

  ; fill in caller's return address
  mov qword ptr [rsp + (8 * 8)], rax

  ; restore registers
  pop r11
  pop r10
  pop r9
  pop r8
  pop rdx
  pop rcx
  pop rax

  ; restore flags
  popfq

  ret
_gum_interceptor_function_context_on_leave_thunk ENDP

END