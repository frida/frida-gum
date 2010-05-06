.intel_syntax noprefix

.section .text

.set GUM_CPU_CONTEXT_OFFSET_EDI,  4
.set GUM_CPU_CONTEXT_OFFSET_ESI,  8
.set GUM_CPU_CONTEXT_OFFSET_EBP, 12
.set GUM_CPU_CONTEXT_OFFSET_EBX, 20
.set GUM_CPU_CONTEXT_OFFSET_EDX, 24
.set GUM_CPU_CONTEXT_OFFSET_ECX, 28
.set GUM_CPU_CONTEXT_OFFSET_EAX, 32

.global invoke_clobber_test_function_with_cpu_context
  .type invoke_clobber_test_function_with_cpu_context, @function
  .balign 16, 0x90
invoke_clobber_test_function_with_cpu_context:
  .set CPU_CONTEXT_INPUT_ARG_OFFSET,  32 + 4 + 0
  .set CPU_CONTEXT_OUTPUT_ARG_OFFSET, 32 + 4 + 4

  pushad;

  mov eax, [esp + CPU_CONTEXT_INPUT_ARG_OFFSET];

  mov edi, [eax + GUM_CPU_CONTEXT_OFFSET_EDI];
  mov esi, [eax + GUM_CPU_CONTEXT_OFFSET_ESI];
  mov ebp, [eax + GUM_CPU_CONTEXT_OFFSET_EBP];
  mov ebx, [eax + GUM_CPU_CONTEXT_OFFSET_EBX];
  mov edx, [eax + GUM_CPU_CONTEXT_OFFSET_EDX];
  mov ecx, [eax + GUM_CPU_CONTEXT_OFFSET_ECX];
  mov eax, [eax + GUM_CPU_CONTEXT_OFFSET_EAX];

  call clobber_test_function;

  push eax;
  mov eax, [esp + 4 + CPU_CONTEXT_OUTPUT_ARG_OFFSET];
  mov [eax + GUM_CPU_CONTEXT_OFFSET_EDI], edi;
  mov [eax + GUM_CPU_CONTEXT_OFFSET_ESI], esi;
  mov [eax + GUM_CPU_CONTEXT_OFFSET_EBP], ebp;
  mov [eax + GUM_CPU_CONTEXT_OFFSET_EBX], ebx;
  mov [eax + GUM_CPU_CONTEXT_OFFSET_EDX], edx;
  mov [eax + GUM_CPU_CONTEXT_OFFSET_ECX], ecx;
  pop eax;

  mov ecx, [esp + CPU_CONTEXT_OUTPUT_ARG_OFFSET];
  mov [ecx + GUM_CPU_CONTEXT_OFFSET_EAX], eax;

  popad;
  ret;

.global invoke_clobber_test_function_with_carry_set
  .type invoke_clobber_test_function_with_carry_set, @function
  .balign 16, 0x90
invoke_clobber_test_function_with_carry_set:
  .set CARRY_SET_INPUT_ARG_OFFSET,  8 + 4 + 0
  .set CARRY_SET_OUTPUT_ARG_OFFSET, 8 + 4 + 4

  pushfd;
  push ecx;

  stc; /* enable carry flag, very likely to get clobbered */

  pushfd;
  mov ecx, [esp + 4 + CARRY_SET_INPUT_ARG_OFFSET];
  pop [ecx];

  call clobber_test_function;

  pushfd;
  mov ecx, [esp + 4 + CARRY_SET_OUTPUT_ARG_OFFSET];
  pop [ecx];

  pop ecx;
  popfd;
  ret;

.global clobber_test_function
  .type clobber_test_function, @function
  .balign 16, 0x90
clobber_test_function:
  /* 5 bytes of padding */
  nop;
  nop;
  nop;
  nop;
  nop;

  ret;
