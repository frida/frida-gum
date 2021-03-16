.text

 #
 # static void
 # gum_process_call_function_stub (GumCpuContext * cpu_context,
 #                                 gpointer user_data,
 #                                 GumProcessRunOnThreadFunc callback);
 #
.globl gum_process_call_function_stub
gum_process_call_function_stub:
#ifdef i386
    pushf
    push %ebp
    mov %esp, %ebp

    push 0x10(%ebp)
    push 0xc(%ebp)
    call *0x14(%ebp)

    mov %ebp, %esp
    pop %ebp
    popf
    ret
#else
    pushfq
    cld
# ifdef HAVE_WINDOWS
    call *%r8
# else
    call *%rdx
# endif
    popfq
    ret
#endif
