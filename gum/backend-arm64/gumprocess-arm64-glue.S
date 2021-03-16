.text

 #
 # static void
 # gum_process_call_function_stub (GumCpuContext * cpu_context,
 #                                 gpointer user_data,
 #                                 GumProcessRunOnThreadFunc callback);
 #
.globl gum_process_call_function_stub
gum_process_call_function_stub:
    stp     x29, x30, [sp, #-16]!

    # Store x9 and x10 so we can use x9 as a scratch register
    stp     x9, x10, [sp, #-16]!

    # Store the flags as well as some padding
    mrs     x9, NZCV
    stp     x9, x10, [sp, #-16]!

    blr     x2

    # Restore the flags (and padding)
    ldp     x9, x10, [sp], #16
    msr NZCV, x9

    # Restore x9 and x10
    ldp     x9, x10, [sp], #16

    ldp     x29, x30, [sp], #16
    ret
