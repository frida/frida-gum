    .text
    .align  2

    .global gum_stalker_follow_me
    .type   gum_stalker_follow_me, %function
gum_stalker_follow_me:
    stp	x29, x30, [sp,-16]!
    mov	x29, sp
    mov x2, x30
    bl _gum_stalker_do_follow_me
    ldp	x29, x30, [sp],16
    mov x30, x0
    stp x16, x17, [sp,-16]!
    ret

    .global gum_stalker_unfollow_me
    .type   gum_stalker_unfollow_me, %function
gum_stalker_unfollow_me:
    ldp x16, x17, [sp], 16
    stp	x29, x30, [sp,-16]!
    mov	x29, sp
    bl _gum_stalker_do_unfollow_me
    ldp	x29, x30, [sp],16
    ret