  .text
  .align 2

  .global gum_stalker_follow_me
  .type gum_stalker_follow_me, %function
gum_stalker_follow_me:
  stp x29, x30, [sp, -16]!
  mov x29, sp
  mov x2, x30
  bl _gum_stalker_do_follow_me
  ldp x29, x30, [sp], 16
  add x30, x0, #4
  ret
