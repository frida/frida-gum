  .text
  .align 2

  .globl gum_stalker_follow_me
  .type gum_stalker_follow_me, %function
gum_stalker_follow_me:
  stmdb sp!,{lr}
  add r3, lr, #0
  bl _gum_stalker_do_follow_me
  ldmia sp!,{pc}