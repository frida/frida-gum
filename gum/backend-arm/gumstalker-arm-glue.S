  .text
  .align 2

#ifdef __APPLE__
  .globl _gum_stalker_follow_me
_gum_stalker_follow_me:
#else
  .globl gum_stalker_follow_me
  .type gum_stalker_follow_me, %function
gum_stalker_follow_me:
#endif
  /*
   * We need to store LR onto the stack, so that it can be restored after
   * returning from do_follow_me(). However, when calling C code, the stack
   * is expected to be 8 byte aligned. We therefore push R3 simply as padding.
   * This is otherwise unnecessary since the calling convention dictates that
   * R3 is the 4th argument and is therefore caller rather than callee saved.
   * We don't use R0, as otherwise when restoring the stack, we would clobber
   * the return value from do_follow_me().
   */
  stmdb sp!, {r3, r6, r9, r11, r12, lr}
  add r3, lr, #0
  sub sp, sp, #8
  add r12, sp, #8
  str r12, [sp]
#ifdef __APPLE__
  bl __gum_stalker_do_follow_me
#else
  bl _gum_stalker_do_follow_me
#endif
  add sp, sp, #8
  ldmia sp!, {r3, r6, r9, r11, r12, lr}
  bx r0

#ifdef __APPLE__
  .globl _gum_stalker_activate
_gum_stalker_activate:
#else
  .globl gum_stalker_activate
  .type gum_stalker_activate, %function
gum_stalker_activate:
#endif
  stmdb sp!, {r3, r6, r9, r11, r12, lr}
  add r2, lr, #0
  add r3, sp, #0
#ifdef __APPLE__
  bl __gum_stalker_do_activate
#else
  bl _gum_stalker_do_activate
#endif
  ldmia sp!, {r3, r6, r9, r11, r12, lr}
  bx r0

#ifdef __APPLE__
  .globl _gum_stalker_deactivate
_gum_stalker_deactivate:
#else
  .globl gum_stalker_deactivate
  .type gum_stalker_deactivate, %function
gum_stalker_deactivate:
#endif
  stmdb sp!, {r1, lr}
  add r1, lr, #0
#ifdef __APPLE__
  bl __gum_stalker_do_deactivate
#else
  bl _gum_stalker_do_deactivate
#endif
  ldmia sp!, {r1, lr}
  bx r0
