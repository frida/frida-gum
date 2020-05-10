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
   * We need to store the lr onto the stack, so that it can be restored after
   * returning from __gum_stalker_do_follow_me. However, when calling C code,
   * the stack is expected to be 8 byte aligned. We therefore push r3 simply as
   * padding. This is otherwise unnecessary since the calling convention
   * dictates that r3 is the 4th argument and is therefore caller rather than
   * callee saved. We don't use r0, as otherwise when restoring the stack, we
   * would clobber the return value from __gum_stalker_do_follow_me.
   */
  stmdb sp!, {r3, lr}
  add r3, lr, #0
#ifdef __APPLE__
  bl __gum_stalker_do_follow_me
#else
  bl _gum_stalker_do_follow_me
#endif
  ldmia sp!, {r3, lr}
  add pc, r0, #0
