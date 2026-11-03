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
  mov x3, x30
#ifdef __APPLE__
  bl __gum_stalker_do_follow_me
#else
  bl _gum_stalker_do_follow_me
#endif
  cbz x0, 2f
  stp x21, x22, [x0, #0]
  stp x23, x24, [x0, #16]
  stp x25, x26, [x0, #32]
  stp x27, x28, [x0, #48]
  ldr x30, [x0, #64]
  b 1f
2:
  mov x30, x1
1:
  mov x0, x1
  br x0

#ifdef __APPLE__
  .globl _gum_stalker_activate
_gum_stalker_activate:
#else
  .globl gum_stalker_activate
  .type gum_stalker_activate, %function
gum_stalker_activate:
#endif
  sub sp, sp, #64
  stp x21, x22, [sp, #0]
  stp x23, x24, [sp, #16]
  stp x25, x26, [sp, #32]
  stp x27, x28, [sp, #48]
  mov x3, sp
  mov x2, x30
#ifdef __APPLE__
  bl __gum_stalker_do_activate
#else
  bl _gum_stalker_do_activate
#endif
  ldp x21, x22, [sp, #0]
  ldp x23, x24, [sp, #16]
  ldp x25, x26, [sp, #32]
  ldp x27, x28, [sp, #48]
  add sp, sp, #64
  mov x30, x1
  br x0

#ifdef __APPLE__
  .globl _gum_stalker_deactivate
_gum_stalker_deactivate:
#else
  .globl gum_stalker_deactivate
  .type gum_stalker_deactivate, %function
gum_stalker_deactivate:
#endif
  mov x1, x30
#ifdef __APPLE__
  bl __gum_stalker_do_deactivate
#else
  bl _gum_stalker_do_deactivate
#endif
  mov x30, x1
  br x0
