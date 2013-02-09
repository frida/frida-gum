.text

#ifdef __APPLE__
.globl _gum_stalker_follow_me
_gum_stalker_follow_me:
#else
.globl gum_stalker_follow_me
gum_stalker_follow_me:
#endif
#ifdef i386
pushl %esp
pushl (8 + 4)(%esp)
pushl (12 + 0)(%esp)
#ifdef __APPLE__
call __gum_stalker_do_follow_me
#else
call _gum_stalker_do_follow_me
#endif
addl $12, %esp
ret
#else
mov %rsp, %rdx
#ifdef __APPLE__
jmp __gum_stalker_do_follow_me
#else
jmp _gum_stalker_do_follow_me
#endif
#endif
