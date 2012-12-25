.intel_syntax noprefix
.text

.globl _gum_stalker_follow_me
_gum_stalker_follow_me:
#ifdef i386
push esp
push [esp + 8 + 4]
push [esp + 12 + 0]
call __gum_stalker_do_follow_me
add esp, 12
ret
#else
mov rdx, rsp
jmp __gum_stalker_do_follow_me
#endif
