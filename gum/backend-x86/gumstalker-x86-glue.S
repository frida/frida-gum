.intel_syntax noprefix
.text

#ifdef __APPLE__
.globl _gum_stalker_follow_me
_gum_stalker_follow_me:
#else
.globl gum_stalker_follow_me
gum_stalker_follow_me:
#endif
#ifdef i386
push esp
push [esp + 8 + 4]
push [esp + 12 + 0]
#ifdef __APPLE__
call __gum_stalker_do_follow_me
#else
call _gum_stalker_do_follow_me
#endif
add esp, 12
ret
#else
mov rdx, rsp
#ifdef __APPLE__
jmp __gum_stalker_do_follow_me
#else
jmp _gum_stalker_do_follow_me
#endif
#endif
