.text

#ifdef __APPLE__
.globl _gum_stalker_follow_me
_gum_stalker_follow_me:
#else
.globl gum_stalker_follow_me
gum_stalker_follow_me:
#endif
#ifdef i386
movl %esp, %eax
subl $12, %esp
pushl %eax
pushl (4 + 8)(%eax)
pushl (4 + 4)(%eax)
pushl (4 + 0)(%eax)
#ifdef __APPLE__
call __gum_stalker_do_follow_me
#else
call _gum_stalker_do_follow_me
#endif
addl $28, %esp
ret
#else
mov %rsp, %rcx
#ifdef __APPLE__
jmp __gum_stalker_do_follow_me
#else
jmp _gum_stalker_do_follow_me
#endif
#endif

#ifdef __APPLE__
.globl _gum_stalker_activate
_gum_stalker_activate:
#else
.globl gum_stalker_activate
gum_stalker_activate:
#endif
#ifdef i386
movl %esp, %eax
pushl %eax
pushl (4 + 4)(%eax)
pushl (4 + 0)(%eax)
#ifdef __APPLE__
call __gum_stalker_do_activate
#else
call _gum_stalker_do_activate
#endif
addl $12, %esp
ret
#else
mov %rsp, %rdx
#ifdef __APPLE__
jmp __gum_stalker_do_activate
#else
jmp _gum_stalker_do_activate
#endif
#endif
