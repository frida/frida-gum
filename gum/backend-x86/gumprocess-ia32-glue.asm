
 ;
 ; static void
 ; gum_process_call_function_stub (GumCpuContext * cpu_context,
 ;                                 gpointer user_data,
 ;                                 GumProcessRunOnThreadFunc callback);
 ;

.MODEL FLAT
.CODE
_gum_process_call_function_stub PROC
    pushfd
    push ebp
    mov ebp, esp

    push [ebp+10h]
    push [ebp+0ch]
    call dword ptr [ebp+14h]

    mov esp, ebp
    pop ebp
    popfd
    ret
_gum_process_call_function_stub ENDP

;
; void
; gum_process_fxsave (GumIA32FpuRegs * regs)
;
_gum_process_fxsave PROC
    push ebp
    mov ebp, esp
    push edi

    mov edi, [ebp+08h]
    BYTE 00fh, 0aeh, 007h ; fxsave [edi]

    pop edi
    mov esp, ebp
    pop ebp
    ret
_gum_process_fxsave ENDP

;
; void
; gum_process_fxrestore (GumIA32FpuRegs * regs)
;
_gum_process_fxrestore PROC
    push ebp
    mov ebp, esp
    push edi

    mov edi, [ebp+08h]
    BYTE 00fh, 0aeh, 00fh ; fxrstor [edi]

    pop edi
    mov esp, ebp
    pop ebp
    ret
_gum_process_fxrestore ENDP

;
; void
; gum_process_save_avx (GumIA32AvxRegs * regs)
;
_gum_process_save_avx PROC
    push ebp
    mov ebp, esp
    push edi

    mov edi, [ebp+08h]

    ; vextracti128 xmmword ptr [edi], ymm0, 1
    ; vextracti128 xmmword ptr [edi + 0x10], ymm1, 1
    ; vextracti128 xmmword ptr [edi + 0x20], ymm2, 1
    ; vextracti128 xmmword ptr [edi + 0x30], ymm3, 1
    ; vextracti128 xmmword ptr [edi + 0x40], ymm4, 1
    ; vextracti128 xmmword ptr [edi + 0x50], ymm5, 1
    ; vextracti128 xmmword ptr [edi + 0x60], ymm6, 1
    ; vextracti128 xmmword ptr [edi + 0x70], ymm7, 1

    BYTE 0c4h, 0e3h, 07dh, 039h, 007h, 001h
    BYTE 0c4h, 0e3h, 07dh, 039h, 04fh, 010h, 001h
    BYTE 0c4h, 0e3h, 07dh, 039h, 057h, 020h, 001h
    BYTE 0c4h, 0e3h, 07dh, 039h, 05fh, 030h, 001h
    BYTE 0c4h, 0e3h, 07dh, 039h, 067h, 040h, 001h
    BYTE 0c4h, 0e3h, 07dh, 039h, 06fh, 050h, 001h
    BYTE 0c4h, 0e3h, 07dh, 039h, 077h, 060h, 001h
    BYTE 0c4h, 0e3h, 07dh, 039h, 07fh, 070h, 001h

    pop edi
    mov esp, ebp
    pop ebp
    ret
_gum_process_save_avx ENDP

;
; void
; gum_process_restore_avx (GumIA32AvxRegs * regs)
;
_gum_process_restore_avx PROC
    push ebp
    mov ebp, esp
    push edi

    mov edi, [ebp+08h]

    ; vinserti128 ymm0, ymm0, xmmword ptr [edi], 1
    ; vinserti128 ymm1, ymm1, xmmword ptr [edi + 0x10], 1
    ; vinserti128 ymm2, ymm2, xmmword ptr [edi + 0x20], 1
    ; vinserti128 ymm3, ymm3, xmmword ptr [edi + 0x30], 1
    ; vinserti128 ymm4, ymm4, xmmword ptr [edi + 0x40], 1
    ; vinserti128 ymm5, ymm5, xmmword ptr [edi + 0x50], 1
    ; vinserti128 ymm6, ymm6, xmmword ptr [edi + 0x60], 1
    ; vinserti128 ymm7, ymm7, xmmword ptr [edi + 0x70], 1

    BYTE 0c4h, 0e3h, 07dh, 038h, 007h, 001h
    BYTE 0c4h, 0e3h, 075h, 038h, 04fh, 010h, 001h
    BYTE 0c4h, 0e3h, 06dh, 038h, 057h, 020h, 001h
    BYTE 0c4h, 0e3h, 065h, 038h, 05fh, 030h, 001h
    BYTE 0c4h, 0e3h, 05dh, 038h, 067h, 040h, 001h
    BYTE 0c4h, 0e3h, 055h, 038h, 06fh, 050h, 001h
    BYTE 0c4h, 0e3h, 04dh, 038h, 077h, 060h, 001h
    BYTE 0c4h, 0e3h, 045h, 038h, 07fh, 070h, 001h

    pop edi
    mov esp, ebp
    pop ebp
    ret
_gum_process_restore_avx ENDP

end
