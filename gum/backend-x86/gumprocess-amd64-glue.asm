
 ;
 ; static void
 ; gum_process_call_function_stub (GumCpuContext * cpu_context,
 ;                                 gpointer user_data,
 ;                                 GumProcessRunOnThreadFunc callback);
 ;

.CODE
gum_process_call_function_stub PROC
    pushfq
    cld
    call r8
    popfq
    ret
gum_process_call_function_stub ENDP

;
; void
; gum_process_fxsave (GumX64FpuRegs * regs)
;
gum_process_fxsave PROC
    BYTE 00fh, 0aeh, 001h ; fxsave [rcx]
    ret
gum_process_fxsave ENDP

;
; void
; gum_process_fxrestore (GumX64FpuRegs * regs)
;
gum_process_fxrestore PROC
    BYTE 00fh, 0aeh, 009h ; fxrstor [rcx]
    ret
gum_process_fxrestore ENDP

;
; void
; gum_process_save_avx (GumX64AvxRegs * regs)
;
gum_process_save_avx PROC

    ; vextracti128 xmmword ptr [rcx]h, ymm0h, 1
    ; vextracti128 xmmword ptr [rcx + 0x10]h, ymm1h, 1
    ; vextracti128 xmmword ptr [rcx + 0x20]h, ymm2h, 1
    ; vextracti128 xmmword ptr [rcx + 0x30]h, ymm3h, 1
    ; vextracti128 xmmword ptr [rcx + 0x40]h, ymm4h, 1
    ; vextracti128 xmmword ptr [rcx + 0x50]h, ymm5h, 1
    ; vextracti128 xmmword ptr [rcx + 0x60]h, ymm6h, 1
    ; vextracti128 xmmword ptr [rcx + 0x70]h, ymm7h, 1
    ; vextracti128 xmmword ptr [rcx + 0x80]h, ymm8h, 1
    ; vextracti128 xmmword ptr [rcx + 0x90]h, ymm9h, 1
    ; vextracti128 xmmword ptr [rcx + 0xa0]h, ymm10h, 1
    ; vextracti128 xmmword ptr [rcx + 0xb0]h, ymm11h, 1
    ; vextracti128 xmmword ptr [rcx + 0xc0]h, ymm12h, 1
    ; vextracti128 xmmword ptr [rcx + 0xd0]h, ymm13h, 1
    ; vextracti128 xmmword ptr [rcx + 0xe0]h, ymm14h, 1
    ; vextracti128 xmmword ptr [rcx + 0xf0]h, ymm15h, 1

    BYTE 0c4h, 0e3h, 07dh, 039h, 001h, 001h
    BYTE 0c4h, 0e3h, 07dh, 039h, 049h, 010h, 001h
    BYTE 0c4h, 0e3h, 07dh, 039h, 051h, 020h, 001h
    BYTE 0c4h, 0e3h, 07dh, 039h, 059h, 030h, 001h
    BYTE 0c4h, 0e3h, 07dh, 039h, 061h, 040h, 001h
    BYTE 0c4h, 0e3h, 07dh, 039h, 069h, 050h, 001h
    BYTE 0c4h, 0e3h, 07dh, 039h, 071h, 060h, 001h
    BYTE 0c4h, 0e3h, 07dh, 039h, 079h, 070h, 001h
    BYTE 0c4h, 063h, 07dh, 039h, 081h, 080h, 000h, 000h, 000h, 001h
    BYTE 0c4h, 063h, 07dh, 039h, 089h, 090h, 000h, 000h, 000h, 001h
    BYTE 0c4h, 063h, 07dh, 039h, 091h, 0a0h, 000h, 000h, 000h, 001h
    BYTE 0c4h, 063h, 07dh, 039h, 099h, 0b0h, 000h, 000h, 000h, 001h
    BYTE 0c4h, 063h, 07dh, 039h, 0a1h, 0c0h, 000h, 000h, 000h, 001h
    BYTE 0c4h, 063h, 07dh, 039h, 0a9h, 0d0h, 000h, 000h, 000h, 001h
    BYTE 0c4h, 063h, 07dh, 039h, 0b1h, 0e0h, 000h, 000h, 000h, 001h
    BYTE 0c4h, 063h, 07dh, 039h, 0b9h, 0f0h, 000h, 000h, 000h, 001h
    ret
gum_process_save_avx ENDP

;
; void
; gum_process_restore_avx (GumX64AvxRegs * regs)
;
gum_process_restore_avx PROC
    ; vinserti128 ymm0h, ymm0h, xmmword ptr [rcx]h, 1
    ; vinserti128 ymm1h, ymm1h, xmmword ptr [rcx + 0x10]h, 1
    ; vinserti128 ymm2h, ymm2h, xmmword ptr [rcx + 0x20]h, 1
    ; vinserti128 ymm3h, ymm3h, xmmword ptr [rcx + 0x30]h, 1
    ; vinserti128 ymm4h, ymm4h, xmmword ptr [rcx + 0x40]h, 1
    ; vinserti128 ymm5h, ymm5h, xmmword ptr [rcx + 0x50]h, 1
    ; vinserti128 ymm6h, ymm6h, xmmword ptr [rcx + 0x60]h, 1
    ; vinserti128 ymm7h, ymm7h, xmmword ptr [rcx + 0x70]h, 1
    ; vinserti128 ymm8h, ymm8h, xmmword ptr [rcx + 0x80]h, 1
    ; vinserti128 ymm9h, ymm9h, xmmword ptr [rcx + 0x90]h, 1
    ; vinserti128 ymm10h, ymm10h, xmmword ptr [rcx + 0xa0]h, 1
    ; vinserti128 ymm11h, ymm11h, xmmword ptr [rcx + 0xb0]h, 1
    ; vinserti128 ymm12h, ymm12h, xmmword ptr [rcx + 0xc0]h, 1
    ; vinserti128 ymm13h, ymm13h, xmmword ptr [rcx + 0xd0]h, 1
    ; vinserti128 ymm14h, ymm14h, xmmword ptr [rcx + 0xe0]h, 1
    ; vinserti128 ymm15h, ymm15h, xmmword ptr [rcx + 0xf0]h, 1

    BYTE 0c4h, 0e3h, 07dh, 038h, 001h, 001h
    BYTE 0c4h, 0e3h, 075h, 038h, 049h, 010h, 001h
    BYTE 0c4h, 0e3h, 06dh, 038h, 051h, 020h, 001h
    BYTE 0c4h, 0e3h, 065h, 038h, 059h, 030h, 001h
    BYTE 0c4h, 0e3h, 05dh, 038h, 061h, 040h, 001h
    BYTE 0c4h, 0e3h, 055h, 038h, 069h, 050h, 001h
    BYTE 0c4h, 0e3h, 04dh, 038h, 071h, 060h, 001h
    BYTE 0c4h, 0e3h, 045h, 038h, 079h, 070h, 001h
    BYTE 0c4h, 063h, 03dh, 038h, 081h, 080h, 000h, 000h, 000h, 001h
    BYTE 0c4h, 063h, 035h, 038h, 089h, 090h, 000h, 000h, 000h, 001h
    BYTE 0c4h, 063h, 02dh, 038h, 091h, 0a0h, 000h, 000h, 000h, 001h
    BYTE 0c4h, 063h, 025h, 038h, 099h, 0b0h, 000h, 000h, 000h, 001h
    BYTE 0c4h, 063h, 01dh, 038h, 0a1h, 0c0h, 000h, 000h, 000h, 001h
    BYTE 0c4h, 063h, 015h, 038h, 0a9h, 0d0h, 000h, 000h, 000h, 001h
    BYTE 0c4h, 063h, 00dh, 038h, 0b1h, 0e0h, 000h, 000h, 000h, 001h
    BYTE 0c4h, 063h, 005h, 038h, 0b9h, 0f0h, 000h, 000h, 000h, 001h
    ret
gum_process_restore_avx ENDP

end
