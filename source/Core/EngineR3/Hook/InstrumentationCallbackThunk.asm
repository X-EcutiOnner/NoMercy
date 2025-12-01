IFDEF RAX
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;; x64 ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

include ksamd64.inc

extern InstrumentationCallback:proc
EXTERNDEF __imp_RtlCaptureContext:QWORD

.code

InstrumentationCallbackThunk proc

	mov     gs:[2e0h], rsp            ; Win10 TEB InstrumentationCallbackPreviousSp
	mov     gs:[2d8h], r10            ; Win10 TEB InstrumentationCallbackPreviousPc

	mov     r10, rcx                  ; Save original RCX
	sub     rsp, 4d0h                 ; Alloc stack space for CONTEXT structure
	and     rsp, -10h                 ; RSP must be 16 byte aligned before calls
	mov     rcx, rsp
	call    __imp_RtlCaptureContext   ; Save the current register state. RtlCaptureContext does not require shadow space

	sub     rsp, 20h                  ; Shadow space
	call    InstrumentationCallback

	int     3

InstrumentationCallbackThunk endp

ELSE

.model flat

assume fs:nothing
extern _InstrumentationCallback:near

.code
_InstrumentationCallbackProxy proc

    mov     fs:1b0h, ecx                ; InstrumentationCallbackPreviousPc
    mov     fs:1b4h, esp                ; InstrumentationCallbackPreviousSp
    
    push    eax                         ; Return value
    push    ecx                         ; Return address
    call    _InstrumentationCallback

    mov     esp, fs:1b4h
    mov     ecx, fs:1b0h
    jmp     ecx

_InstrumentationCallbackProxy endp

assume fs:error

ENDIF

END