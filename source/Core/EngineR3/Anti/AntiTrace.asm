; 'AMD64' defined in MASM command line in a properties of the project (for the x64 only)

IFDEF RAX
.CODE

asm_pg_single_step proc
    pushfq
    mov rax,0
    or dword ptr [rsp], 0100h
    mov eax, 0FFFFFFFFh
    popfq
    mov rax,1
    nop
    ret
asm_pg_single_step endp

asm_pg_KiErrata361Present proc
    mov ax,ss
    pushfq
    or qword ptr[rsp],100h
    popfq
    mov ss,ax
    db 0f1h ;icebp
    pushfq
    and qword ptr[rsp],0FFFFFEFFh
    popfq
    ret
asm_pg_KiErrata361Present endp

asm_single_step_cpuid proc
    pushfq
    or dword ptr [rsp], 0100h 
    popfq
    cpuid
    nop
    ret
asm_single_step_cpuid endp

asm_single_step_rdtsc proc
    pushfq
    or dword ptr [rsp], 0100h 
    popfq
    rdtsc
    nop
    ret
asm_single_step_rdtsc endp

ELSE

.model flat

assume fs:nothing

.code
_asm_single_step_cpuid proc
    pushfd
    or dword ptr [esp], 0100h 
    popfd
    cpuid
    nop
    ret
_asm_single_step_cpuid endp

_asm_single_step_rdtsc proc
    pushfd
    or dword ptr [esp], 0100h 
    popfd
    rdtsc
    nop
    ret
_asm_single_step_rdtsc endp

assume fs:error

ENDIF

END