
PUBLIC DieBugCheck

EXTERN g_pDieDummyObjThread:QWORD

EXTERN g_DieDeadlockMethod:BYTE

EXTERN g_pDieIndirectCallBugCheck:QWORD

EXTERN g_pTheiaCtx:QWORD

_TEXT SEGMENT

DieBugCheck PROC

cli

test byte ptr[g_DieDeadlockMethod],1

jnz DeadLockRoutine

; r13 for TMDB
; r15 for CurrStackHigh

mov r13,rcx

mov r15,rdx

mov r10,qword ptr gs:[0188h]

mov eax,dword ptr[r13 + 52]  ; Get offset ETHREAD.Win32StartAddress 
mov qword ptr [r10 + rax],0  ; Nulling Win32StartAddress        

mov eax,dword ptr[r13 + 64]  ; Get offset KTHREAD.InitialStack 
mov qword ptr [r10 + rax],0  ; Nulling InitialStack             

mov eax,dword ptr[r13 + 68]  ; Get offset KTHREAD.StackLimit 
mov qword ptr [r10 + rax],0  ; Nulling StackLimit               
 
mov eax,dword ptr[r13 + 72]  ; Get offset KTHREAD.StackBase 
mov qword ptr [r10 + rax],0  ; Nulling StackBase                

mov eax,dword ptr[r13 + 76]  ; Get offset KTHREAD.KernelStack 
mov qword ptr [r10 + rax],0  ; Nulling KernelStack              

mov eax,dword ptr[r13 + 88]  ; Get offset KTHREAD.ContextSwitches 
mov qword ptr [r10 + rax],0  ; Nulling ContextSwitches          

mov eax,dword ptr[r13 + 92]  ; Get offset KTHREAD.WaitTime 
mov qword ptr [r10 + rax],0  ; Nulling WaitTime                 

mov eax,dword ptr[r13 + 96]  ; Get offset KTHREAD.KernelTime 
mov qword ptr [r10 + rax],0  ; Nulling KernelTime

mov rax,qword ptr[g_pDieDummyObjThread]

mov qword ptr gs:[0188h], rax

ClearStackLoop:

mov rcx,r15

ror rcx,cl

xor qword ptr [r15],rcx

sub r15,8

cmp r15,rsp

jnb short ClearStackLoop

sub rsp,0100h

and rsp,0fffffffffffffff0h

mov ecx,0124h

mov edx,r8d

mov r9d,r8d

mov dword ptr[rsp + 32],r8d

mov rax,qword ptr[g_pDieIndirectCallBugCheck]

jmp rax ; (JOP)

int 3

int 3

int 3

DeadLockRoutine:

mov r12w,ss

mov ss,r12w
xor eax,eax

mov ss,r12w
xor edx,edx

mov ss,r12w
xor ebx,ebx

mov ss,r12w
xor esi,esi

mov ss,r12w
xor edi,edi

mov ss,r12w
xor r8d,r8d

mov ss,r12w
xor r9d,r9d

mov ss,r12w
xor r10d,r10d

mov ss,r12w
xor r11d,r11d

mov ss,r12w
xor r13d,r13d

mov ss,r12w
xor r14d,r14d

mov ss,r12w
xor r15d,r15d

mov ss,r12w
xor esp,esp

mov ss,r12w
xor ebp,ebp

mov ss,r12w
mov ecx, 00000001Bh

mov ss,r12w
rdmsr

mov ss,r12w
and eax, 0FFFFF7FFh

mov ss,r12w
wrmsr ; OffCurrLocalAPIC

mov ss,r12w
cmp qword ptr[g_pTheiaCtx],0

mov ss,r12w
jz short SkipSynchDeadOtherCores

mov ss,r12w
mov rax, qword ptr[g_pTheiaCtx]

mov ss,r12w
mov qword ptr [rax],0 ; Erase COMPLETE_SIGNATURE_TC in gTheiaCtx (To bring the remaining physical CPU cores into a deadlock state via the CheckStatusCtx routine)

SkipSynchDeadOtherCores:

mov ss,r12w
xor eax,eax

DeadLockLoop:

mov ss,r12w
jmp short DeadLockLoop

DieBugCheck ENDP

_TEXT ENDS

END
