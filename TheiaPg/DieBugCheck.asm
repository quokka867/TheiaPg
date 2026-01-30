
PUBLIC DieBugCheck


EXTERN g_DieDeadlockMethod:BYTE

EXTERN g_pDieIndirectCallBugCheck:QWORD

EXTERN g_DieNtosHeadThreadList:QWORD

EXTERN g_pTheiaCtx:QWORD


_TEXT SEGMENT

DieBugCheck PROC

cli

test byte ptr[g_DieDeadlockMethod],1

jnz DeadLockRoutine

sub rsp,34

mov r10, qword ptr gs:[0188h]

mov r13, rcx

mov ecx, edx

; r13 for TMDB
; r14 for value-ThreadListEntry
; r15 for value-InitialStack

mov eax,dword ptr[r13 + 44]  ; Get offset ETHREAD.Win32StartAddress 
mov qword ptr [r10 + rax] , 0    ; Nulling Win32StartAddress        

mov eax,dword ptr[r13 + 56]  ; Get offset KTHREAD.InitialStack 
mov r15, qword ptr [r10 + rax]   ; Save value InitialStack
mov qword ptr [r10 + rax] , 0    ; Nulling InitialStack             

mov eax,dword ptr[r13 + 60]  ; Get offset KTHREAD.StackLimit 
mov qword ptr [r10 + rax] , 0    ; Nulling StackLimit               
 
mov eax,dword ptr[r13 + 64]  ; Get offset KTHREAD.StackBase 
mov qword ptr [r10 + rax] , 0    ; Nulling StackBase                

mov eax,dword ptr[r13 + 68]  ; Get offset KTHREAD.KernelStack 
mov qword ptr [r10 + rax] , 0    ; Nulling KernelStack              

mov eax,dword ptr[r13 + 80]  ; Get offset KTHREAD.ContextSwitches 
mov qword ptr [r10 + rax] , 0    ; Nulling ContextSwitches          

mov eax,dword ptr[r13 + 84]  ; Get offset KTHREAD.WaitTime 
mov qword ptr [r10 + rax] , 0    ; Nulling WaitTime                 

mov eax,dword ptr[r13 + 88]  ; Get offset KTHREAD.KernelTime 
mov qword ptr [r10 + rax] , 0    ; Nulling KernelTime               

mov eax, dword ptr[r13 + 96] ; Get offset KTHREAD.ThreadListEntry 

cmp qword ptr[g_DieNtosHeadThreadList], 0

jz UsingThreadListCurrProc

mov r14, qword ptr[g_DieNtosHeadThreadList]

mov r11, qword ptr[g_DieNtosHeadThreadList]    ; Save address current Thread-Obj 

add r11, rax

jmp short SkipUsingThreadListCurrProc

UsingThreadListCurrProc:

mov r14, qword ptr [r10 + rax]   ; Save value ThreadListEntry

mov r11, qword ptr gs:[0188h]    ; Save address current Thread-Obj 

add r11, rax

SkipUsingThreadListCurrProc:
					   
rdtsc

shl rdx, 32

or rdx,rax

mov rax,rdx

xor rdx,rdx

movzx eax, al

add ax, 32

SpinChooseThread:

mov r14, qword ptr[r14]

dec ax

cmp ax, 0

jnz short SpinChooseThread

cmp r14,r11

jnz short NoExceptionThread

add ax, 3

jmp short SpinChooseThread

NoExceptionThread:

mov eax, dword ptr[r13 + 96] ; Get offset KTHREAD.ThreadListEntry 

sub r14, rax

mov qword ptr gs:[0188h], r14

xor r11,r11

ClearStackLoop:

mov qword ptr [r15],0

sub r15,8

cmp r15,rsp

jnb short ClearStackLoop

sub rsp,0100h

and rsp,0fffffffffffffff0h

mov edx,ecx

mov r8d,ecx

mov r9d,ecx

mov qword ptr[rsp + 32],rcx

mov ecx,0124h

mov rax, qword ptr[g_pDieIndirectCallBugCheck]

jmp rax  

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
wrmsr

mov ss,r12w
cmp qword ptr[g_pTheiaCtx], 0

mov ss,r12w
jz short SkipSynchDeadOtherCores

mov ss,r12w
mov rax, qword ptr[g_pTheiaCtx]

mov ss,r12w
mov qword ptr [rax], 0

SkipSynchDeadOtherCores:

mov ss,r12w
xor eax,eax

DeadLockLoop:

mov ss,r12w
jmp short DeadLockLoop

DieBugCheck ENDP

_TEXT ENDS

END
