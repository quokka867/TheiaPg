#include "LinkHeader.h"

/*++
* Routine: BuildStubCallHook
*
* MaxIRQL: DISPATCH_LEVEL
*
* Public/Private: Private
*
* @param RelatedDataICT: Pointer to PICT_DATA_RELATED
*
* Description: Important for kernel module mapping support,
* without stub Stack-Unwind will not be able to correctly working without kernel routine access to the kernel module .pdata.
--*/
static PVOID BuildStubCallHook(IN PICH_DATA pICH)
{
    #define ERROR_BUILD_STUB_CALL_TRMPLN 0x8eabcf40I32

    UCHAR CoreStubCall[] =
    {
      0x48, 0x89, 0xe5,                                 // mov    rbp,rsp    
      0x48, 0x89, 0xe1,                                 // mov    rcx,rsp
      0x48, 0x81, 0xec, 0x00, 0x01, 0x00, 0x00,         // sub    rsp,0100h
      0x48, 0x83, 0xe4, 0xf0,                           // and    rsp,0fffffffffffffff0h
      0x55,                                             // push   rbp
      0x48, 0x83, 0xec, 0x28,                           // sub    rsp,028h *028h because: Microsoft-x64-Calling-Convention requires that the lower 4 bits of SP be 0 before the call instruction*
      0x48, 0xb8, 0x88, 0x88, 0x88, 0x88, 0x78,         // mov    rax,01234567888888888h
      0x56, 0x34, 0x12,                                 // 
      0xff, 0xd0,                                       // call   rax
      0x48, 0x83, 0xc4, 0x28,                           // add    rsp,028h
      0x5c                                              // pop    rsp
    };

    CONST UCHAR SaveContext[] =
    {
      0x9c,                                             // pushfq
      0xfa,                                             // cli
      0x54,                                             // push   rsp
      0x48, 0x83, 0x04, 0x24, 0x18,                     // add    QWORD PTR[rsp],018h     
      0x48, 0x83, 0xec, 0x08,                           // sub    rsp,08h
      0x48, 0x8b, 0x44, 0x24, 0x08,                     // mov    rax,QWORD PTR[rsp + 08h]
      0x48, 0x83, 0xe8, 0x10,                           // sub    rax,010h
      0x48, 0x8b, 0x00,                                 // mov    rax,QWORD PTR[rax]
      0x48, 0x83, 0xe8, 0x0d,                           // sub    rax,0dh
      0x48, 0x89, 0x04, 0x24,                           // mov    QWORD PTR[rsp],rax
      0x55,                                             // push   rbp     
      0x41, 0x57,                                       // push   r15
      0x41, 0x56,                                       // push   r14
      0x41, 0x55,                                       // push   r13
      0x41, 0x54,                                       // push   r12
      0x41, 0x53,                                       // push   r11
      0x41, 0x52,                                       // push   r10
      0x41, 0x51,                                       // push   r9
      0x41, 0x50,                                       // push   r8
      0x57,                                             // push   rdi
      0x56,                                             // push   rsi
      0x53,                                             // push   rbx
      0x52,                                             // push   rdx
      0x51                                              // push   rcx           
    };

    CONST UCHAR RestoreContext1[] =
    {
      0x59,                                             // pop    rcx                        
      0x5a,                                             // pop    rdx                      
      0x5b,                                             // pop    rbx                        
      0x5e,                                             // pop    rsi                        
      0x5f,                                             // pop    rdi                        
      0x41, 0x58,                                       // pop    r8                        
      0x41, 0x59,                                       // pop    r9                        
      0x41, 0x5a,                                       // pop    r10                         
      0x41, 0x5b,                                       // pop    r11                                
      0x41, 0x5c,                                       // pop    r12                         
      0x41, 0x5d,                                       // pop    r13                         
      0x41, 0x5e,                                       // pop    r14                         
      0x41, 0x5f,                                       // pop    r15
      0x5d,                                             // pop    rbp
      0x48, 0x83, 0xc4, 0x10,                           // add    rsp,010h
      0x48, 0x83, 0xec, 0x08,                           // sub    rsp,0x8
      0x48, 0x8b, 0x44, 0x24, 0x08,                     // mov    rax,QWORD PTR[rsp + 0x8]    
      0x48, 0x89, 0x04, 0x24,                           // mov    QWORD PTR[rsp], rax
      0x48, 0x81, 0x24, 0x24, 0xff, 0xfd, 0xff,         // and    QWORD PTR[rsp],0xfffffffffffffdff
      0xff,                                             // 
      0x9d,                                             // popfq
      0x48, 0x8B, 0x44, 0x24, 0x10,                     // mov    rax, QWORD PTR [rsp+10h]
    };

    CONST UCHAR RestoreContext2[] =
    {
      0x50,                                             // push   rax                     
      0x48, 0x8b, 0x44, 0x24, 0x10,                     // mov    rax,QWORD PTR[rsp + 10h]
      0x48, 0x89, 0x44, 0x24, 0x18,                     // mov    QWORD PTR[rsp + 18h],rax
      0x9c,                                             // pushfq
      0x58,                                             // pop    rax
      0x48, 0x25, 0xff, 0xfd, 0xff, 0xff,               // and    rax,0xfffffffffffffdff
      0x48, 0x81, 0x64, 0x24, 0x08, 0x00, 0x02,         // and    QWORD PTR[rsp + 08h],0x200
      0x00, 0x00,                                       // 
      0x48, 0x09, 0x44, 0x24, 0x08,                     // or     QWORD PTR[rsp + 08h],rax
      0x58,                                             // pop    rax
      0x9d,                                             // popfq
      0x48, 0x83, 0xc4, 0x08,                           // add    rsp,08h
      0xc3                                              // ret
    };

    UCHAR CurrIrql = (UCHAR)__readcr8();

    PVOID pPageStub = NULL;

    if (CurrIrql > DISPATCH_LEVEL)
    {
        DbgLog("[TheiaPg <->] BuildStubCallHook: Inadmissible IRQL | IRQL: 0x%02X\n", CurrIrql);

        DieDispatchIntrnlError(ERROR_BUILD_STUB_CALL_TRMPLN);
    }
    else { pPageStub = g_pTheiaCtx->pMmAllocateIndependentPagesEx(PAGE_SIZE, -1, 0I64, 0); }

    if (!pPageStub)
    {
        DbgLog("[TheiaPg <->] BuildStubCallHook: Bad alloc page for PageStub\n");

        DieDispatchIntrnlError(ERROR_BUILD_STUB_CALL_TRMPLN);
    }

    HrdPatchAttributesInputPte(0I64, 0x800I64, pPageStub);

    HrdPatchAttributesInputPte(0x7FFFFFFFFFFFFFFFI64, 0I64, pPageStub);

    *(PVOID*)((PUCHAR)&CoreStubCall + 24) = pICH->pHookRoutine;

    memset(pPageStub, 0, PAGE_SIZE);

    memcpy(pPageStub, SaveContext, sizeof(SaveContext));

    memcpy((PUCHAR)pPageStub + sizeof(SaveContext), CoreStubCall, sizeof(CoreStubCall));

    memcpy((PUCHAR)pPageStub + (sizeof(SaveContext) + sizeof(CoreStubCall)), RestoreContext1, sizeof(RestoreContext1));

    memcpy((PUCHAR)pPageStub + (sizeof(SaveContext) + sizeof(CoreStubCall) + sizeof(RestoreContext1)), pICH->pHandlerHook, pICH->LengthHandler);

    memcpy((PUCHAR)pPageStub + (sizeof(SaveContext) + sizeof(CoreStubCall) + sizeof(RestoreContext1) + pICH->LengthHandler), RestoreContext2, sizeof(RestoreContext2));

    return pPageStub;
}

/*++
* Routine: InitCallHookIntrnl
*
* MaxIRQL: DISPATCH_LEVEL
*
* Public/Private: Private
*
* @param RelatedDataICT: Pointer to PICT_DATA_RELATED
*
* Description: The main ICT routine engaged in the installation of a CallTrampoline.
--*/
static VOID InitCallHookIntrnl(IN OUT PICH_DATA pICH)
{
    #define ERROR_INIT_CALL_TRMPLN_INTRNL 0x6f21b8d4I32

    UCHAR CurrIrql = (UCHAR)__readcr8();

    UCHAR CallTrmpln[] =
    {
      0x50,                                     // push   rax
      0x48, 0xb8, 0x88, 0x88, 0x88, 0x88, 0x78, // mov    rax, 1234567888888888h
      0x56, 0x34, 0x12,
      0xff, 0xd0,                               // call   rax
      0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
      0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
      0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
      0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
      0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
      0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
      0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
      0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
      0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
      0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
      0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
      0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
      0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90 // nops (alignment area)
    };

    INDPN_RW_V_MEMORY_DATA DataIndpnRWVMem = { 0 };
    DataIndpnRWVMem.FlagsExecute = MEM_INDPN_RW_WRITE_OP_BIT;
    DataIndpnRWVMem.pVa = pICH->pBasePatch;
    DataIndpnRWVMem.pIoBuffer = &CallTrmpln;
    DataIndpnRWVMem.LengthRW = (!pICH->LengthAlignment ? (sizeof(CallTrmpln) - 256) : ((sizeof(CallTrmpln) - 256) + pICH->LengthAlignment));

    PVOID pPageStub = NULL;

    if (CurrIrql > DISPATCH_LEVEL)
    {
        DbgLog("[TheiaPg <->] InitCallHookIntrnl: Inadmissible IRQL | IRQL: 0x%02X\n", CurrIrql);

        DieDispatchIntrnlError(ERROR_INIT_CALL_TRMPLN_INTRNL);
    }

    pPageStub = BuildStubCallHook(pICH);

    *(PVOID*)(CallTrmpln + 3) = pPageStub;

    //
    // To increase the probability of successful installation of inline trmpln, 
    // can use HalSendNMI with the affinity of all processor cores and in the body of the NMI-callback routine find the IST in the processor region (KPCR->KTSS64.IST[NMI]),
    // and check the interrupted IP from the MACHINE_FRAME on the memory range where plan to install trmpln.
    // 
    // This requires a change in the CPU synchronization logic of routine HrdIndpnRWVMemory.
    //
    HrdIndpnRWVMemory(&DataIndpnRWVMem);
  
    return;
}

/*++
* Routine: InitCallHook
*
* MaxIRQL: DISPATCH_LEVEL
*
* Public/Private: Public
*
* @param RelatedDataICT: Pointer to ICH_DATA
*
* Description: Wrapper for InitCallHookIntrnl.
--*/
VOID InitCallHook(IN PICH_DATA pICH)
{
    #define ERROR_INIT_CALL_TRMPLN 0x8319ebd9UI32

    CheckStatusTheiaCtx();

    UCHAR CurrIrql = (UCHAR)__readcr8();

    if (CurrIrql > DISPATCH_LEVEL)
    {
        DbgLog("[TheiaPg <->] InitCallHook: Inadmissible IRQL | IRQL: 0x%02X\n", CurrIrql);

        DieDispatchIntrnlError(ERROR_INIT_CALL_TRMPLN);
    }

    InitCallHookIntrnl(pICH);
 
    return STATUS_SUCCESS;
}

