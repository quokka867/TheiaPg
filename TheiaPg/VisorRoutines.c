#include "LinkHeader.h"

/*++
* Routine: VsrKiExecuteAllDpcs
*
* MaxIRQL: DISPATCH_LEVEL
*
* Public/Private: Public
*
* @param InputCtx: Context passed from StubCallTrmpln
*
* Description: Hook KiExecuteAllDpcs for controling _KDPC in DPC_QUEUE current Cpu-Core.
--*/
volatile VOID VsrKiExecuteAllDpcs(IN PINPUTCONTEXT_ICT pInputCtx)
{
    CheckStatusTheiaCtx();

    UCHAR ReasonDetect0[] = { "Unbacked DeferredRoutine" };

    UCHAR ReasonDetect1[] = { "PG DeferredContext" };

    UCHAR TypeDetect = 2UI8;

    BOOLEAN OldIF = FALSE;

    CONST UCHAR RetOpcode = 0xC3UI8;

    PVOID pDpcListHead[2] = { 0 };

    INDPN_RW_V_MEMORY_DATA DataIndpnRWVMem = { 0 };

    DataIndpnRWVMem.FlagsExecute = MEM_INDPN_RW_WRITE_OP_BIT;

    DataIndpnRWVMem.pIoBuffer = &RetOpcode;

    DataIndpnRWVMem.LengthRW = 1UI64;

    pDpcListHead[DPC_NORMAL] = (PVOID)__readgsqword((g_pTheiaCtx->TheiaMetaDataBlock.KPCR_Prcb_OFFSET + g_pTheiaCtx->TheiaMetaDataBlock.KPRCB_DpcData0_OFFSET)); ///< Get address first node DPC_NORMAL_QUEUE.

    pDpcListHead[DPC_THREADED] = (PVOID)__readgsqword((g_pTheiaCtx->TheiaMetaDataBlock.KPCR_Prcb_OFFSET + g_pTheiaCtx->TheiaMetaDataBlock.KPRCB_DpcData1_OFFSET)); ///< Get address first node DPC_THREADED_QUEUE.

    PKDPC pCurrentKDPC = NULL;

    BOOLEAN FlagCurrentQueue = FALSE; ///< FALSE: DPC_NORMAL & TRUE: DPC_THREADED

    BOOLEAN LockCurrentQueue = FALSE;

    for(; ;)
    {
        if (!FlagCurrentQueue && !LockCurrentQueue)
        {
            if (!pDpcListHead[DPC_NORMAL]) { FlagCurrentQueue = TRUE; }
            else { pCurrentKDPC = CONTAINING_RECORD(pDpcListHead[DPC_NORMAL], KDPC, DpcListEntry); LockCurrentQueue = TRUE; }
        }

        if (FlagCurrentQueue && !LockCurrentQueue)
        {
            if (!pDpcListHead[DPC_THREADED]) { break; }
            else { pCurrentKDPC = CONTAINING_RECORD(pDpcListHead[DPC_THREADED], KDPC, DpcListEntry); LockCurrentQueue = TRUE; }
        }

        if (!(_IsAddressSafe(pCurrentKDPC->DeferredRoutine))) 
        { 
            TypeDetect = 0UI8;
        }       
        else if (!(g_pTheiaCtx->pMmIsAddressValid(pCurrentKDPC->DeferredContext)) && (((ULONG64)pCurrentKDPC->DeferredContext) & ~0x03I64))
        {
            TypeDetect = 1UI8;
        }
        else { VOID; } ///< For clarity.

        if (TypeDetect < 2)
        {
            DbgLog("[TheiaPg <+>] VsrKiExecuteAllDpcs: Detect possibly PG-KDPC | Reason: %s | _KDPC: 0x%I64X | DeferredRoutine: 0x%I64X | DeferredContext: 0x%I64X\n\n", ((!TypeDetect) ? ReasonDetect0 : ReasonDetect1), pCurrentKDPC, pCurrentKDPC->DeferredRoutine, pCurrentKDPC->DeferredContext);

            DataIndpnRWVMem.pVa = pCurrentKDPC->DeferredRoutine;

            HrdIndpnRWVMemory(&DataIndpnRWVMem);

            TypeDetect = 2UI32;
        }

        if (!(pCurrentKDPC->DpcListEntry.Next) && !FlagCurrentQueue) { FlagCurrentQueue = TRUE; LockCurrentQueue = FALSE; continue; }

        else if (!(pCurrentKDPC->DpcListEntry.Next) && FlagCurrentQueue) { break; }

        else { pCurrentKDPC = CONTAINING_RECORD(pCurrentKDPC->DpcListEntry.Next, KDPC, DpcListEntry); }
    }

    return;
}

/*++
* Routine: VsrKiRetireDpcList
*
* MaxIRQL: DISPATCH_LEVEL
*
* Public/Private: Public
*
* @param InputCtx: Context passed from StubCallTrmpln
*
* Description: Hook VsrKiRetireDpcList for controling _KDPC in Timer-Tables current Cpu-Core.
--*/
volatile VOID VsrKiRetireDpcList(IN PINPUTCONTEXT_ICT pInputCtx)
{
    CheckStatusTheiaCtx();

    UCHAR ReasonDetect0[] = { "Unbacked DeferredRoutine" };

    UCHAR ReasonDetect1[] = { "PG DeferredContext" };

    UCHAR TypeDetect = 2UI8;

    CONST UCHAR RetOpcode = 0xC3UI8;

    BOOLEAN OldIF = FALSE;

    PKTIMER_TABLE_ENTRY pCurrentKTimerTableEntry = NULL;

    PKTIMER pCurrentKtimer = NULL;

    PKDPC pCurrKdpc = NULL;

    pCurrentKTimerTableEntry = (PKTIMER_TABLE_ENTRY) & (((PKTIMER_TABLE)(__readgsqword(0x20I32) + g_pTheiaCtx->TheiaMetaDataBlock.KPRCB_TimerTable))->TimerEntries);

    for (USHORT i = 0UI16; i < 512; ++i)
    {
        if (((pCurrentKtimer = ((pCurrentKTimerTableEntry + i)->Entry.Flink)) != &((pCurrentKTimerTableEntry + i)->Entry)))
        {
            pCurrentKtimer = CONTAINING_RECORD(pCurrentKtimer, KTIMER, TimerListEntry);
        }
        else { continue; }

        do
        {
            //
            // KeSetTimer (_KTIMER initialization routine) Windows 11 25H2:
            // 
            // v5 = (_KDPC*)(KiWaitNever
            //     ^ __ROR8__((unsigned __int64)Timer ^ _byteswap_uint64(KiWaitAlways ^ (unsigned __int64)Dpc), KiWaitNever));
            // 
            // Timer->Dpc = v5;
            // 
            //  
            // KiProcessExpiredTimerList (_KTIMER-List handler routine) Windows 11 25H2:
            // 
            // v34 = KiWaitAlways ^ _byteswap_uint64(v9 ^ __ROL8__(KiWaitNever ^ *(_QWORD *)(v9 + 48), KiWaitNever));
            // 
   
            pCurrKdpc = (PKDPC)(*(g_pTheiaCtx->ppKiWaitAlways) ^ _byteswap_uint64((ULONG64)(pCurrentKtimer) ^ _rotl64(*(g_pTheiaCtx->ppKiWaitNever) ^ (ULONG64)(pCurrentKtimer->Dpc), (UCHAR) * (g_pTheiaCtx->ppKiWaitNever))));

            if (!pCurrKdpc) { goto SkipCheckKDPC; }

            if (!(g_pTheiaCtx->pMmIsAddressValid(pCurrKdpc))) { goto SkipCheckKDPC; }
            
            if (*(PUCHAR)(pCurrKdpc->DeferredRoutine) == 0xC3UI8) { goto SkipCheckKDPC; }

            if (!(_IsAddressSafe(pCurrKdpc->DeferredRoutine)))
            {
                TypeDetect = 0UI8;
            }
            else if (!(g_pTheiaCtx->pMmIsAddressValid(pCurrKdpc->DeferredContext)) && (((ULONG64)(pCurrKdpc->DeferredContext)) & ~0x03I64))
            {
                TypeDetect = 1UI8;
            }
            else { VOID; } ///< For clarity.

            if (TypeDetect < 2)
            {
                DbgLog("[TheiaPg <+>] VsrKiRetireDpcList: Detect possibly PG-KTIMER | Reason: %s | _KTIMER: 0x%I64X | _KDPC: 0x%I64X | DeferredRoutine: 0x%I64X | DeferredContext: 0x%I64X\n\n", ((!TypeDetect) ? ReasonDetect0 : ReasonDetect1), pCurrentKtimer, pCurrKdpc, pCurrKdpc->DeferredRoutine, pCurrKdpc->DeferredContext);
    
                if (OldIF = HrdGetIF()) { _disable(); }

                HrdGetPteInputVa(pCurrKdpc->DeferredRoutine)->Dirty1 = 1;

                __writecr3(__readcr3());

                *(PUCHAR)pCurrKdpc->DeferredRoutine = 0xC3UI8;

                HrdGetPteInputVa(pCurrKdpc->DeferredRoutine)->Dirty1 = 0;

                __writecr3(__readcr3());

                if (OldIF) { _enable(); }

                TypeDetect = 2UI8;
            }

            SkipCheckKDPC:

            pCurrentKtimer = CONTAINING_RECORD(pCurrentKtimer->TimerListEntry.Flink, KTIMER, TimerListEntry);

        } while (&(pCurrentKtimer->TimerListEntry) != &((pCurrentKTimerTableEntry + i)->Entry));
    }

    return;
}

/*++
* Routine: VsrExAllocatePool2
*
* MaxIRQL: DISPATCH_LEVEL
*
* Public/Private: Public
*
* @param InputCtx: Context passed from StubCallTrmpln
*
* Description: This visor is required as a last resort if the PG check routine (SysThread/WorkItem/APC) continues to overcome countermeasures.
* PG check routine Windows 11 25H2 for memory allocation use ExAllocatePool2/MmAllocateIndependentPages(for re-allocation LocalPgCtx).
--*/
volatile VOID VsrExAllocatePool2(IN OUT PINPUTCONTEXT_ICT pInputCtx)
{
    CheckStatusTheiaCtx();

    if (!(g_pTheiaCtx->pPsIsSystemThread((PETHREAD)__readgsqword(0x188UI32)))) { return; }
    
    PCONTEXT pInternalCtx = (PCONTEXT)g_pTheiaCtx->pMmAllocateIndependentPagesEx(PAGE_SIZE, -1I32, 0I64, 0I32);

    if (!pInternalCtx) { DbgLog("[TheiaPg <->] VsrExAllocatePool2: Bad alloc page for InternalCtx\n"); return; }

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

    PULONG64 pRetAddrsTrace = (PULONG64)g_pTheiaCtx->pMmAllocateIndependentPagesEx(PAGE_SIZE, -1I32, 0I64, 0I32);

    if (!pRetAddrsTrace) { DbgLog("[TheiaPg <->] VsrExAllocatePool2: Bad alloc page for RetAddrsTrace\n"); return; }

    PVOID StackHigh, StackLow;

    PVOID pImageBase = NULL;

    PVOID pRuntimeFunction = NULL;

    PVOID pHandlerData = NULL;

    ULONG64 EstablisherFrame = 0UI64;

    PUCHAR pCurrentObjThread = (PUCHAR)__readgsqword(0x188UI32);

    PUSHORT pCurrentTID = (PUSHORT)(pCurrentObjThread + (g_pTheiaCtx->TheiaMetaDataBlock.ETHREAD_Cid_OFFSET + g_pTheiaCtx->TheiaMetaDataBlock.CLIENT_ID_UniqueThread_OFFSET));

    CONST LONG64 Timeout = (-10000UI64 * 31536000000UI64); ///< 1 year.

    CONST UCHAR RetOpcode = 0xC3UI8;

    LONG32 SaveRel32Offset = 0I32;

    PVOID pSearchSdbpCheckDllRWX = NULL;

    PVOID pPgDpcRoutine = NULL;

    PVOID pPgApcRoutine = NULL;

    BOOLEAN OldIF = FALSE;

    INDPN_RW_V_MEMORY_DATA DataIndpnRWVMem = { 0 };

    DataIndpnRWVMem.FlagsExecute = MEM_INDPN_RW_WRITE_OP_BIT;

    DataIndpnRWVMem.pIoBuffer = &RetOpcode;

    DataIndpnRWVMem.LengthRW = 1UI64;

    BOOLEAN IsSleep = FALSE;

    PVOID pPgCtx = NULL;

    StackHigh = *(PVOID*)(pCurrentObjThread + g_pTheiaCtx->TheiaMetaDataBlock.KTHREAD_InitialStack_OFFSET);

    StackLow = *(PVOID*)(pCurrentObjThread + g_pTheiaCtx->TheiaMetaDataBlock.KTHREAD_StackLimit_OFFSET);

    if (_IsAddressSafe(pInternalCtx->Rip))
    {
        for (ULONG32 i = 0; ; ++i)
        {
            pRuntimeFunction = g_pTheiaCtx->pRtlLookupFunctionEntry(pInternalCtx->Rip, &pImageBase, NULL);

            if (!pRuntimeFunction) ///< If the current routine leaf.
            {
                pInternalCtx->Rip = *(PVOID*)pInternalCtx->Rsp;

                pInternalCtx->Rsp += 8I64;
            }

            g_pTheiaCtx->pRtlVirtualUnwind(0UI32, pImageBase, pInternalCtx->Rip, pRuntimeFunction, pInternalCtx, &pHandlerData, &EstablisherFrame, NULL);

            if ((pInternalCtx->Rsp >= StackHigh) || (pInternalCtx->Rsp <= StackLow) || (pInternalCtx->Rip < 0xffff800000000000UI64)) { break; }

            if (!(_IsAddressSafe(pInternalCtx->Rip)))
            {             
                JmpDetectNonBackedStack:

                DbgLog("[TheiaPg <+>] VsrExAllocatePool2: Detect non-backed stack calls | TCB: 0x%I64X TID: 0x%hX\n", pCurrentObjThread, *pCurrentTID);

                JmpDetectPgCtxInCpuExecuteCtx:
                
                pRetAddrsTrace[i] = pInternalCtx->Rip;

                DbgLog("=================================================================\n");
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
                DbgLog("================================================================\n");

                DbgText
                ( // {
                
                for (ULONG32 j = 0UI32; ; ++j)
                {
                    if (j == i) { DbgLog("%I32d frame: 0x%I64X <- unbacked\n\n", j, pRetAddrsTrace[j]); break; }

                    DbgLog("%I32d frame: 0x%I64X\n", j, pRetAddrsTrace[j]);
                }

                ) // }

                DbgLog("[TheiaPg <+>] VsrExAllocatePool2: Handling exit phase...\n\n");

                if (pInputCtx->rax) { ExFreePool(pInputCtx->rax); pInputCtx->rax = 0I64; }

                if ((!pPgCtx ? (pPgCtx = SearchPgCtxInCtx(pInternalCtx)) : pPgCtx))
                {
                    DbgLog("[TheiaPg <+>] VsrExAllocatePool2: Detect possibly PgCaller | pPgCtx: 0x%I64X\n\n", pPgCtx);

                    if (g_pTheiaCtx->pMmIsAddressValid(pPgDpcRoutine = *(PVOID*)((PUCHAR)pPgCtx + 0x7f8))) ///< LocalPgCtxBase + 0x7f8: PgDpcRoutine
                    {
                        if (!((HrdGetPteInputVa(pPgDpcRoutine))->NoExecute))
                        {
                            DbgLog("[TheiaPg <+>] VsrExAllocatePool2: Detect PgDpcRoutine in PgCtx | PgDpcRoutine: 0x%I64X\n\n", pPgDpcRoutine);
                   
                            DataIndpnRWVMem.pVa = pPgDpcRoutine;

                            HrdIndpnRWVMemory(&DataIndpnRWVMem);
                        }
                    }

                    if (g_pTheiaCtx->pMmIsAddressValid(pPgApcRoutine = *(PVOID*)((PUCHAR)pPgCtx + 0xa30))) ///< LocalPgCtxBase + 0xA30: PgApcRoutine (basically KiDispatchCallout)
                    {
                        if (!((HrdGetPteInputVa(pPgApcRoutine))->NoExecute))
                        {
                            DbgLog("[TheiaPg <+>] VsrExAllocatePool2: Detect PgApcRoutine in PgCtx | PgApcRoutine: 0x%I64X\n\n", pPgApcRoutine);

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

                            DbgLog("[TheiaPg <+>] VsrExAllocatePool2: SdbpCheckDllRWX is found: 0x%I64X\n\n", pSearchSdbpCheckDllRWX);

                            break;
                        }
                    }

                    JmpToPossibleSleep:

                    if (__readcr8() < DISPATCH_LEVEL)
                    {
                        DbgLog("[TheiaPg <+>] VsrExAllocatePool2: Enter to dead sleep... | IRQL: 0x%02X\n\n", __readcr8());

                        // __debugbreak();

                        IsSleep = TRUE;

                        break;
                    }
                    else 
                    { 
                        DbgLog("[TheiaPg <+>] VsrExAllocatePool2: Unsuccessful enter to dead sleep... | IRQL: 0x%02X\n\n", __readcr8());

                        // __debugbreak();

                        //
                        // After an unsuccessful call to the ExAllocatePool2 routine by PG,
                        // it will attempt to increment the 32-bit counter of unsuccessful allocations in the context structure,
                        // so it is necessary to set the counter to -1 to perform an overflow of the 32-bit field to keep the counter at 0.
                        //
                        *(PULONG32)((PUCHAR)pPgCtx + 0xA60) = -1UI32; ///< Required as an alternative method to prevent the rescheduling of the PG check procedure execution in the case of (CurrIRQL > APC_LEVEL).

                        break; 
                    }
                }
                else
                {
                    DbgLog("[TheiaPg <+>] VsrExAllocatePool2: Detect possibly PgCaller | pPgCtx: Not-Found\n\n");

                    // __debugbreak();

                    goto JmpToPossibleSleep;
                }         
            }

            if (pPgCtx = SearchPgCtxInCtx(pInternalCtx))
            {
                DbgLog("[TheiaPg <+>] VsrExAllocatePool2: Detect PgCtx in CpuExecuteCtx | TCB: 0x%I64X TID: 0x%hX\n", pCurrentObjThread, *pCurrentTID);

                goto JmpDetectPgCtxInCpuExecuteCtx;
            }
                             
            pRetAddrsTrace[i] = pInternalCtx->Rip;
        }
    }
    else { goto JmpDetectNonBackedStack; }

    // if (!IsSleep)
    // {
    //     if (pInputCtx->rax)
    //     {
    //         if ((*(PULONG64)(HrdGetPteInputVa((PVOID)pInputCtx->rax)) & 0x10801UI64) == 0x801UI64) ///< Checking RWX PTE-Attributes.
    //         {
    //             DbgLog("[TheiaPg <+>] VsrExAllocatePool2: Detect attempt allocate RWX-Page | NoPgArtifacts\n\n");
    // 
    //             if (__readcr8() < DISPATCH_LEVEL) { IsSleep = TRUE; }
    //             else { ExFreePool(pInputCtx->rax); pInputCtx->rax = 0I64; }
    //         }
    //     }
    // }

    g_pTheiaCtx->pMmFreeIndependentPages(pInternalCtx, PAGE_SIZE, 0I64);

    g_pTheiaCtx->pMmFreeIndependentPages(pRetAddrsTrace, PAGE_SIZE, 0I64);

    if (IsSleep) { g_pTheiaCtx->pKeDelayExecutionThread(KernelMode, FALSE, &Timeout); }

    return;
}

/**
* Routine: VsrKiCustomRecurseRoutineX
*
* MaxIRQL: DISPATCH_LEVEL
*
* Public/Private: Public
*
* @param pInputCtx: Context passed from StubCallTrmpln
*
* Description: Similar to VsrExAllocatePool2, but for the most part aims to be called from the DISPATCH_LEVEL-ISR context.
* If VsrKiExecuteAllDpcs skips _KDPC-PG in the CURRENT-DPC-QUEUE, VsrKiCustomRecurseRoutineX is possibly to initiate a rebounce context execution.
*/
volatile VOID VsrKiCustomRecurseRoutineX(IN OUT PINPUTCONTEXT_ICT pInputCtx)
{
    CheckStatusTheiaCtx();

    PCONTEXT pInternalCtx = (PCONTEXT)g_pTheiaCtx->pMmAllocateIndependentPagesEx(PAGE_SIZE, -1I32, 0I64, 0I32);

    if (!pInternalCtx) { DbgLog("[TheiaPg <->] VsrKiCustomRecurseRoutineX: Bad alloc page for InternalCtx\n"); return; }

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

    PVOID StackHigh, StackLow;

    PVOID pImageBase = NULL;

    PVOID pRuntimeFunction = NULL;

    PVOID pHandlerData = NULL;

    ULONG64 EstablisherFrame = 0UI64;

    PUCHAR pCurrentObjThread = (PUCHAR)__readgsqword(0x188UI32);

    PUSHORT pCurrentTID = (PUSHORT)(pCurrentObjThread + (g_pTheiaCtx->TheiaMetaDataBlock.ETHREAD_Cid_OFFSET + g_pTheiaCtx->TheiaMetaDataBlock.CLIENT_ID_UniqueThread_OFFSET));

    CONST LONG64 Timeout = (-10000UI64 * 31536000000UI64); ///< 1 year.

    CONST UCHAR RetOpcode = 0xC3UI8;

    BOOLEAN OldIF = FALSE;

    LONG32 SaveRel32Offset = 0I32;

    PVOID pRetAddrCallerPgAccessRoutine = NULL;

    PKDPC pPgKDPC = NULL;

    INDPN_RW_V_MEMORY_DATA DataIndpnRWVMem = { 0 };

    DataIndpnRWVMem.FlagsExecute = MEM_INDPN_RW_WRITE_OP_BIT;

    DataIndpnRWVMem.pIoBuffer = &RetOpcode;

    DataIndpnRWVMem.LengthRW = 1UI64;

    BOOLEAN IsSleep = FALSE;

    StackHigh = *(PVOID*)(pCurrentObjThread + g_pTheiaCtx->TheiaMetaDataBlock.KTHREAD_InitialStack_OFFSET);

    StackLow = *(PVOID*)(pCurrentObjThread + g_pTheiaCtx->TheiaMetaDataBlock.KTHREAD_StackLimit_OFFSET);

    //
    // 3 Iteration-unwind for "default" chain call PgRoutines from DISPATCH_LEVEL-ISR context.  
    // 
    //            2-iteration-unwind         1-iteration-unwind     0-iteration-unwind
    // example: KiProcessExpiredTimerList -> ExpTimerDpcRoutine -> KiCustomAccessRoutine0 -> KiCustomRecurseRoutine0Hook
    //
    for (UCHAR i = 0UI8; i < 3; ++i) 
    {    
        pRuntimeFunction = g_pTheiaCtx->pRtlLookupFunctionEntry(pInternalCtx->Rip, &pImageBase, NULL);

        if (!pRuntimeFunction) ///< If the current routine leaf.
        {
            pInternalCtx->Rip = *(PVOID*)pInternalCtx->Rsp;

            pInternalCtx->Rsp += 8I64;
        }

        g_pTheiaCtx->pRtlVirtualUnwind(0UI32, pImageBase, pInternalCtx->Rip, pRuntimeFunction, pInternalCtx, &pHandlerData, &EstablisherFrame, NULL);

        if (i == 1) { pRetAddrCallerPgAccessRoutine = pInternalCtx->Rip; }
    }

    DbgLog("[TheiaPg <+>] VsrKiCustomRecurseRoutineX: Detect PgCallChain | TCB: 0x%I64X TID: 0x%hX\n", pCurrentObjThread, *pCurrentTID);
    DbgLog("==============================================================\n");
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
    DbgLog("==============================================================\n\n");

    DbgLog("[TheiaPg <+>] VsrKiCustomRecurseRoutineX: Handling exit phase...\n\n");

    DbgLog("[TheiaPg <+>] VsrKiCustomRecurseRoutineX: Return address CallerPgAccessRoutine: 0x%I64X\n\n", pRetAddrCallerPgAccessRoutine);

    if (pPgKDPC = _HeurisSearchKdpcInCtx(pInternalCtx))
    {
        DbgLog("[TheiaPg <+>] VsrKiCustomRecurseRoutineX: Detect PG-KDPC from cpu-unwind-ctx | _KDPC: 0x%I64X\n\n", pPgKDPC);

        DataIndpnRWVMem.pVa = pPgKDPC->DeferredRoutine;

        HrdIndpnRWVMemory(&DataIndpnRWVMem);
    }

    //
    // If IRQL > DISPATCH_LEVEL then the current executor is APC or THREAD, you can enter the current APC/THREAD in the delay.
    //
    if (__readcr8() < DISPATCH_LEVEL)
    {
        DbgLog("[TheiaPg <+>] VsrKiCustomRecurseRoutineX: Enter to dead sleep... | IRQL: 0x%02X\n\n", __readcr8());

        IsSleep = TRUE;
    }
    else { DbgLog("[TheiaPg <+>] VsrKiCustomRecurseRoutineX: Rebound execution context... | IRQL: 0x%02X\n\n", __readcr8()); }
     
    g_pTheiaCtx->pMmFreeIndependentPages(pInternalCtx, PAGE_SIZE, 0I64);

    if (IsSleep) { g_pTheiaCtx->pKeDelayExecutionThread(KernelMode, FALSE, &Timeout); }

    //
    // Restore prev-cpu-context. 
    // 
    pInputCtx->rax    = pInternalCtx->Rsp;
    pInputCtx->rcx    = pInternalCtx->Rip;
    pInputCtx->rdx    = pInternalCtx->Rdx;
    pInputCtx->rbx    = pInternalCtx->Rbx;
    pInputCtx->rsi    = pInternalCtx->Rsi;
    pInputCtx->rdi    = pInternalCtx->Rdi;
    pInputCtx->r8     = pInternalCtx->R8;
    pInputCtx->r9     = pInternalCtx->R9;
    pInputCtx->r10    = pInternalCtx->R10;
    pInputCtx->r11    = pInternalCtx->R11;
    pInputCtx->r12    = pInternalCtx->R12;
    pInputCtx->r13    = pInternalCtx->R13;
    pInputCtx->r14    = pInternalCtx->R14;
    pInputCtx->r15    = pInternalCtx->R15;
    pInputCtx->rbp    = pInternalCtx->Rbp;
    pInputCtx->Rflags = pInternalCtx->EFlags;

    return;
}
