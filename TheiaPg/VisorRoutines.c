#include "LinkHeader.h"

/*++
* Routine: VsrKiExecuteAllDpcs
*
* MaxIRQL: DISPATCH_LEVEL
*
* Public/Private: Public
*
* @param InputCtx: Context passed from WrapperCallTrmpln
*
* Description: Hook KiExecuteAllDpcs for controling _KDPCs in QUEUE-DPCs current CpuCore.
--*/
volatile VOID VsrKiExecuteAllDpcs(IN PINPUTCONTEXT_ICT pInputCtx)
{
    CheckStatusTheiaCtx();

    CONST UCHAR ReasonDetect0[] = { "Unbacked DeferredRoutine" };

    CONST UCHAR ReasonDetect1[] = { "PG DeferredContext" };

    CONST UCHAR ReasonDetectError[] = { "UNKNOWN" };

    CONST UCHAR RetOpcode = 0xc3UI8;

    INDPN_RW_V_MEMORY_DATA DataIndpnRWVMem = { 0 };

    DataIndpnRWVMem.FlagsExecute = MEM_INDPN_RW_WRITE_OP_BIT;

    DataIndpnRWVMem.pIoBuffer = &RetOpcode;

    DataIndpnRWVMem.LengthRW = 1UI64;

    UCHAR TypeDetect = 2UI8;

    PVOID pHeadDpcList[2] = { 0 };

    pHeadDpcList[DPC_NORMAL] = (PVOID)__readgsqword((g_pTheiaCtx->TheiaMetaDataBlock.KPCR_Prcb_OFFSET + g_pTheiaCtx->TheiaMetaDataBlock.KPRCB_DpcData0_OFFSET)); ///< Get address first node DPC_NORMAL_QUEUE.

    pHeadDpcList[DPC_THREADED] = (PVOID)__readgsqword((g_pTheiaCtx->TheiaMetaDataBlock.KPCR_Prcb_OFFSET + g_pTheiaCtx->TheiaMetaDataBlock.KPRCB_DpcData1_OFFSET)); ///< Get address first node DPC_THREADED_QUEUE.

    PKDPC pCurrKDPC = NULL;

    BOOLEAN FlagCurrQueue = FALSE; ///< FALSE: DPC_NORMAL & TRUE: DPC_THREADED

    BOOLEAN LockCurrQueue = FALSE;

    ULONG32 CurrCoreNum = (ULONG32)__readgsdword(g_pTheiaCtx->TheiaMetaDataBlock.KPCR_Prcb_OFFSET + g_pTheiaCtx->TheiaMetaDataBlock.KPRCB_Number_OFFSET);

    for(; ;)
    {
        if (!FlagCurrQueue && !LockCurrQueue)
        {
            if (!pHeadDpcList[DPC_NORMAL]) { FlagCurrQueue = TRUE; }

            else { pCurrKDPC = CONTAINING_RECORD(pHeadDpcList[DPC_NORMAL], KDPC, DpcListEntry); LockCurrQueue = TRUE; }
        }

        if (FlagCurrQueue && !LockCurrQueue)
        {
            if (!pHeadDpcList[DPC_THREADED]) { break; }

            else { pCurrKDPC = CONTAINING_RECORD(pHeadDpcList[DPC_THREADED], KDPC, DpcListEntry); LockCurrQueue = TRUE; }
        }

        if (*(PUCHAR)pCurrKDPC->DeferredRoutine == 0xc3UI8) { goto SkipCheckKDPC; }

        if (!(_IsSafeAddress(pCurrKDPC->DeferredRoutine)))
        { 
            TypeDetect = 0UI8;

            goto DetectPgKDPC;
        }

        if ((g_pTheiaCtx->pMmIsAddressValid(pCurrKDPC->DeferredContext) && (((ULONG64)pCurrKDPC->DeferredContext >> 47) == 0x1ffffUI64)))
        {
            if ((*(PULONG64)pCurrKDPC->DeferredContext == 0x085131481131482eUI64 || ((*(PULONG64)(HrdGetPteInputVa(pCurrKDPC->DeferredContext)) & 0x8000000000000802UI64) == 0x802UI64)))
            {
                TypeDetect = 1UI8;
            }
        }
        else
        {
            if (((ULONG32)(pCurrKDPC->DeferredContext) & 0xffffffffUI32) > 0xffffUI32)
            {
                for (UCHAR i = 0UI8, j = 0UI8; ; ++i)
                {
                    if (((ULONG64)(pCurrKDPC->DeferredContext) >> i) & 0x01UI64) { ++j; }

                    if (i == 63)
                    {
                        if (j > 4)
                        {
                            TypeDetect = 1UI8;
                        }

                        break;
                    }
                }
            }
        }

        DetectPgKDPC:

        if (TypeDetect < 2)
        {
            DbgLog("[TheiaPg <+>] VsrKiExecuteAllDpcs: Detect possibly PG-KDPC | CpuCore: 0x%I32X\n", CurrCoreNum);
            DbgLog("============================================================\n");
            DbgLog("Reason:          %s\n", ((!TypeDetect) ?
                         ReasonDetect0 : (TypeDetect == 1) ?
                         ReasonDetect1 : ReasonDetectError));
            DbgLog("_KDPC:           0x%I64X\n", pCurrKDPC);
            DbgLog("DeferredRoutine: 0x%I64X\n", pCurrKDPC->DeferredRoutine);
            DbgLog("DeferredContext: 0x%I64X\n", pCurrKDPC->DeferredContext);
            DbgLog("SystemArgument1: 0x%I64X\n", pCurrKDPC->SystemArgument1);
            DbgLog("SystemArgument2: 0x%I64X\n", pCurrKDPC->SystemArgument2);
            DbgLog("CpuCore:         0x%I32X\n", CurrCoreNum);
            DbgLog("============================================================\n\n");

            if (pCurrKDPC->DeferredRoutine != g_pTheiaCtx->pKiBalanceSetManagerDeferredRoutine)
            {
                DataIndpnRWVMem.pVa = pCurrKDPC->DeferredRoutine;

                HrdIndpnRWVMemory(&DataIndpnRWVMem);
            }
            else { pCurrKDPC->DeferredRoutine = &Voidx64; }
            
            TypeDetect = 2UI8;
        }

        SkipCheckKDPC:

        if (!(pCurrKDPC->DpcListEntry.Next) && !FlagCurrQueue) { FlagCurrQueue = TRUE; LockCurrQueue = FALSE; continue; }

        else if (!(pCurrKDPC->DpcListEntry.Next) && FlagCurrQueue) { break; }

        else { pCurrKDPC = CONTAINING_RECORD(pCurrKDPC->DpcListEntry.Next, KDPC, DpcListEntry); }
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
* @param InputCtx: Context passed from WrapperCallTrmpln
*
* Description: Hook KiRetireDpcList for controling _KDPCs in TABLES-KTIMERs current CpuCore.
--*/
volatile VOID VsrKiRetireDpcList(IN PINPUTCONTEXT_ICT pInputCtx)
{
    CheckStatusTheiaCtx();

    CONST UCHAR ReasonDetect0[] = { "Unbacked DeferredRoutine" };

    CONST UCHAR ReasonDetect1[] = { "PG DeferredContext" };

    CONST UCHAR ReasonDetectError[] = { "UNKNOWN" };

    CONST UCHAR RetOpcode = 0xc3UI8;

    UCHAR TypeDetect = 2UI8;

    BOOLEAN OldIF = FALSE;

    ULONG32 CurrCoreNum = (ULONG32)__readgsdword(g_pTheiaCtx->TheiaMetaDataBlock.KPCR_Prcb_OFFSET + g_pTheiaCtx->TheiaMetaDataBlock.KPRCB_Number_OFFSET);

    PKTIMER_TABLE_ENTRY pCurrKTimerTableEntry = (PKTIMER_TABLE_ENTRY) & (((PKTIMER_TABLE)(__readgsqword(g_pTheiaCtx->TheiaMetaDataBlock.KPCR_CurrentPrcb_OFFSET) + g_pTheiaCtx->TheiaMetaDataBlock.KPRCB_TimerTable))->TimerEntries);

    PKTIMER pCurrKTIMER = NULL;

    PKDPC pCurrKDPC= NULL;

    for (USHORT i = 0UI16; i < 512; ++i)
    {
        if (((pCurrKTIMER = ((pCurrKTimerTableEntry + i)->Entry.Flink)) != &((pCurrKTimerTableEntry + i)->Entry)))
        {
            pCurrKTIMER = CONTAINING_RECORD(pCurrKTIMER, KTIMER, TimerListEntry);
        }
        else { continue; }

        do
        {
            //
            // KeSetTimer (_KTIMER initialization routine) Windows 11 25H2:
            // 
            // v5 = (_KDPC*)(KiWaitNever
            //     ^ __ROR8__((unsigned __int64)Timer ^ _byteswap_uint64(KiWaitAlways ^ (unsigned __int64)Dpc), KiWaitNever)); (cry)
            // 
            // Timer->Dpc = v5;
            // 
            //  
            // KiProcessExpiredTimerList (handler routine TABLES-KTIMERs) Windows 11 25H2:
            // 
            // v34 = KiWaitAlways ^ _byteswap_uint64(v9 ^ __ROL8__(KiWaitNever ^ *(_QWORD *)(v9 + 48), KiWaitNever)); (dec)
            // 
            pCurrKDPC = (PKDPC)(*(g_pTheiaCtx->ppKiWaitAlways) ^ _byteswap_uint64((ULONG64)(pCurrKTIMER) ^ _rotl64(*(g_pTheiaCtx->ppKiWaitNever) ^ (ULONG64)(pCurrKTIMER->Dpc), (UCHAR) * (g_pTheiaCtx->ppKiWaitNever))));

            if (!pCurrKDPC || !(g_pTheiaCtx->pMmIsAddressValid(pCurrKDPC))) { goto SkipCheckKTIMER; }
        
            if (*(PUCHAR)(pCurrKDPC->DeferredRoutine) == 0xc3UI8) { goto SkipCheckKTIMER; }

            if (!(_IsSafeAddress(pCurrKDPC->DeferredRoutine)))
            {
                TypeDetect = 0UI8;

                goto DetectPgKTIMER;
            }
            
            if ((g_pTheiaCtx->pMmIsAddressValid(pCurrKDPC->DeferredContext) && (((ULONG64)pCurrKDPC->DeferredContext >> 47) == 0x1ffffUI64)))
            {
                if ((*(PULONG64)pCurrKDPC->DeferredContext == 0x085131481131482eUI64 || ((*(PULONG64)(HrdGetPteInputVa(pCurrKDPC->DeferredContext)) & 0x8000000000000802UI64) == 0x802UI64)))
                {
                    TypeDetect = 1UI8;
                }
            }
            else
            {
                if (((ULONG32)(pCurrKDPC->DeferredContext) & 0xffffffffUI32) > 0xffffUI32)
                {
                    for (UCHAR i = 0UI8, j = 0UI8; ; ++i)
                    {
                        if (((ULONG64)(pCurrKDPC->DeferredContext) >> i) & 0x01UI64) { ++j; }

                        if (i == 63)
                        {
                            if (j > 4)
                            {
                                TypeDetect = 1UI8;
                            }

                            break;
                        }
                    }
                }
            }

            DetectPgKTIMER:

            if (TypeDetect < 2)
            {
                DbgLog("[TheiaPg <+>] VsrKiRetireDpcList: Detect possibly PG-KTIMER | CpuCore: 0x%I32X\n", CurrCoreNum);
                DbgLog("=============================================================\n");
                DbgLog("Reason:          %s\n", ((!TypeDetect) ?
                             ReasonDetect0 : (TypeDetect == 1) ?
                             ReasonDetect1 : ReasonDetectError));
                DbgLog("_KTIMER:         0x%I64X\n", pCurrKTIMER);
                DbgLog("_KDPC:           0x%I64X\n", pCurrKDPC);
                DbgLog("DeferredRoutine: 0x%I64X\n", pCurrKDPC->DeferredRoutine);
                DbgLog("DeferredContext: 0x%I64X\n", pCurrKDPC->DeferredContext);
                DbgLog("SystemArgument1: 0x%I64X\n", pCurrKDPC->SystemArgument1);
                DbgLog("SystemArgument2: 0x%I64X\n", pCurrKDPC->SystemArgument2);
                DbgLog("CpuCore:         0x%I32X\n", CurrCoreNum);
                DbgLog("=============================================================\n\n");

                if (pCurrKDPC->DeferredRoutine != g_pTheiaCtx->pKiBalanceSetManagerDeferredRoutine)
                {
                    if (OldIF = HrdGetIF()) { _disable(); }

                    HrdGetPteInputVa(pCurrKDPC->DeferredRoutine)->Dirty1 = 1;

                    __writecr3(__readcr3());

                    *(PUCHAR)pCurrKDPC->DeferredRoutine = 0xc3UI8;

                    HrdGetPteInputVa(pCurrKDPC->DeferredRoutine)->Dirty1 = 0;

                    __writecr3(__readcr3());

                    if (OldIF) { _enable(); }
                }
                else { pCurrKDPC->DeferredRoutine = &Voidx64; }

                TypeDetect = 2UI8;
            }

            SkipCheckKTIMER:

            pCurrKTIMER = CONTAINING_RECORD(pCurrKTIMER->TimerListEntry.Flink, KTIMER, TimerListEntry);

        } while (&(pCurrKTIMER->TimerListEntry) != &((pCurrKTimerTableEntry + i)->Entry));
    }

    return;
}

/*++
* Routine: VsrKiDeliverApc
*
* MaxIRQL: DISPATCH_LEVEL
*
* Public/Private: Public
*
* @param InputCtx: Context passed from WrapperCallTrmpln
*
* Description: Hook KiDeliverApc for controling _KAPCs in QUEUE-APCs current Thread-Obj.
--*/
volatile VOID VsrKiDeliverApc(IN PINPUTCONTEXT_ICT pInputCtx)
{
    CheckStatusTheiaCtx();

    CONST UCHAR ReasonDetect0[] = { "Unbacked KernelRoutine" };

    CONST UCHAR ReasonDetect1[] = { "Unbacked NormalRoutine" };

    CONST UCHAR ReasonDetectError[] = { "UNKNOWN" };

    CONST UCHAR RetOpcode = 0xc3UI8;

    INDPN_RW_V_MEMORY_DATA DataIndpnRWVMem = { 0 };

    DataIndpnRWVMem.FlagsExecute = MEM_INDPN_RW_WRITE_OP_BIT;

    DataIndpnRWVMem.pIoBuffer = &RetOpcode;

    DataIndpnRWVMem.LengthRW = 1UI64;

    UCHAR TypeDetect = 2UI8;

    PVOID pCurrObjThread = (PVOID)__readgsqword(0x188UI32);

    PKAPC_STATE pCurrKAPCState = (PKAPC_STATE)((PUCHAR)pCurrObjThread + g_pTheiaCtx->TheiaMetaDataBlock.KTHREAD_ApcState_OFFSET); ///< Pointer to Head-QueueKernelApcs.

    PKAPC_TRUE pCurrKAPC = ((PLIST_ENTRY)&(pCurrKAPCState->ApcListHead[KernelMode]))->Flink;

    if (pCurrKAPC == pCurrKAPCState) { goto Exit; }

    pCurrKAPC = CONTAINING_RECORD(pCurrKAPC, KAPC_TRUE, ApcListEntry);
 
    for(; ;)
    {       
        if (*(PUCHAR)pCurrKAPC->KernelRoutine == 0xc3UI8 || pCurrKAPC->SystemArgument1 == IS_SAFE_KAPC_SIGNATURE) { goto SkipCheckKAPC; }

        if (!(_IsSafeAddress(pCurrKAPC->KernelRoutine)))
        {
            TypeDetect = 0UI8;

            goto DetectPgKAPC;
        }

        if (pCurrKAPC->NormalRoutine)
        {
            if ((g_pTheiaCtx->pMmIsAddressValid(pCurrKAPC->NormalRoutine) && (((ULONG64)pCurrKAPC->NormalRoutine >> 47) == 0x1ffffUI64)))
            {
                if (!(_IsSafeAddress(pCurrKAPC->NormalRoutine)))
                {
                    TypeDetect = 1UI8;
                }
            }
        }
        
        DetectPgKAPC:

        if (TypeDetect < 2)
        {
            DbgLog("[TheiaPg <+>] VsrKiDeliverApc: Detect possibly PG-KAPC | TCB: 0x%I64X\n");
            DbgLog("========================================================\n");
            DbgLog("Reason:          %s\n", ((!TypeDetect) ?
                         ReasonDetect0 : (TypeDetect == 1) ?
                         ReasonDetect1 : ReasonDetectError));
            DbgLog("_KAPC:           0x%I64X\n",   pCurrKAPC);
            DbgLog("KernelRoutine:   0x%I64X\n",   pCurrKAPC->KernelRoutine);
            DbgLog("NormalRoutine:   0x%I64X\n",   pCurrKAPC->NormalRoutine);
            DbgLog("RundownRoutine:  0x%I64X\n",   pCurrKAPC->RundownRoutine);
            DbgLog("NormalContext:   0x%I64X\n",   pCurrKAPC->NormalContext);
            DbgLog("SystemArgument1: 0x%I64X\n",   pCurrKAPC->SystemArgument1);
            DbgLog("SystemArgument2: 0x%I64X\n\n", pCurrKAPC->SystemArgument2);
            DbgLog("========================================================\n\n");


            DataIndpnRWVMem.pVa = pCurrKAPC->KernelRoutine;

            HrdIndpnRWVMemory(&DataIndpnRWVMem);

            TypeDetect = 2UI8;
        }

        SkipCheckKAPC:

        pCurrKAPC = pCurrKAPC->ApcListEntry.Flink;

        if (pCurrKAPC == pCurrKAPCState) { break; }

        pCurrKAPC = CONTAINING_RECORD(pCurrKAPC, KAPC_TRUE, ApcListEntry);
    } 

    Exit:

    return;
}

/*++
* Routine: VsrExQueueWorkItem
*
* MaxIRQL: DISPATCH_LEVEL
*
* Public/Private: Public
*
* @param InputCtx: Context passed from WrapperCallTrmpln
*
* Description: Hook ExQueueWorkItem for controling insertions _WORK_QUEUE_ITEMs in WORK-QUEUEs.
--*/
volatile VOID VsrExQueueWorkItem(IN PINPUTCONTEXT_ICT pInputCtx)
{
    CheckStatusTheiaCtx();

    CONST UCHAR ReasonDetect0[] = { "Unbacked WorkerRoutine" };

    CONST UCHAR ReasonDetect1[] = { "PG WorkerRoutine" };

    CONST UCHAR ReasonDetect2[] = { "PG WorkItem-Parameter" };

    CONST UCHAR ReasonDetectError[] = { "UNKNOWN" };

    CONST UCHAR RetOpcode = 0xc3UI8;

    INDPN_RW_V_MEMORY_DATA DataIndpnRWVMem = { 0 };

    DataIndpnRWVMem.FlagsExecute = MEM_INDPN_RW_WRITE_OP_BIT;

    DataIndpnRWVMem.pIoBuffer = &RetOpcode;

    DataIndpnRWVMem.LengthRW = 1UI64;

    UCHAR TypeDetect = 3UI8;

    PWORK_QUEUE_ITEM pCurrWorkItem = (PWORK_QUEUE_ITEM)(pInputCtx->rcx);

    if (*(PUCHAR)pCurrWorkItem->WorkerRoutine == 0xc3UI8) { goto SkipCheckWorkItem; }

    if (!(_IsSafeAddress(pCurrWorkItem->WorkerRoutine)))
    {
        TypeDetect = 0UI8;

        goto DetectPgWorkItem;
    }

    // PgWorkItemRoutine0:
    //
    // fffff807`7b042300 4053               push    rbx
    // fffff807`7b042302 4883ec20           sub     rsp, 20h
    // fffff807`7b042306 8b99a0000000       mov     ebx, dword ptr [rcx+0A0h]
    // fffff807`7b04230c 33d2               xor     edx, edx
    // fffff807`7b04230e 4c8b15439ef7ff     mov     r10, qword ptr [0FFFFF8077AFBC158h]
    // fffff807`7b042315 e8b669526e         call    ntkrnlmp!ExFreePoolWithTag (fffff807e9568cd0)
    // fffff807`7b04231a 83fb01             cmp     ebx, 1
    // fffff807`7b04231d 750d               jne     FFFFF8077B04232C
    // fffff807`7b04231f 33c0               xor     eax, eax
    // fffff807`7b042321 87057101f7ff       xchg    eax, dword ptr [0FFFFF8077AFB2498h]
    // fffff807`7b042327 e89841fcff         call    FFFFF8077B0064C4
    // fffff807`7b04232c 4883c420           add     rsp, 20h
    // fffff807`7b042330 5b                 pop     rbx
    // fffff807`7b042331 c3                 ret
    // 
    if (*(PULONG64)pCurrWorkItem->WorkerRoutine == 0x40534883ec208b99UI64 && ((PULONG64)pCurrWorkItem->WorkerRoutine)[1] == 0xa000000033d24c8bUI64)
    {
        TypeDetect = 1UI8;

        goto DetectPgWorkItem;
    }

    if ((g_pTheiaCtx->pMmIsAddressValid(pCurrWorkItem->Parameter) && (((ULONG64)pCurrWorkItem->Parameter >> 47) == 0x1ffffUI64)))
    {
        if ((*(PULONG64)pCurrWorkItem->Parameter == 0x085131481131482eUI64) || ((*(PULONG64)(HrdGetPteInputVa(pCurrWorkItem->Parameter)) & 0x8000000000000802UI64) == 0x802UI64))
        {
            TypeDetect = 2UI8;
        }
    }
    else
    {
        if (((ULONG32)(pCurrWorkItem->Parameter) & 0xffffffffUI32) > 0xffffUI32)
        {
            for (UCHAR i = 0UI8, j = 0UI8; ; ++i)
            {
                if (((ULONG64)(pCurrWorkItem->Parameter) >> i) & 0x01UI64) { ++j; }

                if (i == 63)
                {
                    if (j > 4)
                    {
                        TypeDetect = 2UI8;
                    }

                    break;
                }
            }
        }
    }

    DetectPgWorkItem:

    if (TypeDetect < 3)
    {
        DbgLog("[TheiaPg <+>] VsrExQueueWorkItem: Detect possibly PG-WORKITEM | TCB: 0x%I64X\n");
        DbgLog("===============================================================\n");
        DbgLog("Reason:           %s\n", ((!TypeDetect) ?
                      ReasonDetect0 : (TypeDetect == 1) ?
                      ReasonDetect1 : (TypeDetect == 2) ?
                      ReasonDetect2 : ReasonDetectError));

        DbgLog("_WORK_QUEUE_ITEM: 0x%I64X\n", pInputCtx->rcx);
        DbgLog("WorkerRoutine:    0x%I64X\n", ((PWORK_QUEUE_ITEM)pInputCtx->rcx)->WorkerRoutine);
        DbgLog("Parameter:        0x%I64X\n", ((PWORK_QUEUE_ITEM)pInputCtx->rcx)->Parameter);
        DbgLog("===============================================================\n\n");

        DataIndpnRWVMem.pVa = pCurrWorkItem->WorkerRoutine;

        HrdIndpnRWVMemory(&DataIndpnRWVMem);

        TypeDetect = 3UI8;
    }

    SkipCheckWorkItem:

    return;
}

/*++
* Routine: VsrExAllocatePool2
*
* MaxIRQL: DISPATCH_LEVEL
*
* Public/Private: Public
*
* @param InputCtx: Context passed from WrapperCallTrmpln
*
* Description: This visor is required as a last resort if the PG check routine (SysThread/WorkItem/APC) continues to overcome countermeasures.
* PG check routine primarily uses ExAllocatePool2/MmAllocateIndependentPages for pages allocation in Windows 11 25h2.
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

    if (_IsSafeAddress(pInternalCtx->Rip))
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

            if (!(_IsSafeAddress(pInternalCtx->Rip)))
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
* @param pInputCtx: Context passed from WrapperCallTrmpln
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

    ULONG32 CurrCoreNum = (ULONG32)__readgsdword(g_pTheiaCtx->TheiaMetaDataBlock.KPCR_Prcb_OFFSET + g_pTheiaCtx->TheiaMetaDataBlock.KPRCB_Number_OFFSET);

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

    DbgLog("[TheiaPg <+>] VsrKiCustomRecurseRoutineX: Detect PgCallChain | CpuCore: 0x%I32X\n", CurrCoreNum);
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
