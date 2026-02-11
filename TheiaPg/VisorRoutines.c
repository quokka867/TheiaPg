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
* Description: Hook KiExecuteAllDpcs for controling _KDPCs in QUEUE-DPCs current CpuCore.
--*/
volatile VOID VsrKiExecuteAllDpcs(IN PINPUTCONTEXT_ICT pInputCtx)
{
    CheckStatusTheiaCtx();

    UCHAR TypeDetect = 2UI8;

    CONST UCHAR ReasonDetect0[] = { "Unbacked DeferredRoutine" };
    CONST UCHAR ReasonDetect1[] = { "High-Entropy DeferredContext" };
    CONST UCHAR ReasonDetectError[] = { "UNKNOWN" };

    ULONG32 CurrCoreNum = (ULONG32)__readgsdword(g_pTheiaCtx->TheiaMetaDataBlock.KPCR_Prcb_OFFSET + g_pTheiaCtx->TheiaMetaDataBlock.KPRCB_Number_OFFSET);
    CONST UCHAR RetOpcode = 0xc3UI8;

    INDPN_RW_V_MEMORY_DATA DataIndpnRWVMem = { 0 };
    DataIndpnRWVMem.FlagsExecute = MEM_INDPN_RW_WRITE_OP_BIT;
    DataIndpnRWVMem.pIoBuffer = &RetOpcode;
    DataIndpnRWVMem.LengthRW = 1UI64;

    PVOID pHeadDpcList[2] = { 0 };
    pHeadDpcList[DPC_NORMAL] = (PVOID)__readgsqword((g_pTheiaCtx->TheiaMetaDataBlock.KPCR_Prcb_OFFSET + g_pTheiaCtx->TheiaMetaDataBlock.KPRCB_DpcData0_OFFSET)); 
    pHeadDpcList[DPC_THREADED] = (PVOID)__readgsqword((g_pTheiaCtx->TheiaMetaDataBlock.KPCR_Prcb_OFFSET + g_pTheiaCtx->TheiaMetaDataBlock.KPRCB_DpcData1_OFFSET));

    PKDPC pCurrKDPC = NULL;

    BOOLEAN FlagCurrQueue = FALSE; ///< FALSE: DPC_NORMAL & TRUE: DPC_THREADED
    BOOLEAN LockCurrQueue = FALSE;

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
* @param InputCtx: Context passed from StubCallTrmpln
*
* Description: Hook KiRetireDpcList for controling _KDPCs in TABLES-KTIMERs current CpuCore.
--*/
volatile VOID VsrKiRetireDpcList(IN PINPUTCONTEXT_ICT pInputCtx)
{
    CheckStatusTheiaCtx();

    UCHAR TypeDetect = 2UI8;

    CONST UCHAR ReasonDetect0[] = { "Unbacked DeferredRoutine" };
    CONST UCHAR ReasonDetect1[] = { "High-Entropy DeferredContext" };
    CONST UCHAR ReasonDetectError[] = { "UNKNOWN" };

    CONST UCHAR RetOpcode = 0xc3UI8;

    ULONG32 CurrCoreNum = (ULONG32)__readgsdword(g_pTheiaCtx->TheiaMetaDataBlock.KPCR_Prcb_OFFSET + g_pTheiaCtx->TheiaMetaDataBlock.KPRCB_Number_OFFSET);
    BOOLEAN CurrIF = FALSE;

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
                    SAFE_DISABLE(CurrIF,
                    {
                      HrdGetPteInputVa(pCurrKDPC->DeferredRoutine)->Dirty1 = 1;

                      __writecr3(__readcr3());

                      *(PUCHAR)(pCurrKDPC->DeferredRoutine) = 0xc3UI8;

                      HrdGetPteInputVa(pCurrKDPC->DeferredRoutine)->Dirty1 = 0;

                      __writecr3(__readcr3());
                    });
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
* @param InputCtx: Context passed from StubCallTrmpln
*
* Description: Hook KiDeliverApc for controling _KAPCs in QUEUE-APCs current Thread-Obj.
--*/
volatile VOID VsrKiDeliverApc(IN PINPUTCONTEXT_ICT pInputCtx)
{
    CheckStatusTheiaCtx();

    UCHAR TypeDetect = 2UI8;

    CONST UCHAR ReasonDetect0[] = { "Unbacked KernelRoutine" };
    CONST UCHAR ReasonDetect1[] = { "Unbacked NormalRoutine" };
    CONST UCHAR ReasonDetectError[] = { "UNKNOWN" };

    PVOID pCurrObjThread = (PVOID)__readgsqword(0x188UI32);
    CONST UCHAR RetOpcode = 0xc3UI8;

    INDPN_RW_V_MEMORY_DATA DataIndpnRWVMem = { 0 };
    DataIndpnRWVMem.FlagsExecute = MEM_INDPN_RW_WRITE_OP_BIT;
    DataIndpnRWVMem.pIoBuffer = &RetOpcode;
    DataIndpnRWVMem.LengthRW = 1UI64;

    PKAPC_STATE pCurrKAPCState = (PKAPC_STATE)((PUCHAR)pCurrObjThread + g_pTheiaCtx->TheiaMetaDataBlock.KTHREAD_ApcState_OFFSET); ///< Pointer to Head-QueueKernelApcs.
    PKAPC_TRUE pCurrKAPC = ((PLIST_ENTRY)&(pCurrKAPCState->ApcListHead[KernelMode]))->Flink;

    if (pCurrKAPC == pCurrKAPCState) { goto Exit; }

    pCurrKAPC = CONTAINING_RECORD(pCurrKAPC, KAPC_TRUE, ApcListEntry);
 
    for(; ;)
    {       
        if (*(PUCHAR)pCurrKAPC->KernelRoutine == 0xc3UI8 || pCurrKAPC->SystemArgument1 == IS_SAFE_APC_SIGNATURE) { goto SkipCheckKAPC; }

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
* @param InputCtx: Context passed from StubCallTrmpln
*
* Description: Hook ExQueueWorkItem for controling insertions _WORK_QUEUE_ITEMs in WORK-QUEUEs.
--*/
volatile VOID VsrExQueueWorkItem(IN OUT PINPUTCONTEXT_ICT pInputCtx)
{
    CheckStatusTheiaCtx();

    // SUBROUTINE_0_DATA ================================================++
    //                                                                   //
                                                                         //
    UCHAR TypeDetect = 2UI8;                                             //
                                                                         //
    CONST UCHAR ReasonDetect0[] = { "Unbacked WorkerRoutine" };          //
    CONST UCHAR ReasonDetect1[] = { "High-Entropy Parameter" };          //
    CONST UCHAR ReasonDetectError[] = { "UNKNOWN" };                     //
                                                                         //
    PWORK_QUEUE_ITEM pCurrWorkItem = (PWORK_QUEUE_ITEM)(pInputCtx->rcx); //
                                                                         //
    //                                                                   //
    // ==================================================================++

    BOOLEAN CurrIF = HrdGetIF();
    UCHAR CurrIrql = (UCHAR)__readcr8();

    PCONTEXT pInternalCtx = NULL;

    SAFE_ENABLE(CurrIF, CurrIrql, DISPATCH_LEVEL, pInternalCtx = (PCONTEXT)g_pTheiaCtx->pMmAllocateIndependentPagesEx(PAGE_SIZE, -1I32, 0I64, 0I32););

    if (!pInternalCtx) { DbgLog("[TheiaPg <->] VsrExQueueWorkItem: Bad alloc page for InternalCtx\n"); return; }

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

    PULONG64 pRetAddrsTrace = NULL;

    SAFE_ENABLE(CurrIF, CurrIrql, DISPATCH_LEVEL, pRetAddrsTrace = (PULONG64)g_pTheiaCtx->pMmAllocateIndependentPagesEx(PAGE_SIZE, -1I32, 0I64, 0I32););

    if (!pRetAddrsTrace) { DbgLog("[TheiaPg <->] VsrExQueueWorkItem: Bad alloc page for RetAddrsTrace\n"); return; }

    PUCHAR pCurrentObjThread = (PUCHAR)__readgsqword(0x188UI32);
    PUSHORT pCurrentTID = (PUSHORT)(pCurrentObjThread + (g_pTheiaCtx->TheiaMetaDataBlock.ETHREAD_Cid_OFFSET + g_pTheiaCtx->TheiaMetaDataBlock.CLIENT_ID_UniqueThread_OFFSET));

    PVOID pImageBase = NULL;
    PVOID pRuntimeFunction = NULL;
    PVOID pHandlerData = NULL;
    ULONG64 EstablisherFrame = 0UI64;

    CONST LONG64 Timeout = (-10000UI64 * 31536000000UI64); ///< 1 year.
    LONG32 SaveRel32Offset = 0I32;
    CONST UCHAR RetOpcode = 0xc3UI8;

    PVOID pSearchSdbpCheckDllRWX = NULL;
    PVOID pPgDpcRoutine = NULL;
    PVOID pPgApcRoutine = NULL;

    INDPN_RW_V_MEMORY_DATA DataIndpnRWVMem = { 0 };
    DataIndpnRWVMem.FlagsExecute = MEM_INDPN_RW_WRITE_OP_BIT;
    DataIndpnRWVMem.pIoBuffer = &RetOpcode;
    DataIndpnRWVMem.LengthRW = 1UI64;

    BOOLEAN IsSleep = FALSE;
    PVOID pPgCtx = NULL;

    // SUBROUTINE_0 ==============================================================================================================================================================++
    //                                                                                                                                                                            //
                                                                                                                                                                                  //
    if (*(PUCHAR)pCurrWorkItem->WorkerRoutine == 0xc3UI8) { goto SkipCheckWorkItem; }                                                                                             //
                                                                                                                                                                                  //
    if (!(_IsSafeAddress(pCurrWorkItem->WorkerRoutine)))                                                                                                                          //
    {                                                                                                                                                                             //
        TypeDetect = 0UI8;                                                                                                                                                        //
                                                                                                                                                                                  //
        goto DetectPgWorkItem;                                                                                                                                                    //
    }                                                                                                                                                                             //
                                                                                                                                                                                  //
    if ((g_pTheiaCtx->pMmIsAddressValid(pCurrWorkItem->Parameter) && (((ULONG64)pCurrWorkItem->Parameter >> 47) == 0x1ffffUI64)))                                                 //
    {                                                                                                                                                                             //
        if ((*(PULONG64)pCurrWorkItem->Parameter == 0x085131481131482eUI64) || ((*(PULONG64)(HrdGetPteInputVa(pCurrWorkItem->Parameter)) & 0x8000000000000802UI64) == 0x802UI64)) //
        {                                                                                                                                                                         //
            TypeDetect = 1UI8;                                                                                                                                                    //
        }                                                                                                                                                                         //
    }                                                                                                                                                                             //
    else                                                                                                                                                                          //
    {                                                                                                                                                                             //
        for (UCHAR i = 0UI8, j = 0UI8; ; ++i)                                                                                                                                     //
        {                                                                                                                                                                         //
            if (((ULONG64)(pCurrWorkItem->Parameter) >> i) & 0x01UI64) { ++j; }                                                                                                   //
                                                                                                                                                                                  //
            if (i == 63)                                                                                                                                                          //
            {                                                                                                                                                                     //
                if (j > 4)                                                                                                                                                        //
                {                                                                                                                                                                 //
                    TypeDetect = 1UI8;                                                                                                                                            //
                }                                                                                                                                                                 //
                                                                                                                                                                                  //
                break;                                                                                                                                                            //
            }                                                                                                                                                                     //
        }                                                                                                                                                                         //
    }                                                                                                                                                                             //
                                                                                                                                                                                  //
    DetectPgWorkItem:                                                                                                                                                             //
                                                                                                                                                                                  //
    if (TypeDetect < 2)                                                                                                                                                           //
    {                                                                                                                                                                             //
        DbgLog("[TheiaPg <+>] VsrExQueueWorkItem: Detect possibly PG-WORKITEM | TCB: 0x%I64X\n");                                                                                 //
        DbgLog("===============================================================\n");                                                                                              //
        DbgLog("Reason:           %s\n", ((!TypeDetect) ?                                                                                                                         //
            ReasonDetect0 : (TypeDetect == 1) ?                                                                                                                                   //
            ReasonDetect1 : ReasonDetectError));                                                                                                                                  //
        DbgLog("_WORK_QUEUE_ITEM: 0x%I64X\n", pInputCtx->rcx);                                                                                                                    //
        DbgLog("WorkerRoutine:    0x%I64X\n", ((PWORK_QUEUE_ITEM)pInputCtx->rcx)->WorkerRoutine);                                                                                 //
        DbgLog("Parameter:        0x%I64X\n", ((PWORK_QUEUE_ITEM)pInputCtx->rcx)->Parameter);                                                                                     //
        DbgLog("===============================================================\n\n");                                                                                            //
                                                                                                                                                                                  //
        DataIndpnRWVMem.pVa = pCurrWorkItem->WorkerRoutine;                                                                                                                       //
                                                                                                                                                                                  //
        HrdIndpnRWVMemory(&DataIndpnRWVMem);                                                                                                                                      //
                                                                                                                                                                                  //
    }                                                                                                                                                                             //
                                                                                                                                                                                  //
    SkipCheckWorkItem:                                                                                                                                                            //
                                                                                                                                                                                  //
    //                                                                                                                                                                            //
    // ===========================================================================================================================================================================++

    for (ULONG32 i = 0; i < 16; ++i)
    {
        pRuntimeFunction = g_pTheiaCtx->pRtlLookupFunctionEntry(pInternalCtx->Rip, &pImageBase, NULL);

        if (!pRuntimeFunction) ///< If the current routine leaf.
        {
            pInternalCtx->Rip = *(PVOID*)pInternalCtx->Rsp;

            pInternalCtx->Rsp += 8I64;
        }

        g_pTheiaCtx->pRtlVirtualUnwind(0UI32, pImageBase, pInternalCtx->Rip, pRuntimeFunction, pInternalCtx, &pHandlerData, &EstablisherFrame, NULL);

        if (((CurrIrql <= DISPATCH_LEVEL) ? g_pTheiaCtx->pMmIsAddressValid(pInternalCtx->Rip) : g_pTheiaCtx->pMmIsNonPagedSystemAddressValid(pInternalCtx->Rip)))
        {
           if (((pInternalCtx->Rip >> 47) != 0x1ffffUI64) || ((*(PULONG64)(HrdGetPteInputVa((PVOID)pInternalCtx->Rip)) & 0x8000000000000000UI64) != 0x00UI64)) { goto Exit; }

           if ((((PUCHAR)pInternalCtx->Rip)[0] == 0xfaUI8 &&
                ((PUCHAR)pInternalCtx->Rip)[1] == 0x54UI8 &&
                ((PUCHAR)pInternalCtx->Rip)[2] == 0x48UI8 &&
                ((PUCHAR)pInternalCtx->Rip)[3] == 0x83UI8 &&
                ((PUCHAR)pInternalCtx->Rip)[4] == 0x04UI8)
                                     ||
               (((PUCHAR)pInternalCtx->Rip)[0] == 0x48UI8 &&
                ((PUCHAR)pInternalCtx->Rip)[1] == 0x83UI8 &&
                ((PUCHAR)pInternalCtx->Rip)[2] == 0xc4UI8 &&
                ((PUCHAR)pInternalCtx->Rip)[3] == 0x08UI8)
                                     ||
               (((PUCHAR)pInternalCtx->Rip)[0] == 0xc3UI8 &&
                ((PUCHAR)pInternalCtx->Rip)[1] == 0x00UI8 &&
                ((PUCHAR)pInternalCtx->Rip)[2] == 0x00UI8 &&
                ((PUCHAR)pInternalCtx->Rip)[3] == 0x00UI8 &&
                ((PUCHAR)pInternalCtx->Rip)[4] == 0x00UI8)) { goto Exit; }

           for (UCHAR i = 0UI8; i < 32; ++i)
           {
               if((*((PULONG64)(pInternalCtx->Rip + i)) == HANDLER_VSR_EXALLOCATEPOOL2_IMMUNITY_SIG) || (*((PULONG64)(pInternalCtx->Rip + i)) == 0x9090909090909090UI64)) { goto Exit; }
           }
        }
        else { goto Exit; }

        pRetAddrsTrace[i] = pInternalCtx->Rip;

        if (!(_IsSafeAddress(pInternalCtx->Rip)))
        {
            DbgLog("[TheiaPg <+>] VsrExQueueWorkItem: Detect non-backed stack calls | TCB: 0x%I64X TID: 0x%hX | IRQL: 0x%02X\n", pCurrentObjThread, *pCurrentTID, CurrIrql);

            OtherDetects:

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
            DbgLog("=================================================================\n");

            DbgText
            ( // {

                for (ULONG32 j = 0UI32; ; ++j)
                {
                    if (j == i) { DbgLog("%I32d frame: 0x%I64X <- unbacked\n\n", j, pRetAddrsTrace[j]); break; }

                    DbgLog("%I32d frame: 0x%I64X\n", j, pRetAddrsTrace[j]);
                }

            ) // }

                DbgLog("[TheiaPg <+>] VsrExQueueWorkItem: Handling exit phase...\n\n");

            DbgLog("[TheiaPg <+>] VsrExQueueWorkItem: Detect possibly PgCaller | pPgCtx: 0x%I64X\n\n", (pPgCtx = SearchPgCtxInCtx(pInternalCtx)));

            if (pPgCtx)
            {
                if (g_pTheiaCtx->pMmIsAddressValid(pPgDpcRoutine = *(PVOID*)((PUCHAR)pPgCtx + 0x7f8))) ///< LocalPgCtxBase + 0x7f8: PgDpcRoutine
                {
                    if (!((HrdGetPteInputVa(pPgDpcRoutine))->NoExecute))
                    {
                        DbgLog("[TheiaPg <+>] VsrExQueueWorkItem: Detect PgDpcRoutine in PgCtx | PgDpcRoutine: 0x%I64X\n\n", pPgDpcRoutine);

                        DataIndpnRWVMem.pVa = pPgDpcRoutine;

                        HrdIndpnRWVMemory(&DataIndpnRWVMem);
                    }
                }

                if (g_pTheiaCtx->pMmIsAddressValid(pPgApcRoutine = *(PVOID*)((PUCHAR)pPgCtx + 0xa30))) ///< LocalPgCtxBase + 0xA30: PgApcRoutine (basically KiDispatchCallout)
                {
                    if (!((HrdGetPteInputVa(pPgApcRoutine))->NoExecute))
                    {
                        DbgLog("[TheiaPg <+>] VsrExQueueWorkItem: Detect PgApcRoutine in PgCtx | PgApcRoutine: 0x%I64X\n\n", pPgApcRoutine);

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

                        DbgLog("[TheiaPg <+>] VsrExQueueWorkItem: SdbpCheckDllRWX is found: 0x%I64X\n\n", pSearchSdbpCheckDllRWX);

                        break;
                    }
                }

            }

            if (!IsSleep)
            {
                if (CurrIrql < DISPATCH_LEVEL)
                {
                    DbgLog("[TheiaPg <+>] VsrExQueueWorkItem: Enter to dead sleep... | IRQL: 0x%02X\n\n", CurrIrql);

                    IsSleep = TRUE;

                    goto Exit;
                }
                else
                {
                    DbgLog("[TheiaPg <+>] VsrExQueueWorkItem: Unsuccessful enter to dead sleep... | IRQL: 0x%02X\n\n", CurrIrql);

                    goto Exit;
                }
            }
            else { goto Exit; }
        }

        if (pPgCtx = SearchPgCtxInCtx(pInternalCtx))
        {
            DbgLog("[TheiaPg <+>] VsrExQueueWorkItem: Detect PgCtx in CpuCtx | TCB: 0x%I64X TID: 0x%hX | IRQL: 0x%02X\n", pCurrentObjThread, *pCurrentTID, CurrIrql);

            goto OtherDetects;
        }
    }

    Exit:

    SAFE_ENABLE(CurrIF, CurrIrql, DISPATCH_LEVEL, g_pTheiaCtx->pMmFreeIndependentPages(pInternalCtx, PAGE_SIZE, 0I64););

    SAFE_ENABLE(CurrIF, CurrIrql, DISPATCH_LEVEL, g_pTheiaCtx->pMmFreeIndependentPages(pRetAddrsTrace, PAGE_SIZE, 0I64););

    if (IsSleep) { SAFE_ENABLE(CurrIF, CurrIrql, CurrIrql, g_pTheiaCtx->pKeDelayExecutionThread(KernelMode, FALSE, &Timeout);); }

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
* Description: This hook is required as a last resort if the PG check routine continues to overcome countermeasures.
* PG check routine primarily uses ExAllocatePool2/MmAllocateIndependentPages for pages allocation in Windows 11 25h2.
--*/
volatile VOID VsrExAllocatePool2(IN OUT PINPUTCONTEXT_ICT pInputCtx)
{
    CheckStatusTheiaCtx();

    BOOLEAN CurrIF = HrdGetIF();
    UCHAR CurrIrql = (UCHAR)__readcr8();

    PCONTEXT pInternalCtx = NULL;

    SAFE_ENABLE(CurrIF, CurrIrql, DISPATCH_LEVEL, pInternalCtx = (PCONTEXT)g_pTheiaCtx->pMmAllocateIndependentPagesEx(PAGE_SIZE, -1I32, 0I64, 0I32););

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

    PULONG64 pRetAddrsTrace = NULL;

    SAFE_ENABLE(CurrIF, CurrIrql, DISPATCH_LEVEL, pRetAddrsTrace = (PULONG64)g_pTheiaCtx->pMmAllocateIndependentPagesEx(PAGE_SIZE, -1I32, 0I64, 0I32););

    if (!pRetAddrsTrace) { DbgLog("[TheiaPg <->] VsrExAllocatePool2: Bad alloc page for RetAddrsTrace\n"); return; }

    PUCHAR pCurrentObjThread = (PUCHAR)__readgsqword(0x188UI32);
    PUSHORT pCurrentTID = (PUSHORT)(pCurrentObjThread + (g_pTheiaCtx->TheiaMetaDataBlock.ETHREAD_Cid_OFFSET + g_pTheiaCtx->TheiaMetaDataBlock.CLIENT_ID_UniqueThread_OFFSET));

    PVOID pImageBase = NULL;
    PVOID pRuntimeFunction = NULL;
    PVOID pHandlerData = NULL;
    ULONG64 EstablisherFrame = 0UI64;

    CONST LONG64 Timeout = (-10000UI64 * 31536000000UI64); ///< 1 year.
    LONG32 SaveRel32Offset = 0I32;
    CONST UCHAR RetOpcode = 0xc3UI8;

    PVOID pSearchSdbpCheckDllRWX = NULL;
    PVOID pPgDpcRoutine = NULL;
    PVOID pPgApcRoutine = NULL;

    INDPN_RW_V_MEMORY_DATA DataIndpnRWVMem = { 0 };
    DataIndpnRWVMem.FlagsExecute = MEM_INDPN_RW_WRITE_OP_BIT;
    DataIndpnRWVMem.pIoBuffer    = &RetOpcode;
    DataIndpnRWVMem.LengthRW     = 1UI64;

    BOOLEAN IsSleep = FALSE;
    PVOID pPgCtx = NULL;

    if (pInputCtx->rax)
    {
        SAFE_ENABLE(CurrIF, CurrIrql, CurrIrql, { *(PUCHAR)pInputCtx->rax = 0x00UI8; }); ///< Fix DemandZero-PTE (Only PT-PTEs level)

        if ((*(PULONG64)(HrdGetPteInputVa((PVOID)pInputCtx->rax)) & 0x8000000000000801UI64) == 0x801UI64) ///< Checking RWX PTE-Attributes.
        {
            DbgLog("[TheiaPg <+>] VsrExAllocatePool2: Detect attempt allocate RWX-Page\n\n");

            if (CurrIrql < DISPATCH_LEVEL) { IsSleep = TRUE; }
            else { ExFreePool(pInputCtx->rax); pInputCtx->rax = 0I64; }
        }
    }

    for (ULONG32 i = 0; i < 16; ++i)
    {
        pRuntimeFunction = g_pTheiaCtx->pRtlLookupFunctionEntry(pInternalCtx->Rip, &pImageBase, NULL);

        if (!pRuntimeFunction) ///< If the current routine leaf.
        {
            pInternalCtx->Rip = *(PVOID*)pInternalCtx->Rsp;

            pInternalCtx->Rsp += 8I64;
        }

        g_pTheiaCtx->pRtlVirtualUnwind(0UI32, pImageBase, pInternalCtx->Rip, pRuntimeFunction, pInternalCtx, &pHandlerData, &EstablisherFrame, NULL);

        if (((CurrIrql <= DISPATCH_LEVEL) ? g_pTheiaCtx->pMmIsAddressValid(pInternalCtx->Rip) : g_pTheiaCtx->pMmIsNonPagedSystemAddressValid(pInternalCtx->Rip)))
        {
           if (((pInternalCtx->Rip >> 47) != 0x1ffffUI64) || ((*(PULONG64)(HrdGetPteInputVa((PVOID)pInternalCtx->Rip)) & 0x8000000000000000UI64) != 0x00UI64)) { goto Exit; }

           if ((((PUCHAR)pInternalCtx->Rip)[0] == 0xfaUI8 &&
                ((PUCHAR)pInternalCtx->Rip)[1] == 0x54UI8 &&
                ((PUCHAR)pInternalCtx->Rip)[2] == 0x48UI8 &&
                ((PUCHAR)pInternalCtx->Rip)[3] == 0x83UI8 &&
                ((PUCHAR)pInternalCtx->Rip)[4] == 0x04UI8)
                                     ||
               (((PUCHAR)pInternalCtx->Rip)[0] == 0x48UI8 &&
                ((PUCHAR)pInternalCtx->Rip)[1] == 0x83UI8 &&
                ((PUCHAR)pInternalCtx->Rip)[2] == 0xc4UI8 &&
                ((PUCHAR)pInternalCtx->Rip)[3] == 0x08UI8)
                                     ||
               (((PUCHAR)pInternalCtx->Rip)[0] == 0xc3UI8 &&
                ((PUCHAR)pInternalCtx->Rip)[1] == 0x00UI8 &&
                ((PUCHAR)pInternalCtx->Rip)[2] == 0x00UI8 &&
                ((PUCHAR)pInternalCtx->Rip)[3] == 0x00UI8 &&
                ((PUCHAR)pInternalCtx->Rip)[4] == 0x00UI8)) { goto Exit; }

           for (UCHAR i = 0UI8; i < 32; ++i)
           {
               if((*((PULONG64)(pInternalCtx->Rip + i)) == HANDLER_VSR_EXALLOCATEPOOL2_IMMUNITY_SIG) || (*((PULONG64)(pInternalCtx->Rip + i)) == 0x9090909090909090UI64)) { goto Exit; }
           }
        }
        else { goto Exit; }

        pRetAddrsTrace[i] = pInternalCtx->Rip;

        if (!(_IsSafeAddress(pInternalCtx->Rip)))
        {
            DbgLog("[TheiaPg <+>] VsrExAllocatePool2: Detect non-backed stack calls | TCB: 0x%I64X TID: 0x%hX | IRQL: 0x%02X\n", pCurrentObjThread, *pCurrentTID, CurrIrql);

            OtherDetects:

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
            DbgLog("=================================================================\n");

            DbgText
            ( // {

                for (ULONG32 j = 0UI32; ; ++j)
                {
                    if (j == i) { DbgLog("%I32d frame: 0x%I64X <- unbacked\n\n", j, pRetAddrsTrace[j]); break; }

                    DbgLog("%I32d frame: 0x%I64X\n", j, pRetAddrsTrace[j]);
                }

            ) // }

            DbgLog("[TheiaPg <+>] VsrExAllocatePool2: Handling exit phase...\n\n");

            DbgLog("[TheiaPg <+>] VsrExAllocatePool2: Detect possibly PgCaller | pPgCtx: 0x%I64X\n\n", (pPgCtx = SearchPgCtxInCtx(pInternalCtx)));

            if (pPgCtx)
            {
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

            }

            if (!IsSleep)
            {
                if (CurrIrql < DISPATCH_LEVEL)
                {
                    DbgLog("[TheiaPg <+>] VsrExAllocatePool2: Enter to dead sleep... | IRQL: 0x%02X\n\n", CurrIrql);

                    IsSleep = TRUE;

                    goto Exit;
                }
                else
                {
                    DbgLog("[TheiaPg <+>] VsrExAllocatePool2: Unsuccessful enter to dead sleep... | IRQL: 0x%02X\n\n", CurrIrql);

                    if (pPgCtx) { *(PULONG32)((PUCHAR)pPgCtx + 0xA60) = -1UI32; } ///< Counter of unsuccessful memory allocation attempts in PgCtx.

                    if (!i) ///< If the detection occurred on a non-caller stack frame, returning NULL would be dangerous.
                    {
                        if (pInputCtx->rax)
                        {
                            SAFE_ENABLE(CurrIF, CurrIrql, CurrIrql, { *(PUCHAR)pInputCtx->rax = 0x00UI8; });

                            ExFreePool(pInputCtx->rax);

                            pInputCtx->rax = 0I64;
                        }
                    }

                    goto Exit;
                }
            }
            else { goto Exit; }
        }

        if (pPgCtx = SearchPgCtxInCtx(pInternalCtx))
        {
            DbgLog("[TheiaPg <+>] VsrExAllocatePool2: Detect PgCtx in CpuCtx | TCB: 0x%I64X TID: 0x%hX | IRQL: 0x%02X\n", pCurrentObjThread, *pCurrentTID, CurrIrql);

            goto OtherDetects;
        }
    }

    Exit:

    SAFE_ENABLE(CurrIF, CurrIrql, DISPATCH_LEVEL, g_pTheiaCtx->pMmFreeIndependentPages(pInternalCtx, PAGE_SIZE, 0I64););

    SAFE_ENABLE(CurrIF, CurrIrql, DISPATCH_LEVEL, g_pTheiaCtx->pMmFreeIndependentPages(pRetAddrsTrace, PAGE_SIZE, 0I64););

    if (IsSleep) { SAFE_ENABLE(CurrIF, CurrIrql, CurrIrql, g_pTheiaCtx->pKeDelayExecutionThread(KernelMode, FALSE, &Timeout);); }

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
* Description: This function is similar to VsrExAllocatePool2, but is primarily intended to be called from the context of KiCustomAccessRoutineX.
*/
volatile VOID VsrKiCustomRecurseRoutineX(IN OUT PINPUTCONTEXT_ICT pInputCtx)
{
    CheckStatusTheiaCtx();

    UCHAR CurrIrql = (UCHAR)__readcr8();
    BOOLEAN CurrIF = HrdGetIF();
    ULONG32 CurrCoreNum = (ULONG32)__readgsdword(g_pTheiaCtx->TheiaMetaDataBlock.KPCR_Prcb_OFFSET + g_pTheiaCtx->TheiaMetaDataBlock.KPRCB_Number_OFFSET);

    PCONTEXT pInternalCtx = NULL;

    SAFE_ENABLE(CurrIF, CurrIrql, DISPATCH_LEVEL, pInternalCtx = (PCONTEXT)g_pTheiaCtx->pMmAllocateIndependentPagesEx(PAGE_SIZE, -1I32, 0I64, 0I32););

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

    PUCHAR pCurrentObjThread = (PUCHAR)__readgsqword(0x188UI32);

    PVOID pImageBase = NULL;
    PVOID pRuntimeFunction = NULL;
    PVOID pHandlerData = NULL;
    ULONG64 EstablisherFrame = 0UI64;

    CONST LONG64 Timeout = (-10000UI64 * 31536000000UI64); ///< 1 year.
    LONG32 SaveRel32Offset = 0I32;
    CONST UCHAR RetOpcode = 0xc3UI8;

    PVOID pSearchSdbpCheckDllRWX = NULL;
    PVOID pPgDpcRoutine = NULL;
    PVOID pPgApcRoutine = NULL;

    INDPN_RW_V_MEMORY_DATA DataIndpnRWVMem = { 0 };
    DataIndpnRWVMem.FlagsExecute = MEM_INDPN_RW_WRITE_OP_BIT;
    DataIndpnRWVMem.pIoBuffer = &RetOpcode;
    DataIndpnRWVMem.LengthRW = 1UI64;

    PVOID pRetAddrCallerPgAccessRoutine = NULL;
    PKDPC pPgKDPC = NULL;

    BOOLEAN IsSleep = FALSE;
    PVOID pPgCtx = NULL;

    //
    // 3 Iteration-unwind for "default" chain call PgRoutines from DISPATCH_LEVEL-ISR context.  
    // 
    //            2-iteration-unwind         1-iteration-unwind     0-iteration-unwind
    // example: KiProcessExpiredTimerList -> ExpTimerDpcRoutine -> KiCustomAccessRoutineX -> VsrKiCustomRecurseRoutineX
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
    if (CurrIrql < DISPATCH_LEVEL)
    {
        DbgLog("[TheiaPg <+>] VsrKiCustomRecurseRoutineX: Enter to dead sleep... | IRQL: 0x%02X\n\n", CurrIrql);

        IsSleep = TRUE;
    }
    else { DbgLog("[TheiaPg <+>] VsrKiCustomRecurseRoutineX: Rebound execution context... | IRQL: 0x%02X\n\n", CurrIrql); }
     

    SAFE_ENABLE(CurrIF, CurrIrql, DISPATCH_LEVEL, g_pTheiaCtx->pMmFreeIndependentPages(pInternalCtx, PAGE_SIZE, 0I64););

    if (IsSleep) { SAFE_ENABLE(CurrIF, CurrIrql, CurrIrql, g_pTheiaCtx->pKeDelayExecutionThread(KernelMode, FALSE, &Timeout);); }

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
