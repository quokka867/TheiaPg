#include "LinkHeader.h"

/*++
* Routine: FltrKiExecuteAllDpcs
*
* MaxIRQL: DISPATCH_LEVEL
*
* Public/Private: Public
*
* @param pInputCtx: Context passed from StubCallTrmpln
*
* Description: Hook KiExecuteAllDpcs for controling _KDPCs in QUEUE-DPCs current CpuCore.
--*/
volatile VOID FltrKiExecuteAllDpcs(IN PINPUTCONTEXT_ICH pInputCtx)
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
            DbgLog("[TheiaPg <+>] FltrKiExecuteAllDpcs: Detect possibly PG-KDPC | CpuCore: 0x%I32X\n", CurrCoreNum);
            DbgLog("=============================================================\n");
            DbgLog("Reason:          %s\n", ((!TypeDetect) ?
                         ReasonDetect0 : (TypeDetect == 1) ?
                         ReasonDetect1 : ReasonDetectError));
            DbgLog("_KDPC:           0x%I64X\n", pCurrKDPC);
            DbgLog("DeferredRoutine: 0x%I64X\n", pCurrKDPC->DeferredRoutine);
            DbgLog("DeferredContext: 0x%I64X\n", pCurrKDPC->DeferredContext);
            DbgLog("SystemArgument1: 0x%I64X\n", pCurrKDPC->SystemArgument1);
            DbgLog("SystemArgument2: 0x%I64X\n", pCurrKDPC->SystemArgument2);
            DbgLog("CpuCore:         0x%I32X\n", CurrCoreNum);
            DbgLog("=============================================================\n\n");

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
* Routine: FltrKiRetireDpcList
*
* MaxIRQL: DISPATCH_LEVEL
*
* Public/Private: Public
*
* @param pInputCtx: Context passed from StubCallTrmpln
*
* Description: Hook KiRetireDpcList for controling _KDPCs in TABLES-KTIMERs current CpuCore.
--*/
volatile VOID FltrKiRetireDpcList(IN PINPUTCONTEXT_ICH pInputCtx)
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
                DbgLog("[TheiaPg <+>] FltrKiRetireDpcList: Detect possibly PG-KTIMER | CpuCore: 0x%I32X\n", CurrCoreNum);
                DbgLog("==============================================================\n");
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
                DbgLog("==============================================================\n\n");

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
* Routine: FltrKiDeliverApc
*
* MaxIRQL: DISPATCH_LEVEL
*
* Public/Private: Public
*
* @param InputCtx: Context passed from StubCallTrmpln
*
* Description: Hook KiDeliverApc for controling _KAPCs in QUEUE-APCs current Thread-Obj.
--*/
volatile VOID FltrKiDeliverApc(IN PINPUTCONTEXT_ICH pInputCtx)
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
            DbgLog("[TheiaPg <+>] FltrKiDeliverApc: Detect possibly PG-KAPC | TCB: 0x%I64X\n");
            DbgLog("=========================================================\n");
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
            DbgLog("=========================================================\n\n");

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
* Routine: FltrExQueueWorkItem
*
* MaxIRQL: DISPATCH_LEVEL
*
* Public/Private: Public
*
* @param pInputCtx: Context passed from StubCallTrmpln
*
* Description: Hook ExQueueWorkItem for controling insertions _WORK_QUEUE_ITEMs in WORK-QUEUEs and caller.
--*/
volatile VOID FltrExQueueWorkItem(IN OUT PINPUTCONTEXT_ICH pInputCtx)
{
    CheckStatusTheiaCtx();

    BOOLEAN CurrIF = HrdGetIF();
    UCHAR CurrIrql = (UCHAR)__readcr8();
                                                                                                                                           
    UCHAR TypeDetect = 2UI8;                                                                                                                  
    CONST UCHAR ReasonDetect0[] = { "Unbacked WorkerRoutine" };          
    CONST UCHAR ReasonDetect1[] = { "High-Entropy Parameter" };          
    CONST UCHAR ReasonDetectError[] = { "UNKNOWN" };                                                                                          
    PWORK_QUEUE_ITEM pCurrWorkItem = (PWORK_QUEUE_ITEM)(pInputCtx->rcx); 

    PCONTEXT pInternalCtx = NULL;

    SAFE_ENABLE(CurrIF, CurrIrql, DISPATCH_LEVEL, pInternalCtx = (PCONTEXT)g_pTheiaCtx->pMmAllocateIndependentPagesEx(PAGE_SIZE, -1I32, 0I64, 0I32););

    if (!pInternalCtx) { DbgLog("[TheiaPg <->] FltrExQueueWorkItem: Bad alloc page for InternalCtx\n"); return; }

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

    CONST LONG64 Timeout = (-10000UI64 * 31536000000UI64); ///< 1 year.
    CONST UCHAR RetOpcode = 0xc3UI8;
    LONG32 SaveRel32Offset = 0I32;

    PVOID pSearchSdbpCheckDllRWX = NULL;
    PVOID pPgDpcRoutine = NULL;
    PVOID pPgApcRoutine = NULL;

    INDPN_RW_V_MEMORY_DATA DataIndpnRWVMem = { 0 };
    DataIndpnRWVMem.FlagsExecute = MEM_INDPN_RW_WRITE_OP_BIT;
    DataIndpnRWVMem.pIoBuffer = &RetOpcode;
    DataIndpnRWVMem.LengthRW = 1UI64;

    BOOLEAN IsSleep = FALSE;

    PVOID pPgCtx = NULL;

    if (*(PUCHAR)pCurrWorkItem->WorkerRoutine == 0xc3UI8) { goto SkipCheckWorkItem; }                                                                                             
                                                                                                                                                                                  
    if (!(_IsSafeAddress(pCurrWorkItem->WorkerRoutine)))                                                                                                                          
    {                                                                                                                                                                             
        TypeDetect = 0UI8;                                                                                                                                                        
                                                                                                                                                                                  
        goto DetectPgWorkItem;                                                                                                                                                    
    }                                                                                                                                                                             
                                                                                                                                                                                  
    if ((g_pTheiaCtx->pMmIsAddressValid(pCurrWorkItem->Parameter) && (((ULONG64)pCurrWorkItem->Parameter >> 47) == 0x1ffffUI64)))                                                 
    {                                                                                                                                                                             
        if ((*(PULONG64)pCurrWorkItem->Parameter == 0x085131481131482eUI64) || ((*(PULONG64)(HrdGetPteInputVa(pCurrWorkItem->Parameter)) & 0x8000000000000802UI64) == 0x802UI64)) 
        {                                                                                                                                                                         
            TypeDetect = 1UI8;                                                                                                                                                    
        }                                                                                                                                                                         
    }                                                                                                                                                                             
    else                                                                                                                                                                          
    {                                                                                                                                                                             
        for (UCHAR i = 0UI8, j = 0UI8; ; ++i)                                                                                                                                     
        {                                                                                                                                                                         
            if (((ULONG64)(pCurrWorkItem->Parameter) >> i) & 0x01UI64) { ++j; }                                                                                                   
                                                                                                                                                                                  
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
                                                                                                                                                                                  
    DetectPgWorkItem:                                                                                                                                                             
                                                                                                                                                                                  
    if (TypeDetect < 2)                                                                                                                                                           
    {                                                                                                                                                                             
        DbgLog("[TheiaPg <+>] FltrExQueueWorkItem: Detect possibly PG-WorkItem | IRQL: 0x%02X\n", CurrIrql);                                                                                 
        DbgLog("================================================================\n");                                                                                              
        DbgLog("Reason:           %s\n", ((!TypeDetect) ?                                                                                                                         
                      ReasonDetect0 : (TypeDetect == 1) ?                                                                                                                                   
                      ReasonDetect1 : ReasonDetectError));                                                                                                                                  
        DbgLog("_WORK_QUEUE_ITEM: 0x%I64X\n", pInputCtx->rcx);                                                                                                                    
        DbgLog("WorkerRoutine:    0x%I64X\n", ((PWORK_QUEUE_ITEM)pInputCtx->rcx)->WorkerRoutine);                                                                                 
        DbgLog("Parameter:        0x%I64X\n", ((PWORK_QUEUE_ITEM)pInputCtx->rcx)->Parameter);                                                                                     
        DbgLog("================================================================\n\n");                                                                                            
                                                                                                                                                                                  
        DataIndpnRWVMem.pVa = pCurrWorkItem->WorkerRoutine;                                                                                                                       
                                                                                                                                                                                  
        HrdIndpnRWVMemory(&DataIndpnRWVMem);                                                                                                                                                                                                                                                                                                                    
    }                                                                                                                                                                             
                                                                                                                                                                                  
    SkipCheckWorkItem:                                                                                                                                                            

    pRuntimeFunction = g_pTheiaCtx->pRtlLookupFunctionEntry(pInternalCtx->Rip, &pImageBase, NULL);

    g_pTheiaCtx->pRtlVirtualUnwind(0UI32, pImageBase, pInternalCtx->Rip, pRuntimeFunction, pInternalCtx, &pHandlerData, &EstablisherFrame, NULL);

    if (!(_IsSafeAddress(pInternalCtx->Rip)))
    {
        DbgLog("[TheiaPg <+>] FltrExQueueWorkItem: Detect Unbacked-Caller | IRQL: 0x%02X\n", CurrIrql);
        DbgLog("===========================================================\n");
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
        DbgLog("===========================================================\n");
        DbgLog("caller frame: 0x%I64X\n\n", pInternalCtx->Rip);

        DbgLog("[TheiaPg <+>] FltrExQueueWorkItem: Handling exit phase...\n\n");

        DbgLog("[TheiaPg <+>] FltrExQueueWorkItem: Search PgCtx... | PgCtx: 0x%I64X\n\n", (pPgCtx = SearchPgCtxInCtx(pInternalCtx)));

        if (pPgCtx)
        {
            if (g_pTheiaCtx->pMmIsAddressValid(pPgDpcRoutine = *(PVOID*)((PUCHAR)pPgCtx + 0x7f8))) ///< LocalPgCtxBase + 0x7f8: PgDpcRoutine
            {
                if (!((HrdGetPteInputVa(pPgDpcRoutine))->NoExecute))
                {
                    DbgLog("[TheiaPg <+>] FltrExQueueWorkItem: Detect PgDpcRoutine in PgCtx | PgDpcRoutine: 0x%I64X\n\n", pPgDpcRoutine);

                    DataIndpnRWVMem.pVa = pPgDpcRoutine;

                    HrdIndpnRWVMemory(&DataIndpnRWVMem);
                }
            }

            if (g_pTheiaCtx->pMmIsAddressValid(pPgApcRoutine = *(PVOID*)((PUCHAR)pPgCtx + 0xa30))) ///< LocalPgCtxBase + 0xA30: PgApcRoutine (basically KiDispatchCallout)
            {
                if (!((HrdGetPteInputVa(pPgApcRoutine))->NoExecute))
                {
                    DbgLog("[TheiaPg <+>] FltrExQueueWorkItem: Detect PgApcRoutine in PgCtx | PgApcRoutine: 0x%I64X\n\n", pPgApcRoutine);

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

                    DbgLog("[TheiaPg <+>] FltrExQueueWorkItem: SdbpCheckDllRWX is found: 0x%I64X\n\n", pSearchSdbpCheckDllRWX);

                    break;
                }
            }

        }

        if (!IsSleep)
        {
            if (CurrIrql < DISPATCH_LEVEL)
            {
                DbgLog("[TheiaPg <+>] FltrExQueueWorkItem: Enter to dead sleep... | IRQL: 0x%02X\n\n", CurrIrql);

                IsSleep = TRUE;
            }
            else
            {
                DbgLog("[TheiaPg <+>] FltrExQueueWorkItem: Unsuccessful enter to dead sleep... | IRQL: 0x%02X\n\n", CurrIrql);              
            }
        }
    }

    SAFE_ENABLE(CurrIF, CurrIrql, DISPATCH_LEVEL, g_pTheiaCtx->pMmFreeIndependentPages(pInternalCtx, PAGE_SIZE, 0I64););

    if (IsSleep) { SAFE_ENABLE(CurrIF, CurrIrql, CurrIrql, g_pTheiaCtx->pKeDelayExecutionThread(KernelMode, FALSE, &Timeout);); }

    return;
}

/*++
* Routine: FltrExAllocatePool2
*
* MaxIRQL: DISPATCH_LEVEL
*
* Public/Private: Public
*
* @param pInputCtx: Context passed from StubCallTrmpln
*
* Description: This hook is required as a last resort if the PG check routine continues to overcome countermeasures.
* PG check routine primarily uses ExAllocatePool2/MmAllocateIndependentPages for pages allocation in Windows 11 25h2.
--*/
volatile VOID FltrExAllocatePool2(IN OUT PINPUTCONTEXT_ICH pInputCtx)
{
    CheckStatusTheiaCtx();

    BOOLEAN CurrIF = HrdGetIF();
    UCHAR CurrIrql = (UCHAR)__readcr8();

    PCONTEXT pInternalCtx = NULL;

    SAFE_ENABLE(CurrIF, CurrIrql, DISPATCH_LEVEL, pInternalCtx = (PCONTEXT)g_pTheiaCtx->pMmAllocateIndependentPagesEx(PAGE_SIZE, -1I32, 0I64, 0I32););

    if (!pInternalCtx) { DbgLog("[TheiaPg <->] FltrExAllocatePool2: Bad alloc page for InternalCtx\n"); return; }

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

    CONST LONG64 Timeout = (-10000UI64 * 31536000000UI64); ///< 1 year.
    CONST UCHAR RetOpcode = 0xc3UI8;
    LONG32 SaveRel32Offset = 0I32;

    PVOID pSearchSdbpCheckDllRWX = NULL;
    PVOID pPgDpcRoutine = NULL;
    PVOID pPgApcRoutine = NULL;

    INDPN_RW_V_MEMORY_DATA DataIndpnRWVMem = { 0 };
    DataIndpnRWVMem.FlagsExecute = MEM_INDPN_RW_WRITE_OP_BIT;
    DataIndpnRWVMem.pIoBuffer = &RetOpcode;
    DataIndpnRWVMem.LengthRW = 1UI64;

    BOOLEAN IsSleep = FALSE;

    PVOID pPgCtx = NULL;

    if (pInputCtx->rax)
    {
        SAFE_ENABLE(CurrIF, CurrIrql, CurrIrql, { *(PUCHAR)pInputCtx->rax = 0x00UI8; }); ///< Fix DemandZero-PTE (Only PT-PTEs level)

        if ((*(PULONG64)(HrdGetPteInputVa((PVOID)pInputCtx->rax)) & 0x8000000000000801UI64) == 0x801UI64) ///< Checking RWX PTE-Attributes.
        {
            DbgLog("[TheiaPg <+>] FltrExAllocatePool2: Detect attempt allocate RWX-Page\n\n");

            if (CurrIrql < DISPATCH_LEVEL) { IsSleep = TRUE; }
            else { ExFreePool(pInputCtx->rax); pInputCtx->rax = 0I64; }
        }
    }

    pRuntimeFunction = g_pTheiaCtx->pRtlLookupFunctionEntry(pInternalCtx->Rip, &pImageBase, NULL);

    g_pTheiaCtx->pRtlVirtualUnwind(0UI32, pImageBase, pInternalCtx->Rip, pRuntimeFunction, pInternalCtx, &pHandlerData, &EstablisherFrame, NULL);

    if (!(_IsSafeAddress(pInternalCtx->Rip)))
    {
        DbgLog("[TheiaPg <+>] FltrExAllocatePool2: Detect Unbacked-Caller | IRQL: 0x%02X\n", CurrIrql);
        DbgLog("===========================================================\n");
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
        DbgLog("===========================================================\n");
        DbgLog("caller frame: 0x%I64X\n\n", pInternalCtx->Rip);

        DbgLog("[TheiaPg <+>] FltrExAllocatePool2: Handling exit phase...\n\n");

        DbgLog("[TheiaPg <+>] FltrExAllocatePool2: Search PgCtx... | PgCtx: 0x%I64X\n\n", (pPgCtx = SearchPgCtxInCtx(pInternalCtx)));

        if (pPgCtx)
        {
            if (g_pTheiaCtx->pMmIsAddressValid(pPgDpcRoutine = *(PVOID*)((PUCHAR)pPgCtx + 0x7f8))) ///< LocalPgCtxBase + 0x7f8: PgDpcRoutine
            {
                if (!((HrdGetPteInputVa(pPgDpcRoutine))->NoExecute))
                {
                    DbgLog("[TheiaPg <+>] FltrExAllocatePool2: Detect PgDpcRoutine in PgCtx | PgDpcRoutine: 0x%I64X\n\n", pPgDpcRoutine);

                    DataIndpnRWVMem.pVa = pPgDpcRoutine;

                    HrdIndpnRWVMemory(&DataIndpnRWVMem);
                }
            }

            if (g_pTheiaCtx->pMmIsAddressValid(pPgApcRoutine = *(PVOID*)((PUCHAR)pPgCtx + 0xa30))) ///< LocalPgCtxBase + 0xA30: PgApcRoutine (basically KiDispatchCallout)
            {
                if (!((HrdGetPteInputVa(pPgApcRoutine))->NoExecute))
                {
                    DbgLog("[TheiaPg <+>] FltrExAllocatePool2: Detect PgApcRoutine in PgCtx | PgApcRoutine: 0x%I64X\n\n", pPgApcRoutine);

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

                    DbgLog("[TheiaPg <+>] FltrExAllocatePool2: SdbpCheckDllRWX is found: 0x%I64X\n\n", pSearchSdbpCheckDllRWX);

                    break;
                }
            }

        }

        if (!IsSleep)
        {
            if (CurrIrql < DISPATCH_LEVEL)
            {
                DbgLog("[TheiaPg <+>] FltrExAllocatePool2: Enter to dead sleep... | IRQL: 0x%02X\n\n", CurrIrql);

                IsSleep = TRUE;
            }
            else
            {
                DbgLog("[TheiaPg <+>] FltrExAllocatePool2: Unsuccessful enter to dead sleep... | IRQL: 0x%02X\n\n", CurrIrql);

                if (pPgCtx) { *(PULONG32)((PUCHAR)pPgCtx + 0xA60) = -1UI32; } ///< Counter of unsuccessful memory allocation attempts in PgCtx.

                if (pInputCtx->rax)
                {
                    SAFE_ENABLE(CurrIF, CurrIrql, CurrIrql, { *(PUCHAR)pInputCtx->rax = 0x00UI8; });

                    ExFreePool(pInputCtx->rax);

                    pInputCtx->rax = 0I64;
                }
            }
        }
    }

    SAFE_ENABLE(CurrIF, CurrIrql, DISPATCH_LEVEL, g_pTheiaCtx->pMmFreeIndependentPages(pInternalCtx, PAGE_SIZE, 0I64););

    if (IsSleep) { SAFE_ENABLE(CurrIF, CurrIrql, CurrIrql, g_pTheiaCtx->pKeDelayExecutionThread(KernelMode, FALSE, &Timeout);); }

    return;
}

/**
* Routine: FltrKiCustomRecurseRoutineX
*
* MaxIRQL: DISPATCH_LEVEL
*
* Public/Private: Public
*
* @param pInputCtx: Context passed from StubCallTrmpln
*
* Description: This function is similar to FltrExAllocatePool2, but is primarily intended to be called from the context of DISPATCH_LEVEL-ISR.
*/
volatile VOID FltrKiCustomRecurseRoutineX(IN OUT PINPUTCONTEXT_ICH pInputCtx)
{
    CheckStatusTheiaCtx();

    UCHAR CurrIrql = (UCHAR)__readcr8();
    BOOLEAN CurrIF = HrdGetIF();
    ULONG32 CurrCoreNum = (ULONG32)__readgsdword(g_pTheiaCtx->TheiaMetaDataBlock.KPCR_Prcb_OFFSET + g_pTheiaCtx->TheiaMetaDataBlock.KPRCB_Number_OFFSET);

    PCONTEXT pInternalCtx = NULL;

    SAFE_ENABLE(CurrIF, CurrIrql, DISPATCH_LEVEL, pInternalCtx = (PCONTEXT)g_pTheiaCtx->pMmAllocateIndependentPagesEx(PAGE_SIZE, -1I32, 0I64, 0I32););

    if (!pInternalCtx) { DbgLog("[TheiaPg <->] FltrKiCustomRecurseRoutineX: Unsuccessful alloc page for InternalCtx\n"); return; }

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

    CONST LONG64 Timeout = (-10000UI64 * 31536000000UI64); ///< 1 year.
    LONG32 SaveRel32Offset = 0I32;
    CONST UCHAR RetOpcode = 0xc3UI8;

    INDPN_RW_V_MEMORY_DATA DataIndpnRWVMem = { 0 };
    DataIndpnRWVMem.FlagsExecute = MEM_INDPN_RW_WRITE_OP_BIT;
    DataIndpnRWVMem.pIoBuffer = &RetOpcode;
    DataIndpnRWVMem.LengthRW = 1UI64;

    PVOID pSearchSdbpCheckDllRWX = NULL;
    PVOID pPgDpcRoutine = NULL;
    PVOID pPgApcRoutine = NULL;

    PVOID pRetAddrPgDpcRoutine = NULL;
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

        g_pTheiaCtx->pRtlVirtualUnwind(0UI32, pImageBase, pInternalCtx->Rip, pRuntimeFunction, pInternalCtx, &pHandlerData, &EstablisherFrame, NULL);

        if (i == 1) { pRetAddrPgDpcRoutine = pInternalCtx->Rip; }
    }

    DbgLog("[TheiaPg <+>] FltrKiCustomRecurseRoutineX: Detect PgCallChain | CpuCore: 0x%I32X\n", CurrCoreNum);
    DbgLog("===============================================================\n");
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
    DbgLog("===============================================================\n\n");

    DbgLog("[TheiaPg <+>] FltrKiCustomRecurseRoutineX: Handling exit phase...\n\n");

    DbgLog("[TheiaPg <+>] FltrKiCustomRecurseRoutineX: Return address PgDpcRoutine: 0x%I64X\n\n", pRetAddrPgDpcRoutine);

    if (pPgKDPC = _HeurisSearchKdpcInCtx(pInternalCtx))
    {
        DbgLog("[TheiaPg <+>] FltrKiCustomRecurseRoutineX: Detect PG-KDPC from cpu-unwind-ctx | _KDPC: 0x%I64X\n\n", pPgKDPC);

        DataIndpnRWVMem.pVa = pPgKDPC->DeferredRoutine;

        HrdIndpnRWVMemory(&DataIndpnRWVMem);
    }

    DbgLog("[TheiaPg <+>] FltrKiCustomRecurseRoutineX: Search PgCtx... | PgCtx: 0x%I64X\n\n", (pPgCtx = SearchPgCtxInCtx(pInternalCtx)));

    if (pPgCtx)
    {
        if (g_pTheiaCtx->pMmIsAddressValid(pPgDpcRoutine = *(PVOID*)((PUCHAR)pPgCtx + 0x7f8))) ///< LocalPgCtxBase + 0x7f8: PgDpcRoutine
        {
            if (!((HrdGetPteInputVa(pPgDpcRoutine))->NoExecute))
            {
                DbgLog("[TheiaPg <+>] FltrKiCustomRecurseRoutineX: Detect PgDpcRoutine in PgCtx | PgDpcRoutine: 0x%I64X\n\n", pPgDpcRoutine);

                DataIndpnRWVMem.pVa = pPgDpcRoutine;

                HrdIndpnRWVMemory(&DataIndpnRWVMem);
            }
        }

        if (g_pTheiaCtx->pMmIsAddressValid(pPgApcRoutine = *(PVOID*)((PUCHAR)pPgCtx + 0xa30))) ///< LocalPgCtxBase + 0xA30: PgApcRoutine (basically KiDispatchCallout)
        {
            if (!((HrdGetPteInputVa(pPgApcRoutine))->NoExecute))
            {
                DbgLog("[TheiaPg <+>] FltrKiCustomRecurseRoutineX: Detect PgApcRoutine in PgCtx | PgApcRoutine: 0x%I64X\n\n", pPgApcRoutine);

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

                DbgLog("[TheiaPg <+>] FltrKiCustomRecurseRoutineX: SdbpCheckDllRWX is found: 0x%I64X\n\n", pSearchSdbpCheckDllRWX);

                break;
            }
        }
    }
  
    if (CurrIrql < DISPATCH_LEVEL)
    {
        DbgLog("[TheiaPg <+>] FltrKiCustomRecurseRoutineX: Enter to dead sleep... | IRQL: 0x%02X\n\n", CurrIrql);

        IsSleep = TRUE;
    }
    else { DbgLog("[TheiaPg <+>] FltrKiCustomRecurseRoutineX: Rebound execution context... | IRQL: 0x%02X\n\n", CurrIrql); } 

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

    SAFE_ENABLE(CurrIF, CurrIrql, DISPATCH_LEVEL, g_pTheiaCtx->pMmFreeIndependentPages(pInternalCtx, PAGE_SIZE, 0I64););

    if (IsSleep) { SAFE_ENABLE(CurrIF, CurrIrql, CurrIrql, g_pTheiaCtx->pKeDelayExecutionThread(KernelMode, FALSE, &Timeout);); }

    return;
}
