#include "LinkHeader.h"
  
/**
* Routine: TheiaEntry
*
* MaxIRQL: DISPATCH_LEVEL
*
* Public/Private: Public
*
* @param NoParams
*
* Description: TheiaEntry routine.
*/
VOID TheiaEntry(VOID)
{
    #define ERROR_THEIA_ENTRY 0xd1baa81aUI32

    CONST UCHAR RetOpcode = 0xC3UI8;
  
    CONST UCHAR StopSig[3] = { 0xCC,0xCC,0xCC };

    ICT_DATA_RELATED RelatedDataICT = { 0 };

    INDPN_RW_V_MEMORY_DATA DataIndpnRWVMem = { 0 };

    DataIndpnRWVMem.FlagsExecute = MEM_INDPN_RW_WRITE_OP_BIT;

    DataIndpnRWVMem.pIoBuffer = &RetOpcode;

    DataIndpnRWVMem.LengthRW = 1UI64;

    InitTheiaContext();

    DataIndpnRWVMem.pVa = g_pTheiaCtx->pKiMcaDeferredRecoveryService;;
    
    DbgLog("[TheiaPg <+>] TheiaEntry: FixKiMcaDeferredRecoveryService\n");
    
    HrdIndpnRWVMemory(&DataIndpnRWVMem);
    
    DataIndpnRWVMem.pVa = g_pTheiaCtx->pFsRtlUninitializeSmallMcb;

    DbgLog("[TheiaPg <+>] TheiaEntry: FixFsRtlUninitializeSmallMcb\n");

    HrdIndpnRWVMemory(&DataIndpnRWVMem);

    DataIndpnRWVMem.pVa = g_pTheiaCtx->pFsRtlTruncateSmallMcb;
    
    DbgLog("[TheiaPg <+>] TheiaEntry: FixFsRtlTruncateSmallMcb\n");
    
    HrdIndpnRWVMemory(&DataIndpnRWVMem);
    
    DataIndpnRWVMem.pVa = g_pTheiaCtx->pKiDecodeMcaFault;
    
    DbgLog("[TheiaPg <+>] TheiaEntry: FixKiDecodeMcaFault\n");
    
    HrdIndpnRWVMemory(&DataIndpnRWVMem);
    
    DataIndpnRWVMem.pVa = g_pTheiaCtx->pCcBcbProfiler;
    
    DbgLog("[TheiaPg <+>] TheiaEntry: FixCcBcbProfiler\n");
    
    HrdIndpnRWVMemory(&DataIndpnRWVMem);
    
    DataIndpnRWVMem.pVa = g_pTheiaCtx->pCcBcbProfiler2;
    
    DbgLog("[TheiaPg <+>] TheiaEntry: FixCcBcbProfiler2\n");
    
    HrdIndpnRWVMemory(&DataIndpnRWVMem);
    
    DataIndpnRWVMem.pVa = g_pTheiaCtx->pKiDispatchCallout;
    
    DbgLog("[TheiaPg <+>] TheiaEntry: FixKiDispatchCallout\n");
    
    HrdIndpnRWVMemory(&DataIndpnRWVMem);
    
    DataIndpnRWVMem.pVa = g_pTheiaCtx->pKiSwInterruptDispatch;
    
    DbgLog("[TheiaPg <+>] TheiaEntry: FixKiSwInterruptDispatch\n");
    
    HrdIndpnRWVMemory(&DataIndpnRWVMem);
    
    DbgLog("[TheiaPg <+>] TheiaEntry: FixMaxDataSize\n");
    
    //
    // Nulling gMaxDataSize is necessary to neutralize the PG check routine,
    // which is called through a global pointer in the kernel module mssecflt.sys and checks MaxDataSize is NULL, if NULL is detected
    // then the execution of the check routine logically jump to epilog, unlike KiSwInterruptDispatch.
    //
    *(PULONG64)g_pTheiaCtx->ppMaxDataSize = NULL; ///< pp: pointer to pointer.
    
    DbgLog("[TheiaPg <+>] TheiaEntry: FixPgPrcbFields\n");
    
    g_pTheiaCtx->pKeIpiGenericCall(&SearchKdpcInPgPrcbFields, NULL);

    DbgLog("[TheiaPg <+>] TheiaEntry: FixKiBalanceSetManagerPeriodicDpc\n");

    if (((PKDPC)g_pTheiaCtx->pKiBalanceSetManagerPeriodicDpc)->DeferredRoutine != g_pTheiaCtx->pKiBalanceSetManagerDeferredRoutine)
    {
        DbgLog("[TheiaPg <+>] TheiaEntry: Detect PG DeferredRoutine in KiBalanceSetManagerPeriodicDpc\n");

        ((PKDPC)g_pTheiaCtx->pKiBalanceSetManagerPeriodicDpc)->DeferredRoutine = g_pTheiaCtx->pKiBalanceSetManagerDeferredRoutine;
    }
    
    RelatedDataICT.pHookRoutine = &VsrKiExecuteAllDpcs;
    RelatedDataICT.pBasePatch = _SearchPatternInRegion(NULL, SPIR_NO_OPTIONAL, g_pTheiaCtx->pKiExecuteAllDpcs, g_pTheiaCtx->TheiaMetaDataBlock.KIEXECUTEALLDPCS_SIG, g_pTheiaCtx->TheiaMetaDataBlock.KIEXECUTEALLDPCS_MASK, &StopSig, sizeof StopSig);
    
    if (!RelatedDataICT.pBasePatch)
    {
        DbgLog("[TheiaPg <->] TheiaEntry: Base for Call-Trampoline VsrKiExecuteAllDpcs not found\n");
    
        DieDispatchIntrnlError(ERROR_THEIA_ENTRY);
    }
    
    RelatedDataICT.pHandlerHook = g_pTheiaCtx->TheiaMetaDataBlock.KIEXECUTEALLDPCS_HANDLER;
    RelatedDataICT.LengthHandler = g_pTheiaCtx->TheiaMetaDataBlock.KIEXECUTEALLDPCS_LEN_HANDLER;
    RelatedDataICT.LengthAlignment = g_pTheiaCtx->TheiaMetaDataBlock.KIEXECUTEALLDPCS_HOOK_ALIGNMENT;
    
    HkInitCallTrmpln(&RelatedDataICT);
    
    DbgLog("[TheiaPg <+>] TheiaEntry: VsrKiExecuteAllDpcs is init\n");
    
    RelatedDataICT.pHookRoutine = &VsrKiRetireDpcList;
    RelatedDataICT.pBasePatch = _SearchPatternInRegion(NULL, SPIR_NO_OPTIONAL, g_pTheiaCtx->pKiRetireDpcList, g_pTheiaCtx->TheiaMetaDataBlock.KIRETIREDPCLIST_SIG, g_pTheiaCtx->TheiaMetaDataBlock.KIRETIREDPCLIST_MASK, &StopSig, sizeof StopSig);
    
    if (!RelatedDataICT.pBasePatch)
    {
        DbgLog("[TheiaPg <->] TheiaEntry: Base for Call-Trampoline VsrKiRetireDpcList not found\n");
    
        DieDispatchIntrnlError(ERROR_THEIA_ENTRY);
    }
    
    RelatedDataICT.pHandlerHook = g_pTheiaCtx->TheiaMetaDataBlock.KIRETIREDPCLIST_HANDLER;
    RelatedDataICT.LengthHandler = g_pTheiaCtx->TheiaMetaDataBlock.KIRETIREDPCLIST_LEN_HANDLER;
    RelatedDataICT.LengthAlignment = g_pTheiaCtx->TheiaMetaDataBlock.KIRETIREDPCLIST_HOOK_ALIGNMENT;
    
    HkInitCallTrmpln(&RelatedDataICT);
    
    DbgLog("[TheiaPg <+>] TheiaEntry: VsrKiRetireDpcList is init\n");

    RelatedDataICT.pHookRoutine = &VsrKiDeliverApc;
    RelatedDataICT.pBasePatch = _SearchPatternInRegion(NULL, SPIR_NO_OPTIONAL, g_pTheiaCtx->pKiDeliverApc, g_pTheiaCtx->TheiaMetaDataBlock.KIDELIVERAPC_SIG, g_pTheiaCtx->TheiaMetaDataBlock.KIDELIVERAPC_MASK, &StopSig, sizeof StopSig);

    if (!RelatedDataICT.pBasePatch)
    {
        DbgLog("[TheiaPg <->] TheiaEntry: Base for Call-Trampoline VsrKiDeliverApc not found\n");

        DieDispatchIntrnlError(ERROR_THEIA_ENTRY);
    }

    RelatedDataICT.pHandlerHook = g_pTheiaCtx->TheiaMetaDataBlock.KIDELIVERAPC_HANDLER;
    RelatedDataICT.LengthHandler = g_pTheiaCtx->TheiaMetaDataBlock.KIDELIVERAPC_LEN_HANDLER;
    RelatedDataICT.LengthAlignment = g_pTheiaCtx->TheiaMetaDataBlock.KIDELIVERAPC_HOOK_ALIGNMENT;

    HkInitCallTrmpln(&RelatedDataICT);

    DbgLog("[TheiaPg <+>] TheiaEntry: VsrKiDeliverApc is init\n");

    RelatedDataICT.pHookRoutine = &VsrExQueueWorkItem;
    RelatedDataICT.pBasePatch = _SearchPatternInRegion(NULL, SPIR_NO_OPTIONAL, g_pTheiaCtx->pExQueueWorkItem, g_pTheiaCtx->TheiaMetaDataBlock.EXQUEUEWORKITEM_SIG, g_pTheiaCtx->TheiaMetaDataBlock.EXQUEUEWORKITEM_MASK, &StopSig, sizeof StopSig);

    if (!RelatedDataICT.pBasePatch)
    {
        DbgLog("[TheiaPg <->] TheiaEntry: Base for Call-Trampoline VsrExQueueWorkItem not found\n");

        DieDispatchIntrnlError(ERROR_THEIA_ENTRY);
    }

    RelatedDataICT.pHandlerHook = g_pTheiaCtx->TheiaMetaDataBlock.EXQUEUEWORKITEM_HANDLER;
    RelatedDataICT.LengthHandler = g_pTheiaCtx->TheiaMetaDataBlock.EXQUEUEWORKITEM_LEN_HANDLER;
    RelatedDataICT.LengthAlignment = g_pTheiaCtx->TheiaMetaDataBlock.EXQUEUEWORKITEM_HOOK_ALIGNMENT;

    HkInitCallTrmpln(&RelatedDataICT);

    DbgLog("[TheiaPg <+>] TheiaEntry: VsrExQueueWorkItem is init\n");

    RelatedDataICT.pHookRoutine = &VsrExAllocatePool2; 
    RelatedDataICT.pBasePatch = _SearchPatternInRegion(NULL, SPIR_NO_OPTIONAL, g_pTheiaCtx->pExAllocatePool2, g_pTheiaCtx->TheiaMetaDataBlock.EXALLOCATEPOOL2_SIG, g_pTheiaCtx->TheiaMetaDataBlock.EXALLOCATEPOOL2_MASK, &StopSig, sizeof StopSig);
    
    if (!RelatedDataICT.pBasePatch)
    {
        DbgLog("[TheiaPg <->] TheiaEntry: Base for Call-Trampoline VsrExAllocatePool2 not found\n");
    
        DieDispatchIntrnlError(ERROR_THEIA_ENTRY);
    }
    
    RelatedDataICT.pHandlerHook = g_pTheiaCtx->TheiaMetaDataBlock.EXALLOCATEPOOL2_HANDLER;
    RelatedDataICT.LengthHandler = g_pTheiaCtx->TheiaMetaDataBlock.EXALLOCATEPOOL2_LEN_HANDLER;
    RelatedDataICT.LengthAlignment = g_pTheiaCtx->TheiaMetaDataBlock.EXALLOCATEPOOL2_HOOK_ALIGNMENT;
    
    HkInitCallTrmpln(&RelatedDataICT);
    
    DbgLog("[TheiaPg <+>] TheiaEntry: VsrExAllocatePool2 is init\n");
    
    do
    {
        LONG32 SaveRel32Offset = 0I32;
    
        PVOID pCurrentRecurseRoutine = NULL;
    
        for (BOOLEAN i = FALSE; ; )
        {
            if (!i)
            {
                i = TRUE;
    
                RelatedDataICT.pHookRoutine = &VsrKiCustomRecurseRoutineX;
                RelatedDataICT.pBasePatch = g_pTheiaCtx->pKiCustomRecurseRoutineX;
                RelatedDataICT.pHandlerHook = g_pTheiaCtx->TheiaMetaDataBlock.KICUSTOMRECURSEROUTINEX_HANDLER;
                RelatedDataICT.LengthHandler = g_pTheiaCtx->TheiaMetaDataBlock.KICUSTOMRECURSEROUTINEX_LEN_HANDLER;
                RelatedDataICT.LengthAlignment = g_pTheiaCtx->TheiaMetaDataBlock.KICUSTOMRECURSEROUTINEX_HOOK_ALIGNMENT;
    
                pCurrentRecurseRoutine = g_pTheiaCtx->pKiCustomRecurseRoutineX;
    
                SaveRel32Offset = *(PLONG32)((PUCHAR)pCurrentRecurseRoutine + 5);
    
                pCurrentRecurseRoutine = (PVOID)(((ULONG64)pCurrentRecurseRoutine + 9) + ((SaveRel32Offset < 0I32) ? ((ULONG64)SaveRel32Offset | 0xffffffff00000000UI64) : (ULONG64)SaveRel32Offset));
            }
            else
            {
                if (pCurrentRecurseRoutine == ((PUCHAR)g_pTheiaCtx->pKiCustomRecurseRoutineX - 4)) { break; }
    
                RelatedDataICT.pBasePatch = ((PUCHAR)pCurrentRecurseRoutine + 4);
    
                SaveRel32Offset = *(PLONG32)((PUCHAR)pCurrentRecurseRoutine + 9);
    
                pCurrentRecurseRoutine = (PVOID)(((ULONG64)pCurrentRecurseRoutine + 13) + ((SaveRel32Offset < 0I32) ? ((ULONG64)SaveRel32Offset | 0xffffffff00000000UI64) : (ULONG64)SaveRel32Offset));
            }
    
            HkInitCallTrmpln(&RelatedDataICT);
        };
    
        DbgLog("[TheiaPg <+>] TheiaEntry: VsrKiCustomRecurseRoutineX is init\n\n");
    
    } while (FALSE);

    InitSearchPgSysThread(); ///< Calling initalizer sys-threads-walk.

    return;
}
