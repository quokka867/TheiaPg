#include "LinkHeader.h"

/*++
* Routine: InitTheiaMetaDataBlock
*
* MaxIRQL: Any level
* 
* Public/Private: Public
*
* @param pTheiaMetaDataBlock: TheiaMetaDataBlock
* 
* Description: Initializator of metadata KernelNT in TheiaCtx.
--*/
VOID InitTheiaMetaDataBlock(IN OUT PTHEIA_METADATA_BLOCK pTheiaMetaDataBlock)
{
    #define ERROR_INIT_META_DATA_BLOCK 0xdbdea4c3UI32

    #define ITMDB_LOCAL_CONTEXT_MMISADDRESSVALID 0

    #define ITMDB_LOCAL_CONTEXT_MMISNONPAGEDSYSTEMADDRESSVALID 1

    PVOID(__fastcall *ITMDBCtx[2])(PVOID, ...) = { 0 }; ///< Routine is critical, so it should not depend on gTheiaCtx.

    UNICODE_STRING StrMmIsAddressValid = { 0 };                                                                  
    
    StrMmIsAddressValid.Buffer = L"MmIsAddressValid";                                                            
    
    StrMmIsAddressValid.Length = (USHORT)((wcslen(StrMmIsAddressValid.Buffer)) * 2);                             
    
    StrMmIsAddressValid.MaximumLength = (StrMmIsAddressValid.Length + 2);      

    ITMDBCtx[ITMDB_LOCAL_CONTEXT_MMISADDRESSVALID] = MmGetSystemRoutineAddress(&StrMmIsAddressValid);
    
    UNICODE_STRING StrMmIsNonPagedSystemAddressValid = { 0 };                                                    
    
    StrMmIsNonPagedSystemAddressValid.Buffer = L"MmIsNonPagedSystemAddressValid";                                
    
    StrMmIsNonPagedSystemAddressValid.Length = (USHORT)((wcslen(StrMmIsNonPagedSystemAddressValid.Buffer)) * 2); 
    
    StrMmIsNonPagedSystemAddressValid.MaximumLength = (StrMmIsNonPagedSystemAddressValid.Length + 2);   

    ITMDBCtx[ITMDB_LOCAL_CONTEXT_MMISNONPAGEDSYSTEMADDRESSVALID] = MmGetSystemRoutineAddress(&StrMmIsNonPagedSystemAddressValid);

    if (!pTheiaMetaDataBlock || !((__readcr8() <= DISPATCH_LEVEL) ? ITMDBCtx[ITMDB_LOCAL_CONTEXT_MMISADDRESSVALID](pTheiaMetaDataBlock) : ITMDBCtx[ITMDB_LOCAL_CONTEXT_MMISNONPAGEDSYSTEMADDRESSVALID](pTheiaMetaDataBlock) || !(((ULONG64)pTheiaMetaDataBlock >> 47) == 0x1ffffUI64)))
    {
        DbgLog("[TheiaPg <->] InitMetaDataBlock: Invalid TheiaMetaDataBlock\n");

        DieDispatchIntrnlError(ERROR_INIT_META_DATA_BLOCK);
    }

    if (NtBuildNumber >= 26200UI32) ///< Windows 11 25h2
    {
        //
        // KOFFSETS ======================================================================================
        //
        pTheiaMetaDataBlock->KPCR_TssBase_OFFSET                       = 0x08UI32;
        pTheiaMetaDataBlock->KPCR_CurrentPrcb_OFFSET                   = 0x20UI32;
        pTheiaMetaDataBlock->KPCR_Prcb_OFFSET                          = 0x180UI32;

        pTheiaMetaDataBlock->KPRCB_CurrentThread_OFFSET                = 0x08UI32;
        pTheiaMetaDataBlock->KPRCB_Number_OFFSET                       = 0x24UI32;
        pTheiaMetaDataBlock->KPRCB_IdleThread_OFFSET                   = 0x18UI32;
        pTheiaMetaDataBlock->KPRCB_HalReserved_OFFSET                  = 0x48UI32;
        pTheiaMetaDataBlock->KPRCB_AcpiReserved_OFFSET                 = 0xe0UI32;
        pTheiaMetaDataBlock->KPRCB_DpcData0_OFFSET                     = 0x3840UI32;
        pTheiaMetaDataBlock->KPRCB_DpcData1_OFFSET                     = 0x3870UI32;
        pTheiaMetaDataBlock->KPRCB_DpcStack_OFFSET                     = 0x38a0UI32;
        pTheiaMetaDataBlock->KPRCB_TimerTable_OFFSET                   = 0x4100UI32;

        pTheiaMetaDataBlock->ETHREAD_Cid_OFFSET                        = 0x508UI32;
        pTheiaMetaDataBlock->ETHREAD_Win32StartAddress_OFFSET          = 0x560UI32;

        pTheiaMetaDataBlock->CLIENT_ID_UniqueProcess_OFFSET            = 0x00UI32;
        pTheiaMetaDataBlock->CLIENT_ID_UniqueThread_OFFSET             = 0x08UI32;

        pTheiaMetaDataBlock->KTHREAD_InitialStack_OFFSET               = 0x28UI32;
        pTheiaMetaDataBlock->KTHREAD_StackLimit_OFFSET                 = 0x30UI32;
        pTheiaMetaDataBlock->KTHREAD_StackBase_OFFSET                  = 0x38UI32;
        pTheiaMetaDataBlock->KTHREAD_KernelStack_OFFSET                = 0x58UI32;
        pTheiaMetaDataBlock->KTHREAD_MiscFlags_OFFSET                  = 0x74UI32;
        pTheiaMetaDataBlock->KTHREAD_ApcState_OFFSET                   = 0x98UI32;
        pTheiaMetaDataBlock->KTHREAD_ContextSwitches_OFFSET            = 0x154UI32;
        pTheiaMetaDataBlock->KTHREAD_WaitTime_OFFSET                   = 0x1b4UI32;
        pTheiaMetaDataBlock->KTHREAD_KernelTime_OFFSET                 = 0x28cUI32;
        pTheiaMetaDataBlock->KTHREAD_CombinedApcDisable_OFFSET         = 0x1e4UI32;
        pTheiaMetaDataBlock->KTHREAD_Process_OFFSET                    = 0x220UI32;
        pTheiaMetaDataBlock->KTHREAD_ThreadListEntry_OFFSET            = 0x2f8UI32;

        pTheiaMetaDataBlock->KAPC_STATE_ApcListHead0_OFFSET            = 0x0UI32;
        pTheiaMetaDataBlock->KAPC_STATE_ApcListHead1_OFFSET            = 0x10UI32;

        pTheiaMetaDataBlock->EPROCESS_Peb_OFFSET                       = 0x2e0UI32;
        pTheiaMetaDataBlock->EPROCESS_ThreadListHead_OFFSET            = 0x370UI32;

        pTheiaMetaDataBlock->KPROCESS_DirectoryTableBase_OFFSET        = 0x28UI32;

        pTheiaMetaDataBlock->PEB_Ldr_OFFSET                            = 0x18UI32;

        pTheiaMetaDataBlock->PEB_LDR_DATA_InLoadOrderModuleList_OFFSET = 0x10UI32;

        pTheiaMetaDataBlock->KLDR_InLoadOrderList_OFFSET               = 0x00UI32;
        pTheiaMetaDataBlock->KLDR_DllBase_OFFSET                       = 0x30UI32;
        pTheiaMetaDataBlock->KLDR_DllName_OFFSET                       = 0x58UI32;

        pTheiaMetaDataBlock->LDR_InLoadOrderList_OFFSET                = 0x00UI32;
        pTheiaMetaDataBlock->LDR_DllBase_OFFSET                        = 0x30UI32;
        pTheiaMetaDataBlock->LDR_DllName_OFFSET                        = 0x58UI32;

        //
        // KROUTINES_SIG_MASK ============================================================================
        //
        pTheiaMetaDataBlock->KIEXECUTEALLDPCS_SIG = &_25h2_w11_KiExecuteAllDpcs_SIG;
        pTheiaMetaDataBlock->KIEXECUTEALLDPCS_MASK = &_25h2_w11_KiExecuteAllDpcs_MASK;
        pTheiaMetaDataBlock->KIEXECUTEALLDPCS_HANDLER = &_25h2_w11_HandlerFltrKiExecuteAllDpcs;
        pTheiaMetaDataBlock->KIEXECUTEALLDPCS_LEN_HANDLER = sizeof _25h2_w11_HandlerFltrKiExecuteAllDpcs;
        pTheiaMetaDataBlock->KIEXECUTEALLDPCS_HOOK_ALIGNMENT = 2UI32;

        pTheiaMetaDataBlock->KIRETIREDPCLIST_SIG = &_25h2_w11_KiRetireDpcList_SIG;
        pTheiaMetaDataBlock->KIRETIREDPCLIST_MASK = &_25h2_w11_KiRetireDpcList_MASK;
        pTheiaMetaDataBlock->KIRETIREDPCLIST_HANDLER = &_25h2_w11_HandlerFltrKiRetireDpcList;
        pTheiaMetaDataBlock->KIRETIREDPCLIST_LEN_HANDLER = sizeof _25h2_w11_HandlerFltrKiRetireDpcList;
        pTheiaMetaDataBlock->KIRETIREDPCLIST_HOOK_ALIGNMENT = 0UI32;

        pTheiaMetaDataBlock->KIDELIVERAPC_SIG = &_25h2_w11_KiDeliverApc_SIG;
        pTheiaMetaDataBlock->KIDELIVERAPC_MASK = &_25h2_w11_KiDeliverApc_MASK;
        pTheiaMetaDataBlock->KIDELIVERAPC_HANDLER = &_25h2_w11_HandlerFltrKiDeliverApc;
        pTheiaMetaDataBlock->KIDELIVERAPC_LEN_HANDLER = sizeof _25h2_w11_HandlerFltrKiDeliverApc;
        pTheiaMetaDataBlock->KIDELIVERAPC_HOOK_ALIGNMENT = 1UI32;

        pTheiaMetaDataBlock->EXQUEUEWORKITEM_SIG = &_25h2_w11_ExQueueWorkItem_SIG;
        pTheiaMetaDataBlock->EXQUEUEWORKITEM_MASK = &_25h2_w11_ExQueueWorkItem_MASK;
        pTheiaMetaDataBlock->EXQUEUEWORKITEM_HANDLER = &_25h2_w11_HandlerFltrExQueueWorkItem;
        pTheiaMetaDataBlock->EXQUEUEWORKITEM_LEN_HANDLER = sizeof _25h2_w11_HandlerFltrExQueueWorkItem;
        pTheiaMetaDataBlock->EXQUEUEWORKITEM_HOOK_ALIGNMENT = 0UI32;

        pTheiaMetaDataBlock->EXALLOCATEPOOL2_SIG = &_25h2_w11_ExAllocatePool2_SIG;
        pTheiaMetaDataBlock->EXALLOCATEPOOL2_MASK = &_25h2_w11_ExAllocatePool2_MASK;
        pTheiaMetaDataBlock->EXALLOCATEPOOL2_HANDLER = &_25h2_w11_HandlerFltrExAllocatePool2;
        pTheiaMetaDataBlock->EXALLOCATEPOOL2_LEN_HANDLER = sizeof _25h2_w11_HandlerFltrExAllocatePool2;
        pTheiaMetaDataBlock->EXALLOCATEPOOL2_HOOK_ALIGNMENT = 0UI32;

        pTheiaMetaDataBlock->KICUSTOMRECURSEROUTINEX_SIG = &_25h2_w11_KiCustomRecurseRoutineX_SIG;
        pTheiaMetaDataBlock->KICUSTOMRECURSEROUTINEX_MASK = &_25h2_w11_KiCustomRecurseRoutineX_MASK;
        pTheiaMetaDataBlock->KICUSTOMRECURSEROUTINEX_HANDLER = &_25h2_w11_HandlerFltrKiCustomRecurseRoutineX;
        pTheiaMetaDataBlock->KICUSTOMRECURSEROUTINEX_LEN_HANDLER = sizeof _25h2_w11_HandlerFltrKiCustomRecurseRoutineX;
        pTheiaMetaDataBlock->KICUSTOMRECURSEROUTINEX_HOOK_ALIGNMENT = 0UI32;

        pTheiaMetaDataBlock->KIBALANCESETMANANGERDEFERREDROUTINE_SIG = &_25h2_w11_KiBalanceSetManagerDeferredRoutine_SIG;
        pTheiaMetaDataBlock->KIBALANCESETMANANGERDEFERREDROUTINE_MASK = &_25h2_w11_KiBalanceSetManagerDeferredRoutine_MASK;

        pTheiaMetaDataBlock->KIMCADEFERREDRECOVERYSERVICE_SIG = &_25h2_w11_KiMcaDeferredRecoveryService_SIG;
        pTheiaMetaDataBlock->KIMCADEFERREDRECOVERYSERVICE_MASK = &_25h2_w11_KiMcaDeferredRecoveryService_MASK;

        pTheiaMetaDataBlock->FSRTLUNINITIALIZESMALLMCB_SIG = &_25h2_w11_FsRtlUninitializeSmallMcb_SIG;
        pTheiaMetaDataBlock->FSRTLUNINITIALIZESMALLMCB_MASK = &_25h2_w11_FsRtlUninitializeSmallMcb_MASK;

        pTheiaMetaDataBlock->FSRTLTRUNCATESMALLMCB_SIG = &_25h2_w11_FsRtlTruncateSmallMcb_SIG;
        pTheiaMetaDataBlock->FSRTLTRUNCATESMALLMCB_MASK = &_25h2_w11_FsRtlTruncateSmallMcb_MASK;

        pTheiaMetaDataBlock->KIDECODEMCAFAULT_SIG = &_25h2_w11_KiDecodeMcaFault_SIG;
        pTheiaMetaDataBlock->KIDECODEMCAFAULT_MASK = &_25h2_w11_KiDecodeMcaFault_MASK;

        pTheiaMetaDataBlock->CCBCBPROFILER_SIG = &_25h2_w11_CcBcbProfiler_SIG;
        pTheiaMetaDataBlock->CCBCBPROFILER_MASK = &_25h2_w11_CcBcbProfiler_MASK;

        pTheiaMetaDataBlock->CCBCBPROFILER2_SIG = &_25h2_w11_CcBcbProfiler2_SIG;
        pTheiaMetaDataBlock->CCBCBPROFILER2_MASK = &_25h2_w11_CcBcbProfiler2_MASK;

        pTheiaMetaDataBlock->KIDISPATCHCALLOUT_SIG = &_25h2_w11_KiDispatchCallout_SIG;
        pTheiaMetaDataBlock->KIDISPATCHCALLOUT_MASK = &_25h2_w11_KiDispatchCallout_MASK;

        pTheiaMetaDataBlock->MMALLOCATEINDEPENDENTPAGESEX_SIG = &_25h2_w11_MmAllocateIndependentPagesEx_SIG;
        pTheiaMetaDataBlock->MMALLOCATEINDEPENDENTPAGESEX_MASK = &_25h2_w11_MmAllocateIndependentPagesEx_MASK;

        pTheiaMetaDataBlock->MMFREEINDEPENDENTPAGESEX_SIG = &_25h2_w11_MmFreeIndependentPages_SIG;
        pTheiaMetaDataBlock->MMFREEINDEPENDENTPAGESEX_MASK = &_25h2_w11_MmFreeIndependentPages_MASK;
    }
    else
    {
        DbgLog("[TheiaPg <->] InitMetaDataBlock: OsVersion 0xI32X non-supported\n", NtBuildNumber);

        DieDispatchIntrnlError(ERROR_INIT_META_DATA_BLOCK);
    }
          
    return;
}

/*++
* Routine: InitTheiaContext
*
* MaxIRQL: DISPATCH_LEVEL
*
* Public/Private: Public
*
* @param NoParams
* 
* Description: Global context initializer.
--*/
VOID InitTheiaContext(VOID)
{  
    #define ERROR_INIT_THEIA_CONTEXT 0x4a9d62b5UI32
    #define ERROR_DOUBLE_INIT_THEIA_CONTEXT 0x62c7bf9fUI32

    // OtherData =============================================================================================================================================++
                                                                                                                                                              //
    CONST UCHAR StopSig[4] = { 0xcc,0xcc,0xcc,0xcc };                                                                                                         //
                                                                                                                                                              //
    CONST UCHAR INIT_THEIA_CTX_KIEXECUTEALLDPCS_SUBSIG[] = { 0x48, 0xb8, 0x77, 0x72, 0xdd, 0xf3, 0xc7, 0xc6, 0x35, 0x7e }; ///< For KiWaitAlways/KiWaitNever. //
    CONST UCHAR INIT_THEIA_CTX_KIEXECUTEALLDPCS_SUBSIG_MASK[] = { "xxxxxxxxxx" };                                                                             // 
                                                                                                                                                              //
    CONST UCHAR PgXorRoutineSig[52] = ///< The byte pattern of the top of PgCtx is needed for routines of PgCtx interceptors.                                 //
    {                                                                                                                                                         //
      0x2e, 0x48, 0x31, 0x11,                                                                                                                                 //
      0x48, 0x31, 0x51, 0x08,                                                                                                                                 //
      0x48, 0x31, 0x51, 0x10,                                                                                                                                 //
      0x48, 0x31, 0x51, 0x18,                                                                                                                                 //
      0x48, 0x31, 0x51, 0x20,                                                                                                                                 //
      0x48, 0x31, 0x51, 0x28,                                                                                                                                 //
      0x48, 0x31, 0x51, 0x30,                                                                                                                                 //
      0x48, 0x31, 0x51, 0x38,                                                                                                                                 //
      0x48, 0x31, 0x51, 0x40,                                                                                                                                 //
      0x48, 0x31, 0x51, 0x48,                                                                                                                                 //
      0x48, 0x31, 0x51, 0x50,                                                                                                                                 //
      0x48, 0x31, 0x51, 0x58,                                                                                                                                 //
      0x48, 0x31, 0x51, 0x60                                                                                                                                  //
    };                                                                                                                                                        //
                                                                                                                                                              //
    PVOID(__stdcall*pExAllocatePool2)(POOL_FLAGS Flags, SIZE_T NumberOfBytes, ULONG Tag);                                                                     //
                                                                                                                                                              //
    CONST UCHAR INIT_THEIA_CTX_KIUPDATETIME_SUBSIG[] = ///< For KiBalanceSetManagerPeriodicDpc.                                                               //
    {                                                                                                                                                         //
      0x65, 0x48, 0x8B, 0x0C, 0x25,                                                                                                                           //
      0x20, 0x00, 0x00, 0x00, 0x4C,                                                                                                                           //
      0x8B, 0x81, 0xB8, 0x8E, 0x00,                                                                                                                           //
      0x00, 0x4D, 0x85, 0xC0, 0x0F,                                                                                                                           //
      0x85, 0x00, 0x00, 0x00, 0x00,                                                                                                                           //
      0xFB, 0xE9, 0x00, 0x00, 0x00,                                                                                                                           //
      0x00, 0x0F, 0xB6, 0xD0, 0x40,                                                                                                                           //
      0x0F, 0xB6, 0xCF, 0xE8, 0x00,                                                                                                                           //
      0x00, 0x00, 0x00, 0xE9, 0x00,                                                                                                                           //
      0x00, 0x00, 0x00, 0x00, 0x00                                                                                                                            //
    };                                                                                                                                                        //
    CONST UCHAR INIT_THEIA_CTX_KIUPDATETIME_MASK[] = { "xxxxxxxxxxxxxxxxxxxxx????xx????xxxxxxxx????x??????" };                                                //
                                                                                                                                                              //
    CONST UCHAR INIT_THEIA_KEBALANCESETMANANGER_SUBSIG[] = ///< For KiBalanceSetManagerPeriodicEvent.                                                         //
    {                                                                                                                                                         //
      0x48, 0x89, 0x5C, 0x24, 0x08,                                                                                                                           //
      0x48, 0x89, 0x6C, 0x24, 0x18,                                                                                                                           //
      0x57, 0x41, 0x54, 0x41, 0x57,                                                                                                                           //
      0x48, 0x83, 0xEC, 0x50, 0x65,                                                                                                                           //
      0x48, 0x8B, 0x0C, 0x25, 0x88,                                                                                                                           //
      0x01, 0x00, 0x00, 0xBA, 0x11,                                                                                                                           //
      0x00, 0x00, 0x00, 0xE8, 0xDA,                                                                                                                           //
      0xE3, 0xE2, 0xFF, 0x48, 0x8B,                                                                                                                           //
      0x05, 0x6B, 0x1D, 0xA0, 0x00,                                                                                                                           //
      0x4C, 0x8D, 0x3D, 0x8C, 0x36,                                                                                                                           //
      0xA0, 0x00, 0xB9, 0x80, 0xD1,                                                                                                                           //
      0xF0, 0x08, 0x00, 0x00, 0x00                                                                                                                            //
    };                                                                                                                                                        //
    CONST UCHAR INIT_THEIA_KEBALANCESETMANANGER_MASK[] = { "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx????xxx????xxx????xxxxx???" };                                  //
                                                                                                                                                              //
    LONG32 SaveRel32Offset = 0I32;                                                                                                                            //
                                                                                                                                                              //
    // =======================================================================================================================================================++
                                                                                                                                                 
    // RelatedData =====================++                                                                                                       
                                        //                                                                                                       
    ULONG64 RelatedDataSPII[4] = { 0 }; //                                                                                                       
                                        //                                                                                                                                           
    // =================================++                                                                                                           
                                                                                                                                                 
    // KiSwInterruptDispatch/MaxDataSize BlockVars =++                                                                                               
                                                    //                                                                                               
    UCHAR IDTR[10];                                 //                                                                                                                                                                                                                                    
    PKIDTENTRY64 pSwKIDTENTRY64 = NULL;             //                                                                                           
    PVOID pKiSwInterruptDispatch = NULL;            //  
                                                    //         
    // =============================================++
    
    // NamesRequiredRoutines ====================================================================================++
                                                                                                                 //
    UNICODE_STRING StrKeIpiGenericCall = { 0 };                                                                  //
                                                                                                                 //
    StrKeIpiGenericCall.Buffer = L"KeIpiGenericCall";                                                            //
                                                                                                                 //
    StrKeIpiGenericCall.Length = (USHORT)((wcslen(StrKeIpiGenericCall.Buffer)) * 2);                             //
                                                                                                                 //
    StrKeIpiGenericCall.MaximumLength = (StrKeIpiGenericCall.Length + 2);                                        //
                                                                                                                 //
    UNICODE_STRING StrKeQueryActiveProcessorCountEx = { 0 };                                                     //
                                                                                                                 //
    StrKeQueryActiveProcessorCountEx.Buffer = L"KeQueryActiveProcessorCountEx";                                  //
                                                                                                                 //
    StrKeQueryActiveProcessorCountEx.Length = (USHORT)((wcslen(StrKeQueryActiveProcessorCountEx.Buffer)) * 2);   //
                                                                                                                 //
    StrKeQueryActiveProcessorCountEx.MaximumLength = (StrKeQueryActiveProcessorCountEx.Length + 2);              //
                                                                                                                 //
    UNICODE_STRING StrMmGetPhysicalAddress = { 0 };                                                              //
                                                                                                                 //
    StrMmGetPhysicalAddress.Buffer = L"MmGetPhysicalAddress";                                                    //
                                                                                                                 //
    StrMmGetPhysicalAddress.Length = (USHORT)((wcslen(StrMmGetPhysicalAddress.Buffer)) * 2);                     //
                                                                                                                 //
    StrMmGetPhysicalAddress.MaximumLength = (StrMmGetPhysicalAddress.Length + 2);                                //
                                                                                                                 //
    UNICODE_STRING StrMmMapIoSpaceEx = { 0 };                                                                    //
                                                                                                                 //
    StrMmMapIoSpaceEx.Buffer = L"MmMapIoSpaceEx";                                                                //
                                                                                                                 //
    StrMmMapIoSpaceEx.Length = (USHORT)((wcslen(StrMmMapIoSpaceEx.Buffer)) * 2);                                 //
                                                                                                                 //
    StrMmMapIoSpaceEx.MaximumLength = (StrMmMapIoSpaceEx.Length + 2);                                            //
                                                                                                                 //
    UNICODE_STRING StrMmUnmapIoSpace = { 0 };                                                                    //
                                                                                                                 //
    StrMmUnmapIoSpace.Buffer = L"MmUnmapIoSpace";                                                                //
                                                                                                                 //
    StrMmUnmapIoSpace.Length = (USHORT)((wcslen(StrMmUnmapIoSpace.Buffer)) * 2);                                 //
                                                                                                                 //
    StrMmUnmapIoSpace.MaximumLength = (StrMmUnmapIoSpace.Length + 2);                                            //
                                                                                                                 //
    UNICODE_STRING StrRtlLookupFunctionEntry = { 0 };                                                            //
                                                                                                                 //
    StrRtlLookupFunctionEntry.Buffer = L"RtlLookupFunctionEntry";                                                //
                                                                                                                 //
    StrRtlLookupFunctionEntry.Length = (USHORT)((wcslen(StrRtlLookupFunctionEntry.Buffer)) * 2);                 //
                                                                                                                 //
    StrRtlLookupFunctionEntry.MaximumLength = (StrRtlLookupFunctionEntry.Length + 2);                            //
                                                                                                                 //
    UNICODE_STRING StrPsLookupThreadByThreadId = { 0 };                                                          //
                                                                                                                 //
    StrPsLookupThreadByThreadId.Buffer = L"PsLookupThreadByThreadId";                                            //
                                                                                                                 //
    StrPsLookupThreadByThreadId.Length = (USHORT)((wcslen(StrPsLookupThreadByThreadId.Buffer)) * 2);             //
                                                                                                                 //
    StrPsLookupThreadByThreadId.MaximumLength = (StrPsLookupThreadByThreadId.Length + 2);                        //
                                                                                                                 //
    UNICODE_STRING StrRtlVirtualUnwind = { 0 };                                                                  //
                                                                                                                 //
    StrRtlVirtualUnwind.Buffer = L"RtlVirtualUnwind";                                                            //
                                                                                                                 //
    StrRtlVirtualUnwind.Length = (USHORT)((wcslen(StrRtlVirtualUnwind.Buffer)) * 2);                             //
                                                                                                                 //
    StrRtlVirtualUnwind.MaximumLength = (StrRtlVirtualUnwind.Length + 2);                                        //
                                                                                                                 //
    UNICODE_STRING StrKeInitializeApc = { 0 };                                                                   //
                                                                                                                 //
    StrKeInitializeApc.Buffer = L"KeInitializeApc";                                                              //
                                                                                                                 //
    StrKeInitializeApc.Length = (USHORT)((wcslen(StrKeInitializeApc.Buffer)) * 2);                               //
                                                                                                                 //
    StrKeInitializeApc.MaximumLength = (StrKeInitializeApc.Length + 2);                                          //
                                                                                                                 //
    UNICODE_STRING StrKeInsertQueueApc = { 0 };                                                                  //
                                                                                                                 //
    StrKeInsertQueueApc.Buffer = L"KeInsertQueueApc";                                                            //
                                                                                                                 //
    StrKeInsertQueueApc.Length = (USHORT)((wcslen(StrKeInsertQueueApc.Buffer)) * 2);                             //
                                                                                                                 //
    StrKeInsertQueueApc.MaximumLength = (StrKeInsertQueueApc.Length + 2);                                        //
                                                                                                                 //
    UNICODE_STRING StrKeDelayExecutionThread = { 0 };                                                            //
                                                                                                                 //
    StrKeDelayExecutionThread.Buffer = L"KeDelayExecutionThread";                                                //
                                                                                                                 //
    StrKeDelayExecutionThread.Length = (USHORT)((wcslen(StrKeDelayExecutionThread.Buffer)) * 2);                 //
                                                                                                                 //
    StrKeDelayExecutionThread.MaximumLength = (StrKeDelayExecutionThread.Length + 2);                            //
                                                                                                                 //
    UNICODE_STRING StrMmIsAddressValid = { 0 };                                                                  //
                                                                                                                 //
    StrMmIsAddressValid.Buffer = L"MmIsAddressValid";                                                            //
                                                                                                                 //
    StrMmIsAddressValid.Length = (USHORT)((wcslen(StrMmIsAddressValid.Buffer)) * 2);                             //
                                                                                                                 //
    StrMmIsAddressValid.MaximumLength = (StrMmIsAddressValid.Length + 2);                                        //
                                                                                                                 //
    UNICODE_STRING StrMmIsNonPagedSystemAddressValid = { 0 };                                                    //
                                                                                                                 //
    StrMmIsNonPagedSystemAddressValid.Buffer = L"MmIsNonPagedSystemAddressValid";                                //
                                                                                                                 //
    StrMmIsNonPagedSystemAddressValid.Length = (USHORT)((wcslen(StrMmIsNonPagedSystemAddressValid.Buffer)) * 2); //
                                                                                                                 //
    StrMmIsNonPagedSystemAddressValid.MaximumLength = (StrMmIsNonPagedSystemAddressValid.Length + 2);            //
                                                                                                                 //
    UNICODE_STRING StrExAllocatePool2 = { 0 };                                                                   //
                                                                                                                 //
    StrExAllocatePool2.Buffer = L"ExAllocatePool2";                                                              //
                                                                                                                 //
    StrExAllocatePool2.Length = (USHORT)((wcslen(StrExAllocatePool2.Buffer)) * 2);                               //
                                                                                                                 //
    StrExAllocatePool2.MaximumLength = (StrExAllocatePool2.Length + 2);                                          //
                                                                                                                 //
    UNICODE_STRING StrExFreePoolWithTag = { 0 };                                                                 //
                                                                                                                 //
    StrExFreePoolWithTag.Buffer = L"ExFreePoolWithTag";                                                          //
                                                                                                                 //
    StrExFreePoolWithTag.Length = (USHORT)((wcslen(StrExFreePoolWithTag.Buffer)) * 2);                           //
                                                                                                                 //
    StrExFreePoolWithTag.MaximumLength = (StrExFreePoolWithTag.Length + 2);                                      //
                                                                                                                 //
    UNICODE_STRING StrIoCancelIrp = { 0 };                                                                       //
                                                                                                                 //
    StrIoCancelIrp.Buffer = L"IoCancelIrp";                                                                      //
                                                                                                                 //
    StrIoCancelIrp.Length = (USHORT)((wcslen(StrIoCancelIrp.Buffer)) * 2);                                       //
                                                                                                                 //
    StrIoCancelIrp.MaximumLength = (StrIoCancelIrp.Length + 2);                                                  //
                                                                                                                 //
    UNICODE_STRING StrKeBugCheckEx = { 0 };                                                                      //
                                                                                                                 //
    StrKeBugCheckEx.Buffer = L"KeBugCheckEx";                                                                    //
                                                                                                                 //
    StrKeBugCheckEx.Length = (USHORT)((wcslen(StrKeBugCheckEx.Buffer)) * 2);                                     //
                                                                                                                 //
    StrKeBugCheckEx.MaximumLength = (StrKeBugCheckEx.Length + 2);                                                //
                                                                                                                 //
    UNICODE_STRING StrPsIsSystemThread = { 0 };                                                                  //
                                                                                                                 //
    StrPsIsSystemThread.Buffer = L"PsIsSystemThread";                                                            //
                                                                                                                 //
    StrPsIsSystemThread.Length = (USHORT)((wcslen(StrPsIsSystemThread.Buffer)) * 2);                             //
                                                                                                                 //
    StrPsIsSystemThread.MaximumLength = (StrPsIsSystemThread.Length + 2);                                        //
                                                                                                                 //
    UNICODE_STRING StrObfDereferenceObject = { 0 };                                                              //
                                                                                                                 //
    StrObfDereferenceObject.Buffer = L"ObfDereferenceObject";                                                    //
                                                                                                                 //
    StrObfDereferenceObject.Length = (USHORT)((wcslen(StrObfDereferenceObject.Buffer)) * 2);                     //
                                                                                                                 //
    StrObfDereferenceObject.MaximumLength = (StrObfDereferenceObject.Length + 2);                                //
                                                                                                                 //
    UNICODE_STRING StrExQueueWorkItem = { 0 };                                                                   //
                                                                                                                 //
    StrExQueueWorkItem.Buffer = L"ExQueueWorkItem";                                                              //
                                                                                                                 //
    StrExQueueWorkItem.Length = (USHORT)((wcslen(StrExQueueWorkItem.Buffer)) * 2);                               //
                                                                                                                 //
    StrExQueueWorkItem.MaximumLength = (StrExQueueWorkItem.Length + 2);                                          //
                                                                                                                 //
    // ==========================================================================================================++
                                                                                                                   
    // KdDebuggerBlock BlockVars ===========================================================================================================================================++                          
                                                                                                                                                                            //
    UNICODE_STRING StrKeCapturePersistentThreadState = { 0 };                                                                                                               //
                                                                                                                                                                            //
    StrKeCapturePersistentThreadState.Buffer = L"KeCapturePersistentThreadState";                                                                                           //
                                                                                                                                                                            //
    StrKeCapturePersistentThreadState.Length = (USHORT)((wcslen(StrKeCapturePersistentThreadState.Buffer)) * 2);                                                            //
                                                                                                                                                                            //
    StrKeCapturePersistentThreadState.MaximumLength = (StrKeCapturePersistentThreadState.Length + 2);                                                                       //
                                                                                                                                                                            //
    PVOID pKeCapturePersistentThreadState = NULL;                                                                                                                           //
                                                                                                                                                                            //
    CONST UCHAR INIT_THEIA_CTX_KECAPTUREPERSISTENTTHREADSTATE_SUBSIG[] =                                                                                                    //
    {                                                                                                                                                                       //
      0x48, 0x89, 0x83, 0x80, 0x00, 0x00, 0x00,                   // mov     qword ptr[rbx + 80h], rax                                                                      //
      0xc7, 0x83, 0x70, 0x20, 0x00, 0x00, 0x80, 0x20, 0x00, 0x00, // mov     dword ptr[rbx + 2070h], 2080h                                                                  //
      0xc7, 0x83, 0x74, 0x20, 0x00, 0x00, 0xa0, 0x03, 0x00, 0x00  // mov     dword ptr[rbx + 2074h], 3A0h                                                                   //
    };                                                                                                                                                                      //
    CONST UCHAR INIT_THEIA_CTX_KECAPTUREPERSISTENTTHREADSTATE_SUBSIG_MASK[] = { "xxxxxxxxxxxxxxxxxxxxxxxxxxx" };                                                            //
                                                                                                                                                                            //
    VOID(__fastcall* pKdCopyDataBlock)(PKDDEBUGGER_DATA64 pKdDebuggerDataBlockDec);                                                                                         //
    PKDDEBUGGER_DATA64 pKdDebuggerDataBlockDec = NULL;                                                                                                                      //
                                                                                                                                                                            //
    // =====================================================================================================================================================================++    
                                                                                                                                                                              
    if (g_pTheiaCtx)
    {
        DbgLog("[TheiaPg <->] InitTheiaContext: Attempt double init gTheiaCtx\n");

        DieDispatchIntrnlError(ERROR_DOUBLE_INIT_THEIA_CONTEXT);
    }

    if (__readcr8() > DISPATCH_LEVEL)
    {
        DbgLog("[TheiaPg <->] InitTheiaContext: Inadmissible IRQL\n");

        DieDispatchIntrnlError(ERROR_INIT_THEIA_CONTEXT);
    }

    // AllocateGTheiaCtx ========================================================================================================================================================++
                                                                                                                                                                                 //
    pExAllocatePool2 = (PVOID)MmGetSystemRoutineAddress(&StrExAllocatePool2);                                                                                                    //
                                                                                                                                                                                 //                                                                                                                                                          
    g_pTheiaCtx = (PTHEIA_CONTEXT)pExAllocatePool2(POOL_FLAG_NON_PAGED, (PAGE_SIZE * ((((0x1000 - 1) + sizeof(THEIA_CONTEXT)) & ~(0x1000 - 1)) / PAGE_SIZE)), EX_GEN_ALLOC_TAG); //
                                                                                                                                                                                 //
    if (!g_pTheiaCtx)                                                                                                                                                            //
    {                                                                                                                                                                            //
        DbgLog("[TheiaPg <->] InitTheiaContext: Unsuccessful alloc page for gTheiaCtx\n");                                                                                       //
                                                                                                                                                                                 //
        DieDispatchIntrnlError(ERROR_INIT_THEIA_CONTEXT);                                                                                                                        //
    }                                                                                                                                                                            //
                                                                                                                                                                                 //
    // ==========================================================================================================================================================================++

    g_pDieNonLargePage = pExAllocatePool2(POOL_FLAG_NON_PAGED, PAGE_SIZE, EX_GEN_ALLOC_TAG);
    
    if (!g_pDieNonLargePage)                                                                                                                                                     
    {                                                                                                                                                                           
        DbgLog("[TheiaPg <->] InitTheiaContext: Unsuccessful alloc page for gDieNonLargePage\n");                                                                                       
        
        DieDispatchIntrnlError(ERROR_INIT_THEIA_CONTEXT);                                                                                                                       
    }

    g_pSpiiNonLargePage = pExAllocatePool2(POOL_FLAG_NON_PAGED, PAGE_SIZE, EX_GEN_ALLOC_TAG);

    if (!g_pSpiiNonLargePage)
    {
        DbgLog("[TheiaPg <->] InitTheiaContext: Unsuccessful alloc page for gSpiiNonLargePage\n");

        DieDispatchIntrnlError(ERROR_INIT_THEIA_CONTEXT);
    }

    //
    // Initialization A2-Block
    //
    InitTheiaMetaDataBlock(&g_pTheiaCtx->TheiaMetaDataBlock);

    //
    // Initialization A0-Block
    //
    g_pTheiaCtx->pKiExecuteAllDpcs = _SearchPatternInImg(NULL, SPII_NO_OPTIONAL, PsInitialSystemProcess, ".text", NULL, g_pTheiaCtx->TheiaMetaDataBlock.KIEXECUTEALLDPCS_SIG, g_pTheiaCtx->TheiaMetaDataBlock.KIEXECUTEALLDPCS_MASK);

    if (!g_pTheiaCtx->pKiExecuteAllDpcs)
    {
        DbgLog("[TheiaPg <->] InitTheiaContext: BaseVA KiExecuteAllDpcs not found\n");

        DieDispatchIntrnlError(ERROR_INIT_THEIA_CONTEXT);
    }

    g_pTheiaCtx->pKiRetireDpcList = _SearchPatternInImg(NULL, SPII_NO_OPTIONAL, PsInitialSystemProcess, ".text", NULL, g_pTheiaCtx->TheiaMetaDataBlock.KIRETIREDPCLIST_SIG, g_pTheiaCtx->TheiaMetaDataBlock.KIRETIREDPCLIST_MASK);

    if (!g_pTheiaCtx->pKiRetireDpcList)
    {
        DbgLog("[TheiaPg <->] InitTheiaContext: BaseVA KiRetireDpcList not found\n");

        DieDispatchIntrnlError(ERROR_INIT_THEIA_CONTEXT);
    }

    g_pTheiaCtx->pKiDeliverApc = _SearchPatternInImg(NULL, SPII_NO_OPTIONAL, PsInitialSystemProcess, ".text", NULL, g_pTheiaCtx->TheiaMetaDataBlock.KIDELIVERAPC_SIG, g_pTheiaCtx->TheiaMetaDataBlock.KIDELIVERAPC_MASK);

    if (!g_pTheiaCtx->pKiDeliverApc)
    {
        DbgLog("[TheiaPg <->] InitTheiaContext: BaseVA KiDeliverApc not found\n");

        DieDispatchIntrnlError(ERROR_INIT_THEIA_CONTEXT);
    }

    g_pTheiaCtx->pKiCustomRecurseRoutineX = _SearchPatternInImg(NULL, SPII_NO_OPTIONAL, PsInitialSystemProcess, ".text", NULL, g_pTheiaCtx->TheiaMetaDataBlock.KICUSTOMRECURSEROUTINEX_SIG, g_pTheiaCtx->TheiaMetaDataBlock.KICUSTOMRECURSEROUTINEX_MASK);

    if (!g_pTheiaCtx->pKiCustomRecurseRoutineX)
    {
        DbgLog("[TheiaPg <->] InitTheiaContext: BaseVA KiCustomRecurseRoutineX not found\n");

        DieDispatchIntrnlError(ERROR_INIT_THEIA_CONTEXT);
    }

    g_pTheiaCtx->pKiBalanceSetManagerDeferredRoutine = _SearchPatternInImg(NULL, SPII_NO_OPTIONAL, PsInitialSystemProcess, ".text", NULL, g_pTheiaCtx->TheiaMetaDataBlock.KIBALANCESETMANANGERDEFERREDROUTINE_SIG, g_pTheiaCtx->TheiaMetaDataBlock.KIBALANCESETMANANGERDEFERREDROUTINE_MASK);

    if (!g_pTheiaCtx->pKiBalanceSetManagerDeferredRoutine)
    {
        DbgLog("[TheiaPg <->] InitTheiaContext: BaseVA KiBalanceSetManagerDeferredRoutine not found\n");

        DieDispatchIntrnlError(ERROR_INIT_THEIA_CONTEXT);
    }

    g_pTheiaCtx->pKiBalanceSetManagerPeriodicDpc = _SearchPatternInImg(NULL, SPII_NO_OPTIONAL, PsInitialSystemProcess, ".text", NULL, &INIT_THEIA_CTX_KIUPDATETIME_SUBSIG, &INIT_THEIA_CTX_KIUPDATETIME_MASK);

    if (!g_pTheiaCtx->pKiBalanceSetManagerPeriodicDpc)
    {
        DbgLog("[TheiaPg <->] InitTheiaContext: BaseVA KiBalanceSetManagerPeriodicDpc not found\n");

        DieDispatchIntrnlError(ERROR_INIT_THEIA_CONTEXT);
    }
    else
    {
        (PUCHAR)g_pTheiaCtx->pKiBalanceSetManagerPeriodicDpc += 0x4d;

        SaveRel32Offset = *(PLONG32)(g_pTheiaCtx->pKiBalanceSetManagerPeriodicDpc);

        g_pTheiaCtx->pKiBalanceSetManagerPeriodicDpc = (((ULONG64)g_pTheiaCtx->pKiBalanceSetManagerPeriodicDpc + 4) + ((SaveRel32Offset < 0I32) ? ((LONG64)SaveRel32Offset | 0xffffffff00000000UI64) : (LONG64)SaveRel32Offset));
    }

    g_pTheiaCtx->pKiBalanceSetManagerPeriodicEvent = _SearchPatternInImg(NULL, SPII_NO_OPTIONAL, PsInitialSystemProcess, ".text", NULL, &INIT_THEIA_KEBALANCESETMANANGER_SUBSIG, &INIT_THEIA_KEBALANCESETMANANGER_MASK);

    if (!g_pTheiaCtx->pKiBalanceSetManagerPeriodicEvent)
    {
        DbgLog("[TheiaPg <->] InitTheiaContext: BaseVA KiBalanceSetManagerPeriodicEvent not found\n");

        DieDispatchIntrnlError(ERROR_INIT_THEIA_CONTEXT);
    }
    else
    {
        (PUCHAR)g_pTheiaCtx->pKiBalanceSetManagerPeriodicEvent += 0x4a;

        SaveRel32Offset = *(PLONG32)(g_pTheiaCtx->pKiBalanceSetManagerPeriodicEvent);

        g_pTheiaCtx->pKiBalanceSetManagerPeriodicEvent = (((ULONG64)g_pTheiaCtx->pKiBalanceSetManagerPeriodicEvent + 4) + ((SaveRel32Offset < 0I32) ? ((LONG64)SaveRel32Offset | 0xffffffff00000000UI64) : (LONG64)SaveRel32Offset));
    }

    g_pTheiaCtx->pKiMcaDeferredRecoveryService = _SearchPatternInImg(NULL, SPII_NO_OPTIONAL, PsInitialSystemProcess, ".text", NULL, g_pTheiaCtx->TheiaMetaDataBlock.KIMCADEFERREDRECOVERYSERVICE_SIG, g_pTheiaCtx->TheiaMetaDataBlock.KIMCADEFERREDRECOVERYSERVICE_MASK);

    if (!g_pTheiaCtx->pKiMcaDeferredRecoveryService)
    {
        DbgLog("[TheiaPg <->] InitTheiaContext: BaseVA KiMcaDeferredRecoveryService not found\n");

        DieDispatchIntrnlError(ERROR_INIT_THEIA_CONTEXT);
    }

    g_pTheiaCtx->pFsRtlUninitializeSmallMcb = _SearchPatternInImg(NULL, SPII_NO_OPTIONAL, PsInitialSystemProcess, "INITKDBG", NULL, g_pTheiaCtx->TheiaMetaDataBlock.FSRTLUNINITIALIZESMALLMCB_SIG, g_pTheiaCtx->TheiaMetaDataBlock.FSRTLUNINITIALIZESMALLMCB_MASK);

    if (!g_pTheiaCtx->pFsRtlUninitializeSmallMcb)
    {
        DbgLog("[TheiaPg <->] InitTheiaContext: BaseVA FsRtlUninitializeSmallMcb not found\n");

        DieDispatchIntrnlError(ERROR_INIT_THEIA_CONTEXT);
    }

    g_pTheiaCtx->pFsRtlTruncateSmallMcb = _SearchPatternInImg(NULL, SPII_NO_OPTIONAL, PsInitialSystemProcess, ".text", NULL, g_pTheiaCtx->TheiaMetaDataBlock.FSRTLTRUNCATESMALLMCB_SIG, g_pTheiaCtx->TheiaMetaDataBlock.FSRTLTRUNCATESMALLMCB_MASK);

    if (!g_pTheiaCtx->pFsRtlTruncateSmallMcb)
    {
        DbgLog("[TheiaPg <->] InitTheiaContext: BaseVA FsRtlTruncateSmallMcb not found\n");

        DieDispatchIntrnlError(ERROR_INIT_THEIA_CONTEXT);
    }

    g_pTheiaCtx->pKiDecodeMcaFault = _SearchPatternInImg(NULL, SPII_NO_OPTIONAL, PsInitialSystemProcess, ".text", NULL, g_pTheiaCtx->TheiaMetaDataBlock.KIDECODEMCAFAULT_SIG, g_pTheiaCtx->TheiaMetaDataBlock.KIDECODEMCAFAULT_MASK);

    if (!g_pTheiaCtx->pKiDecodeMcaFault)
    {
        DbgLog("[TheiaPg <->] InitTheiaContext: BaseVA KiDecodeMcaFault not found\n");

        DieDispatchIntrnlError(ERROR_INIT_THEIA_CONTEXT);
    }

    g_pTheiaCtx->pCcBcbProfiler = _SearchPatternInImg(NULL, SPII_NO_OPTIONAL, PsInitialSystemProcess, ".text", NULL, g_pTheiaCtx->TheiaMetaDataBlock.CCBCBPROFILER_SIG, g_pTheiaCtx->TheiaMetaDataBlock.CCBCBPROFILER_MASK);

    if (!g_pTheiaCtx->pCcBcbProfiler)
    {
        DbgLog("[TheiaPg <->] InitTheiaContext: BaseVA CcBcbProfiler not found\n");

        DieDispatchIntrnlError(ERROR_INIT_THEIA_CONTEXT);
    }

    g_pTheiaCtx->pCcBcbProfiler2 = _SearchPatternInImg(NULL, SPII_NO_OPTIONAL, PsInitialSystemProcess, "PAGE", NULL, g_pTheiaCtx->TheiaMetaDataBlock.CCBCBPROFILER2_SIG, g_pTheiaCtx->TheiaMetaDataBlock.CCBCBPROFILER2_MASK);

    if (!g_pTheiaCtx->pCcBcbProfiler2)
    {
        DbgLog("[TheiaPg <->] InitTheiaContext: BaseVA CcBcbProfiler2 not found\n");

        DieDispatchIntrnlError(ERROR_INIT_THEIA_CONTEXT);
    }

    g_pTheiaCtx->pKiDispatchCallout = _SearchPatternInImg(NULL, SPII_NO_OPTIONAL, PsInitialSystemProcess, ".text", NULL, g_pTheiaCtx->TheiaMetaDataBlock.KIDISPATCHCALLOUT_SIG, g_pTheiaCtx->TheiaMetaDataBlock.KIDISPATCHCALLOUT_MASK);

    if (!g_pTheiaCtx->pKiDispatchCallout)
    {
        DbgLog("[TheiaPg <->] InitTheiaContext: BaseVA KiDispatchCallout not found\n");

        DieDispatchIntrnlError(ERROR_INIT_THEIA_CONTEXT);;
    }

    g_pTheiaCtx->pMmAllocateIndependentPagesEx = _SearchPatternInImg(NULL, SPII_NO_OPTIONAL, PsInitialSystemProcess, "PAGE", NULL, g_pTheiaCtx->TheiaMetaDataBlock.MMALLOCATEINDEPENDENTPAGESEX_SIG, g_pTheiaCtx->TheiaMetaDataBlock.MMALLOCATEINDEPENDENTPAGESEX_MASK);

    if (!g_pTheiaCtx->pMmAllocateIndependentPagesEx)
    {
        DbgLog("[TheiaPg <->] InitTheiaContext: BaseVA MmAllocateIndependentPagesEx not found\n");

        DieDispatchIntrnlError(ERROR_INIT_THEIA_CONTEXT);
    }

    g_pTheiaCtx->pMmFreeIndependentPages = _SearchPatternInImg(NULL, SPII_NO_OPTIONAL, PsInitialSystemProcess, ".text", NULL, g_pTheiaCtx->TheiaMetaDataBlock.MMFREEINDEPENDENTPAGESEX_SIG, g_pTheiaCtx->TheiaMetaDataBlock.MMFREEINDEPENDENTPAGESEX_MASK);

    if (!g_pTheiaCtx->pMmFreeIndependentPages)
    {
        DbgLog("[TheiaPg <->] InitTheiaContext: BaseVA MmFreeIndependentPages not found\n");

        DieDispatchIntrnlError(ERROR_INIT_THEIA_CONTEXT);
    }

    __sidt(&IDTR);

    pSwKIDTENTRY64 = (PKIDTENTRY64)((PUCHAR)(*(PVOID*)(IDTR + 2)) + (0x10UI64 * 0x20UI64));

    pKiSwInterruptDispatch = (PVOID)((ULONG64)(pSwKIDTENTRY64->OffsetLow) | (((ULONG64)(pSwKIDTENTRY64->OffsetMiddle)) << 16UI16) | (((ULONG64)(pSwKIDTENTRY64->OffsetHigh)) << 32UI32));

    SaveRel32Offset = *(PLONG32)((PUCHAR)pKiSwInterruptDispatch + 0x3a0UI64);

    g_pTheiaCtx->pKiSwInterruptDispatch = (((ULONG64)pKiSwInterruptDispatch + 0x3a4UI64) + ((SaveRel32Offset < 0I32) ? ((LONG64)SaveRel32Offset | 0xffffffff00000000UI64) : (LONG64)SaveRel32Offset));

    SaveRel32Offset = *(PLONG32)((PUCHAR)g_pTheiaCtx->pKiSwInterruptDispatch + 0x20UI64);

    g_pTheiaCtx->ppMaxDataSize = (((ULONG64)g_pTheiaCtx->pKiSwInterruptDispatch + 0x24UI64) + ((SaveRel32Offset < 0I32) ? ((LONG64)SaveRel32Offset | 0xffffffff00000000UI64) : (LONG64)SaveRel32Offset));

    //
    // Initialization A3-Block
    //
    memcpy(&g_pTheiaCtx->PgXorRoutineSig, &PgXorRoutineSig, sizeof PgXorRoutineSig);

    //
    // Initialization A4-Block
    //
    g_pTheiaCtx->pKeIpiGenericCall               = MmGetSystemRoutineAddress(&StrKeIpiGenericCall);

    g_pTheiaCtx->pKeQueryActiveProcessorCountEx  = MmGetSystemRoutineAddress(&StrKeQueryActiveProcessorCountEx);

    g_pTheiaCtx->pMmGetPhysicalAddress           = MmGetSystemRoutineAddress(&StrMmGetPhysicalAddress);

    g_pTheiaCtx->pMmMapIoSpaceEx                 = MmGetSystemRoutineAddress(&StrMmMapIoSpaceEx);

    g_pTheiaCtx->pMmUnmapIoSpace                 = MmGetSystemRoutineAddress(&StrMmUnmapIoSpace);

    g_pTheiaCtx->pRtlLookupFunctionEntry         = MmGetSystemRoutineAddress(&StrRtlLookupFunctionEntry);

    g_pTheiaCtx->pPsLookupThreadByThreadId       = MmGetSystemRoutineAddress(&StrPsLookupThreadByThreadId);

    g_pTheiaCtx->pRtlVirtualUnwind               = MmGetSystemRoutineAddress(&StrRtlVirtualUnwind);

    g_pTheiaCtx->pKeInitializeApc                = MmGetSystemRoutineAddress(&StrKeInitializeApc);

    g_pTheiaCtx->pKeInsertQueueApc               = MmGetSystemRoutineAddress(&StrKeInsertQueueApc);

    g_pTheiaCtx->pKeDelayExecutionThread         = MmGetSystemRoutineAddress(&StrKeDelayExecutionThread);

    g_pTheiaCtx->pMmIsAddressValid               = MmGetSystemRoutineAddress(&StrMmIsAddressValid);

    g_pTheiaCtx->pMmIsNonPagedSystemAddressValid = MmGetSystemRoutineAddress(&StrMmIsNonPagedSystemAddressValid);

    g_pTheiaCtx->pExAllocatePool2                = pExAllocatePool2;

    g_pTheiaCtx->pExFreePoolWithTag              = MmGetSystemRoutineAddress(&StrExFreePoolWithTag);

    g_pTheiaCtx->pPsIsSystemThread               = MmGetSystemRoutineAddress(&StrPsIsSystemThread);

    g_pTheiaCtx->pObfDereferenceObject           = MmGetSystemRoutineAddress(&StrObfDereferenceObject);

    g_pTheiaCtx->pExQueueWorkItem                = MmGetSystemRoutineAddress(&StrExQueueWorkItem);

    //
    // Initialization A5-Block
    //                                                
    g_pTheiaCtx->pIoCancelIrp                    = MmGetSystemRoutineAddress(&StrIoCancelIrp);
                                                 
    g_pTheiaCtx->pKeBugCheckEx                   = MmGetSystemRoutineAddress(&StrKeBugCheckEx);

    //
    // Initialization A6-Block
    //
    g_pTheiaCtx->ppKiWaitNever = _SearchPatternInRegion(NULL, SPIR_NO_OPTIONAL, g_pTheiaCtx->pKiExecuteAllDpcs, &INIT_THEIA_CTX_KIEXECUTEALLDPCS_SUBSIG, &INIT_THEIA_CTX_KIEXECUTEALLDPCS_SUBSIG_MASK, &StopSig, sizeof StopSig);
                                                                                                                                                                                   
    if (!g_pTheiaCtx->ppKiWaitNever)                                                                                                                                                                                                        
    {                                                                                                                                                                                                                                       
        DbgLog("[TheiaPg <->] InitTheiaContext: SubSig for KiExecuteAllDpcs (KiWaitAlways/KiWaitNever) not found\n");                                                                                                                       
        
        DieDispatchIntrnlError(ERROR_INIT_THEIA_CONTEXT);                                                                                                                                                                                   
    }

    g_pTheiaCtx->ppKiWaitAlways = g_pTheiaCtx->ppKiWaitNever;
                                                                                                                                                                                                                                            
    g_pTheiaCtx->ppKiWaitNever = (g_pTheiaCtx->ppKiWaitNever = ((PUCHAR)g_pTheiaCtx->ppKiWaitNever - 8));                                                                                                                                   
    
    SaveRel32Offset = *((PLONG32)g_pTheiaCtx->ppKiWaitNever - 1);                                                                                                                                                                           
    
    g_pTheiaCtx->ppKiWaitNever = (((ULONG64)g_pTheiaCtx->ppKiWaitNever) + ((SaveRel32Offset < 0I32) ? ((LONG64)SaveRel32Offset | 0xffffffff00000000UI64) : (LONG64)SaveRel32Offset));                                                       

    g_pTheiaCtx->ppKiWaitAlways = (g_pTheiaCtx->ppKiWaitAlways = ((PUCHAR)g_pTheiaCtx->ppKiWaitAlways - 21));                                                                                                                               
    
    SaveRel32Offset = *((PLONG32)g_pTheiaCtx->ppKiWaitAlways - 1);                                                                                                                                                                          
    
    g_pTheiaCtx->ppKiWaitAlways = (((ULONG64)g_pTheiaCtx->ppKiWaitAlways) + ((SaveRel32Offset < 0I32) ? ((LONG64)SaveRel32Offset | 0xffffffff00000000UI64) : (LONG64)SaveRel32Offset));

    // Initialization A1/A7-Blocks =================================================================================================================================================================================================================================++
    //                                                                                                                                                                                                                                                              // 
                                                                                                                                                                                                                                                                    //
    pKeCapturePersistentThreadState = MmGetSystemRoutineAddress(&StrKeCapturePersistentThreadState);                                                                                                                                                                //
                                                                                                                                                                                                                                                                    //
    pKeCapturePersistentThreadState = _SearchPatternInRegion(NULL, SPIR_NO_OPTIONAL, pKeCapturePersistentThreadState, &INIT_THEIA_CTX_KECAPTUREPERSISTENTTHREADSTATE_SUBSIG, &INIT_THEIA_CTX_KECAPTUREPERSISTENTTHREADSTATE_SUBSIG_MASK, &StopSig, sizeof StopSig); //
                                                                                                                                                                                                                                                                    //
    if (!pKeCapturePersistentThreadState)                                                                                                                                                                                                                           //
    {                                                                                                                                                                                                                                                               //
        DbgLog("[TheiaPg <->] InitTheiaContext: SubSig for KeCapturePersistentThreadState (KdCopyDataBlock) not found\n");                                                                                                                                          //
                                                                                                                                                                                                                                                                    //
        DieDispatchIntrnlError(ERROR_INIT_THEIA_CONTEXT);                                                                                                                                                                                                           //
    }                                                                                                                                                                                                                                                               //
                                                                                                                                                                                                                                                                    //
    SaveRel32Offset = *(PLONG32)((PUCHAR)pKeCapturePersistentThreadState + 28);                                                                                                                                                                                     //
                                                                                                                                                                                                                                                                    //
    pKdCopyDataBlock = (((ULONG64)((PUCHAR)pKeCapturePersistentThreadState + 32)) + ((SaveRel32Offset < 0I32) ? ((LONG64)SaveRel32Offset | 0xffffffff00000000UI64) : (LONG64)SaveRel32Offset));                                                                     //
                                                                                                                                                                                                                                                                    //
    pKdDebuggerDataBlockDec = pExAllocatePool2(POOL_FLAG_NON_PAGED, (PAGE_SIZE * ((((0x1000 - 1) + sizeof(THEIA_CONTEXT)) & ~(0x1000 - 1)) / PAGE_SIZE)), 'UTR$');                                                                                                  //
                                                                                                                                                                                                                                                                    //
    if (!pKdDebuggerDataBlockDec)                                                                                                                                                                                                                                   //
    {                                                                                                                                                                                                                                                               // 
        DbgLog("[TheiaPg <->] InitTheiaContext: Unsuccessful alloc page for KdDebuggerDataBlockDec\n");                                                                                                                                                             //
                                                                                                                                                                                                                                                                    //
        DieDispatchIntrnlError(ERROR_INIT_THEIA_CONTEXT);                                                                                                                                                                                                           //
    }                                                                                                                                                                                                                                                               //
                                                                                                                                                                                                                                                                    //
    pKdCopyDataBlock(pKdDebuggerDataBlockDec);                                                                                                                                                                                                                      //
                                                                                                                                                                                                                                                                    //                                                                                                                                                                                                                                              
    //                                                                                                                                                                                                                                                              //                      
    // Initialization A1-Block                                                                                                                                                                                                                                      //                      
    //                                                                                                                                                                                                                                                              //                      
    g_pTheiaCtx->pKernelBase = pKdDebuggerDataBlockDec->KernBase;                                                                                                                                                                                                   //                      
                                                                                                                                                                                                                                                                    //                                                                                                                                                                                                                          
    // Initialization A7-Block ==================================================================================++                                                                                                                                                 //                      
                                                                                                                 //                                                                                                                                                 //                      
    g_pTheiaCtx->pMmPteBase = pKdDebuggerDataBlockDec->PteBase;                                                  //                                                                                                                                                 //                      
                                                                                                                 //                                                                                                                                                 //                      
    g_pTheiaCtx->pMmPdeBase = g_pTheiaCtx->pMmPteBase + ((g_pTheiaCtx->pMmPteBase >> 9UI64) & 0x7FFFFFFFFFUI64); //                                                                                                                                                 //                      
                                                                                                                 //                                                                                                                                                 //                      
    g_pTheiaCtx->pMmPpeBase = g_pTheiaCtx->pMmPdeBase + ((g_pTheiaCtx->pMmPdeBase >> 9UI64) & 0x3FFFFFF8UI64);   //                                                                                                                                                 //                      
                                                                                                                 //                                                                                                                                                 //                      
    g_pTheiaCtx->pMmPxeBase = g_pTheiaCtx->pMmPpeBase + ((g_pTheiaCtx->pMmPpeBase >> 9UI64) & 0x1FFFFFUI64);     //                                                                                                                                                 //
                                                                                                                 //                                                                                                                                                 //
    g_pTheiaCtx->pMmPxeSelf = ((g_pTheiaCtx->pMmPxeBase >> 9UI64) & 0xFFFUI64);                                  //                                                                                                                                                 //
                                                                                                                 //                                                                                                                                                 //
    // ==========================================================================================================++                                                                                                                                                 //
                                                                                                                                                                                                                                                                    //
    //                                                                                                                                                                                                                                                              //
    // =============================================================================================================================================================================================================================================================++
    
    g_pTheiaCtx->pExFreePoolWithTag(pKdDebuggerDataBlockDec, EX_GEN_ALLOC_TAG);

    g_pTheiaCtx->CompleteSignatureTC = COMPLETE_SIGNATURE_TC;

    return;
}

/*++
* Routine: CheckStatusTheiaCtx
*
* MaxIRQL: Any level
*
* Public/Private: Public
*
* @param NoParams
*
* Description: Checking current state gTheiaCtx.
--*/
VOID CheckStatusTheiaCtx(VOID)
{
    #define ERROR_THEIA_CTX_NOT_INIT 0xbb722de3UI32

    if (!g_pTheiaCtx)
    {
        DbgLog("[TheiaPg <->] CheckStatusTheiaCtx: gTheiaCtx is not allocate\n");

        DieDispatchIntrnlError(ERROR_THEIA_CTX_NOT_INIT);
    }
    else if (g_pTheiaCtx->CompleteSignatureTC != COMPLETE_SIGNATURE_TC)
    {
        DbgLog("[TheiaPg <->] CheckStatusTheiaCtx: gTheiaCtx is not complete\n");

        DieDispatchIntrnlError(ERROR_THEIA_CTX_NOT_INIT);
    }
    else { VOID; } ///< For clarity.
 
    return;
}
