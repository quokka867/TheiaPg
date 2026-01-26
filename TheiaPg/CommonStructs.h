#pragma once

#include "LinkHeader.h"

typedef struct _DBGKD_DEBUG_DATA_HEADER64 {

    //
    // Link to other blocks
    //

    LIST_ENTRY64 List;

    //
    // This is a unique tag to identify the owner of the block.
    // If your component only uses one pool tag, use it for this, too.
    //

    ULONG           OwnerTag;

    //
    // This must be initialized to the size of the data block,
    // including this structure.
    //

    ULONG           Size;

} DBGKD_DEBUG_DATA_HEADER64, *PDBGKD_DEBUG_DATA_HEADER64;

typedef struct _KDDEBUGGER_DATA64 {

    DBGKD_DEBUG_DATA_HEADER64 Header;

    //
    // Base address of kernel image
    //

    ULONG64   KernBase;

    //
    // DbgBreakPointWithStatus is a function which takes an argument
    // and hits a breakpoint.  This field contains the address of the
    // breakpoint instruction.  When the debugger sees a breakpoint
    // at this address, it may retrieve the argument from the first
    // argument register, or on x86 the eax register.
    //

    ULONG64   BreakpointWithStatus;       // address of breakpoint

    //
    // Address of the saved context record during a bugcheck
    //
    // N.B. This is an automatic in KeBugcheckEx's frame, and
    // is only valid after a bugcheck.
    //

    ULONG64   SavedContext;

    //
    // help for walking stacks with user callbacks:
    //

    //
    // The address of the thread structure is provided in the
    // WAIT_STATE_CHANGE packet.  This is the offset from the base of
    // the thread structure to the pointer to the kernel stack frame
    // for the currently active usermode callback.
    //

    USHORT  ThCallbackStack;            // offset in thread data

    //
    // these values are offsets into that frame:
    //

    USHORT  NextCallback;               // saved pointer to next callback frame
    USHORT  FramePointer;               // saved frame pointer

    //
    // pad to a quad boundary
    //
    USHORT  PaeEnabled : 1;
    USHORT  KiBugCheckRecoveryActive : 1; // Windows 10 Manganese Addition
    USHORT  PagingLevels : 4;

    //
    // Address of the kernel callout routine.
    //

    ULONG64   KiCallUserMode;             // kernel routine

    //
    // Address of the usermode entry point for callbacks.
    //

    ULONG64   KeUserCallbackDispatcher;   // address in ntdll


    //
    // Addresses of various kernel data structures and lists
    // that are of interest to the kernel debugger.
    //

    ULONG64   PsLoadedModuleList;
    ULONG64   PsActiveProcessHead;
    ULONG64   PspCidTable;

    ULONG64   ExpSystemResourcesList;
    ULONG64   ExpPagedPoolDescriptor;
    ULONG64   ExpNumberOfPagedPools;

    ULONG64   KeTimeIncrement;
    ULONG64   KeBugCheckCallbackListHead;
    ULONG64   KiBugcheckData;

    ULONG64   IopErrorLogListHead;

    ULONG64   ObpRootDirectoryObject;
    ULONG64   ObpTypeObjectType;

    ULONG64   MmSystemCacheStart;
    ULONG64   MmSystemCacheEnd;
    ULONG64   MmSystemCacheWs;

    ULONG64   MmPfnDatabase;
    ULONG64   MmSystemPtesStart;
    ULONG64   MmSystemPtesEnd;
    ULONG64   MmSubsectionBase;
    ULONG64   MmNumberOfPagingFiles;

    ULONG64   MmLowestPhysicalPage;
    ULONG64   MmHighestPhysicalPage;
    ULONG64   MmNumberOfPhysicalPages;

    ULONG64   MmMaximumNonPagedPoolInBytes;
    ULONG64   MmNonPagedSystemStart;
    ULONG64   MmNonPagedPoolStart;
    ULONG64   MmNonPagedPoolEnd;

    ULONG64   MmPagedPoolStart;
    ULONG64   MmPagedPoolEnd;
    ULONG64   MmPagedPoolInformation;
    ULONG64   MmPageSize;

    ULONG64   MmSizeOfPagedPoolInBytes;

    ULONG64   MmTotalCommitLimit;
    ULONG64   MmTotalCommittedPages;
    ULONG64   MmSharedCommit;
    ULONG64   MmDriverCommit;
    ULONG64   MmProcessCommit;
    ULONG64   MmPagedPoolCommit;
    ULONG64   MmExtendedCommit;

    ULONG64   MmZeroedPageListHead;
    ULONG64   MmFreePageListHead;
    ULONG64   MmStandbyPageListHead;
    ULONG64   MmModifiedPageListHead;
    ULONG64   MmModifiedNoWritePageListHead;
    ULONG64   MmAvailablePages;
    ULONG64   MmResidentAvailablePages;

    ULONG64   PoolTrackTable;
    ULONG64   NonPagedPoolDescriptor;

    ULONG64   MmHighestUserAddress;
    ULONG64   MmSystemRangeStart;
    ULONG64   MmUserProbeAddress;

    ULONG64   KdPrintCircularBuffer;
    ULONG64   KdPrintCircularBufferEnd;
    ULONG64   KdPrintWritePointer;
    ULONG64   KdPrintRolloverCount;

    ULONG64   MmLoadedUserImageList;

    // NT 5.1 Addition

    ULONG64   NtBuildLab;
    ULONG64   KiNormalSystemCall;

    // NT 5.0 hotfix addition

    ULONG64   KiProcessorBlock;
    ULONG64   MmUnloadedDrivers;
    ULONG64   MmLastUnloadedDriver;
    ULONG64   MmTriageActionTaken;
    ULONG64   MmSpecialPoolTag;
    ULONG64   KernelVerifier;
    ULONG64   MmVerifierData;
    ULONG64   MmAllocatedNonPagedPool;
    ULONG64   MmPeakCommitment;
    ULONG64   MmTotalCommitLimitMaximum;
    ULONG64   CmNtCSDVersion;

    // NT 5.1 Addition

    ULONG64   MmPhysicalMemoryBlock;
    ULONG64   MmSessionBase;
    ULONG64   MmSessionSize;
    ULONG64   MmSystemParentTablePage;

    // Server 2003 addition

    ULONG64   MmVirtualTranslationBase;

    USHORT    OffsetKThreadNextProcessor;
    USHORT    OffsetKThreadTeb;
    USHORT    OffsetKThreadKernelStack;
    USHORT    OffsetKThreadInitialStack;

    USHORT    OffsetKThreadApcProcess;
    USHORT    OffsetKThreadState;
    USHORT    OffsetKThreadBStore;
    USHORT    OffsetKThreadBStoreLimit;

    USHORT    SizeEProcess;
    USHORT    OffsetEprocessPeb;
    USHORT    OffsetEprocessParentCID;
    USHORT    OffsetEprocessDirectoryTableBase;

    USHORT    SizePrcb;
    USHORT    OffsetPrcbDpcRoutine;
    USHORT    OffsetPrcbCurrentThread;
    USHORT    OffsetPrcbMhz;

    USHORT    OffsetPrcbCpuType;
    USHORT    OffsetPrcbVendorString;
    USHORT    OffsetPrcbProcStateContext;
    USHORT    OffsetPrcbNumber;

    USHORT    SizeEThread;

    UCHAR     L1tfHighPhysicalBitIndex;  // Windows 10 19H1 Addition
    UCHAR     L1tfSwizzleBitIndex;       // Windows 10 19H1 Addition

    ULONG     Padding0;

    ULONG64   KdPrintCircularBufferPtr;
    ULONG64   KdPrintBufferSize;

    ULONG64   KeLoaderBlock;

    USHORT    SizePcr;
    USHORT    OffsetPcrSelfPcr;
    USHORT    OffsetPcrCurrentPrcb;
    USHORT    OffsetPcrContainedPrcb;

    USHORT    OffsetPcrInitialBStore;
    USHORT    OffsetPcrBStoreLimit;
    USHORT    OffsetPcrInitialStack;
    USHORT    OffsetPcrStackLimit;

    USHORT    OffsetPrcbPcrPage;
    USHORT    OffsetPrcbProcStateSpecialReg;
    USHORT    GdtR0Code;
    USHORT    GdtR0Data;

    USHORT    GdtR0Pcr;
    USHORT    GdtR3Code;
    USHORT    GdtR3Data;
    USHORT    GdtR3Teb;

    USHORT    GdtLdt;
    USHORT    GdtTss;
    USHORT    Gdt64R3CmCode;
    USHORT    Gdt64R3CmTeb;

    ULONG64   IopNumTriageDumpDataBlocks;
    ULONG64   IopTriageDumpDataBlocks;

    // Longhorn addition

    ULONG64   VfCrashDataBlock;
    ULONG64   MmBadPagesDetected;
    ULONG64   MmZeroedPageSingleBitErrorsDetected;

    // Windows 7 addition

    ULONG64   EtwpDebuggerData;
    USHORT    OffsetPrcbContext;

    // Windows 8 addition

    USHORT    OffsetPrcbMaxBreakpoints;
    USHORT    OffsetPrcbMaxWatchpoints;

    ULONG     OffsetKThreadStackLimit;
    ULONG     OffsetKThreadStackBase;
    ULONG     OffsetKThreadQueueListEntry;
    ULONG     OffsetEThreadIrpList;

    USHORT    OffsetPrcbIdleThread;
    USHORT    OffsetPrcbNormalDpcState;
    USHORT    OffsetPrcbDpcStack;
    USHORT    OffsetPrcbIsrStack;

    USHORT    SizeKDPC_STACK_FRAME;

    // Windows 8.1 Addition

    USHORT    OffsetKPriQueueThreadListHead;
    USHORT    OffsetKThreadWaitReason;

    // Windows 10 RS1 Addition

    USHORT    Padding1;
    ULONG64   PteBase;

    // Windows 10 RS5 Addition

    ULONG64   RetpolineStubFunctionTable;
    ULONG     RetpolineStubFunctionTableSize;
    ULONG     RetpolineStubOffset;
    ULONG     RetpolineStubSize;

    // Windows 10 Iron Addition

    USHORT OffsetEProcessMmHotPatchContext;

    // Windows 11 Cobalt Addition

    ULONG   OffsetKThreadShadowStackLimit;
    ULONG   OffsetKThreadShadowStackBase;
    ULONG64 ShadowStackEnabled;

    // Windows 11 Nickel Addition

    ULONG64 PointerAuthMask;
    USHORT  OffsetPrcbExceptionStack;

} KDDEBUGGER_DATA64, *PKDDEBUGGER_DATA64;

typedef struct _LDR_DATA_TABLE_ENTRY
{
    struct _LIST_ENTRY InLoadOrderLinks;                                    
    struct _LIST_ENTRY InMemoryOrderLinks;                                  
    struct _LIST_ENTRY InInitializationOrderLinks;                          
    VOID* DllBase;                                                          
    VOID* EntryPoint;                                                       
    ULONG SizeOfImage;                                                      
    struct _UNICODE_STRING FullDllName;                                     
    struct _UNICODE_STRING BaseDllName;                                     
}LDR_DATA_TABLE_ENTRY,*PLDR_DATA_TABLE_ENTRY;


typedef struct _KLDR_DATA_TABLE_ENTRY
{
    struct _LIST_ENTRY InLoadOrderLinks;                                    
    VOID* ExceptionTable;                                                   
    ULONG ExceptionTableSize;                                               
    VOID* GpValue;                                                          
    struct _NON_PAGED_DEBUG_INFO* NonPagedDebugInfo;                        
    VOID* DllBase;                                                          
    VOID* EntryPoint;                                                       
    ULONG SizeOfImage;                                                      
    struct _UNICODE_STRING FullDllName;                                     
    struct _UNICODE_STRING BaseDllName;                                     
}KLDR_DATA_TABLE_ENTRY, * PKLDR_DATA_TABLE_ENTRY;

typedef struct _IMAGE_DOS_HEADER
{
    USHORT e_magic;                                                         
    USHORT e_cblp;                                                          
    USHORT e_cp;                                                            
    USHORT e_crlc;                                                          
    USHORT e_cparhdr;                                                       
    USHORT e_minalloc;                                                      
    USHORT e_maxalloc;                                                      
    USHORT e_ss;                                                            
    USHORT e_sp;                                                            
    USHORT e_csum;                                                          
    USHORT e_ip;                                                            
    USHORT e_cs;                                                            
    USHORT e_lfarlc;                                                        
    USHORT e_ovno;                                                          
    USHORT e_res[4];                                                        
    USHORT e_oemid;                                                         
    USHORT e_oeminfo;                                                       
    USHORT e_res2[10];                                                      
    LONG e_lfanew;                                                          
}IMAGE_DOS_HEADER, * PIMAGE_DOS_HEADER;

typedef struct _IMAGE_FILE_HEADER
{
    USHORT Machine;                                                         
    USHORT NumberOfSections;                                                
    ULONG TimeDateStamp;                                                    
    ULONG PointerToSymbolTable;                                             
    ULONG NumberOfSymbols;                                                  
    USHORT SizeOfOptionalHeader;                                            
    USHORT Characteristics;                                                 
}IMAGE_FILE_HEADER, * PIMAGE_FILE_HEADER;

typedef struct _IMAGE_DATA_DIRECTORY
{
    ULONG VirtualAddress;                                                   
    ULONG Size;                                                             
}IMAGE_DATA_DIRECTORY, * PIMAGE_DATA_DIRECTORY;

typedef struct _IMAGE_OPTIONAL_HEADER64
{
    USHORT Magic;                                                           
    UCHAR MajorLinkerVersion;                                               
    UCHAR MinorLinkerVersion;                                               
    ULONG SizeOfCode;                                                       
    ULONG SizeOfInitializedData;                                            
    ULONG SizeOfUninitializedData;                                          
    ULONG AddressOfEntryPoint;                                              
    ULONG BaseOfCode;                                                       
    ULONGLONG ImageBase;                                                    
    ULONG SectionAlignment;                                                 
    ULONG FileAlignment;                                                    
    USHORT MajorOperatingSystemVersion;                                     
    USHORT MinorOperatingSystemVersion;                                     
    USHORT MajorImageVersion;                                               
    USHORT MinorImageVersion;                                               
    USHORT MajorSubsystemVersion;                                           
    USHORT MinorSubsystemVersion;                                           
    ULONG Win32VersionValue;                                                
    ULONG SizeOfImage;                                                      
    ULONG SizeOfHeaders;                                                    
    ULONG CheckSum;                                                         
    USHORT Subsystem;                                                       
    USHORT DllCharacteristics;                                              
    ULONGLONG SizeOfStackReserve;                                           
    ULONGLONG SizeOfStackCommit;                                            
    ULONGLONG SizeOfHeapReserve;                                            
    ULONGLONG SizeOfHeapCommit;                                             
    ULONG LoaderFlags;                                                      
    ULONG NumberOfRvaAndSizes;                                              
    struct _IMAGE_DATA_DIRECTORY DataDirectory[16];                         
}IMAGE_OPTIONAL_HEADER64, * PIMAGE_OPTIONAL_HEADER64;

typedef struct _IMAGE_NT_HEADERS64
{
    ULONG Signature;                                                        
    struct _IMAGE_FILE_HEADER FileHeader;                                   
    struct _IMAGE_OPTIONAL_HEADER64 OptionalHeader;                         
}IMAGE_NT_HEADERS64, *PIMAGE_NT_HEADERS64;

typedef struct _IMAGE_SECTION_HEADER
{
    UCHAR Name[8];                                                          
    union
    {
        ULONG PhysicalAddress;                                              
        ULONG VirtualSize;                                                  
    } Misc;                                                                 
    ULONG VirtualAddress;                                                   
    ULONG SizeOfRawData;                                                    
    ULONG PointerToRawData;                                                 
    ULONG PointerToRelocations;                                             
    ULONG PointerToLinenumbers;                                             
    USHORT NumberOfRelocations;                                             
    USHORT NumberOfLinenumbers;                                             
    ULONG Characteristics;                                                  


}IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;

typedef struct _MMPTE_HARDWARE
{
    ULONGLONG Valid : 1;                                                    
    ULONGLONG Dirty1 : 1;                                                   
    ULONGLONG Owner : 1;                                                    
    ULONGLONG WriteThrough : 1;                                             
    ULONGLONG CacheDisable : 1;                                             
    ULONGLONG Accessed : 1;                                                 
    ULONGLONG Dirty : 1;                                                    
    ULONGLONG LargePage : 1;                                                
    ULONGLONG Global : 1;                                                   
    ULONGLONG CopyOnWrite : 1;                                              
    ULONGLONG Unused : 1;                                                   
    ULONGLONG Write : 1;                                                    
    ULONGLONG PageFrameNumber : 40;                                         
    ULONGLONG ReservedForSoftware : 4;                                      
    ULONGLONG WsleAge : 4;                                                  
    ULONGLONG WsleProtection : 3;                                           
    ULONGLONG NoExecute : 1;                                                
}MMPTE_HARDWARE, *PMMPTE_HARDWARE;

typedef union _KIDTENTRY64 
{
    struct 
    {
        USHORT OffsetLow;                                                   
        USHORT Selector;                                                    
        USHORT IstIndex : 3;                                                
        USHORT Reserved0 : 5;                                               
        USHORT Type : 5;                                                    
        USHORT Dpl : 2;                                                     
        USHORT Present : 1;                                                 
        USHORT OffsetMiddle;                                                
        ULONG OffsetHigh;                                                   
        ULONG Reserved1;                                                    
    };                                                                      
    ULONGLONG Alignment;                                                    
} KIDTENTRY64, * PKIDTENTRY64;

typedef struct _KAPC_TRUE 
{
    UCHAR Type;                                                             
    union
    {
        UCHAR AllFlags;                                                     
        struct
        {
            UCHAR CallbackDataContext : 1;                                  
            UCHAR Unused : 7;                                               
        };
    };
    UCHAR Size;                                                             
    UCHAR SpareByte1;                                                       
    ULONG SpareLong0;                                                       
    VOID* Thread;                                                           
    struct _LIST_ENTRY ApcListEntry;                                        
    union
    {
        struct
        {
            VOID(*KernelRoutine)(struct _KAPC* arg1, VOID(**arg2)(VOID* arg1, VOID* arg2, VOID* arg3), VOID** arg3, VOID** arg4, VOID** arg5); 
            VOID(*RundownRoutine)(struct _KAPC* arg1);                      
            VOID(*NormalRoutine)(VOID* arg1, VOID* arg2, VOID* arg3);       
        };
        VOID* Reserved[3];                                                  
    };
    VOID* NormalContext;                                                    
    VOID* SystemArgument1;                                                  
    VOID* SystemArgument2;                                                  
    CHAR ApcStateIndex;                                                     
    CHAR ApcMode;                                                           
    UCHAR Inserted;                                                         

}KAPC_TRUE, *PKAPC_TRUE;

typedef struct _KDPC_DATA
{
    struct _SINGLE_LIST_ENTRY DpcList;
    ULONGLONG DpcLock;
    volatile LONG DpcQueueDepth;
    ULONG DpcCount;
    struct _KDPC* volatile ActiveDpc;
    ULONG LongDpcPresent;
    ULONG Padding;
}KDPC_DATA, *PKDPC_DATA;

typedef struct _KTIMER_TABLE_ENTRY
{
    ULONGLONG Lock;                                                         //0x0
    struct _LIST_ENTRY Entry;                                               //0x8
    union _ULARGE_INTEGER Time;                                             //0x18
}KTIMER_TABLE_ENTRY, *PKTIMER_TABLE_ENTRY;

typedef struct _KTIMER_TABLE
{
    struct _KTIMER* TimerExpiry[64];                                        //0x0
    struct _KTIMER_TABLE_ENTRY TimerEntries[2][256];                        //0x200
                         
}KTIMER_TABLE, *PKTIMER_TABLE;

typedef struct _THEIA_METADATA_BLOCK
{
    ULONG32 KPCR_TssBase_OFFSET;
    ULONG32 KPCR_Prcb_OFFSET;
    ULONG32 KPRCB_CurrentThread_OFFSET;
    ULONG32 KPRCB_IdleThread_OFFSET;
    ULONG32 KPRCB_HalReserved;
    ULONG32 KPRCB_AcpiReserved;
    ULONG32 KPRCB_DpcData0_OFFSET;
    ULONG32 KPRCB_DpcData1_OFFSET;
    ULONG32 KPRCB_TimerTable;
    ULONG32 ETHREAD_Cid_OFFSET;
    ULONG32 ETHREAD_Win32StartAddress_OFFSET;
    ULONG32 CLIENT_ID_UniqueProcess_OFFSET;
    ULONG32 CLIENT_ID_UniqueThread_OFFSET;
    ULONG32 KTHREAD_InitialStack_OFFSET;
    ULONG32 KTHREAD_StackLimit_OFFSET;
    ULONG32 KTHREAD_StackBase_OFFSET;
    ULONG32 KTHREAD_KernelStack_OFFSET;
    ULONG32 KTHREAD_MiscFlags_OFFSET;
    ULONG32 KTHREAD_ApcState_OFFSET;
    ULONG32 KTHREAD_ContextSwitches_OFFSET;
    ULONG32 KTHREAD_WaitTime_OFFSET;
    ULONG32 KTHREAD_KernelTime_OFFSET;
    ULONG32 KTHREAD_CombinedApcDisable_OFFSET;
    ULONG32 KTHREAD_ThreadListEntry_OFFSET;
    ULONG32 KAPC_STATE_ApcListHead0_OFFSET;
    ULONG32 KAPC_STATE_ApcListHead1_OFFSET;
    ULONG32 EPROCESS_KPROCESS_OFFSET;
    ULONG32 EPROCESS_ActiveProcessLinks_OFFSET;
    ULONG32 EPROCESS_Peb_OFFSET;
    ULONG32 EPROCESS_ImageFileName_OFFSET;
    ULONG32 EPROCESS_ThreadListHead;
    ULONG32 EPROCESS_ProtectionEprocess_OFFSET;
    ULONG32 KPROCESS_DirectoryTableBase_OFFSET;
    ULONG32 PEB_Ldr_OFFSET;
    ULONG32 PEB_LDR_DATA_InLoadOrderModuleList_OFFSET;
    ULONG32 KLDR_InLoadOrderList_OFFSET;
    ULONG32 KLDR_DllBase_OFFSET;
    ULONG32 KLDR_DllName_OFFSET;
    ULONG32 LDR_InLoadOrderList_OFFSET;
    ULONG32 LDR_DllBase_OFFSET;
    ULONG32 LDR_DllName_OFFSET;

    ULONG64 Alignment0;

    PVOID   KIEXECUTEALLDPCS_SIG;
    PVOID   KIEXECUTEALLDPCS_MASK;
    PVOID   KIEXECUTEALLDPCS_HANDLER;
    PVOID   KIEXECUTEALLDPCS_LEN_HANDLER;
    ULONG32 KIEXECUTEALLDPCS_HOOK_ALIGNMENT;

    PVOID   KIRETIREDPCLIST_SIG;
    PVOID   KIRETIREDPCLIST_MASK;
    PVOID   KIRETIREDPCLIST_HANDLER;
    PVOID   KIRETIREDPCLIST_LEN_HANDLER;
    ULONG32 KIRETIREDPCLIST_HOOK_ALIGNMENT;

    PVOID   EXALLOCATEPOOL2_SIG;
    PVOID   EXALLOCATEPOOL2_MASK;
    PVOID   EXALLOCATEPOOL2_HANDLER;
    PVOID   EXALLOCATEPOOL2_LEN_HANDLER;
    ULONG32 EXALLOCATEPOOL2_HOOK_ALIGNMENT;

    PVOID   KICUSTOMRECURSEROUTINEX_SIG;
    PVOID   KICUSTOMRECURSEROUTINEX_MASK;
    PVOID   KICUSTOMRECURSEROUTINEX_HANDLER;
    PVOID   KICUSTOMRECURSEROUTINEX_LEN_HANDLER;
    ULONG32 KICUSTOMRECURSEROUTINEX_HOOK_ALIGNMENT;

    PVOID KIMCADEFERREDRECOVERYSERVICE_SIG;
    PVOID KIMCADEFERREDRECOVERYSERVICE_MASK;

    PVOID FSRTLUNINITIALIZESMALLMCB_SIG;
    PVOID FSRTLUNINITIALIZESMALLMCB_MASK;

    PVOID FSRTLTRUNCATESMALLMCB_SIG;
    PVOID FSRTLTRUNCATESMALLMCB_MASK;

    PVOID KIDECODEMCAFAULT_SIG;
    PVOID KIDECODEMCAFAULT_MASK;

    PVOID CCBCBPROFILER_SIG;
    PVOID CCBCBPROFILER_MASK;

    PVOID CCBCBPROFILER2_SIG;
    PVOID CCBCBPROFILER2_MASK;

    PVOID KIDISPATCHCALLOUT_SIG;
    PVOID KIDISPATCHCALLOUT_MASK;

    PVOID MMALLOCATEINDEPENDENTPAGESEX_SIG;
    PVOID MMALLOCATEINDEPENDENTPAGESEX_MASK;

    PVOID MMFREEINDEPENDENTPAGESEX_SIG;
    PVOID MMFREEINDEPENDENTPAGESEX_MASK;

}THEIA_METADATA_BLOCK, * PTHEIA_METADATA_BLOCK;

typedef struct _THEIA_CONTEXT
{  
    ULONG64 CompleteSignatureTC;

    //
    // A0-Block.
    //
    PVOID pKiExecuteAllDpcs;
    PVOID pKiRetireDpcList;
    PVOID pKiCustomRecurseRoutineX; ///< IsPgRoutine | Callers: pKiCustomAccessRoutineX | Executed from IsrDispatchLevelExecuteCtx.

    //
    // The engineers of the PatchGuard component, for some reason unknown to me, did not add __noreturn for KiScanQueues/KiSchedulerDpc (Callers KiMcaDeferredRecoveryService), 
    // so 0xc3 fix.
    // 
    // Example ->
    // call    ntkrnlmp!KiMcaDeferredRecoveryService (fffff8018fcace70)
    // add     rsp, 30h
    // pop     rbx
    // ret
    // <- 
    //
    PVOID pKiMcaDeferredRecoveryService; ///< IsPgRoutine | Callers: KiScanQueues/KiSchedulerDpc                   | Executed from IsrDispatchLevelExecuteCtx.

    PVOID pFsRtlUninitializeSmallMcb;    ///< IsPgRoutine | Callers: In early versions of PG KiMachineCheckControl | Executed from IsrDispatchLevelExecuteCtx.
    PVOID pFsRtlTruncateSmallMcb;        ///< IsPgRoutine | Callers: KiInterruptThunk                              | Executed from IsrDispatchLevelExecuteCtx.
    PVOID pKiDecodeMcaFault;             ///< IsPgRoutine | Callers: KiMachineCheckControl                         | Executed from IsrDispatchLevelExecuteCtx.                      
    PVOID pCcBcbProfiler;                ///< IsPgRoutine | Callers: Handler _KTIMER/_KDPC                         | Executed from IsrDispatchLevelExecuteCtx.
    PVOID pCcBcbProfiler2;               ///< IsPgRoutine | Callers: Handler _KTIMER/_KDPC                         | Executed from IsrDispatchLevelExecuteCtx.
    PVOID pKiDispatchCallout;            ///< IsPgRoutine | Callers: KiDeliverApc                                  | Executed from IsrApcLevelExecuteCtx.

    //
    // To prevent dead recursion when using ExAllocatePool2 with VsrExAllocatePool2.
    //
    PVOID (__fastcall* pMmAllocateIndependentPagesEx)(unsigned __int64 a1, int a2, __int64 a3, unsigned int a4); 
    PVOID (__fastcall* pMmFreeIndependentPages) (__int64 a1, __int64 a2, __int64 a3);

    PVOID pKiSwInterruptDispatch; ///< IsPgRoutine | Callers: KiSwInterrupt | Executed from Isr???LevelExecuteCtx.
    PVOID* ppMaxDataSize; ///< Global pointer to global PgCtx.

    //
    // A1-Block.
    //
    PVOID pKernelBase;

    //
    // A2-Block.
    //
    THEIA_METADATA_BLOCK TheiaMetaDataBlock;
   
    //
    // A3-Block.
    //
    UCHAR PgXorRoutineSig[52];
  
    //
    // A4-Block.
    //
    ULONG_PTR(__fastcall* pKeIpiGenericCall)(PVOID BroadcastFunction, ULONG_PTR Context);
    PHYSICAL_ADDRESS(__fastcall* pMmGetPhysicalAddress)(IN PVOID BaseAddress);
    PVOID(__fastcall* pMmMapIoSpaceEx)(IN PHYSICAL_ADDRESS PhysicalAddress, IN SIZE_T NumberOfBytes, ULONG Protect);
    VOID(__fastcall* pMmUnmapIoSpace)(IN PVOID BaseAddress,IN SIZE_T NumberOfBytes);
    PVOID(__stdcall* pRtlLookupFunctionEntry)(IN DWORD64 ControlPc, OUT PDWORD64 ImageBase, OUT PVOID HistoryTable);
    NTSTATUS(__fastcall* pPsLookupThreadByThreadId)(HANDLE ThreadId, PETHREAD* Thread);
    PEXCEPTION_ROUTINE(__fastcall* pRtlVirtualUnwind)(ULONG HandlerType, DWORD64 ImageBase,DWORD64  ControlPc,PVOID FunctionEntry,PCONTEXT ContextRecord,PVOID* HandlerData,PDWORD64 EstablisherFrame,PVOID ContextPointers);
    VOID(__fastcall* pKeInitializeApc)(PKAPC Apc, PKTHREAD Thread, PVOID Environment, PVOID KernelRoutine, PVOID RundownRoutine, PVOID NormalRoutine, KPROCESSOR_MODE ProcessorMode, PVOID NormalContext);
    BOOLEAN(__stdcall* pKeInsertQueueApc)(PKAPC Apc, PVOID SystemArgument1, PVOID SystemArgument2, KPRIORITY PriorityBoost);
    NTSTATUS(__stdcall* pKeDelayExecutionThread)(KPROCESSOR_MODE WaitMode, BOOLEAN Alertable, PLARGE_INTEGER Interval);
    BOOLEAN(__fastcall* pMmIsAddressValid)(PVOID VirtualAddress);
    BOOLEAN(__fastcall* pMmIsNonPagedSystemAddressValid)(PVOID VirtualAddress);
    PVOID(__stdcall* pExAllocatePool2)(POOL_FLAGS Flags, SIZE_T NumberOfBytes, ULONG Tag);
    BOOLEAN(__fastcall* pPsIsSystemThread)(PETHREAD Thread);
    LONG_PTR(__fastcall* pObfDereferenceObject)(PVOID Object);
    PVOID(__fastcall* pExFreePoolWithTag)(PVOID P, ULONG Tag);
  
    //
    // A5-Block.
    //
    PVOID pIoCancelIrp;
    PVOID pKeBugCheckEx;

    //
    // A6-Block.
    //
    PULONG64 ppKiWaitAlways;
    PULONG64 ppKiWaitNever;

    //
    // A7-Block.
    //
    ULONG64 pMmPteBase;
    ULONG64 pMmPdeBase;
    ULONG64 pMmPpeBase;
    ULONG64 pMmPxeBase;
    ULONG64 pMmPxeSelf;
                  
}THEIA_CONTEXT, *PTHEIA_CONTEXT;

typedef struct _INPUTCONTEXT_STUBAPCROUTINE
{
    ULONG64 rcx;
    ULONG64 rdx;
    ULONG64 rbx;
    ULONG64 rsi;
    ULONG64 rdi;
    ULONG64 r8;
    ULONG64 r9;
    ULONG64 r10;
    ULONG64 r11;
    ULONG64 r12;
    ULONG64 r13;
    ULONG64 r14;
    ULONG64 r15;
    ULONG64 rbp;
    ULONG64 rip;
    ULONG64 rsp;
    ULONG64 Rflags;
    ULONG64 rax;
    ULONG64 Reserved0; ///< Return address.

}INPUTCONTEXT_STUBAPCROUTINE, * PINPUTCONTEXT_STUBAPCROUTINE;

typedef struct _INPUTCONTEXT_ICT
{
    ULONG64 rcx;
    ULONG64 rdx;
    ULONG64 rbx;
    ULONG64 rsi;
    ULONG64 rdi;
    ULONG64 r8;
    ULONG64 r9;
    ULONG64 r10;
    ULONG64 r11;
    ULONG64 r12;
    ULONG64 r13;
    ULONG64 r14;
    ULONG64 r15;
    ULONG64 rbp;
    ULONG64 rip;
    ULONG64 rsp;
    ULONG64 Rflags;
    ULONG64 Reserved0; ///< Return address.
    ULONG64 rax;

}INPUTCONTEXT_ICT, * PINPUTCONTEXT_ICT;
