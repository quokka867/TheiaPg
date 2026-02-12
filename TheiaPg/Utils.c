#include "LinkHeader.h"

/*++
* Routine: HeurisSearchKdpcInCtx
*
* MaxIRQL: Any level (If IRQL > DISPATCH_LEVEL then the input address must be NonPaged)
*
* Public/Private: Public
*
* @param Ctx: Pointer to _CONTEXT structure
*
* Description: Routine to check the _CONTEXT structure for found possibly BaseVa _KDPC.
--*/
PVOID _HeurisSearchKdpcInCtx(IN PCONTEXT pCtx)
{
    CheckStatusTheiaCtx();

    UCHAR CurrIrql = (UCHAR)__readcr8();

    if (!((CurrIrql <= DISPATCH_LEVEL) ? g_pTheiaCtx->pMmIsAddressValid(pCtx) : g_pTheiaCtx->pMmIsNonPagedSystemAddressValid(pCtx) || (((ULONG64)pCtx >> 47) != 0x1ffffUI64)))
    {
        DbgLog("[TheiaPg <->] HeurisSearchKdpcInCtx: Invalid Ctx\n\n");

        return NULL;
    }

    PULONG64 pKDPC = (PULONG64)&pCtx->Rax;

    for (UCHAR i = 0UI8; i < 16UI8; ++i, ++pKDPC)
    {
        if (!((CurrIrql <= DISPATCH_LEVEL) ? g_pTheiaCtx->pMmIsAddressValid((PVOID)(*pKDPC)) : g_pTheiaCtx->pMmIsNonPagedSystemAddressValid((PVOID)(*pKDPC)))) { continue; }

        if (((CurrIrql <= DISPATCH_LEVEL) ? g_pTheiaCtx->pMmIsAddressValid(((PKDPC)(*pKDPC))->DeferredRoutine) : g_pTheiaCtx->pMmIsNonPagedSystemAddressValid(((PKDPC)(*pKDPC))->DeferredRoutine)))
        {
            if (!((HrdGetPteInputVa(((PKDPC)(*pKDPC))->DeferredRoutine))->NoExecute)) { return *pKDPC; }
        }
    }

    return NULL;
}

/*++
* Routine: _IsSafeAddress
*
* MaxIRQL: DISPATCH_LEVEL (If IRQL > DISPATCH_LEVEL then the input address must be NonPaged)
*
* Public/Private: Public
*
* @param pVa: Verifiable address
*
* Description: Routine for checking the VA for belonging to one of the loaded kernel modules.
--*/
BOOLEAN _IsSafeAddress(IN PVOID pVa)
{
    #define ERROR_IS_SAFE_ADDRESS 0x43f77387UI32

    CheckStatusTheiaCtx();

    PKLDR_DATA_TABLE_ENTRY pCurrentNode = *(PVOID*)PsLoadedModuleList; ///< Skip dummy node.

    if (!((__readcr8() <= DISPATCH_LEVEL) ? g_pTheiaCtx->pMmIsAddressValid(pVa) : g_pTheiaCtx->pMmIsNonPagedSystemAddressValid(pVa) || (((ULONG64)pVa >> 47) != 0x1ffffUI64)))
    {
        DbgLog("_IsSafeAddress [-] Invalid VA | VA: 0x%I64X\n", pVa);

        DieDispatchIntrnlError(ERROR_IS_SAFE_ADDRESS);
    }
 
    do
    {
        if ((pVa >= pCurrentNode->DllBase) && (pVa <= (((PUCHAR)pCurrentNode->DllBase) + pCurrentNode->SizeOfImage))) { return TRUE; }

        else { pCurrentNode = pCurrentNode->InLoadOrderLinks.Flink; }

    } while (pCurrentNode != PsLoadedModuleList);

    return FALSE;
}
 
volatile PVOID g_pSpiiNonLargePage = NULL;

/*++
* Routine: _SearchPatternInImg
*
* MaxIRQL: Any level
* 
* Public/Private: Public
*
* @param OptionalData: Data array required for OPTIONAL modes
* 
* @param FlagsExecute: Execution modes
* 
* @param pEprocessTrgtImg: _EPROCESS structure target PE-Image
* 
* @param pNameSection: Name target section/segment in target PE-Image
* 
* @param pModuleName: Name module in target _EPROCESS
* 
* @param pSig: Signature
* 
* @param pMaskSig: Mask Signature
*
* Description: Routine for multifunctional analysis of the PE-Image windows.
--*/
PVOID _SearchPatternInImg(IN ULONG64 OptionalData[SPII_AMOUNT_OPTIONAL_DATA], IN ULONG32 FlagsExecute, IN PVOID pEprocessTrgtImg, IN PVOID pNameSection, IN PVOID pModuleName, IN PVOID pSig, IN PVOID pMaskSig)
{  
    #define SPII_LOCAL_CONTEXT_MMISADDRESSVALID 0

    #define SPII_LOCAL_CONTEXT_MMISNONPAGEDSYSTEMADDRESSVALID 1

    LONG32 SaveRel32Offset = 0I32;
    UCHAR CurrIrql = (UCHAR)__readcr8();
    BOOLEAN CurrIF = HrdGetIF();

    PVOID(__fastcall *SpiiCtx[2])(PVOID, ...) = { 0 }; ///< Routine is critical, so it should not depend on gTheiaCtx.

    PTHEIA_METADATA_BLOCK pLocalTMDB = g_pSpiiNonLargePage;
    BOOLEAN IsLocalCtx = FALSE;

    UNICODE_STRING StrMmIsAddressValid = { 0 };
    UNICODE_STRING StrMmIsNonPagedSystemAddressValid = { 0 };

    USHORT LengthModuleName = 0UI16;
    USHORT LenSIG = 0UI16;

    ULONG64 Cr3User = 0UI64;
    ULONG64 Cr3Kernel = __readcr3();

    PVOID pCurrentLdr = NULL;
    PVOID pDummyLdr = NULL;
    PVOID pBaseAddrModule = NULL;

    USHORT SizeOfOptionalHeaderNT = 0UI16;
    USHORT NumberOfSectionsNT = 0UI16;
    PIMAGE_SECTION_HEADER pCurrentSectionHeader = NULL;
    PUCHAR pBaseAddrExeRegion = NULL;

    UCHAR AccessMode = KernelMode; ///< UserMode-TablePages + KVAShadowing: not working.

    PVOID pResultVa = NULL;

    if (!g_pTheiaCtx) { IsLocalCtx = TRUE; }
    else { if (g_pTheiaCtx->CompleteSignatureTC != COMPLETE_SIGNATURE_TC) { IsLocalCtx = TRUE; } }

    if (IsLocalCtx)
    {
        if (!pLocalTMDB)
        {
            DbgLog("[TheiaPg <->] DieDispatchIntrnlError: Page for LocalTMDB is not allocate\n");

            goto Exit;
        }

        InitTheiaMetaDataBlock(pLocalTMDB);

        StrMmIsAddressValid.Buffer = L"MmIsAddressValid";

        StrMmIsAddressValid.Length = (USHORT)(wcslen(StrMmIsAddressValid.Buffer) * 2);

        StrMmIsAddressValid.MaximumLength = (StrMmIsAddressValid.Length + 2);

        SpiiCtx[SPII_LOCAL_CONTEXT_MMISADDRESSVALID] = MmGetSystemRoutineAddress(&StrMmIsAddressValid);

        StrMmIsNonPagedSystemAddressValid.Buffer = L"MmIsNonPagedSystemAddressValid";

        StrMmIsNonPagedSystemAddressValid.Length = (USHORT)(wcslen(StrMmIsNonPagedSystemAddressValid.Buffer) * 2);

        StrMmIsNonPagedSystemAddressValid.MaximumLength = (StrMmIsNonPagedSystemAddressValid.Length + 2);

        SpiiCtx[SPII_LOCAL_CONTEXT_MMISNONPAGEDSYSTEMADDRESSVALID] = MmGetSystemRoutineAddress(&StrMmIsNonPagedSystemAddressValid);
    }

    if (FlagsExecute & SPII_SCAN_CALLER_INPUT_ADDRESS)
    {
        if (FlagsExecute & SPII_SCAN_CALLER_INPUT_ADDRESS && (FlagsExecute & SPII_GET_BASE_MODULE || FlagsExecute & SPII_NO_OPTIONAL))
        {
            DbgLog("[TheiaPg <->] _SearchPatternInImg: Incorrect combination FlagsExecute | FlagsExecute: 0x%I32X\n", FlagsExecute);

            goto Exit;
        }
        else if (!OptionalData[SPII_INDEX_OPTIONAL_DATA_SCIA] ||
                 !((CurrIrql <= DISPATCH_LEVEL) ?
                 (IsLocalCtx ? SpiiCtx[SPII_LOCAL_CONTEXT_MMISADDRESSVALID] : g_pTheiaCtx->pMmIsAddressValid)(OptionalData[SPII_INDEX_OPTIONAL_DATA_SCIA]) :
                 (IsLocalCtx ? SpiiCtx[SPII_LOCAL_CONTEXT_MMISNONPAGEDSYSTEMADDRESSVALID] : g_pTheiaCtx->pMmIsNonPagedSystemAddressValid)(OptionalData[SPII_INDEX_OPTIONAL_DATA_SCIA]))
                 || (((ULONG64)OptionalData[SPII_INDEX_OPTIONAL_DATA_SCIA] >> 47) != 0x1ffffUI64))
        {
            DbgLog("[TheiaPg <->] _SearchPatternInImg: Invalid SCIA address | FlagsExecute: 0x%I32X\n", FlagsExecute);

            goto Exit;
        }
        else if (!pEprocessTrgtImg || !(IsLocalCtx ? SpiiCtx[SPII_LOCAL_CONTEXT_MMISNONPAGEDSYSTEMADDRESSVALID] : g_pTheiaCtx->pMmIsNonPagedSystemAddressValid)(pEprocessTrgtImg))
        {
            DbgLog("[TheiaPg <->] _SearchPatternInImg: Invalid VA EprocessTrgtImg\n");

            goto Exit;
        }
        else if (!pNameSection || !((CurrIrql <= DISPATCH_LEVEL) ?
                 (IsLocalCtx ? SpiiCtx[SPII_LOCAL_CONTEXT_MMISADDRESSVALID] : g_pTheiaCtx->pMmIsAddressValid)(pNameSection) :
                 (IsLocalCtx ? SpiiCtx[SPII_LOCAL_CONTEXT_MMISNONPAGEDSYSTEMADDRESSVALID] : g_pTheiaCtx->pMmIsNonPagedSystemAddressValid)(pNameSection))
                 || (((ULONG64)pNameSection >> 47) != 0x1ffffUI64))
        {
            DbgLog("[TheiaPg <->] _SearchPatternInImg: Invalid NameSection | FlagsExecute: 0x%I32X\n", FlagsExecute);

            goto Exit;
        }
        else if (pSig || pMaskSig)
        {
            DbgLog("[TheiaPg <->] _SearchPatternInImg: Incorrect combination flag SPII_SCAN_CALLER_INPUT_ADDRESS with (Sig || MaskSig) | FlagsExecute: 0x%I32X\n", FlagsExecute);

            goto Exit;
        }
        else { VOID; } ///< For clarity.     
    }
    else if (FlagsExecute & SPII_GET_BASE_MODULE)
    {
        if (FlagsExecute & SPII_GET_BASE_MODULE && (FlagsExecute & SPII_SCAN_CALLER_INPUT_ADDRESS || FlagsExecute & SPII_NO_OPTIONAL))
        {
            DbgLog("[TheiaPg <->] _SearchPatternInImg: Incorrect combination FlagsExecute | FlagsExecute: 0x%I32X\n", FlagsExecute);

            goto Exit;
        }
        else if (!pEprocessTrgtImg || !(IsLocalCtx ? SpiiCtx[SPII_LOCAL_CONTEXT_MMISNONPAGEDSYSTEMADDRESSVALID] : g_pTheiaCtx->pMmIsNonPagedSystemAddressValid)(pEprocessTrgtImg)
                 || (((ULONG64)pEprocessTrgtImg >> 47) != 0x1ffffUI64))
        {
            DbgLog("[TheiaPg <->] _SearchPatternInImg: Invalid VA EprocessTrgtImg\n");

            goto Exit;
        }
        else if (pNameSection)
        {
            DbgLog("[TheiaPg <->] _SearchPatternInImg: Incorrect combination flag SPII_GET_BASE_MODULE with NameSection\n");

            goto Exit;
        }
        else if (pSig || pMaskSig)
        {
            DbgLog("[[TheiaPg <->] _SearchPatternInImg: Incorrect combination flag SPII_GET_BASE_MODULE with (Sig || MaskSig)\n");
        }
        else { VOID; } ///< For clarity.    
    }
    else if (FlagsExecute & SPII_NO_OPTIONAL)
    {
        if (CurrIrql > DISPATCH_LEVEL)
        {
            DbgLog("[TheiaPg <->] _SearchPatternInImg: Inadmissible IRQL | FlagsExecute: 0x%I32X | IRQL: 0x%02X\n", FlagsExecute, CurrIrql);

            goto Exit;
        }

        if (FlagsExecute & SPII_NO_OPTIONAL && (FlagsExecute & SPII_GET_BASE_MODULE || FlagsExecute & SPII_SCAN_CALLER_INPUT_ADDRESS))
        {
            DbgLog("[TheiaPg <->] _SearchPatternInImg: Incorrect combination FlagsExecute | FlagsExecute: 0x%I32X\n", FlagsExecute);

            goto Exit;
        }
        else if (!pEprocessTrgtImg || !(IsLocalCtx ? SpiiCtx[SPII_LOCAL_CONTEXT_MMISNONPAGEDSYSTEMADDRESSVALID] : g_pTheiaCtx->pMmIsNonPagedSystemAddressValid)(pEprocessTrgtImg)
                 || (((ULONG64)pEprocessTrgtImg >> 47) != 0x1ffffUI64))
        {
            DbgLog("[TheiaPg <->] _SearchPatternInImg: Invalid VA EprocessTrgtImg\n");

            goto Exit;
        }
        else if (!pNameSection || !((CurrIrql <= DISPATCH_LEVEL) ?
                 (IsLocalCtx ? SpiiCtx[SPII_LOCAL_CONTEXT_MMISADDRESSVALID] : g_pTheiaCtx->pMmIsAddressValid)(pNameSection) :
                 (IsLocalCtx ? SpiiCtx[SPII_LOCAL_CONTEXT_MMISNONPAGEDSYSTEMADDRESSVALID] : g_pTheiaCtx->pMmIsNonPagedSystemAddressValid)(pNameSection))
                 || (((ULONG64)pNameSection >> 47) != 0x1ffffUI64))
        {
            DbgLog("[TheiaPg <->] _SearchPatternInImg: Invalid VA NameSection\n");

            goto Exit;
        }
        else if ((!pSig || !((CurrIrql <= DISPATCH_LEVEL) ?
                 (IsLocalCtx ? SpiiCtx[SPII_LOCAL_CONTEXT_MMISADDRESSVALID] : g_pTheiaCtx->pMmIsAddressValid)(pSig) :
                 (IsLocalCtx ? SpiiCtx[SPII_LOCAL_CONTEXT_MMISNONPAGEDSYSTEMADDRESSVALID] : g_pTheiaCtx->pMmIsNonPagedSystemAddressValid)(pSig))
                 || (((ULONG64)pSig >> 47) != 0x1ffffUI64))
                                           ||
                 (!pMaskSig || !((CurrIrql <= DISPATCH_LEVEL) ?
                 (IsLocalCtx ? SpiiCtx[SPII_LOCAL_CONTEXT_MMISADDRESSVALID] : g_pTheiaCtx->pMmIsAddressValid)(pMaskSig) :
                 (IsLocalCtx ? SpiiCtx[SPII_LOCAL_CONTEXT_MMISNONPAGEDSYSTEMADDRESSVALID] : g_pTheiaCtx->pMmIsNonPagedSystemAddressValid)(pMaskSig)))
                 || (((ULONG64)pMaskSig >> 47) != 0x1ffffUI64))
        {
            DbgLog("[TheiaPg <->] _SearchPatternInImg: Invalid VA Sig/MaskSig\n");

            goto Exit;
        }
        else { VOID; } ///< For clarity.

        if (!(LenSIG = strlen(pMaskSig)))
        {
            DbgLog("[TheiaPg <->] _SearchPatternInImg: Length Sig/Mask is NULL\n");

            goto Exit;
        }
    }
    else
    {
        DbgLog("[TheiaPg <->] _SearchPatternInImg: Unknown FlagsExecute | FlagsExecute: 0x%I32X\n", FlagsExecute);

        goto Exit;
    }
  
    if (*((PVOID*)((PUCHAR)pEprocessTrgtImg + (IsLocalCtx ? pLocalTMDB->EPROCESS_Peb_OFFSET : g_pTheiaCtx->TheiaMetaDataBlock.EPROCESS_Peb_OFFSET))))
    {
        AccessMode = UserMode;

        Cr3User = *((PULONG64)((PUCHAR)pEprocessTrgtImg + (IsLocalCtx ? pLocalTMDB->KPROCESS_DirectoryTableBase_OFFSET : g_pTheiaCtx->TheiaMetaDataBlock.KPROCESS_DirectoryTableBase_OFFSET)));

        if (CurrIF) { _disable(); }

        __writecr3(Cr3User);

        HrdClacx64();
    }
    
    if (pModuleName)
    {
        if (!pModuleName || !((CurrIrql <= DISPATCH_LEVEL) ?
            (IsLocalCtx ? SpiiCtx[SPII_LOCAL_CONTEXT_MMISADDRESSVALID] : g_pTheiaCtx->pMmIsAddressValid)(pModuleName) :
            (IsLocalCtx ? SpiiCtx[SPII_LOCAL_CONTEXT_MMISNONPAGEDSYSTEMADDRESSVALID] : g_pTheiaCtx->pMmIsNonPagedSystemAddressValid)(pModuleName))
            || (((ULONG64)pModuleName >> 47) != 0x1ffffUI64))
        {
            DbgLog("[TheiaPg <->] _SearchPatternInImg: Invalid VA ModuleName\n");

            goto Exit;
        }

        LengthModuleName = strlen(pModuleName);

        if (LengthModuleName < 4UI16)
        {
            DbgLog("[TheiaPg <->] _SearchPatternInImg: Incorrect length ModuleName\n");

            goto Exit;
        }

        if (!AccessMode)
        {
            pDummyLdr = PsLoadedModuleList;

            pCurrentLdr = *(PVOID*)pDummyLdr;
        }
        else
        {
            pDummyLdr = *(PVOID*)((PUCHAR)(*(PVOID*)((PUCHAR)(*(PVOID*)((PUCHAR)pEprocessTrgtImg + 
            (IsLocalCtx ? pLocalTMDB->EPROCESS_Peb_OFFSET : g_pTheiaCtx->TheiaMetaDataBlock.EPROCESS_Peb_OFFSET))) + (IsLocalCtx ? pLocalTMDB->PEB_Ldr_OFFSET : g_pTheiaCtx->TheiaMetaDataBlock.PEB_Ldr_OFFSET))) +
            (IsLocalCtx ? pLocalTMDB->PEB_LDR_DATA_InLoadOrderModuleList_OFFSET : g_pTheiaCtx->TheiaMetaDataBlock.PEB_LDR_DATA_InLoadOrderModuleList_OFFSET));

            pCurrentLdr = pDummyLdr;
        }

        do
        {
            for (ULONG32 i = 0UI32; i < LengthModuleName; ++i)
            {
                if (((UCHAR)(((PUNICODE_STRING)((PUCHAR)pCurrentLdr + (!AccessMode ? g_pTheiaCtx->TheiaMetaDataBlock.KLDR_DllName_OFFSET : g_pTheiaCtx->TheiaMetaDataBlock.LDR_DllName_OFFSET, FALSE)))->Buffer)[i]) != ((PUCHAR)pModuleName)[i])
                {
                    pCurrentLdr = *(PVOID*)pCurrentLdr;

                    goto Continue0;
                }
            }

            pBaseAddrModule = *(PVOID*)((PUCHAR)pCurrentLdr + (!AccessMode ? (IsLocalCtx ? pLocalTMDB->KLDR_DllBase_OFFSET : g_pTheiaCtx->TheiaMetaDataBlock.KLDR_DllBase_OFFSET) : (IsLocalCtx ? pLocalTMDB->LDR_DllBase_OFFSET : g_pTheiaCtx->TheiaMetaDataBlock.LDR_DllBase_OFFSET)));
         
            if (!(FlagsExecute & SPII_GET_BASE_MODULE))
            { 
                goto NoReturnBaseAddrModule;
            }
            else
            {
                if (AccessMode)
                {
                    __writecr3(Cr3Kernel);

                    if (CurrIF) { _enable(); }
                }

                return pBaseAddrModule;
            }

            Continue0: continue;

        } while (pCurrentLdr != pDummyLdr);

        DbgLog("[TheiaPg <->] _SearchPatternInImg: Base address module %s not found\n", (PUCHAR)pModuleName);

        goto Exit;
    }
    else
    {
        if (!AccessMode)
        {
            pBaseAddrModule = ((PKLDR_DATA_TABLE_ENTRY)(*((PVOID*)PsLoadedModuleList)))->DllBase;

            if (FlagsExecute & SPII_GET_BASE_MODULE)
            {
                return pBaseAddrModule;
            }
        }
        else
        {
            pBaseAddrModule = *((PVOID*)((PUCHAR)(*((PVOID*)((PUCHAR)(*((PVOID*)((PUCHAR)*((PVOID*)((PUCHAR)pEprocessTrgtImg +
            (IsLocalCtx ? pLocalTMDB->EPROCESS_Peb_OFFSET : g_pTheiaCtx->TheiaMetaDataBlock.EPROCESS_Peb_OFFSET))) +
            (IsLocalCtx ? pLocalTMDB->PEB_Ldr_OFFSET : g_pTheiaCtx->TheiaMetaDataBlock.PEB_Ldr_OFFSET)))) +
            (IsLocalCtx ? pLocalTMDB->PEB_LDR_DATA_InLoadOrderModuleList_OFFSET : g_pTheiaCtx->TheiaMetaDataBlock.PEB_LDR_DATA_InLoadOrderModuleList_OFFSET)))) +
            (IsLocalCtx ? pLocalTMDB->LDR_DllBase_OFFSET : g_pTheiaCtx->TheiaMetaDataBlock.LDR_DllBase_OFFSET)));

            if (FlagsExecute & SPII_GET_BASE_MODULE)
            {
                __writecr3(Cr3Kernel);

                if (CurrIF) { _enable(); }

                return pBaseAddrModule;
            }
        }
    }

    NoReturnBaseAddrModule:
  
    if (((PIMAGE_DOS_HEADER)pBaseAddrModule)->e_magic == 0x5a4dUI16)
    {
        if (*((PUSHORT)(((PUCHAR)pBaseAddrModule) + ((PIMAGE_DOS_HEADER)pBaseAddrModule)->e_lfanew)) == 0x4550UI32)
        {
            SizeOfOptionalHeaderNT = (((PIMAGE_FILE_HEADER)&((PIMAGE_NT_HEADERS64)(((PUCHAR)pBaseAddrModule) + ((PIMAGE_DOS_HEADER)pBaseAddrModule)->e_lfanew))->FileHeader)->SizeOfOptionalHeader);
            NumberOfSectionsNT = (((PIMAGE_FILE_HEADER)&((PIMAGE_NT_HEADERS64)(((PUCHAR)pBaseAddrModule) + ((PIMAGE_DOS_HEADER)pBaseAddrModule)->e_lfanew))->FileHeader)->NumberOfSections);

            pCurrentSectionHeader = ((PUCHAR)&(((PIMAGE_NT_HEADERS64)(((PUCHAR)pBaseAddrModule) + ((PIMAGE_DOS_HEADER)pBaseAddrModule)->e_lfanew))->OptionalHeader) + SizeOfOptionalHeaderNT);
        }
        else
        {
            DbgLog("[TheiaPg <->] _SearchPatternInImg: NT signature not found\n");

            goto Exit;
        }
    }
    else
    {
        DbgLog("[TheiaPg <->] _SearchPatternInImg: MZ signature not found\n");

        goto Exit;
    }

    for (ULONG32 i = 0UI32; ; ++i, (((PUCHAR)pCurrentSectionHeader) += 0x28))
    {
        for (ULONG32 j = 0UI32; ((PUCHAR)pNameSection)[j]; ++j)
        {
            if ((pCurrentSectionHeader->Name)[j] != ((PUCHAR)pNameSection)[j])
            {
                if (i == (NumberOfSectionsNT - 1))
                {
                    DbgLog("[TheiaPg <->] _SearchPatternInImg: section %s not found\n", ((PUCHAR)pNameSection));

                    goto Exit;
                }

                goto Continue1;
            }
        }

        pBaseAddrExeRegion = ((PUCHAR)pBaseAddrModule + pCurrentSectionHeader->VirtualAddress);

        break;

        Continue1: continue;
    }


    for (ULONG32 i = 0UI32, j = 0UI32; i < (pCurrentSectionHeader->Misc.VirtualSize - ((FlagsExecute & SPII_NO_OPTIONAL) ? LenSIG : 5UI16)); ++i, ++pBaseAddrExeRegion)
    {
        if (FlagsExecute & SPII_NO_OPTIONAL)
        {
            for (ULONG32 l = 0; l < LenSIG; ++l, ++j)
            {
                if (j >= 64UI32 && !(j % 64UI32))
                {
                    _mm_prefetch((((ULONG64)pBaseAddrExeRegion + j) & ~0x3f), PF_NON_TEMPORAL_LEVEL_ALL);

                    _mm_prefetch(((PUCHAR)pSig) + j, PF_NON_TEMPORAL_LEVEL_ALL);

                    _mm_prefetch(((PUCHAR)pMaskSig) + j, PF_NON_TEMPORAL_LEVEL_ALL);
                }
                else if (!j)
                {
                    _mm_prefetch(((ULONG64)pBaseAddrExeRegion & ~0x3f), PF_NON_TEMPORAL_LEVEL_ALL);

                    _mm_prefetch(pSig, PF_NON_TEMPORAL_LEVEL_ALL);

                    _mm_prefetch(pMaskSig, PF_NON_TEMPORAL_LEVEL_ALL);
                }
                else { VOID; } ///< For clarity.

                if (((PUCHAR)pMaskSig)[l] == 'x')
                {
                    if (pBaseAddrExeRegion[l] != ((PUCHAR)pSig)[l])
                    {
                        goto Continue2;
                    }
                }
            }

            pResultVa = pBaseAddrExeRegion;

            goto Exit;
        }
        else if (FlagsExecute & SPII_SCAN_CALLER_INPUT_ADDRESS)
        {
            _mm_prefetch(((ULONG64)pBaseAddrExeRegion & ~0x3f), PF_NON_TEMPORAL_LEVEL_ALL);
            
            if (*pBaseAddrExeRegion == 0xe8UI8)
            {
                SaveRel32Offset = *(PLONG32)(pBaseAddrExeRegion + 1UI64);

                if ((PVOID)(((ULONG64)pBaseAddrExeRegion + 5UI64) + ((SaveRel32Offset < 0UI32) ? ((LONG64)SaveRel32Offset | 0xffffffff00000000UI64) : (LONG64)SaveRel32Offset)) == (PVOID)(OptionalData[SPII_INDEX_OPTIONAL_DATA_SCIA]))
                {
                    pResultVa = pBaseAddrExeRegion;

                    goto Exit;
                }
            }
        }
        else { VOID; } ///< For clarity.      

      Continue2: continue;
    }

    Exit:

    if (AccessMode)
    {
        __writecr3(Cr3Kernel);

        HrdStacx64();

        if (CurrIF) { _enable(); }
    }

    return pResultVa;
}

/*++
* Routine: _SearchPatternInRegion
*
* MaxIRQL: Any level
*
* Public/Private: Public
*
* @param OptionalData: Data array required for OPTIONAL modes
*
* @param FlagsExecute: Execution modes
* 
* @param pRegionSearch: Base VA search
*
* @param pSig: Signature/Pattern
*
* @param pMaskSig: Mask Signature/Pattern
* 
* @param pStopSig: Signature of stop search
* 
* @param LenStopSig: Signature of stop search length
*
* Description: Routine for multifunctional analysis of the memory region.
--*/
PVOID _SearchPatternInRegion(IN ULONG64 OptionalData[SPIR_AMOUNT_OPTIONAL_DATA], IN ULONG32 FlagsExecute, IN PUCHAR pRegionSearch, IN PUCHAR pSig, IN PUCHAR pMaskSig, IN PUCHAR pStopSig, IN ULONG32 LenStopSig)
{
    #define SPIR_LOCAL_CONTEXT_MMISADDRESSVALID 0
    #define SPIR_LOCAL_CONTEXT_MMISNONPAGEDSYSTEMADDRESSVALID 1

    LONG32 SaveRel32Offset = 0I32;
    UCHAR CurrIrql = (UCHAR)__readcr8();

    PVOID(__fastcall *SpirCtx[2])(PVOID,...) = { 0 }; ///< Routine is critical, so it should not depend on gTheiaCtx.
    BOOLEAN IsLocalCtx = FALSE;

    UNICODE_STRING StrMmIsAddressValid = { 0 };
    UNICODE_STRING StrMmIsNonPagedSystemAddressValid = { 0 };

    ULONG64 LengthSig = 0UI64;

    BOOLEAN StopHit = FALSE;

    PVOID pResultVa = NULL;

    if (!g_pTheiaCtx) { IsLocalCtx = TRUE; } 
    else { if (g_pTheiaCtx->CompleteSignatureTC != COMPLETE_SIGNATURE_TC) { IsLocalCtx = TRUE; } }
    
    if (IsLocalCtx)
    {
        StrMmIsAddressValid.Buffer = L"MmIsAddressValid";

        StrMmIsAddressValid.Length = (USHORT)(wcslen(StrMmIsAddressValid.Buffer) * 2);

        StrMmIsAddressValid.MaximumLength = (StrMmIsAddressValid.Length + 2);

        SpirCtx[SPIR_LOCAL_CONTEXT_MMISADDRESSVALID] = MmGetSystemRoutineAddress(&StrMmIsAddressValid);

        StrMmIsNonPagedSystemAddressValid.Buffer = L"MmIsNonPagedSystemAddressValid";

        StrMmIsNonPagedSystemAddressValid.Length = (USHORT)(wcslen(StrMmIsNonPagedSystemAddressValid.Buffer) * 2);

        StrMmIsNonPagedSystemAddressValid.MaximumLength = (StrMmIsNonPagedSystemAddressValid.Length + 2);

        SpirCtx[SPIR_LOCAL_CONTEXT_MMISNONPAGEDSYSTEMADDRESSVALID] = MmGetSystemRoutineAddress(&StrMmIsNonPagedSystemAddressValid);
    }

    if (!pRegionSearch || !((CurrIrql <= DISPATCH_LEVEL) ?
        (IsLocalCtx ? SpirCtx[SPII_LOCAL_CONTEXT_MMISADDRESSVALID] : g_pTheiaCtx->pMmIsAddressValid)(pRegionSearch) :
        (IsLocalCtx ? SpirCtx[SPIR_LOCAL_CONTEXT_MMISNONPAGEDSYSTEMADDRESSVALID] : g_pTheiaCtx->pMmIsNonPagedSystemAddressValid)(pRegionSearch))
        || (((ULONG64)pRegionSearch >> 47) != 0x1ffffUI64))
    {
        DbgLog("[TheiaPg <->] _SearchPatternInRegion: Invalid RegionSearch\n");

        goto Exit;
    }

    if (FlagsExecute & SPIR_NO_OPTIONAL)
    {
        if ((!pSig || !((CurrIrql <= DISPATCH_LEVEL) ?
            (IsLocalCtx ? SpirCtx[SPII_LOCAL_CONTEXT_MMISADDRESSVALID] : g_pTheiaCtx->pMmIsAddressValid)(pSig) :
            (IsLocalCtx ? SpirCtx[SPIR_LOCAL_CONTEXT_MMISNONPAGEDSYSTEMADDRESSVALID] : g_pTheiaCtx->pMmIsNonPagedSystemAddressValid)(pSig))
            || (((ULONG64)pSig >> 47) != 0x1ffffUI64))
                                      || 
            (!pMaskSig || !((CurrIrql <= DISPATCH_LEVEL) ?
            (IsLocalCtx ? SpirCtx[SPII_LOCAL_CONTEXT_MMISADDRESSVALID] : g_pTheiaCtx->pMmIsAddressValid)(pMaskSig) :
            (IsLocalCtx ? SpirCtx[SPIR_LOCAL_CONTEXT_MMISNONPAGEDSYSTEMADDRESSVALID] : g_pTheiaCtx->pMmIsNonPagedSystemAddressValid)(pMaskSig)))
            || (((ULONG64)pMaskSig >> 47) != 0x1ffffUI64))
        {
            DbgLog("[TheiaPg <->] _SearchPatternInRegion: Invalid Sig/MaskSig\n");

            goto Exit;
        }

        LengthSig = strlen(pMaskSig);
    }
    else if (FlagsExecute & SPIR_SCAN_CALLER_INPUT_ADDRESS)
    {
        if (!OptionalData[SPIR_INDEX_OPTIONAL_DATA_SCIA] || !((CurrIrql <= DISPATCH_LEVEL) ?
            (IsLocalCtx ? SpirCtx[SPII_LOCAL_CONTEXT_MMISADDRESSVALID] : g_pTheiaCtx->pMmIsAddressValid)(OptionalData[SPIR_INDEX_OPTIONAL_DATA_SCIA]) :
            (IsLocalCtx ? SpirCtx[SPIR_LOCAL_CONTEXT_MMISNONPAGEDSYSTEMADDRESSVALID] : g_pTheiaCtx->pMmIsNonPagedSystemAddressValid)(OptionalData[SPIR_INDEX_OPTIONAL_DATA_SCIA]))
            || !(((ULONG64)OptionalData[SPIR_INDEX_OPTIONAL_DATA_SCIA] >> 47) == 0x1ffffUI64))
        {
            DbgLog("[TheiaPg <->] _SearchPatternInRegion: Invalid address SPIR_SCAN_CALLER_INPUT_ADDRESS\n");

            goto Exit;
        }
        else if (pSig || pMaskSig)
        {
            DbgLog("[TheiaPg <->] _SearchPatternInRegion: Combination SPIR_SCAN_CALLER_INPUT_ADDRESS with Sig/Mask\n");

            goto Exit;
        }
    }
    else
    {
        DbgLog("[TheiaPg <->] _SearchPatternInRegion: Unknown FlagsExecute | FlagsExecute: 0x%I32X\n", FlagsExecute);

        goto Exit;
    }

    if (!LenStopSig || !((CurrIrql <= DISPATCH_LEVEL) ?
        (IsLocalCtx ? SpirCtx[SPII_LOCAL_CONTEXT_MMISADDRESSVALID] : g_pTheiaCtx->pMmIsAddressValid)(pStopSig) :
        (IsLocalCtx ? SpirCtx[SPIR_LOCAL_CONTEXT_MMISNONPAGEDSYSTEMADDRESSVALID] : g_pTheiaCtx->pMmIsNonPagedSystemAddressValid)(pStopSig))
        || (((ULONG64)pStopSig >> 47) != 0x1ffffUI64))
    {
        DbgLog("[TheiaPg <->] _SearchPatternInRegion: Invalid StopSig/LenStopSig\n");

        goto Exit;
    }

    for(; ; ++pRegionSearch)
    {
        for (ULONG32 i = 0UI32; ; ++i) 
        { 
            if (pStopSig[i] != pRegionSearch[i])
            {
                break; 
            }

            if (i == (LenStopSig - 1))
            {
                StopHit = TRUE;
            }      
        }

        if (StopHit) { break; }

        if (FlagsExecute & SPIR_NO_OPTIONAL)
        {
            for (ULONG32 i = 0UI32; i < LengthSig; ++i)
            {
                if (pMaskSig[i] == 'x' && pRegionSearch[i] != pSig[i])
                {
                    goto Continue0;
                }
            }

            pResultVa = pRegionSearch;

            goto Exit;
        }
        else if (FlagsExecute & SPIR_SCAN_CALLER_INPUT_ADDRESS)
        {
            if (*pRegionSearch == 0xe8UI8)
            {
                SaveRel32Offset = *(PLONG32)(pRegionSearch + 1UI64);

                if ((PVOID)(((ULONG64)pRegionSearch + 5UI64) + ((SaveRel32Offset < 0UI32) ? ((LONG64)SaveRel32Offset | 0xffffffff00000000UI64) : (LONG64)SaveRel32Offset)) == (PVOID)(OptionalData[SPIR_INDEX_OPTIONAL_DATA_SCIA]))
                {
                    pResultVa = pRegionSearch;

                    goto Exit;
                }
            }
        }
        else { VOID; } ///< For clarity.

      Continue0: continue;
    }

    Exit:

    if (StopHit) { DbgLog("[TheiaPg <->] _SearchPatternInRegion: StopHit is TRUE\n"); }

    return pResultVa;
}
