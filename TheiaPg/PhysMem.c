#include "LinkHeader.h"

/*++
* Routine: HrdIndpnRWVMemory
* 
* MaxIRQL: CLOCK_LEVEL
* 
* Public/Private: Public
* 
* @param FlagsExecute [MEM_INDPN_RW_READ_OP_BIT]: Read operation flag
* 
* @param FlagsExecute [MEM_INDPN_RW_WRITE_OP_BIT]: Write operation flag
* 
* @param Va: The target virtual address of physical memory
* 
* @param IoBufferMirror: I/O buffer for Read/Write
* 
* @param LengthRW: Length Read/Write
* 
* Description: Independent RW virtual memory.
--*/
VOID HrdIndpnRWVMemory(IN OUT PINDPN_RW_V_MEMORY_DATA pInputData)
{	
    #define ERROR_INPUTDATA_INVALID_V_MEMORY 0xd54812ddUI32
    #define ERROR_READ_V_MEMORY  0x848d7e65UI32
    #define ERROR_WRITE_V_MEMORY 0x0fa7049fUI32
	
	CheckStatusTheiaCtx();
	
	volatile static LONG32 SynchBarrier0 = 0I32;
	volatile static LONG32 SynchBarrier1 = 0I32;
	volatile static ULONG32 ActiveProcessorCount = 0UI32;
	volatile static ULONG32 ActiveProcessorCount2 = 0UI32;

	LONG32 SaveRel32Offset = 0I32;
	BOOLEAN OldIF = HrdGetIF();
	UCHAR CurrIrql = (UCHAR)__readcr8();
	PMMPTE_HARDWARE pPteInputVa = NULL;
	PVOID pMetaVPage = NULL;
	PMMPTE_HARDWARE pMetaVPagePte = NULL;
	ULONG64 SizeMetaVPage = 0UI64;
	ULONG64 FilteredConstsAfterCompute[6] = { 0 }; ///< [0/1/2]: MmBase???/Offset/Mask | [3]: Alignment | [4/5]: Mask/Mask
	
	//
	// For bypassing MiShowBadMapper - Windows 11 25H2
	//
	ULONG64 SaveGlobalVarsInMiShwBadMap[2] = { 0 };
	PBOOLEAN pKdPitchDebugger = NULL;
	PULONG64 pVfRuleClasses = NULL;
	
	PVOID pResultVa = NULL;

	if (SynchBarrier0 && CurrIrql != IPI_LEVEL)
	{
		DbgLog("[TheiaPg <->] HrdIndpnRWVMemory: Violation of execution integrity\n");

		if (pInputData->FlagsExecute & MEM_INDPN_RW_READ_OP_BIT) { DieDispatchIntrnlError(ERROR_READ_V_MEMORY); }
		else { DieDispatchIntrnlError(ERROR_WRITE_V_MEMORY); }
	}

	if (!(_interlockedbittestandset(&SynchBarrier0, 0I32)))
	{
		if (!pInputData || !((CurrIrql <= DISPATCH_LEVEL) ? g_pTheiaCtx->pMmIsAddressValid(pInputData) : g_pTheiaCtx->pMmIsNonPagedSystemAddressValid(pInputData) ||
			(((ULONG64)pInputData >> 47) != 0x1ffffUI64)))
		{
			DbgLog("[TheiaPg <->] HrdIndpnRWVMemory: Invalid InputData\n");

			DieDispatchIntrnlError(ERROR_INPUTDATA_INVALID_V_MEMORY);
		}

		if (CurrIrql > CLOCK_LEVEL)
		{
			DbgLog("[TheiaPg <->] HrdIndpnRWVMemory: Inadmissible IRQL | IRQL: 0x%02X\n", CurrIrql);

			if (pInputData->FlagsExecute & MEM_INDPN_RW_READ_OP_BIT) { DieDispatchIntrnlError(ERROR_READ_V_MEMORY); }
			else { DieDispatchIntrnlError(ERROR_WRITE_V_MEMORY); }
		}

		if ((pInputData->FlagsExecute & (MEM_INDPN_RW_READ_OP_BIT | MEM_INDPN_RW_WRITE_OP_BIT)) == (MEM_INDPN_RW_READ_OP_BIT | MEM_INDPN_RW_WRITE_OP_BIT))
		{
			DbgLog("[TheiaPg <->] HrdIndpnRWVMemory: Invalid FlagsExecute | FlagsExecute: 0x%I64X\n", pInputData->FlagsExecute);

			if (pInputData->FlagsExecute & MEM_INDPN_RW_READ_OP_BIT) { DieDispatchIntrnlError(ERROR_READ_V_MEMORY); }
			else { DieDispatchIntrnlError(ERROR_WRITE_V_MEMORY); }
		}
		else if (!pInputData->pVa || !((CurrIrql <= DISPATCH_LEVEL) ? g_pTheiaCtx->pMmIsAddressValid(pInputData->pVa) : g_pTheiaCtx->pMmIsNonPagedSystemAddressValid(pInputData->pVa) || 
			     (((ULONG64)pInputData->pVa >> 47) != 0x1ffffUI64)))
		{
			DbgLog("[TheiaPg <->] HrdIndpnRWVMemory: Invalid VA | VA: 0x%I64X\n", pInputData->pVa);

			if (pInputData->FlagsExecute & MEM_INDPN_RW_READ_OP_BIT) { DieDispatchIntrnlError(ERROR_READ_V_MEMORY); }
			else { DieDispatchIntrnlError(ERROR_WRITE_V_MEMORY); }
		}
		else if (!pInputData->pIoBuffer || !((CurrIrql <= DISPATCH_LEVEL) ? g_pTheiaCtx->pMmIsAddressValid(pInputData->pIoBuffer) : g_pTheiaCtx->pMmIsNonPagedSystemAddressValid(pInputData->pIoBuffer) ||
			     (((ULONG64)pInputData->pIoBuffer >> 47) != 0x1ffffUI64)))
		{
			DbgLog("[TheiaPg <->] HrdIndpnRWVMemory: Invalid InputBuffer\n");

			if (pInputData->FlagsExecute & MEM_INDPN_RW_READ_OP_BIT) { DieDispatchIntrnlError(ERROR_READ_V_MEMORY); }
			else { DieDispatchIntrnlError(ERROR_WRITE_V_MEMORY); }
		}
		else if (!pInputData->LengthRW)
		{
			DbgLog("[TheiaPg <->] HrdIndpnRWVMemory: Invalid LengthRW\n");

			if (pInputData->FlagsExecute & MEM_INDPN_RW_READ_OP_BIT) { DieDispatchIntrnlError(ERROR_READ_V_MEMORY); }
			else { DieDispatchIntrnlError(ERROR_WRITE_V_MEMORY); }
		}
		else { VOID; } ///< For clarity.

		ActiveProcessorCount = g_pTheiaCtx->pKeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);

		ActiveProcessorCount2 = ActiveProcessorCount;
	                                                      	                                        
		g_pTheiaCtx->pKeIpiGenericCall(&HrdIndpnRWVMemory, pInputData); 

		while (SynchBarrier0) { _mm_pause(); }

		goto Exit;
	}
	else
	{
		if (OldIF) { _disable(); }

		_InterlockedDecrement(&ActiveProcessorCount);

		while (ActiveProcessorCount) { _mm_pause(); }

		if (_interlockedbittestandset(&SynchBarrier1,0I32))
		{		
			while (SynchBarrier1) { _mm_pause(); }

			goto IpiExit;
		}
	}

	do
	{
		//
		// PXE is not included in the VA analysis because the probability of a 512-GB LargePage is extremely close to 0.
		//
		pPteInputVa = ((PMMPTE_HARDWARE)(g_pTheiaCtx->pMmPpeBase + (((ULONG64)pInputData->pVa >> 27UI64) & 0x1FFFF8UI64)));

		if (pPteInputVa->LargePage)
		{
			SizeMetaVPage = 0x40000000UI64;

			FilteredConstsAfterCompute[0] = g_pTheiaCtx->pMmPpeBase;

			FilteredConstsAfterCompute[1] = 27UI64;

			FilteredConstsAfterCompute[2] = 0x1FFFF8UI64;

			FilteredConstsAfterCompute[4] = ~0x3FFFFFFFUI64;

			FilteredConstsAfterCompute[5] = 0x3FFFFFFFUI64;

			break;
		}

		pPteInputVa = ((PMMPTE_HARDWARE)(g_pTheiaCtx->pMmPdeBase + (((ULONG64)pInputData->pVa >> 18) & 0x3FFFFFF8I64)));

		if (pPteInputVa->LargePage)
		{
			SizeMetaVPage = 0x200000UI64;

			FilteredConstsAfterCompute[0] = g_pTheiaCtx->pMmPdeBase;

			FilteredConstsAfterCompute[1] = 18;

			FilteredConstsAfterCompute[2] = 0x3FFFFFF8UI64;

			FilteredConstsAfterCompute[4] = ~0x1FFFFFUI64;

			FilteredConstsAfterCompute[5] = 0x1FFFFFUI64;

			break;
		}

		pPteInputVa = ((PMMPTE_HARDWARE)(g_pTheiaCtx->pMmPteBase + (((ULONG64)pInputData->pVa >> 9) & 0x7FFFFFFFF8UI64)));

		SizeMetaVPage = 0x1000UI64;

		FilteredConstsAfterCompute[0] = g_pTheiaCtx->pMmPteBase;

		FilteredConstsAfterCompute[1] = 9;

		FilteredConstsAfterCompute[2] = 0x7FFFFFFFF8UI64;

		FilteredConstsAfterCompute[4] = ~0x0FFFUI64;

		FilteredConstsAfterCompute[5] = 0x0FFFUI64;

		break;

	} while (FALSE);

	SaveGlobalVarsInMiShwBadMap[0] = *KdDebuggerNotPresent;

	*KdDebuggerNotPresent = 1I8;

	SaveRel32Offset = *(PLONG32)((PUCHAR)g_pTheiaCtx->pIoCancelIrp + 0x12);

	pVfRuleClasses = (PULONG64)(((PUCHAR)g_pTheiaCtx->pIoCancelIrp + 0x16) + ((SaveRel32Offset < 0I32) ? ((LONG64)SaveRel32Offset | 0xffffffff00000000UI64) : (LONG64)SaveRel32Offset));

	SaveGlobalVarsInMiShwBadMap[1] = *pVfRuleClasses;

	*pVfRuleClasses |= 0x400000UI64;

	                                                                            /* PaBaseVaSystemRange is used as a stub for mapping */
	                                                                            						/* | */
	                                                                            						/* # */
	pMetaVPage = (PVOID)g_pTheiaCtx->pMmMapIoSpaceEx(g_pTheiaCtx->pMmGetPhysicalAddress(g_pTheiaCtx->pKernelBase), SizeMetaVPage, PAGE_READWRITE | PAGE_NOCACHE);
	                                    /* ^ */
	                                    /* | */ 
	                    /* Important: the call takes place on IPI_LEVEL (With repeated debugging, this did not cause problems) */

	*KdDebuggerNotPresent = (BOOLEAN)(SaveGlobalVarsInMiShwBadMap[0]);

	*pVfRuleClasses = SaveGlobalVarsInMiShwBadMap[1];

	if (!pMetaVPage)
	{
		if (pInputData->FlagsExecute & MEM_INDPN_RW_READ_OP_BIT) { DieDispatchIntrnlError(ERROR_READ_V_MEMORY); }
		else { DieDispatchIntrnlError(ERROR_WRITE_V_MEMORY); }
	}

	pMetaVPagePte = (PMMPTE_HARDWARE)(FilteredConstsAfterCompute[0] + (((ULONG64)pMetaVPage >> FilteredConstsAfterCompute[1]) & FilteredConstsAfterCompute[2]));

	if (SizeMetaVPage != 0x1000UI64) { *(PULONG64)pMetaVPagePte |= 0x82UI64; } ///< LargePageBitFix | Dirty1BitFix

	pMetaVPagePte->PageFrameNumber = pPteInputVa->PageFrameNumber;

	pResultVa = (((ULONG64)pMetaVPage & FilteredConstsAfterCompute[4]) | ((ULONG64)pInputData->pVa & FilteredConstsAfterCompute[5]));

	__writecr3(__readcr3()); ///< Flush TLB.

	if (pInputData->FlagsExecute & MEM_INDPN_RW_READ_OP_BIT) { memcpy(pInputData->pIoBuffer, pResultVa, pInputData->LengthRW); }
	else { memcpy(pResultVa, pInputData->pIoBuffer, pInputData->LengthRW); }

	g_pTheiaCtx->pMmUnmapIoSpace(pMetaVPage, SizeMetaVPage);

	SynchBarrier1 = 0I32;

    IpiExit:

	_InterlockedDecrement(&ActiveProcessorCount2);

	while (ActiveProcessorCount2) { _mm_pause(); }

	SynchBarrier0 = 0I32;

	Exit:

	if (OldIF) { _enable(); }

	return;
}

/*++
* Routine: HrdPatchAttributesInputPte
*
* MaxIRQL: DISPATCH_LEVEL
* 
* Public/Private: Public
*
* @param AndMask: AndMask for PTE attributes
*
* @param OrMask: OrMask for PTE attributes
*
* @param Va: Target virtual address
* 
* Description: Allows you to change the attributes of the end PTE VA/GVA.
--*/
VOID HrdPatchAttributesInputPte(IN ULONG64 AndMask, IN ULONG64 OrMask, IN OUT PVOID pVa)
{
    #define ERROR_PATCH_PTE_ATTRIBUTES 0xdec74dfaUI32

	CheckStatusTheiaCtx();

	PMMPTE_HARDWARE pPteInputVa = NULL;

	if ((!AndMask && !OrMask) || (AndMask && OrMask))
	{
		DbgLog("[TheiaPg <->] HrdPatchAttributesInputPte: Invalid ???Mask\n");

		DieDispatchIntrnlError(ERROR_PATCH_PTE_ATTRIBUTES);
	}
	else if (!pVa || !((__readcr8() <= DISPATCH_LEVEL) ? g_pTheiaCtx->pMmIsAddressValid(pVa) : g_pTheiaCtx->pMmIsNonPagedSystemAddressValid(pVa) || !(((ULONG64)pVa >> 47) == 0x1ffffUI64)))
	{
		DbgLog("[TheiaPg <->] HrdPatchAttributesInputPte: Invalid VA | VA: 0x%I64X\n", pVa);

		DieDispatchIntrnlError(ERROR_PATCH_PTE_ATTRIBUTES);
	}
	else { VOID; } ///< For clarity.

	pPteInputVa = HrdGetPteInputVa(pVa);

	if (AndMask) { _InterlockedAnd64(pPteInputVa, AndMask); }
	else { _InterlockedOr64(pPteInputVa, OrMask); }

	__writecr3(__readcr3()); ///< Flush TLB.

	return;
}

/*++
* Routine: HrdGetPteInputVa
*
* MaxIRQL: Any level
*
* Public/Private: Public
*
* @param Va: Target virtual address
*
* Description: Getting Self-Mapp-PTE VA
--*/
PMMPTE_HARDWARE HrdGetPteInputVa(IN PVOID pVa)
{
    #define ERROR_GET_PTE_VA 0x11ecdf34UI32

	CheckStatusTheiaCtx();

	PMMPTE_HARDWARE pPteInputVa = NULL;

	if (!pVa || !((__readcr8() <= DISPATCH_LEVEL) ? g_pTheiaCtx->pMmIsAddressValid(pVa) : g_pTheiaCtx->pMmIsNonPagedSystemAddressValid(pVa) || !(((ULONG64)pVa >> 47) == 0x1ffffUI64)))
	{
		DbgLog("[TheiaPg <->] HrdGetPteInputVa: Invalid VA | VA: 0x%I64X\n", pVa);

		DieDispatchIntrnlError(ERROR_GET_PTE_VA);
	}

	//
	// PXE is not included in the VA analysis because the probability of a 512-GB LargePage is extremely close to 0.
	//
	pPteInputVa = ((PMMPTE_HARDWARE)(g_pTheiaCtx->pMmPpeBase + (((ULONG64)pVa >> 27UI64) & 0x1FFFF8UI64)));

	if (pPteInputVa->LargePage) { goto IsLargePte; }

	pPteInputVa = ((PMMPTE_HARDWARE)(g_pTheiaCtx->pMmPdeBase + (((ULONG64)pVa >> 18UI64) & 0x3FFFFFF8UI64)));

	if (pPteInputVa->LargePage) { goto IsLargePte; }

	pPteInputVa = ((PMMPTE_HARDWARE)(g_pTheiaCtx->pMmPteBase + (((ULONG64)pVa >> 9UI64) & 0x7FFFFFFFF8UI64)));

    IsLargePte:

	return pPteInputVa;
}
