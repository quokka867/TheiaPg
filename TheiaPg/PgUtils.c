#include "LinkHeader.h"

/*++
* Routine: SearchPgCtxInCtx 
*
* MaxIRQL: Any level (If IRQL > DISPATCH_LEVEL then the input address must be NonPaged)
*
* Public/Private: Public
*
* @param Ctx: Pointer to _CONTEXT structure
*
* Description: Routine to check the _CONTEXT structure for PgCtx.
--*/
PVOID SearchPgCtxInCtx(IN PCONTEXT pCtx)
{
	CheckStatusTheiaCtx();

	UCHAR CurrIrql = (UCHAR)__readcr8();

	if (!((CurrIrql <= DISPATCH_LEVEL) ? g_pTheiaCtx->pMmIsAddressValid(pCtx) : g_pTheiaCtx->pMmIsNonPagedSystemAddressValid(pCtx) || !(((ULONG64)pCtx >> 47) == 0x1ffffUI64)))
	{
		DbgLog("[TheiaPg <->] SearchPgCtxInCtx: Invalid Ctx\n\n");

		return NULL;
	}

	PULONG64 pPgCtx = (PULONG64)&pCtx->Rax;

	for (UCHAR i = 0UI8; i < 16UI8; ++i, ++pPgCtx)
	{
		if (!((CurrIrql <= DISPATCH_LEVEL) ? g_pTheiaCtx->pMmIsAddressValid(*pPgCtx) : g_pTheiaCtx->pMmIsNonPagedSystemAddressValid(*pPgCtx)) || !((*pPgCtx >> 47) == 0x1ffffUI64)) { continue; }

		if (!(memcmp(*pPgCtx, &g_pTheiaCtx->PgXorRoutineSig, sizeof(g_pTheiaCtx->PgXorRoutineSig)))) { return *(PVOID*)pPgCtx; }
	}

	return NULL;
}

/*++
* Routine: SearchKdpcInPgPrcbFields
*
* MaxIRQL: DISPATCH_LEVEL
*
* Public/Private: Public
*
* @param Ctx: Pointer to _CONTEXT structure
*
* Description: Routine for cleaning PgPrcbFields.
--*/
VOID SearchKdpcInPgPrcbFields(VOID)
{
    #define ERROR_IPI_CLEAR_PG_PRCB_FIELDS 0xcedfb673UI32

	CheckStatusTheiaCtx();

	BOOLEAN CurrIF = HrdGetIF();
	ULONG32 CurrCoreNum = (ULONG32)__readgsdword(g_pTheiaCtx->TheiaMetaDataBlock.KPCR_Prcb_OFFSET + g_pTheiaCtx->TheiaMetaDataBlock.KPRCB_Number_OFFSET);

	ULONG32 GsOffsetHalReserved = (g_pTheiaCtx->TheiaMetaDataBlock.KPCR_Prcb_OFFSET + g_pTheiaCtx->TheiaMetaDataBlock.KPRCB_HalReserved_OFFSET);
	ULONG32 GsOffsetAcpiReserved = (g_pTheiaCtx->TheiaMetaDataBlock.KPCR_Prcb_OFFSET + g_pTheiaCtx->TheiaMetaDataBlock.KPRCB_AcpiReserved_OFFSET);

	PKDPC pCurrentCheckKDPC = NULL;

	for (UCHAR i = 0UI8, j = 0UI8; i < 8; i++, j += 8)
	{
		pCurrentCheckKDPC = (PKDPC)__readgsqword(GsOffsetHalReserved + j);

		if ((g_pTheiaCtx->pMmIsAddressValid(pCurrentCheckKDPC)))
		{
			if ((g_pTheiaCtx->pMmIsAddressValid(pCurrentCheckKDPC->DeferredRoutine)))
			{
				if (!(HrdGetPteInputVa(pCurrentCheckKDPC->DeferredRoutine)->NoExecute))
				{
					DbgLog("[TheiaPg <+>] SearchKdpcInPgPrcbFields: Detect PG-KDPC in KPRCB.HalReserved[%01d] | _KDPC: 0x%I64X | CpuCore: 0x%I32X\n", i, pCurrentCheckKDPC, CurrCoreNum);

					SAFE_DISABLE(CurrIF,
					{
					  HrdGetPteInputVa(pCurrentCheckKDPC->DeferredRoutine)->Dirty1 = 1;

					  __writecr3(__readcr3());

					  *(PUCHAR)(pCurrentCheckKDPC->DeferredRoutine) = 0xc3UI8;

					  HrdGetPteInputVa(pCurrentCheckKDPC->DeferredRoutine)->Dirty1 = 0;

					  __writecr3(__readcr3());
					});
						
					__writegsqword((GsOffsetHalReserved + j), 0UI64);
				}
			}
		}
	}

	pCurrentCheckKDPC = (PKDPC)__readgsqword(GsOffsetAcpiReserved);

	if ((g_pTheiaCtx->pMmIsAddressValid(pCurrentCheckKDPC)))
	{
		if ((g_pTheiaCtx->pMmIsAddressValid(pCurrentCheckKDPC->DeferredRoutine)))
		{
			if (!(HrdGetPteInputVa(pCurrentCheckKDPC->DeferredRoutine)->NoExecute))
			{
				DbgLog("[TheiaPg <+>] SearchKdpcInPgPrcbFields: Detect PG-KDPC in KPRCB.AcpiReserved | _KDPC: 0x%I64X | CpuCore: 0x%I32X\n", pCurrentCheckKDPC, CurrCoreNum);

				SAFE_DISABLE(CurrIF,
			    {
			      HrdGetPteInputVa(pCurrentCheckKDPC->DeferredRoutine)->Dirty1 = 1;
			    
			      __writecr3(__readcr3());
			    
			      *(PUCHAR)(pCurrentCheckKDPC->DeferredRoutine) = 0xc3UI8;
			    
			      HrdGetPteInputVa(pCurrentCheckKDPC->DeferredRoutine)->Dirty1 = 0;
			    
			      __writecr3(__readcr3());
			    });

				__writegsqword((GsOffsetAcpiReserved), 0UI64);
			}
		}
	}

	return NULL;
}
