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

	if (!((__readcr8() <= DISPATCH_LEVEL) ? g_pTheiaCtx->pMmIsAddressValid(pCtx) : g_pTheiaCtx->pMmIsNonPagedSystemAddressValid(pCtx)))
	{
		DbgLog("[TheiaPg <->] SearchPgCtxInCtx: Invalid Ctx\n\n");

		return NULL;
	}

	PULONG64 pPgCtx = (PULONG64)&pCtx->Rax;

	for (UCHAR i = 0UI8; i < 16UI8; ++i, ++pPgCtx)
	{
		if (!((__readcr8() <= DISPATCH_LEVEL) ? g_pTheiaCtx->pMmIsAddressValid(*pPgCtx) : g_pTheiaCtx->pMmIsNonPagedSystemAddressValid(*pPgCtx))) { continue; }

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

	ULONG32 GsOffsetHalReserved = (g_pTheiaCtx->TheiaMetaDataBlock.KPCR_Prcb_OFFSET + g_pTheiaCtx->TheiaMetaDataBlock.KPRCB_HalReserved);

	ULONG32 GsOffsetAcpiReserved = (g_pTheiaCtx->TheiaMetaDataBlock.KPCR_Prcb_OFFSET + g_pTheiaCtx->TheiaMetaDataBlock.KPRCB_AcpiReserved);

	PKDPC pCurrentCheckKDPC = NULL;

	BOOLEAN OldIF = FALSE;

	ULONG32 CurrCoreNum = (ULONG32)__readgsdword(g_pTheiaCtx->TheiaMetaDataBlock.KPCR_Prcb_OFFSET + g_pTheiaCtx->TheiaMetaDataBlock.KPRCB_Number_OFFSET);

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

					if (OldIF = HrdGetIF()) { _disable(); }

					HrdGetPteInputVa(pCurrentCheckKDPC->DeferredRoutine)->Dirty1 = 1;

					__writecr3(__readcr3());

					*(PUCHAR)(pCurrentCheckKDPC->DeferredRoutine) = 0xC3UI8;

					HrdGetPteInputVa(pCurrentCheckKDPC->DeferredRoutine)->Dirty1 = 0;

					__writecr3(__readcr3());

					if (OldIF) { _enable(); }

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

				if (OldIF = HrdGetIF()) { _disable(); }

				HrdGetPteInputVa(pCurrentCheckKDPC->DeferredRoutine)->Dirty1 = 1;

				__writecr3(__readcr3());

				*(PUCHAR)(pCurrentCheckKDPC->DeferredRoutine) = 0xC3UI8;

				HrdGetPteInputVa(pCurrentCheckKDPC->DeferredRoutine)->Dirty1 = 0;

				__writecr3(__readcr3());

				if (OldIF) { _enable(); }

				__writegsqword((GsOffsetAcpiReserved), 0UI64);
			}
		}
	}

	return NULL;
}
