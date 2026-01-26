#include "LinkHeader.h"

volatile BOOLEAN g_DieDeadlockMethod = FALSE;

volatile PVOID g_pDieIndirectCallBugCheck = NULL;

volatile PVOID g_DieNtosHeadThreadList = NULL;

volatile PVOID g_DieNonLargePage = NULL;

/*++
* Routine: DieDispatchIntrnlError
*
* MaxIRQL: Any level
*
* Public/Private: Public
*
* @param InternalCode: InternalCodeError
*
* Description: Handler internal error in TheiaPg.
--*/
DECLSPEC_NORETURN VOID DieDispatchIntrnlError(IN ULONG32 InternalCode)
{
    #define DIE_LOCAL_CONTEXT_IOCANCELIRP 0

    #define DIE_LOCAL_CONTEXT_KEBUGCHECKEX 1

	static volatile ULONG32 SynchBarrier0 = 0I32; ///< FixRaceCall.

	PVOID DieCtx[2] = { 0 }; ///< DieRoutine is critical, so it should not depend on gTheiaCtx.

	PTHEIA_METADATA_BLOCK pLocalTMDB = g_DieNonLargePage;

	BOOLEAN IsLocalTMDB = FALSE;

	BOOLEAN IsLocalCtx = FALSE;

	UNICODE_STRING StrIoCancelIrp = { 0 };

	UNICODE_STRING StrKeBugCheckEx = { 0 };

	ULONG64 RelatedDataSPIR[4] = { 0 };

	CONST UCHAR StopSigSPIR[] = { 0xCC,0xCC,0xCC };

	if (!(_interlockedbittestandset(&SynchBarrier0, 0I32)))
	{
		DbgLog("[TheiaPg <!>] DieDispatchIntrnlError: InternalCode: 0x%I32X\n", InternalCode);

		if (!g_pTheiaCtx)
		{
			IsLocalCtx = TRUE;

			IsLocalTMDB = TRUE;
		}
		else
		{
			if (g_pTheiaCtx->CompleteSignatureTC != COMPLETE_SIGNATURE_TC) { IsLocalCtx = TRUE; }

			if (g_pTheiaCtx->TheiaMetaDataBlock.CompleteSignatureTMDB != COMPLETE_SIGNATURE_TMDB) { IsLocalTMDB = TRUE; }
		}

		if (IsLocalCtx)
		{
			StrIoCancelIrp.Buffer = L"IoCancelIrp";

			StrIoCancelIrp.Length = (USHORT)(wcslen(StrIoCancelIrp.Buffer) * 2);

			StrIoCancelIrp.MaximumLength = (StrIoCancelIrp.Length + 2);

			DieCtx[DIE_LOCAL_CONTEXT_IOCANCELIRP] = MmGetSystemRoutineAddress(&StrIoCancelIrp);

			StrKeBugCheckEx.Buffer = L"KeBugCheckEx";

			StrKeBugCheckEx.Length = (USHORT)(wcslen(StrKeBugCheckEx.Buffer) * 2);

			StrKeBugCheckEx.MaximumLength = (StrKeBugCheckEx.Length + 2);

			DieCtx[DIE_LOCAL_CONTEXT_KEBUGCHECKEX] = MmGetSystemRoutineAddress(&StrKeBugCheckEx);
		}

		if (IsLocalTMDB)
		{
			if (!pLocalTMDB)
			{
				DbgLog("[TheiaPg <->] DieDispatchIntrnlError: Page for LocalTMDB is not allocate\n");

				goto InitDeadLock;
			}

			InitTheiaMetaDataBlock(pLocalTMDB);

			if (pLocalTMDB->CompleteSignatureTMDB != COMPLETE_SIGNATURE_TMDB)
			{
				DbgLog("[TheiaPg <->] DieDispatchIntrnlError: LocalTMDB is not complete\n");

				goto InitDeadLock;
			}
		}

		RelatedDataSPIR[SPIR_INDEX_OPTIONAL_DATA_SCIA] = (IsLocalCtx ? DieCtx[DIE_LOCAL_CONTEXT_KEBUGCHECKEX] : g_pTheiaCtx->pKeBugCheckEx);

		g_pDieIndirectCallBugCheck = _SearchPatternInRegion(&RelatedDataSPIR, SPIR_SCAN_CALLER_INPUT_ADDRESS, (IsLocalCtx ? DieCtx[DIE_LOCAL_CONTEXT_IOCANCELIRP] : g_pTheiaCtx->pIoCancelIrp), NULL, NULL, &StopSigSPIR, sizeof StopSigSPIR);

		if (!g_pDieIndirectCallBugCheck)
		{
			DbgLog("[TheiaPg <->] DieDispatchIntrnlError: DieIndirectCallBugCheck is NULL\n");

			goto InitDeadLock;
		}

		DbgLog("[TheiaPg <!>] DieDispatchIntrnlError: DieIndirectCallBugCheck: 0x%I64X\n", g_pDieIndirectCallBugCheck);

		g_DieNtosHeadThreadList = ((PUCHAR)PsInitialSystemProcess + (IsLocalTMDB ? pLocalTMDB->EPROCESS_ThreadListHead : g_pTheiaCtx->TheiaMetaDataBlock.EPROCESS_ThreadListHead));

		DieBugCheck((IsLocalTMDB ? pLocalTMDB : &g_pTheiaCtx->TheiaMetaDataBlock), InternalCode);
	}
	else
	{
		_disable();

		while (TRUE)
		{
			if (g_DieDeadlockMethod)
			{
				goto SkipInitDeadLock;

			InitDeadLock:

				DbgLog("[TheiaPg <!>] DieDispatchIntrnlError: Deadlocking CPU\n");

				g_DieDeadlockMethod = TRUE;

			SkipInitDeadLock:

				DieBugCheck((IsLocalTMDB ? pLocalTMDB : &g_pTheiaCtx->TheiaMetaDataBlock), InternalCode);
			}

			_mm_pause();
		}
	}
}
