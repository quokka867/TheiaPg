#include "LinkHeader.h"

volatile BOOLEAN g_DieDeadlockMethod = FALSE;

volatile PVOID g_pDieIndirectCallBugCheck = NULL;

volatile PVOID g_pDieNonLargePage = NULL;

volatile PVOID g_pDieDummyObjThread = NULL;

/*++
* Routine: DieDispatchIntrnlError
*
* MaxIRQL: Any level (without IST)
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

	CONST UCHAR StopSigSPIR[] = { 0xcc,0xcc,0xcc };

	static volatile ULONG32 SynchBarrier0 = 0I32; ///< FixRaceCall.

	PVOID DieCtx[2] = { 0 }; ///< DieRoutine is critical, so it should not depend on gTheiaCtx.
	PTHEIA_METADATA_BLOCK pLocalTMDB = g_pDieNonLargePage;
	BOOLEAN IsLocalCtx = FALSE;

	UNICODE_STRING StrIoCancelIrp = { 0 };
	UNICODE_STRING StrKeBugCheckEx = { 0 };

	ULONG64 RelatedDataSPIR[4] = { 0 };

	PVOID pCurrPrcb = (PVOID)__readgsqword(g_pTheiaCtx->TheiaMetaDataBlock.KPCR_CurrentPrcb_OFFSET);

	PVOID pCurrStackHigh = NULL, pCurrStackLow = NULL;

	PVOID pStackAddr = (PVOID)&pStackAddr;

	PLIST_ENTRY pCurrThreadListHead = NULL;

	PLIST_ENTRY pCurrObjThread = NULL;

	if (!(_interlockedbittestandset(&SynchBarrier0, 0I32)))
	{
		DbgLog("[TheiaPg <!>] DieDispatchIntrnlError: InternalCode: 0x%I32X\n", InternalCode);

		if (!g_pTheiaCtx) { IsLocalCtx = TRUE; }
		else { if (g_pTheiaCtx->CompleteSignatureTC != COMPLETE_SIGNATURE_TC) { IsLocalCtx = TRUE; } }

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

			if (!pLocalTMDB)
			{
				DbgLog("[TheiaPg <->] DieDispatchIntrnlError: Page for LocalTMDB is not allocate\n");

				goto InitDeadLock;
			}

			InitTheiaMetaDataBlock(pLocalTMDB);
		}

		RelatedDataSPIR[SPIR_INDEX_OPTIONAL_DATA_SCIA] = (IsLocalCtx ? DieCtx[DIE_LOCAL_CONTEXT_KEBUGCHECKEX] : g_pTheiaCtx->pKeBugCheckEx);

		g_pDieIndirectCallBugCheck = _SearchPatternInRegion(&RelatedDataSPIR, SPIR_SCAN_CALLER_INPUT_ADDRESS, (IsLocalCtx ? DieCtx[DIE_LOCAL_CONTEXT_IOCANCELIRP] : g_pTheiaCtx->pIoCancelIrp), NULL, NULL, &StopSigSPIR, sizeof StopSigSPIR);

		if (!g_pDieIndirectCallBugCheck)
		{
			DbgLog("[TheiaPg <->] DieDispatchIntrnlError: DieIndirectCallBugCheck is NULL\n");

			goto InitDeadLock;
		}

		DbgLog("[TheiaPg <!>] DieDispatchIntrnlError: DieIndirectCallBugCheck: 0x%I64X\n", g_pDieIndirectCallBugCheck);

		pCurrStackHigh = *(PVOID*)((PUCHAR)(*(PVOID*)((PUCHAR)pCurrPrcb + (IsLocalCtx ? pLocalTMDB->KPRCB_CurrentThread_OFFSET : g_pTheiaCtx->TheiaMetaDataBlock.KPRCB_CurrentThread_OFFSET))) + (IsLocalCtx ? pLocalTMDB->KTHREAD_InitialStack_OFFSET : g_pTheiaCtx->TheiaMetaDataBlock.KTHREAD_InitialStack_OFFSET));

		pCurrStackLow = *(PVOID*)((PUCHAR)(*(PVOID*)((PUCHAR)pCurrPrcb + (IsLocalCtx ? pLocalTMDB->KPRCB_CurrentThread_OFFSET : g_pTheiaCtx->TheiaMetaDataBlock.KPRCB_CurrentThread_OFFSET))) + (IsLocalCtx ? pLocalTMDB->KTHREAD_StackLimit_OFFSET : g_pTheiaCtx->TheiaMetaDataBlock.KTHREAD_StackLimit_OFFSET));

		if (((ULONG64)pStackAddr > (ULONG64)pCurrStackHigh) || ((ULONG64)pStackAddr < (ULONG64)pCurrStackLow))
		{
			pCurrStackHigh = *(PVOID*)((PUCHAR)pCurrPrcb + (IsLocalCtx ? pLocalTMDB->KPRCB_DpcStack_OFFSET : g_pTheiaCtx->TheiaMetaDataBlock.KPRCB_DpcStack_OFFSET));
		}

		pCurrStackLow = NULL;

		pCurrThreadListHead = ((PUCHAR)PsInitialSystemProcess + (IsLocalCtx ? pLocalTMDB->EPROCESS_ThreadListHead_OFFSET : g_pTheiaCtx->TheiaMetaDataBlock.EPROCESS_ThreadListHead_OFFSET));

		pCurrObjThread = pCurrThreadListHead->Flink;

		for (UCHAR i = (UCHAR)((__rdtsc() % 256) + 32), j = 0UI8; ; --i)
		{
			pCurrObjThread = pCurrObjThread->Flink;

			if (!i)
			{
				if (pCurrObjThread == pCurrThreadListHead)
				{
					i += 8;

					if (j < 8)
					{
						j++;
					}
					else
					{
						pCurrObjThread = pCurrObjThread->Flink;

						if (pCurrObjThread == pCurrThreadListHead)
						{
							pCurrObjThread = pCurrObjThread->Flink;
						}

						break;
					}
				}
				else { break; }
			}
		}

		g_pDieDummyObjThread = (PVOID)((PUCHAR)pCurrObjThread - (IsLocalCtx ? pLocalTMDB->EPROCESS_ThreadListHead_OFFSET : g_pTheiaCtx->TheiaMetaDataBlock.EPROCESS_ThreadListHead_OFFSET));

		DieBugCheck((IsLocalCtx ? pLocalTMDB : &g_pTheiaCtx->TheiaMetaDataBlock), pCurrStackHigh, InternalCode);
	}
	else
	{
		_disable();

		for(; ;)
		{
			if (g_DieDeadlockMethod)
			{
				goto SkipInitDeadLock;

			    InitDeadLock:

				DbgLog("[TheiaPg <!>] DieDispatchIntrnlError: Deadlocking CPU\n");

				g_DieDeadlockMethod = TRUE;

			    SkipInitDeadLock:

				DieBugCheck(NULL, NULL, NULL);
			}

			_mm_pause();
		}
	}
}
