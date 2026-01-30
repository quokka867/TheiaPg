#pragma once

#include "LinkHeader.h"

extern CONST UCHAR _25h2_w11_HandlerVsrKiExecuteAllDpcs[15];
extern CONST UCHAR _25h2_w11_KiExecuteAllDpcs_SIG[];
extern CONST UCHAR _25h2_w11_KiExecuteAllDpcs_MASK[];

extern CONST UCHAR _25h2_w11_HandlerVsrKiRetireDpcList[13];
extern CONST UCHAR _25h2_w11_KiRetireDpcList_SIG[];
extern CONST UCHAR _25h2_w11_KiRetireDpcList_MASK[];

extern CONST UCHAR _25h2_w11_Handler_KiDeliverApc[14];
extern CONST UCHAR _25h2_w11_KiDeliverApc_SIG[];
extern CONST UCHAR _25h2_w11_KiDeliverApc_MASK[];

extern CONST UCHAR _25h2_w11_HandlerVsrExQueueWorkItem[15];
extern CONST UCHAR _25h2_w11_ExQueueWorkItem_SIG[];
extern CONST UCHAR _25h2_w11_ExQueueWorkItem_MASK[];

extern CONST UCHAR _25h2_w11_HandlerVsrExAllocatePool2[16];
extern CONST UCHAR _25h2_w11_ExAllocatePool2_SIG[];
extern CONST UCHAR _25h2_w11_ExAllocatePool2_MASK[];

extern CONST UCHAR _25h2_w11_HandlerVsrKiCustomRecurseRoutineX[8];
extern CONST UCHAR _25h2_w11_KiCustomRecurseRoutineX_SIG[];
extern CONST UCHAR _25h2_w11_KiCustomRecurseRoutineX_MASK[];

extern CONST UCHAR _25h2_w11_KiBalanceSetManagerDeferredRoutine_SIG[];
extern CONST UCHAR _25h2_w11_KiBalanceSetManagerDeferredRoutine_MASK[];

extern CONST UCHAR _25h2_w11_KiMcaDeferredRecoveryService_SIG[];
extern CONST UCHAR _25h2_w11_KiMcaDeferredRecoveryService_MASK[];

extern CONST UCHAR _25h2_w11_FsRtlUninitializeSmallMcb_SIG[];
extern CONST UCHAR _25h2_w11_FsRtlUninitializeSmallMcb_MASK[];

extern CONST UCHAR _25h2_w11_FsRtlTruncateSmallMcb_SIG[];
extern CONST UCHAR _25h2_w11_FsRtlTruncateSmallMcb_MASK[];

extern CONST UCHAR _25h2_w11_KiDecodeMcaFault_SIG[];
extern CONST UCHAR _25h2_w11_KiDecodeMcaFault_MASK[];

extern CONST UCHAR _25h2_w11_CcBcbProfiler_SIG[];
extern CONST UCHAR _25h2_w11_CcBcbProfiler_MASK[];

extern CONST UCHAR _25h2_w11_CcBcbProfiler2_SIG[];
extern CONST UCHAR _25h2_w11_CcBcbProfiler2_MASK[];

extern CONST UCHAR _25h2_w11_KiDispatchCallout_SIG[];
extern CONST UCHAR _25h2_w11_KiDispatchCallout_MASK[];

extern CONST UCHAR _25h2_w11_MmAllocateIndependentPagesEx_SIG[];
extern CONST UCHAR _25h2_w11_MmAllocateIndependentPagesEx_MASK[];

extern CONST UCHAR _25h2_w11_MmFreeIndependentPages_SIG[];
extern CONST UCHAR _25h2_w11_MmFreeIndependentPages_MASK[];
