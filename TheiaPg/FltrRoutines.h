#pragma once

#include "LinkHeader.h"

extern volatile VOID FltrKiExecuteAllDpcs(IN PINPUTCONTEXT_ICH pInputCtx);

extern volatile VOID FltrKiRetireDpcList(IN PINPUTCONTEXT_ICH pInputCtx);

extern volatile VOID FltrKiDeliverApc(IN PINPUTCONTEXT_ICH pInputCtx);

extern volatile VOID FltrExQueueWorkItem(IN PINPUTCONTEXT_ICH pInputCtx);

extern volatile VOID FltrExAllocatePool2(IN OUT PINPUTCONTEXT_ICH pInputCtx);

extern volatile VOID FltrKiCustomRecurseRoutineX(IN OUT PINPUTCONTEXT_ICH pInputCtx);
