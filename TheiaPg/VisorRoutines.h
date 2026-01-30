#pragma once

#include "LinkHeader.h"

extern volatile VOID VsrKiExecuteAllDpcs(IN PINPUTCONTEXT_ICT pInputCtx);

extern volatile VOID VsrKiRetireDpcList(IN PINPUTCONTEXT_ICT pInputCtx);

extern volatile VOID VsrKiDeliverApc(IN PINPUTCONTEXT_ICT pInputCtx);

extern volatile VOID VsrExQueueWorkItem(IN PINPUTCONTEXT_ICT pInputCtx);

extern volatile VOID VsrExAllocatePool2(IN OUT PINPUTCONTEXT_ICT pInputCtx);

extern volatile VOID VsrKiCustomRecurseRoutineX(IN OUT PINPUTCONTEXT_ICT pInputCtx);
