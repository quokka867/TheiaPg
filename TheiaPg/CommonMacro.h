#pragma once

#include "LinkHeader.h"

#define DEBUG_H 1

#if DEBUG_H

#define DbgLog(a1, ...) DbgPrintEx(DPFLTR_SYSTEM_ID, DPFLTR_ERROR_LEVEL, a1, __VA_ARGS__)

#define DbgText(a1) a1

#else

#define DbgLog(a, ...) VOID

#define DbgText(a1) VOID

#endif

#define EX_GEN_ALLOC_TAG ((ULONG32)((ULONG64)_AddressOfReturnAddress() + (ULONG64)_ReturnAddress()) ^ 0xecd64bc1UI32)
