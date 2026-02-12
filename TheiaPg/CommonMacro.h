#pragma once

#include "LinkHeader.h"

#define DEBUG_H 1

#if DEBUG_H

#define DbgLog(a1, ...) DbgPrintEx(DPFLTR_SYSTEM_ID, DPFLTR_ERROR_LEVEL, a1, __VA_ARGS__)

#define DbgText(a1) a1

#else

#define DbgLog(a1, ...) VOID

#define DbgText(a1) VOID

#endif

#define EX_GEN_ALLOC_TAG ((ULONG32)((ULONG64)_AddressOfReturnAddress() + (ULONG64)_ReturnAddress()) ^ 0xecd64bc1UI32) 

#define SAFE_DISABLE(CurrIF, Text)                    \
do                                                    \
{                                                     \
    if ((BOOLEAN)CurrIF) { _disable(); }              \
                                                      \
    { Text }                                          \
                                                      \
    if ((BOOLEAN)CurrIF) { _enable(); }               \
                                                      \
} while (FALSE)


#define SAFE_ENABLE(CurrIF, CurrIrql, TempIrql, Text) \
do                                                    \
{                                                     \
    __writecr8((ULONG64)TempIrql);                    \
                                                      \
    if (!(BOOLEAN)CurrIF) { _enable(); }              \
                                                      \
    { Text }                                          \
                                                      \
    if (!(BOOLEAN)CurrIF) { _disable(); }             \
                                                      \
    __writecr8((ULONG64)CurrIrql);                    \
                                                      \
                                                      \
} while (FALSE)
