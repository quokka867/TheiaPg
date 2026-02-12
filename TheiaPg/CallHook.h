#pragma once

#include "LinkHeader.h"

typedef struct _ICH_DATA
{
    PVOID   pHookRoutine;
    PVOID   pBasePatch;
    PVOID   pHandlerHook;
    ULONG64 LengthHandler;
    UCHAR   LengthAlignment;

}ICH_DATA, * PICH_DATA;

extern VOID InitCallHook(IN PICH_DATA pRelatedDataICT);
