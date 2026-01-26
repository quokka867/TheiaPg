#pragma once

#include "LinkHeader.h"

#define COMPLETE_SIGNATURE_TC 0xaedf1cfd64562bbeI32

extern VOID InitTheiaMetaDataBlock(IN OUT PTHEIA_METADATA_BLOCK pTheiaMetaDataBlock);

extern VOID InitTheiaContext(VOID);

extern VOID CheckStatusTheiaCtx(VOID);
