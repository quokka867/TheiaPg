#pragma once

#include "LinkHeader.h"

// _SearchPatternInImg ExexuteFlags ===========++
                                               //
#define SPII_NO_OPTIONAL               0x01I32 //
                                               //
#define SPII_GET_BASE_MODULE           0x02I32 //
                                               //
#define SPII_SCAN_CALLER_INPUT_ADDRESS 0x04I32 //
                                               //
#define SPII_AMOUNT_OPTIONAL_OBJS      0x02I32 //
                                               //
// ============================================++

// _SearchPatternInImg OptionalData[4] =======++
                                              //
#define SPII_INDEX_OPTIONAL_DATA_SCIA 0x00I8  // SPII: SearchPatternInImg | SCIA: SCAN_CALLER_INPUT_ADDRESS
                                              //
// ===========================================++

// _SearchPatternInRegion ExexuteFlags ========++
                                               //
#define SPIR_NO_OPTIONAL               0x01I32 //
                                               //
#define SPIR_SCAN_CALLER_INPUT_ADDRESS 0x02I32 //
                                               //
#define SPIR_AMOUNT_OPTIONAL_OBJS      0x01I32 //
                                               //
// ============================================++

// _SearchPatternInRegion OptionalData[4] ====++
                                              //
#define SPIR_INDEX_OPTIONAL_DATA_SCIA 0x00I8  // SPIR: SearchPatternInRegion | SCIA: SCAN_CALLER_INPUT_ADDRESS
                                              //
// ===========================================++

extern PVOID _HeurisSearchKdpcInCtx(IN PCONTEXT pCtx);

extern BOOLEAN _IsAddressSafe(IN PVOID pCheckAddress);

extern volatile PVOID g_pSpiiNonLargePage;

extern PVOID _SearchPatternInImg(IN ULONG64 OptionalData[SPII_AMOUNT_OPTIONAL_OBJS], IN ULONG32 FlagsExecute, IN PVOID pEprocessTrgtImg, IN PVOID pNameSection, IN PVOID pModuleName, IN PVOID pSig, IN PVOID pMaskSig);

extern PVOID _SearchPatternInRegion(IN ULONG64 OptionalData[SPIR_AMOUNT_OPTIONAL_OBJS], IN ULONG32 FlagsExecute, IN PUCHAR pRegionSearch, IN PUCHAR pSig, IN PUCHAR pMaskSig, IN PUCHAR pStopSig, IN ULONG32 LenStopSig);
