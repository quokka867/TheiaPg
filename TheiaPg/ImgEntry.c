#include "LinkHeader.h"

extern VOID TheiaEntry(VOID);

/*++
* Routine: ImgEntry
*
* MaxIRQL: Any level
*
* Public/Private: Public
*
* @param NoParamsgpg 
*
* Description: Entry-Routine TheiaPg.sys.
--*/
VOID ImgEntry(VOID) { TheiaEntry(); }
