#include "LinkHeader.h"

extern VOID TheiaEntry(VOID);

/*++
* Routine: ImgEntry
*
* MaxIRQL: DISPATCH_LEVEL
*
* Public/Private: Public
*
* @param NoParams 
*
* Description: Entry-Routine TheiaPg.sys.
--*/
VOID ImgEntry(VOID) { TheiaEntry(); }
