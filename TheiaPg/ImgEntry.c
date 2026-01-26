#include "LinkHeader.h"

extern VOID TheiaEntry(VOID);

/*++
* Routine: ImgEntry
*
* MaxIRQL: Any level
*
* Public/Private: Public
*
* @param NoParams
*
* Description: Main entry routine TheiaPg.sys.
--*/
VOID ImgEntry(VOID)
{
    TheiaEntry();
}
