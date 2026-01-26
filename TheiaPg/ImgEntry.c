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
* Description: Main entry routine Img-TheiaPg.sys.
--*/
VOID ImgEntry(VOID)
{
    TheiaEntry();
}
