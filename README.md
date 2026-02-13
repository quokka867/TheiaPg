# TheiaPg: Bypassing PatchGuard at Runtime - Windows 11 25H2

## Main Description

`TheiaPg` is a PoC NT-Kernel module to prevent `PatchGuard` kernel integrity check routines from being performed before the modification of critical kernel information (Critical-Kernel-Modules/Kernel-Objects/Other) is detected and the irretrievable `PG BugCheck-109h` (BSOD CRITICAL_STRUCTURE_CORRUPTION) occurs.

## Module Сompatibility
                                      
Loading Methods: The module is fully compatible with loading img methods: MappingImg(no dependency on unwind-info)/WinAPI.

Hypervisor-Protected Environment: The internal logic of the module is incompatible with hypervisor-based security (VBS/HVCI), since the module actively interacts with PagesTables, and with EPT/NPT the hardware access attributes to the PhysFrame are controlled in the HPA-PTE.

Secure Boot: The module is conditionally compatible with Secure Boot, if use MappingImg method.

## Additional Description

Module img size with MSVC optimizations ~60kb.

The module was successfully tested on Windows 11 25H2 build: `26200.7840`.

# Result

![test_module_0](TheiaPg/InfoTest/test_module_0.png)
