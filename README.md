# TheiaPg: Defeating PatchGuard at Runtime - Windows 11 25H2

## Main description

`TheiaPg` is an PoC NT-Kernel-Module to prevent `PatchGuard` kernel integrity check routines from being performed before modification of critical kernel information (Critical-Kernel-Modules/Kernel-Objects/Other) is detected and the irretrievable PatchGuard `BugCheck-109h` (CRITICAL_STRUCTURE_CORRUPTION).

## Module compatibility
                                      
Loading methods: The module is fully compatible with loading sys-img methods: Mapping-Img(no dependency on unwind-info)/WinAPI.

Hypervisor protect environment: The internal logic of the module is not compatible with hypervisor security (VBS/HVCI) because the module actively interacts with TablePages, and the access attributes of the GVA end PTE do not affect the attributes of the end PTE located on the EPT/NPT side, which means that the hardware access attributes to the PhysFrame will not be changed when modifying the Guest-End-PTE.

Secure boot: The module is conditionally compatible with SecureBoot, using the Mapping-Img loading method, module image can be mapped to KernelSpace.

## Additional description

Module image size with MSVC optimizations ~50kb.

# Result after the module testing session

![test_module_0](TheiaPg/InfoTest/test_module_0.png)