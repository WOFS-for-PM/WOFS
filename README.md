# WOFS

This repository contains the code base for Wolves atop Optane DCPMM. Our paper "Fast and Synchronous Crash Consistency with Metadata Write-Once File System" is accepted by OSDI'25. Our AE code is currently based on the HUNTER file system, wrapped with `ENABLE_META_PACK(sb)` if-branch. We are working on a new version of the code that will be more modular and easier to use (i.e., the `wofs` branch). The artifact evaluation steps can be obtained from [our AE repository](https://github.com/WOFS-for-PM/tests). We now introduce the code base and the branches corresponding to the paper.

- [WOFS](#wofs)
  - [Code Organization](#code-organization)
  - [Branches Corresponding to the Paper](#branches-corresponding-to-the-paper)
  - [For Reference](#for-reference)


## Code Organization 

Atop HUNTER file system, we mainly add or modify files below for Wolves.

- `tlalloc.c`: Two-level allocator implementation.

- `objm.c`: PTL implementation, package allocation and reclamation (or soft-GC), and the metadata write-once scheme.

- `balloc.c`: Data block allocation/deallocation implementation.

- `bbuild.c`: Recovery routine from packages (including four phases).

The remaining files leverage packages and allocators to implement the basic file system operations. 

## Branches Corresponding to the Paper

| **Branch**              | **Description**                                                                 |
|-------------------------|----------------------------------------------------------------------------------|
| osdi25                  | Wolves without AVX or bandwidth regulation.                                   |
| osdi25-meta-trace       | Wolves with I/O timing breakdown.                                                  |
| osdi25-avx              | Wolves with AVX accelerated I/O.                                                   |
| osdi25-fio-regulate     | Wolves with FIO BW regulation.                                                     |
| osdi25-fb-regulate      | Wolves with Filebench BW regulation.                                               |
| osdi25-failure          | Wolves with failure recovery.                                                      |
| osdi25-dr-recovery      | Wolves with dump&restore recovery.                                                 |
| osdi25-dr-opt-recovery  | Wolves with optimized dump&restore recovery.                                       |
| osdi25-io-trace         | Wolves with PM I/O trace.                                                          |
| osdi25-aging            | Wolves under Agrawal aging profile.                                             |
| wofs                    | A clean code version of Wolves.                                               |
| osdi25-hunter-dac       | HUNTER@DAC'23 file system with asynchronous write.                              |
| osdi25-hunter-async     | HUNTER@TCAD'24 file system with soft update.                                    |
| osdi25-hunter-sync      | HUNTER@TCAD'24 file system with synchronous soft update.                        |

## For Reference

```bib
@inproceedings{pan2025fast,
  title={Fast and Synchronous Crash Consistency with Metadata Write-Once File System},
  author={Pan, Yanqi and Xia, Wen and Zhang, Yifeng and Zou, Xiangyu and Huang, Hao and Li, Zhenhua and Wu, Chentao},
  booktitle={19th USENIX Symposium on Operating Systems Design and Implementation (OSDI 25)},
  year={2025}
}
```