# Ghidra Script for detecting CVE-2021-45608

## Usage
```
ghidra_10.X_PUBLIC/support/analyzeHeadless <.> <./tmp_NetUSB_project> -deleteProject -import <NetUSB.ko> -postscript detect_CVE-2021-45608.py

```

## Description
The script looks for the function `SoftwareBus_dispatchNormalEPMsgOut` and searches for `kmalloc`-calls within. The Basic Blocks of these calls are identified and the parent Basic Blocks are checked if the patch is present:

If a parenting Basic Block contains a INT_LESS instruction with the value `0x1000000`, the patch is present.