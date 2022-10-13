# Ghidra Script for detecting CVE-2021-45608

## Usage
```
ghidra_10.X_PUBLIC/support/analyzeHeadless <.> <./tmp_NetUSB_project> -deleteProject -import <NetUSB.ko> -postscript detect_CVE-2021-45608.py

```

## Description
The script looks for the function `SoftwareBus_dispatchNormalEPMsgOut` and searches for `kmalloc`-calls within. The Basic Blocks of these calls are identified and the parent Basic Blocks are checked if the patch is present:

If a parenting Basic Block contains a INT_LESS instruction, the patch is present.

## Limitations
The binary is considered fixed, if at least one parent block contains INT_LESS.

## Evaluation 

| Sample       | Script result | Fixed? |
|--------------|---------------|-----|
| Netgear AC1750 v1.0.4.120 (before patch)  | vuln      | no |
| Netgear AC1750 v1.0.4.122 (after\ patch)  | not vuln  |   yes  |
| Netgear PR2000  v1.0.0.15                 | vuln      |  does not look like   |
| Netgear R6100 v1.0.1.10                   | vuln      | does not look like |
| Netgear R6220 v1.1.0.34                   | vuln      | does not look like|
| Netgear\ R6300v2 v1.0.4.6                 | vuln      | does not look like|
| Netgear R7000 Nighthawk v1.0.7.6_1.1.99   | vuln      | does not look like |
| EDiMAX BR-6478AC V2 (fixed)               | not vuln  | fixed: `if (0xffffff < size)`|
| TP-Link Archer C7 V5 (fixed)              | not vuln  | fixed: `if (size < 0x1000000)`|
| TP-Link Archer C1200                      | vuln      | does not look like |