#!/usr/bin/env python3
import os
import sys
import argparse
from pathlib import Path
import tempfile

def parseArguments() -> argparse.Namespace():
    parser = argparse.ArgumentParser()
    parser.add_argument("-g", "--ghidraPath", nargs='?', default="/opt/ghidra", help="path to Ghidra")
    parser.add_argument("filePath", help="path to binary/firmware")
    parser.add_argument("resultPath", nargs='?', default="", help="result path")
    args = parser.parse_args()
    return args

"""
Returns script path
"""
def getScriptPath(ghidraPath: Path) -> Path:
    return ghidraPath / "Ghidra/Features/Python/ghidra_scripts/ipcAnalyzer.py"

"""
Checks if Ghidra executable exists
"""
def checkGhidra(ghidraPath: Path) -> bool:
    if not ghidraPath.exists():
        print(f"{ghidraPath} does not exist!")
        print("Try change the ghidraPath with the -g option.")
        sys.exit(-1)

"""
Builds the Ghidra command
"""
def getGhidraCommand(ghidraPath: Path, projectPath: Path, filePath: Path, resultPath: Path) -> str:
    headlessPath = ghidraPath / "support/analyzeHeadless"
    scriptPath = getScriptPath(ghidraPath)
    projectName = "tmp_ghidra_project"
    return f"{headlessPath} {projectPath} {projectName} -readOnly -import {filePath} -postscript {scriptPath} {resultPath}"

"""
Get all executable files
"""
def getBinaries(filePath: Path) -> list:
    if filePath.is_file():
        return [filePath]
    binaries = []
    for file in filePath.iterdir():
        if file.is_symlink():
            continue
        elif file.is_dir():
            binaries += getBinaries(file)
        else:
            if (os.access(file, os.X_OK)):
                binaries.append(file)
    return binaries

"""
Builds Ghidra command and runs exporter script
"""
def runGhidra(ghidraPath: Path, filePath: Path, resultPath: Path) -> None:
    checkGhidra(ghidraPath)
    tmpDir = tempfile.TemporaryDirectory()
    projectPath = Path("/tmp") / tmpDir.name
    binaries = sorted(getBinaries(filePath))
    for binary in binaries:
        cmd = getGhidraCommand(ghidraPath, projectPath, binary, resultPath)
        os.system(cmd)
    tmpDir.cleanup()

def main() -> int:
    args = parseArguments()
    ghidraPath = Path(args.ghidraPath)
    filePath = Path(args.filePath)
    resultPath = Path(args.resultPath)
    runGhidra(ghidraPath, filePath, resultPath)
    return 0

if __name__ == "__main__":
    sys.exit(main())
