# ipc
Inter-Process Communication Analysis

FACT plugin using a Ghidra script with two functionalities:
1. identify IPC paradigms: os.system and exec family, shared files, shared memory, named pipes and message queues
2. resolve version format strings for the `software_components` plugin

## Installation
### Using docker image
Build the docker image yourself, with 
```shell
docker build -t ipc ./docker
```

### Local installation
Put the content of `./docker/ipcAnalyzer/` (the script `ipcAnalyzer.py` and the
folder `ipcAnalysis`) in Ghidra's python scripts directory 
(default `$GHIDRA_HOME/Ghidra/Features/Python/ghidra_scripts`).

## Usage
### Using Docker
If you use the docker image, just run
```shell
docker run --rm -v /PATH/TO/BINARY:/input ipc /input
```

### In Ghidra
Open Ghidra's Script Manager window and look for the script in a folder labeled "IPC".
The green arrow "Run Script" button at the top of the Script Manager window will run the script, with output printed to the console.

### Automate with Ghidra Headless
A python script named `./docker/ghidraHeadless.py` is provided to automatically run the Ghidra script on multiple binaries in the terminal using Ghidra's Headless mode.
Run the script with 
```shell
python3 ghidraHeadless.py [-h] [-g [GHIDRAPATH]] filePath [resultPath]
```
