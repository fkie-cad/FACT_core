FROM fkiecad/ghidra_headless_base:10.1.2 as runtime

WORKDIR /ipc

RUN apt-get update && apt-get install python3 -y

COPY ipcAnalyzer/ /opt/ghidra/Ghidra/Features/Python/ghidra_scripts/
COPY ghidraHeadless.py .

ENTRYPOINT ["/ipc/ghidraHeadless.py"]
