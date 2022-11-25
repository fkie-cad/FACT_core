FROM fkiecad/ghidra_headless_base:10.1.2 as runtime

WORKDIR /ipc

RUN apt-get update && apt-get install -y --no-install-recommends python=3.10  \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

COPY ipcAnalyzer/ /opt/ghidra/Ghidra/Features/Python/ghidra_scripts/
COPY ghidraHeadless.py .

ENTRYPOINT ["/ipc/ghidraHeadless.py"]