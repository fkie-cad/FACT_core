FROM ghcr.io/fkie-cad/ghidra_headless_base:v11.2.1 as runtime

WORKDIR /ipc

# hadolint ignore=DL3018
RUN apk add --no-cache python3

COPY ipc_analyzer/ /opt/ghidra/Ghidra/Features/Jython/ghidra_scripts/
COPY ghidra_headless.py .

ENTRYPOINT ["/ipc/ghidra_headless.py"]
