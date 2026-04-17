# Dockerfile for the FACT_core ghidra_analysis plugin
#
# Builds a minimal image containing:
#   * OpenJDK 17 (required by Ghidra 11.x)
#   * Ghidra (downloaded from the official GitHub release)
#
# The image exposes no ports and is only used in headless / batch mode.

FROM eclipse-temurin:17-jdk-jammy

ARG GHIDRA_VERSION=11.1.2
ARG GHIDRA_DATE=20240709
ARG GHIDRA_SHA256=219ec130b901645779948feeb7cc86f131dd2da3f0e8769f8b006f3007109b93

ENV GHIDRA_INSTALL_DIR=/opt/ghidra

RUN apt-get update && \
    apt-get install -y --no-install-recommends wget unzip && \
    rm -rf /var/lib/apt/lists/*

RUN GHIDRA_ARCHIVE="ghidra_${GHIDRA_VERSION}_PUBLIC_${GHIDRA_DATE}.zip" && \
    wget -q "https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_${GHIDRA_VERSION}_build/${GHIDRA_ARCHIVE}" \
        -O /tmp/ghidra.zip && \
    echo "${GHIDRA_SHA256}  /tmp/ghidra.zip" | sha256sum -c - && \
    unzip -q /tmp/ghidra.zip -d /opt && \
    mv "/opt/ghidra_${GHIDRA_VERSION}_PUBLIC" "${GHIDRA_INSTALL_DIR}" && \
    rm /tmp/ghidra.zip && \
    chmod +x "${GHIDRA_INSTALL_DIR}/support/analyzeHeadless"

# Create a non-root user for running Ghidra
RUN useradd -m -u 1000 ghidra
USER ghidra

WORKDIR /home/ghidra
