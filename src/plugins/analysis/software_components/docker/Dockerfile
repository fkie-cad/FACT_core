FROM openjdk:jdk-slim


ENV GHIDRA_VERSION ghidra_9.1_PUBLIC_20191023

RUN apt-get update && \
    apt-get install -y --no-install-recommends wget unzip && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN wget https://ghidra-sre.org/${GHIDRA_VERSION}.zip && \
    unzip -d ghidra ${GHIDRA_VERSION}.zip && \
    rm ${GHIDRA_VERSION}.zip

VOLUME ["/work"]
WORKDIR /work

ADD ghidra_scripts /ghidra_scripts

ENTRYPOINT [ \
    "/ghidra/ghidra_9.1_PUBLIC/support/analyzeHeadless", \
    "/work", "project_foo", \
    "-scriptPath", "/ghidra_scripts", \
    "-postScript", "format_string_version.py", \
    "-deleteProject", \
    "-import", "ghidra_input" \
]
