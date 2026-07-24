FROM ghcr.io/fkie-cad/ghidra_headless_base:v11.2.1


VOLUME ["/work"]
WORKDIR /work

COPY scripts /work/scripts

ENTRYPOINT [ \
    "analyzeHeadless", \
    "/tmp", "temporary_project", \
    "-postScript", "/work/scripts/detect_CVE-2021-45608.py", \
    "-deleteProject", \
    "-import", "/io/ghidra_input" \
]
