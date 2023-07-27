FROM fkiecad/ghidra_headless_base:10.2.3


VOLUME ["/work"]
WORKDIR /work

ADD scripts /work/scripts

ENTRYPOINT [ \
    "analyzeHeadless", \
    "/tmp", "temporary_project", \
    "-postScript", "/work/scripts/detect_CVE-2021-45608.py", \
    "-deleteProject", \
    "-import", "/io/ghidra_input" \
]
