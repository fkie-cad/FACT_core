FROM fkiecad/ghidra_headless_base:10.1.2


VOLUME ["/work"]
WORKDIR /work

ADD ghidra_scripts /ghidra_scripts

ENTRYPOINT [ \
    "analyzeHeadless", \
    "/tmp", "temporary_project", \
    "-postScript", "/ghidra_scripts/format_string_version.py", \
    "-deleteProject", \
    "-import", "ghidra_input" \
]
