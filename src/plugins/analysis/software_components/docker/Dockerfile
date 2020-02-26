FROM fkiecad/ghidra_headless_base:9.1


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
