# We can't use alpine since alpine (unintentionally) does not include yaml supprot int dtc
FROM ubuntu:jammy
RUN apt update && apt install -y device-tree-compiler && rm -rf /var/lib/apt/lists/*
ENTRYPOINT ["/usr/bin/dtc"]
