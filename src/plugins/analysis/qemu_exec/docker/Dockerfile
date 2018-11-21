FROM phusion/baseimage:0.10.0

RUN apt-get update -y && apt-get install -y gcc cmake make libtool-bin wget python automake bison libglib2.0 git \
    libssl-dev nettle-dev flex python3 build-essential python3-setuptools python3-dev screen gdb libpixman-1-dev \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

WORKDIR /opt
COPY build_qemu.sh /opt/build_qemu.sh
RUN ./build_qemu.sh
ENV PATH="/opt/qemu-targets:${PATH}"

ENV QEMU_LD_PREFIX="/opt/firmware_root/"

COPY start_binary.sh /opt/start_binary.sh

ENTRYPOINT ["/opt/start_binary.sh"]
