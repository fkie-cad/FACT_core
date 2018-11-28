FROM phusion/baseimage:0.11

RUN install_clean gcc cmake make libtool-bin wget python automake bison libglib2.0 git \
    libssl-dev nettle-dev flex python3 build-essential python3-setuptools python3-dev screen gdb libpixman-1-dev

WORKDIR /opt
COPY build_qemu.sh /opt/build_qemu.sh
RUN ./build_qemu.sh
ENV PATH="/opt/qemu-targets:${PATH}"

ENV QEMU_LD_PREFIX="/opt/firmware_root/"

COPY start_binary.sh /opt/start_binary.sh

ENTRYPOINT ["/opt/start_binary.sh"]
