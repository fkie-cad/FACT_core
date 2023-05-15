FROM alpine:3.18
RUN apk add --no-cache python3 \
    qemu-aarch64 \
    qemu-arm \
    qemu-armeb \
    qemu-i386 \
    qemu-mips \
    qemu-mips64 \
    qemu-mips64el \
    qemu-mipsel \
    qemu-mipsn32 \
    qemu-mipsn32el \
    qemu-ppc \
    qemu-ppc64 \
    qemu-ppc64le \
    qemu-sh4 \
    qemu-sh4eb \
    qemu-x86_64


ENV QEMU_LD_PREFIX="/opt/firmware_root/"

COPY start_binary.py /opt/start_binary.py

ENTRYPOINT ["/opt/start_binary.py"]
