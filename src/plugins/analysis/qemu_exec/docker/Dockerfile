FROM fkiecad/qemu_user:qemu-3.1.0


ENV QEMU_LD_PREFIX="/opt/firmware_root/"

COPY start_binary.sh /opt/start_binary.sh

ENTRYPOINT ["/opt/start_binary.sh"]
