FROM fkiecad/qemu_user:qemu-3.1.0


ENV QEMU_LD_PREFIX="/opt/firmware_root/"

COPY start_binary.py /opt/start_binary.py

ENTRYPOINT ["/opt/start_binary.py"]
