FROM fkiecad/fact_extractor:latest

COPY mount.py /root/

RUN mkdir /root/mount_dir

WORKDIR /root

ENTRYPOINT /root/mount.py
