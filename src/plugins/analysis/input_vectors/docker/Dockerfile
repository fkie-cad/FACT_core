FROM fkiecad/radare-web-gui:latest

# Create non-root user
RUN useradd -m r2 && \
    adduser r2 sudo && \
    echo "r2:r2" | chpasswd

# Initilise base user
USER r2
WORKDIR /home/r2
ENV HOME /home/r2

COPY config.json .
COPY input_vectors_r2.py .

ENTRYPOINT [ "python3", "input_vectors_r2.py" ]
