FROM fkiecad/radare-web-gui:latest

# Create non-root user
RUN useradd -m r2 && \
    adduser r2 sudo && \
    echo "r2:r2" | chpasswd

# Initilise base user
USER r2
WORKDIR /home/r2
ENV HOME /home/r2

COPY internal/ /home/r2/input_vectors/

ENTRYPOINT [ "python3", "/home/r2/input_vectors/input_vectors_r2.py" ]
