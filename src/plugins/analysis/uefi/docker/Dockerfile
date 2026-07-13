FROM alpine:3.18

# install rizin
ARG rizin_version="v0.6.2"
ARG ARCHIVE="rizin-${rizin_version}-static-x86_64.tar.xz"
RUN wget https://github.com/rizinorg/rizin/releases/download/${rizin_version}/${ARCHIVE} && \
    tar xf ${ARCHIVE} && \
    rm ${ARCHIVE}

# clone FwHunt rules
WORKDIR /work/FwHunt
ARG fwhunt_sha="1f684f1d0d38ba061988c39e0ac4d43eaeec0e50"
RUN apk add --virtual --no-cache git && \
    git init && \
    git remote add origin https://github.com/binarly-io/fwhunt && \
    git fetch --depth 1 origin ${fwhunt_sha} && \
    git checkout FETCH_HEAD && \
    apk del git

# install fwhunt-scan & python
RUN apk add --virtual --no-cache python3 py3-pip && \
    python3 -m pip install --no-cache-dir fwhunt-scan && \
    apk del py3-pip

COPY scan.py .

ENTRYPOINT ["/work/FwHunt/scan.py"]
