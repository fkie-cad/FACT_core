ARG CODEREC_VER="0.2"

FROM rust:1.97.1-slim-trixie AS builder

ARG CODEREC_VER

WORKDIR /root

# hadolint ignore=DL3008
RUN apt-get update && \
    apt-get install -y --no-install-recommends libfontconfig1-dev pkg-config curl unzip patch && \
    rm -rf /var/lib/apt/lists/*

RUN curl -fsSL "https://github.com/vobst/coderec/archive/refs/tags/${CODEREC_VER}.zip" \
        -o "${CODEREC_VER}.zip" && \
    unzip "${CODEREC_VER}.zip"

WORKDIR "/root/coderec-${CODEREC_VER}"

COPY docker.patch .

RUN patch -p1 <docker.patch

RUN curl --proto '=https' --tlsv1.2 -sSf https://valentinobst.de/a13f15d91f0f8846d748e42e7a881f783eb8f922861a63d9dfb74824d21337039dd8216f0373c3e5820c5e32de8f0a1880ec55456ff0da39f17d32f567d62b84/cpu_rec_corpus.tar.gz -o cpu_rec_corpus.tar.gz && \
    tar xf cpu_rec_corpus.tar.gz && \
    rm cpu_rec_corpus.tar.gz && \
    cargo build --release

FROM debian:trixie-slim AS runtime

ARG CODEREC_VER

ENV USER=coderec
ENV GROUPNAME=coderec
ENV UID=1000
ENV GID=1000

RUN groupadd --gid "$GID" "$GROUPNAME" \
    && useradd \
        --no-log-init \
        --home-dir "/home/coderec" \
        --no-create-home \
        --gid "$GROUPNAME" \
        --uid "$UID" \
        --password "" \
        --shell /bin/bash \
        $USER

RUN mkdir -p /home/coderec

# hadolint ignore=DL3008
RUN apt-get update && \
    apt-get install -y --no-install-recommends libfontconfig1 && \
    rm -rf /var/lib/apt/lists/*

USER coderec

WORKDIR /home/coderec

COPY --chown=${USER} --from=builder "/root/coderec-${CODEREC_VER}/target/release/coderec" /home/coderec/coderec

ENTRYPOINT ["/home/coderec/coderec"]
