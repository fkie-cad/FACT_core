ARG CODEREC_REVISION="4192c2e973923c380e7d69e681a9b694abbf7519"

FROM rust:1.97.1-slim-trixie AS builder

ARG CODEREC_REVISION

WORKDIR /root

# hadolint ignore=DL3008
RUN apt-get update && \
    apt-get install -y --no-install-recommends libfontconfig1-dev pkg-config curl unzip patch git && \
    rm -rf /var/lib/apt/lists/*

RUN curl -fsSL "https://github.com/vobst/coderec/archive/${CODEREC_REVISION}.zip" \
        -o "${CODEREC_REVISION}.zip" && \
    unzip "${CODEREC_REVISION}.zip"

WORKDIR "/root/coderec-${CODEREC_REVISION}"

RUN curl --proto '=https' --tlsv1.2 -sSf https://valentinobst.de/a13f15d91f0f8846d748e42e7a881f783eb8f922861a63d9dfb74824d21337039dd8216f0373c3e5820c5e32de8f0a1880ec55456ff0da39f17d32f567d62b84/cpu_rec_corpus.tar.gz -o cpu_rec_corpus.tar.gz && \
    tar xf cpu_rec_corpus.tar.gz && \
    rm cpu_rec_corpus.tar.gz

RUN cargo build --release

FROM debian:trixie-slim AS runtime

ARG CODEREC_REVISION

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

USER 1000:1000

WORKDIR /home/coderec

COPY --chown=${USER} --from=builder "/root/coderec-${CODEREC_REVISION}/target/release/coderec" /home/coderec/coderec

ENTRYPOINT ["/home/coderec/coderec"]
