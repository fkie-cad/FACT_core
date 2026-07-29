FROM nestybox/ubuntu-noble-systemd-docker@sha256:8b1c4409fe89bc110e1e468767074fe4403ba6bb2d1b34881fec5df8b6c2f9c3 AS fact_base

ARG FACT_DIR=/opt/fact
COPY src $FACT_DIR
WORKDIR $FACT_DIR

RUN --mount=type=cache,target=/var/cache/apt \
    --mount=type=cache,target=/var/lib/apt \
    apt-get update && \
    apt-get install -y --no-install-recommends \
      curl \
      python3-venv \
      postgresql-client \
      redis-tools

RUN python3 -m venv venv
ARG VENV_DIR=$FACT_DIR/venv/bin
ENV PATH=$VENV_DIR:$PATH \
    VIRTUAL_ENV=$VENV_DIR \
    PYTHONPATH=$FACT_DIR \
    FACT_INSTALLER_SKIP_DOCKER=1

RUN --mount=type=cache,target=/var/cache/apt \
    --mount=type=cache,target=/var/lib/apt \
    ./install/pre_install.sh -D

FROM fact_base AS fact_frontend

RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    python3 install.py -F -H

RUN chown -R admin:admin "$FACT_DIR"

COPY --chown=admin docker/entrypoint_frontend.sh .

ENTRYPOINT ["./entrypoint_frontend.sh"]

FROM fact_base AS fact_backend

RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    python3 install.py -B

RUN chown -R admin:admin "$FACT_DIR"

COPY --chown=admin docker/entrypoint_backend.sh .

# This file serves as a flag to indicate that the backend installation of the docker containers is completed
RUN touch DOCKER_INSTALL_INCOMPLETE
# We must still install the docker images, so we need to overwrite the flag now:
ENV FACT_INSTALLER_SKIP_DOCKER=0

ENTRYPOINT ["./entrypoint_backend.sh"]
