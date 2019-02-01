FROM phusion/baseimage:0.11

ARG HTTP_PROXY
ARG HTTPS_PROXY
ARG http_proxy
ARG https_proxy
ARG NO_PROXY
ARG no_proxy

RUN apt-get update && install_clean \
    build-essential npm \
    python3-pip git sudo

WORKDIR /opt/app

COPY install.sh /opt/app/install.sh

RUN /opt/app/install.sh

WORKDIR /opt/app/fact_radare_viewer

CMD ["python3", "src/serve.py"]
