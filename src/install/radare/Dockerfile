FROM phusion/baseimage:0.11

ARG HTTP_PROXY
ARG HTTPS_PROXY
ARG http_proxy
ARG https_proxy
ARG NO_PROXY
ARG no_proxy

WORKDIR /opt/app

COPY install.sh /opt/app/install.sh

RUN apt-get update && install_clean \
    build-essential npm \
    python3-pip git sudo

RUN /opt/app/install.sh

RUN apt-get remove -y build-essential npm python3-pip git && install_clean

WORKDIR /opt/app/fact_radare_viewer

CMD ["python3", "src/serve.py"]
