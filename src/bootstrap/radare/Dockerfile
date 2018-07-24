FROM ubuntu:bionic
MAINTAINER Johannes vom Dorp <johannes.vom.dorp@fkie.fraunhofer.de>

RUN apt-get update
RUN apt-get install -y make gcc npm python3-pip git sudo

WORKDIR /opt/app

ADD install.sh /opt/app

RUN /opt/app/install.sh

WORKDIR /opt/app/fact_radare_viewer

CMD ["python3", "src/serve.py"]
