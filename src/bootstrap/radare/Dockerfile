FROM ubuntu:bionic
MAINTAINER Johannes vom Dorp <johannes.vom.dorp@fkie.fraunhofer.de>

RUN apt-get update
RUN apt-get install -y make gcc nginx npm python3-pip git sudo

WORKDIR /opt/app

ADD install.sh /opt/app
ADD radare-forwarding /opt/app/radare-forwarding

RUN /opt/app/install.sh

WORKDIR /opt/app/radare-forwarding

EXPOSE 8000

# CMD ["python3", "src/serve.py"]
