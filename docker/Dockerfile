FROM ubuntu:focal

RUN apt -y update && apt -y upgrade
# Install deps that are not automatically installed by pre_install.sh
# TODO use "--no-install-recommends" here. git has some optional deps that prevent it from cloning
RUN apt -y install git sudo lsb-release wget

RUN DEBIAN_FRONTEND="noninteractive" apt -y install tzdata

RUN useradd -r fact
RUN mkdir /opt/FACT_core && chown fact: /opt/FACT_core
RUN printf 'fact	ALL=(ALL:ALL) NOPASSWD: ALL\n' > /etc/sudoers.d/99_fact

USER fact:fact
RUN git clone --branch docker https://github.com/maringuu/FACT_core.git /opt/FACT_core
RUN /opt/FACT_core/src/install/pre_install.sh

# We cd to /tmp to have the directory writable for the log file
RUN cd /tmp && FACT_INSTALLER_SKIP_DOCKER=y /opt/FACT_core/src/install.py

COPY entrypoint.sh /usr/local/bin/
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
