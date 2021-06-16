FROM ubuntu:focal

RUN apt -y update && apt -y upgrade
RUN DEBIAN_FRONTEND="noninteractive" apt -y install tzdata
# Install deps that are not automatically installed by pre_install.sh
# TODO use "--no-install-recommends" here. git has some optional deps that prevent it from cloning
RUN apt -y install git sudo lsb-release wget

RUN useradd -r fact
RUN printf 'fact	ALL=(ALL:ALL) NOPASSWD: ALL\n' > /etc/sudoers.d/99_fact

RUN mkdir /opt/FACT_core && chown fact: /opt/FACT_core
RUN mkdir /var/log/fact && chown fact: /var/log/fact

USER fact:fact
WORKDIR /var/log/fact

RUN git clone --branch docker-dev https://github.com/fkie-cad/FACT_core.git /opt/FACT_core

RUN /opt/FACT_core/src/install/pre_install.sh
RUN FACT_INSTALLER_SKIP_DOCKER=y /opt/FACT_core/src/install.py

# Apply some patches to the default config to make it _just work_ without any configuration
# The patched config is only needed during runtime and not during installation
COPY --chown=fact:fact 0000_uwsgi_bindip.patch /tmp/0000_uwsgi_bindip.patch
RUN patch /opt/FACT_core/src/config/uwsgi_config.ini < /tmp/0000_uwsgi_bindip.patch \
    && rm /tmp/0000_uwsgi_bindip.patch
COPY --chown=fact:fact 0001_main_cfg.patch /tmp/0001_main_cfg.patch
RUN patch /opt/FACT_core/src/config/main.cfg < /tmp/0001_main_cfg.patch \
    && rm /tmp/0001_main_cfg.patch

COPY entrypoint.sh /usr/local/bin/
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
