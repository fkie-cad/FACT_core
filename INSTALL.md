# FACT installation

The Firmware and Comparison Tool (FACT) consists of three components: frontend, database and backend.
All components can be installed on different machines (see [Distributed setup](#distributed-setup)), but you can also
install everything on one machine (see [Simple (non-distributed) setup](#simple-non-distributed-setup)).
There is an automated installation script supporting Ubuntu LTS and Debian systems (that are not EoL).
:exclamation: **The automated installation script might remove some packages of your Ubuntu installation. In some cases,
FACT relies on newer software versions than the ones provided by the Ubuntu repositories.**

## TL;DR

Execute the following commands (not as `root`!):

```shell
sudo apt update && sudo apt install -y git
git clone https://github.com/fkie-cad/FACT_core.git ~/FACT_core
~/FACT_core/src/install/pre_install.sh
```

Then reboot (e.g., with `sudo reboot`) or log out and back in and afterward run

```shell
. ~/FACT_core/.venv/bin/activate
~/FACT_core/src/install.py
~/FACT_core/start_all_installed_fact_components
```

Wait a few seconds, open your browser and go to [`http://localhost:5000`](http://localhost:5000).
Use `Ctrl + c` in your terminal to shut down FACT.

> [!NOTE]
> You can run the whole installation without restart by using `newgrp` (useful e.g. for scripting): (Please mind: this
> will only work for the current shell, you still need to reboot before being able to use docker normally)

```shell
sudo apt update && sudo apt install -y git
git clone https://github.com/fkie-cad/FACT_core.git ~/FACT_core
~/FACT_core/src/install/pre_install.sh
newgrp docker << END
. ~/FACT_core/.venv/bin/activate
python3 FACT_core/src/install.py
END
```

### WSL only

Follow the first three installation steps above (stop before the reboot).
To make sure that docker starts when you log in to a WSL machine, follow the instructions on [this webpage](https://blog.nillsf.com/index.php/2020/06/29/how-to-automatically-start-the-docker-daemon-on-wsl2/).
Then continue the installation as usual.

### Virtual environment

FACT is installed in a virtual python environment (venv) to avoid conflicts with system python packages.
Its Python dependencies are managed with [uv](https://docs.astral.sh/uv/) (`pyproject.toml` and `uv.lock`).
`pre_install.sh` installs uv (if it is missing) and the Python dependencies:

- If a venv is active when you run `pre_install.sh`, the dependencies are installed into it.
- Otherwise, `pre_install.sh` creates the venv `.venv` in the FACT_core directory.

Before running `src/install.py` or starting FACT, you need to activate the venv:

```shell
# this is for bash and compatible shells. If you use a different shell, you may need a different script from .venv/bin/
source .venv/bin/activate
```

The installer adds the dependencies of the installed components (frontend, backend, plug-ins) to the active venv.
For development (running the tests, linting), also install the `dev` dependency group (with the venv activated):

```shell
uv sync --locked --inexact --active --all-packages
```

If you have an existing FACT installation without venv, rerun `pre_install.sh` and the installation.

## Simple (non-distributed) setup

### Pre-installation

Some components of FACT depend on docker.
Since a restart is necessary before docker can run.
The system has to be rebooted in between FACT installation.
Thus, the docker setup and some auxiliary stuff have been moved to the `pre_install.sh` script.

The following lines will handle the first half of the installation (based on git not tarball):

```sh
sudo apt update && sudo apt upgrade && sudo apt install git
git clone https://github.com/fkie-cad/FACT_core.git
cd FACT_core
src/install/pre_install.sh
```

Now modify `src/config/fact-core-config.toml` to suit your needs.
Especially, you should change the postgres passwords.
The database is initialized with these passwords on first start.

Create the `firmware_file_storage_directory` defined in `fact-core-config.toml`.
Make sure that the log directory exists as well.

If you have any additional plug-ins, copy/clone them into corresponding `src/plugins/` directory.
Every directory in `src/plugins/analysis/` is part of FACT's uv workspace, so each analysis plug-in needs a
`pyproject.toml` in its directory that declares its Python dependencies (see the existing plug-ins, e.g.
[file_type](src/plugins/analysis/file_type/pyproject.toml)):

```toml
[project]
name = "fact-plugin-my_plugin"
version = "0.1.0"
dependencies = [
    "some-package==1.2.3",  # or `dependencies = []` if the plug-in has no Python dependencies
]
```

Otherwise, the installation fails with an error like
``Workspace member `.../src/plugins/analysis/my_plugin` is missing a `pyproject.toml` ``.
This also happens with leftover plug-in directories, e.g. directories containing only `__pycache__` after switching
git branches: delete them.
If a directory should not be treated as a plug-in, add it to the `exclude` list under `[tool.uv.workspace]` in
the `pyproject.toml` in the root of the repository instead.
After adding or changing a plug-in's `pyproject.toml`, update the lockfile with `uv lock`.

:exclamation: **Reboot before executing the src/install.py** :exclamation:
:exclamation: **You have to do the above steps before you do anything else** :exclamation:

### Main installation

:customs: **The installation script installs a lot of dependencies that may have different licenses**
After reboot, enter the FACT_core directory, activate the venv and execute:

```sh
. .venv/bin/activate
src/install.py
```

:beer: **Get a drink... Installation of the dependencies might take some time...** :tea:

More advanced setup options can be viewed using the help function of the installer `src/install.py --help` and are
explained in some detailed in the following paragraphs.

If the environment variable `FACT_INSTALLER_SKIP_DOCKER` is set the installer
will skip all pulling/building of docker images.
This is primarily used for the docker container of FACT but can also be used to
save some time when you already have the images.

## Distributed setup

The three components (database, backend and frontend) can be installed independently to create a distributed installation.
For this, the components can be individually installed using the command line options `--frontend`, `--backend`, and
`--db` (see `src/install.py --help`).
The two worker components (frontend, backend) both use the database and communicate through Redis.
This means the database and Redis need to be accessible from these systems.
The database in turn does not need any knowledge of its place in the network, other than on which **ip:port**
combination the database server has to be hosted.
The configuration on the frontend system has to be changed so that the values of `common.postgres.server` and
`common.postgres.port` match the **ip:port** for the database.
The same has to be done for Redis and the backend.
In addition, since the raw firmware and file binaries are stored in the backend, the
`backend.firmware-file-storage-directory` has to be created (by default `/media/data/fact_fw_data`).

## Installation with Nginx (**--nginx**)

The installer supports automated installation and configuration of nginx.
This will enable SSL protected access to the frontend via port 443.
To activate nginx support, add the *-N* option.
See our [radare wiki page](https://github.com/fkie-cad/FACT_core/wiki/radare-integration) for some additional steps to
allow forwarding of the radare webUI.

## Making FACT available over the network

Using the default configuration, FACT is only reachable from the system it is running on.
Making FACT reachable from other systems (e.g., on your local network) is simple, though:
All you have to do is replacing `127.0.0.1:5000` in the `uwsgi_config.ini` with `0.0.0.0:5000` (`:5000` also works).
This is not necessary if you are using nginx, because nginx is configured to accept external connections by default.
You may have to reconfigure your firewall to allow connections if you are using one.

## Install Statistic Generation Cron Job (**--statistic_cronjob**)

FACT provides statistics generated by triggering the *update_statistic* script.
The installation script can add a cronjob to trigger this script once an hour.
To do this, add the *-U* option when installing.

## Installation with/without radare (**--no_radare**)

In contrast to nginx, radare has to be deselected as it is installed by default.
This can be done with the `-R` parameter.
On additional notes regarding the setup of the radare web GUI see the extensive notes in the [wiki](https://github.com/fkie-cad/FACT_core/wiki/radare-integration).

## Update an older Installation

Simply checkout the new sources, rerun the `src/install/pre_install.sh` and then `src/install.py` (with the venv
activated, see [Virtual environment](#virtual-environment)).
Rebooting is not necessary if docker is already present.
For tarball installations, the easiest way is to back up the config files, remove the FACT folder, extract the new one
and put the configuration back in.
Then also re-run `src/install/pre_install.sh` and `src/install.py`.

If your FACT installation is v3.2 or lower and you use authentication, then you have to migrate the user database.
To do so, run the [migrate_database.py](src/migrate_database.py) script.

## FACT and your HTTP Proxy

In some advanced network setups, you might need to configure an HTTP proxy for internet connectivity.
Most components of FACT do not require internet access during runtime.
The [hash lookup](https://github.com/fkie-cad/FACT_core/blob/master/src/plugins/analysis/hashlookup/code/hashlookup.py)
plugin, which polls [https://hashlookup.circl.lu/](https://hashlookup.circl.lu/) during analysis, is an exemplary exception.

However, FACT's **installation routine** requires a lot of internet I/O, ranging from fetching APT packages, over static
assets from CDNs using `curl` or `wget`, to docker image builds.
Thus, it is important to properly configure your system.
Below, you will find some hints for system-wide proxy configuration.

### Proxy environment variables

Most dependencies and tools used by FACT honor `*_PROXY` environment variables.
You can set these on a system-wide scope inside `/etc/environment`.

```sh
echo 'HTTP_PROXY=http://<YOUR-PROXY-HERE>:<PORT>/
HTTPS_PROXY=http://<YOUR-PROXY-HERE>:<PORT>/
http_proxy=http://<YOUR-PROXY-HERE>:<PORT>/
https_proxy=http://<YOUR-PROXY-HERE>:<PORT>/
no_proxy="localhost,127.0.0.1,::1"
NO_PROXY="localhost,127.0.0.1,::1"' | sudo tee -a /etc/environment
```

### apt

`apt` is usually called via `sudo` in our installation scripts.
While `apt` honors the previously set `*_PROXY` environment variables, `sudo` is configured on some distributions to
drop them upon privilege elevation.
You have two options to fix this issue.

**Option 1:** Configure `sudo` to not drop these variables:

Open the sudoers file with `sudo visudo` and append the following line:

```sudoers
Defaults env_keep += "ftp_proxy http_proxy https_proxy no_proxy"
```

**Option 2:** Directly configure `apt` to use those env vars:

```sh
echo 'Acquire::http::Proxy "http://<YOUR-PROXY-HERE>:<PORT>/";
Acquire::https::Proxy "http://<YOUR-PROXY-HERE>:<PORT>/";' | sudo tee /etc/apt/apt.conf.d/00proxy
```

### Docker

Please refer to the [official docker documentation](https://docs.docker.com/network/proxy/) to configure it for proxy usage.

## Troubleshooting

If you encounter any problems, check out our [Troubleshooting wiki](https://github.com/fkie-cad/FACT_core/wiki/Troubleshooting)
before opening an issue on GitHub.
