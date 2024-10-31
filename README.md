# The Firmware Analysis and Comparison Tool (FACT)

![](src/web_interface/static/FACT_smaller.png | width=625)

[![codecov](https://codecov.io/gh/fkie-cad/FACT_core/branch/master/graph/badge.svg)](https://codecov.io/gh/fkie-cad/FACT_core)
[![Codacy Badge](https://app.codacy.com/project/badge/Grade/d3910401cb58498a8c2d00be80092080)](https://www.codacy.com/gh/fkie-cad/FACT_core/dashboard?utm_source=github.com&amp;utm_medium=referral&amp;utm_content=fkie-cad/FACT_core&amp;utm_campaign=Badge_Grade)
[![Gitter chat](https://badges.gitter.im/gitterHQ/gitter.png)](https://gitter.im/FACT_core/community)
[![CI Build](https://github.com/fkie-cad/FACT_core/actions/workflows/build_ci.yml/badge.svg)](https://github.com/fkie-cad/FACT_core/actions/workflows/build_ci.yml)
[![Ruff](https://github.com/fkie-cad/FACT_core/actions/workflows/ruff.yml/badge.svg)](https://github.com/fkie-cad/FACT_core/actions/workflows/ruff.yml)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)

The Firmware Analysis and Comparison Tool is intended to automate most of the firmware analysis process.
It recursively unpacks arbitrary firmware images and runs several analyses on each file.
Additionally, it can compare several images or single files.
Furthermore, Unpacking, analysis and comparisons are based on plugins guaranteeing maximal flexibility and
expandability.  
More details and some screenshots can be found on our [project page](https://fkie-cad.github.io/FACT_core/).

## Requirements

FACT is designed as a multiprocess application, the more Cores and RAM, the better.

| Minimal                                 | Recommended                                |
|-----------------------------------------|--------------------------------------------|
| 4 Cores<br>8 GB RAM<br>10 GB disk space | 16 Cores<br>64 GB RAM<br>10* GB disk space |

> ~ 10 GB required to set up FACT code, container and binaries.
> Additional space is necessary for storage of unpacked files and analysis results.
> This can be on a separate partition or drive.

It is possible to install FACT on any Linux distribution, but the installer is limited to

- Debian 11/12 (stable)
- Ubuntu 20.04/22.04/24.04 (stable)
- Linux Mint 20/21/22 (stable)
- Kali (experimental)

FACT requires Python 3.9–3.12 (should be the default in all distributions except Ubuntu 20.04 where you can install
a newer version using `apt`)

:exclamation: **Caution: FACT is not intended to be used as public internet service. The GUI is not a hardened
WEB-application and it may take your server at risk!**

## Usage

You can start FACT by executing the `start_all_installed_fact_components` script.
The script detects all installed components automatically.

```sh
./start_all_installed_fact_components
```

Afterward, FACT can be accessed on <http://localhost:5000> (default) or <https://localhost> (if FACT is installed with
nginx).

You can shut down the system by pressing *Ctrl + c* or by sending a SIGTERM to the *start_all_installed_fact_components*
script.

## Local Installation

The setup process is mostly automated and wrapped in a single script.
Some features can be selected specifically though.
For a detailed guid on how to install FACT see [INSTALL.md](https://github.com/fkie-cad/FACT_core/blob/master/INSTALL.md).

## Alternatives to installing FACT locally

### Vagrant

We provide monthly and ready-to-use vagrant boxes of our master branch.
[Vagrant](https://www.vagrantup.com/) is an easy and convenient way to get started with FACT without having to install
it on your machine.
Just setup vagrant and import our provided box into VirtualBox.
Our boxes can be found [here](https://app.vagrantup.com/fact-cad/boxes/FACT-master)!

Check out on how to get started with FACT and vagrant in
our [tutorial](https://github.com/fkie-cad/FACT_core/blob/master/INSTALL.vagrant.md).

*Thanks to @botlabsDev, who initially provided a [Vagrantfile](https://github.com/botlabsDev/FACTbox) that is now,
however, deprecated.*

### Docker

There is also a dockerized version, but it is currently outdated
(see the [FACT_docker](https://github.com/fkie-cad/FACT_docker) repo for more information).

## Documentation

:information_source: More documentation on how to use FACT can be found on
our [wiki pages](https://github.com/fkie-cad/FACT_core/wiki/).

Our Sphinx documentation can be found [here](https://fkie-cad.github.io/FACT_core/).

Information on what FACT is and how it works can also be found in the slides in the
[`docs` folder](https://github.com/fkie-cad/FACT_core/tree/master/docs).

### REST API

FACT provides a REST API. More information can be found [here](https://github.com/fkie-cad/FACT_core/wiki/Rest-API).

### User Management

FACT provides an optional basic authentication, role and user management.
More information can be found [here](https://github.com/fkie-cad/FACT_core/wiki/Authentication).

## Contributing

The easiest way to contribute is writing your own plugin.
Our Developer Manual can be found [here](https://github.com/fkie-cad/FACT_core/wiki/).

## Additional plugins

Additional plugins are available on GitHub:

- [Codescanner](https://github.com/fkie-cad/Codescanner_FACT_plugin) (:warning: different license)

## Import/Export of Results

The script `src/firmware_import_export.py` can be used to export unpacked files and analysis results and import them
into another FACT instance.
The data is stored as a ZIP archive, and this is also the format the script expects during import. 
To export files and analysis data of analyzed firmware images, run

```shell
python3 firmware_import_export.py export FW_UID [FW_UID_2 ...] [-o OUTPUT_DIR]
```

After this, you can import the exported files with

```shell
python3 firmware_import_export.py import FW.zip [FW_2.zip ...]
```

## Acknowledgments

This project is partly financed by [German Federal Office for Information Security (BSI)](https://www.bsi.bund.de) and
others.

## Publications / Presentations

### BlackHat Arsenal

We've been happy to show FACT in a number of BlackHat Arsenal sessions.

- [![Black Hat Arsenal](https://github.com/toolswatch/badges/blob/master/arsenal/asia/2018.svg)](http://www.toolswatch.org/2018/01/black-hat-arsenal-asia-2018-great-lineup/)
- [![Black Hat Arsenal](https://github.com/toolswatch/badges/blob/master/arsenal/europe/2018.svg)](http://www.toolswatch.org/2018/09/black-hat-arsenal-europe-2018-lineup-announced/)
- [![Black Hat Arsenal](https://github.com/toolswatch/badges/blob/master/arsenal/usa/2019.svg)](http://www.toolswatch.org/2019/05/amazing-black-hat-arsenal-usa-2019-lineup-announced/)
- [![Black Hat Arsenal](https://github.com/toolswatch/badges/blob/master/arsenal/europe/2019.svg)](https://www.blackhat.com/eu-19/arsenal/schedule/#fact--firmware-analysis-and-comparison-tool-18179)
- [![Black Hat Arsenal](https://github.com/toolswatch/badges/blob/master/arsenal/usa/2022.svg)](https://www.blackhat.com/us-22/arsenal/schedule/#fact--26776)

### Other

- [Hardwear.io 2017](https://hardwear.io/the-hague-2017/speakers/johannes-vom-dorp.php) / [Slides](https://hardwear.io/document/hio.pdf)
- [Pass the salt 2019](https://2019.pass-the-salt.org/talks/71.html) /
  [Slides](https://2019.pass-the-salt.org/files/slides/04-FACT.pdf) /
  [Video](https://passthesalt.ubicast.tv/videos/improving-your-firmware-security-analysis-process-with-fact/)
- [Hardwear.io 2019](https://hardwear.io/netherlands-2019/speakers/johannes-vom-dorp-and-peter-weidenbach.php)

## Social

- [Twitter](https://twitter.com/FAandCTool)
- [Gitter](https://app.gitter.im/?updated=1.11.30#/room/#FACT_core_community:gitter.im)

## License

> Firmware Analysis and Comparison Tool (FACT)
>
> Copyright (C) 2015-2024 Fraunhofer FKIE
>
> This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public
> License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any
> later version.
> This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied
> warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  
> See the GNU General Public License for more details.
> You should have received a copy of the GNU General Public License along with this program.  
> If not, see <http://www.gnu.org/licenses/>.
>
> Some plugins may have different licenses.
> If so, a license file is provided in the plugin's folder.
