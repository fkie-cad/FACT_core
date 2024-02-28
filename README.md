<p align="center">
    <img src="src/web_interface/static/FACT_smaller.png" alt="FACT Logo" width="625" height="263"/>
</p>

# The Firmware Analysis and Comparison Tool (FACT)

[![codecov](https://codecov.io/gh/fkie-cad/FACT_core/branch/master/graph/badge.svg)](https://codecov.io/gh/fkie-cad/FACT_core)
[![Codacy Badge](https://app.codacy.com/project/badge/Grade/d3910401cb58498a8c2d00be80092080)](https://www.codacy.com/gh/fkie-cad/FACT_core/dashboard?utm_source=github.com&amp;utm_medium=referral&amp;utm_content=fkie-cad/FACT_core&amp;utm_campaign=Badge_Grade)
[![Gitter chat](https://badges.gitter.im/gitterHQ/gitter.png)](https://gitter.im/FACT_core/community)

The Firmware Analysis and Comparison Tool (formerly known as Fraunhofer's Firmware Analysis Framework (FAF)) is intended to automate most of the firmware analysis process. 
It unpacks arbitrary firmware files and processes several analyses.
Additionally, it can compare several images or single files.  
Furthermore, Unpacking, analysis and comparisons are based on plug-ins guaranteeing maximal flexibility and expandability.  
More details and some screenshots can be found on our [project page](https://fkie-cad.github.io/FACT_core/).

## Requirements

FACT is designed as a multiprocess application, the more Cores and RAM, the better.

Minimal | Recommended | Software
------- | ----------- | --------
4 Cores<br>8GB RAM<br>10 GB disk space | 16 Cores<br>64GB RAM<br>10* GB disk space | git<br>python 3.8 - 3.11<br>OS see below

> ~ 10 GB required to set up FACT code, container and binaries. Additional space is necessary for result storage. That can be on a separate partition or drive.

It is possible to install FACT on any Linux distribution, but the installer is limited to
- Ubuntu 20.04 (stable)
- Ubuntu 22.04 (stable)
- Debian 11 (stable)
- Kali (experimental)

:exclamation: **Caution: FACT is not intended to be used as public internet service. The GUI is not a hardened WEB-application and it may take your server at risk!**

## Installation
FACT can be installed and run via docker. See the [FACT_docker](https://github.com/fkie-cad/FACT_docker) repo for more.

The traditional installation is generally wrapped in a single script. Some features can be selected specifically though.
See [INSTALL.md](https://github.com/fkie-cad/FACT_core/blob/master/INSTALL.md) for details.

## Usage
You can start FACT by executing the *start_all_installed_fact_components* scripts.
The script detects all installed components automatically.

```sh
$ ./start_all_installed_fact_components
```

Afterwards FACT can be accessed on <http://localhost:5000> and <https://localhost> (nginx), respectively.  

You can shut down the system by pressing *Ctrl + c* or by sending a SIGTERM to the *start_all_installed_fact_components* script.

## Advanced Usage

:fire: We're currently working to improving our documentation, including installation, getting started and alike. Follow progress on our [wiki pages](https://github.com/fkie-cad/FACT_core/wiki/). :v:

### REST API
FACT provides a REST API. More information can be found [here](https://github.com/fkie-cad/FACT_core/wiki/Rest-API).

### User Management
FACT provides an optional basic authentication, role and user management. More information can be found [here](https://github.com/fkie-cad/FACT_core/wiki/Authentication).

## List of available community plug-ins and REST scripts
* Plug-ins
  * [CVE Lookup](https://github.com/fkie-cad/FACT_analysis-plugin_CVE-lookup)
  * [Firmadyne](https://github.com/fkie-cad/FACT_firmadyne_analysis_plugin)
* REST
  * [FACT Search and Download](https://github.com/fkie-cad/FACT_Search_and_Download)
  * [PDF Report Generator](https://github.com/fkie-cad/fact_pdf_report)

## Vagrant
We provide monthly and ready-to-use vagrant boxes of our master branch. [Vagrant](https://www.vagrantup.com/) is an easy and convenient way to get started with FACT without having to install it on your machine. Just setup vagrant and import our provided box into VirtualBox. Our boxes can be found [here](https://app.vagrantup.com/fact-cad/boxes/FACT-master)!

Check out on how to get started with FACT and vagrant in our [tutorial](https://github.com/fkie-cad/FACT_core/blob/master/INSTALL.vagrant.md).

*Thanks to @botlabsDev, who initially provided a [Vagrantfile](https://github.com/botlabsDev/FACTbox) that is now, however, deprecated.*

## Contribute
The easiest way to contribute is writing your own plug-in.
Our Developers Manual can be found [here](https://github.com/fkie-cad/FACT_core/wiki/).

## Acknowledgments
This project is partly financed by [German Federal Office for Information Security (BSI)](https://www.bsi.bund.de) and others.  

## Publications / Presentations

### BlackHat Arsenal

We've been happy to show FACT in a number of BlackHat Arsenal sessions.

- [![Black Hat Arsenal](https://github.com/toolswatch/badges/blob/master/arsenal/asia/2018.svg)](http://www.toolswatch.org/2018/01/black-hat-arsenal-asia-2018-great-lineup/)
- [![Black Hat Arsenal](https://github.com/toolswatch/badges/blob/master/arsenal/europe/2018.svg)](http://www.toolswatch.org/2018/09/black-hat-arsenal-europe-2018-lineup-announced/)
- [![Black Hat Arsenal](https://github.com/toolswatch/badges/blob/master/arsenal/usa/2019.svg)](http://www.toolswatch.org/2019/05/amazing-black-hat-arsenal-usa-2019-lineup-announced/)
- [![Black Hat Arsenal](https://github.com/toolswatch/badges/blob/master/arsenal/europe/2019.svg)](https://www.blackhat.com/eu-19/arsenal/schedule/#fact--firmware-analysis-and-comparison-tool-18179)

### Other

- [Hardwear.io 2017](https://hardwear.io/the-hague-2017/speakers/johannes-vom-dorp.php) / [Slides](https://hardwear.io/document/hio.pdf)
- [Pass the salt 2019](https://2019.pass-the-salt.org/talks/71.html) / [Slides](https://2019.pass-the-salt.org/files/slides/04-FACT.pdf) / [Video](https://passthesalt.ubicast.tv/videos/improving-your-firmware-security-analysis-process-with-fact/)
- [Hardwear.io 2019](https://hardwear.io/netherlands-2019/speakers/johannes-vom-dorp-and-peter-weidenbach.php)

## Social

- <a rel="me" href="https://infosec.exchange/@fact">Mastodon</a>
- [Twitter](https://twitter.com/FAandCTool)

## License
```
    Firmware Analysis and Comparison Tool (FACT)
    Copyright (C) 2015-2024  Fraunhofer FKIE

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
    
    Some plug-ins may have different licenses. If so, a license file is provided in the plug-in's folder.
```

