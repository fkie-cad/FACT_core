<p align="center">
    <img src="src/web_interface/static/FACT_smaller.png" alt="FACT Logo" width="625" height="263"/>
</p>

# The Firmware Analysis and Comparison Tool (FACT)

[![codecov](https://codecov.io/gh/fkie-cad/FACT_core/branch/master/graph/badge.svg)](https://codecov.io/gh/fkie-cad/FACT_core)
[![BCH compliance](https://bettercodehub.com/edge/badge/fkie-cad/FACT_core?branch=master)](https://bettercodehub.com/)
[![Codacy Badge](https://api.codacy.com/project/badge/Grade/8101a5fc388848e89ec705e06a5ad734)](https://www.codacy.com/app/johannes.vom.dorp/FACT_core?utm_source=github.com&amp;utm_medium=referral&amp;utm_content=fkie-cad/FACT_core&amp;utm_campaign=Badge_Grade)
[![Gitter chat](https://badges.gitter.im/gitterHQ/gitter.png)](https://gitter.im/FACT_core/community)

The Firmware Analysis and Comparison Tool (formerly known as Fraunhofer's Firmware Analysis Framework (FAF)) is intended to automate most of the firmware analysis process. 
It unpacks arbitrary firmware files and processes several analysis.
Additionally, it can compare several images or single files.  
Furthermore, Unpacking, analysis and compares are based on plug-ins guaranteeing maximal flexibility and expandability.  
More details and some screenshots can be found on our [project page](https://fkie-cad.github.io/FACT_core/).

## Requirements

FACT is designed as a multiprocess application, the more Cores and RAM, the better.

Minimal | Recommended | Software
------- | ----------- | --------
4 Cores<br>8GB RAM | 16 Cores<br>64GB RAM | Ubuntu (16.04 or 18.04)<br>Python 3.5 or above

It is possible to install FACT on any Linux distribution but the installer is limited to Ubuntu 16.04 and 18.04 at the moment.

:exclamation: **Caution: FACT is not intended to be used as public internet service. The GUI is not a hardened WEB-application and it may take your server at risk!**

## Installation

The installation is generally wrapped in a single script. Some features can be selected specifically though.
See [INSTALL.md](https://github.com/fkie-cad/FACT_core/blob/master/INSTALL.md) for details.

## Usage
You can start FACT by executing the *start_all_installed_fact_components* scripts.
The script detects all installed components automatically.

```sh
$ ./start_all_installed_fact_components
```

Afterwards FACT can be accessed on <http://localhost:5000> and <https://localhost> (nginx), respectively.  

You can shutdown the system by pressing *Ctrl + c* or by sending a SIGTERM to the *start_all_installed_faf_components* script.

## Advanced Usage

:fire: We're currently working to improving our documentation, including installation, getting started and alike. Follow progess on our [wiki pages](https://github.com/fkie-cad/FACT_core/wiki/). :v:

### REST API
FACT provides a REST API. More information can be found [here](https://github.com/fkie-cad/FACT_core/wiki/rest-documentation).

### User Management
FACT provides an optional basic authentication, role and user management. More information can be found [here](https://github.com/fkie-cad/FACT_core/wiki/Authentication).

## List of available community plug-ins and REST scripts
* Plug-ins
  * [CVE Lookup](https://github.com/fkie-cad/FACT_analysis-plugin_CVE-lookup)
  * [Firmadyne](https://github.com/fkie-cad/FACT_firmadyne_analysis_plugin)
* REST
  * [FACT Search and Download](https://github.com/fkie-cad/FACT_Search_and_Download)
  * [PDF Report Generator](https://github.com/fkie-cad/fact_pdf_report)

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
- [USA 2019](https://www.blackhat.com/us-19/arsenal/schedule/index.html#fact--firmware-analysis-and-comparison-tool-15216)

### Other

- [Hardwear.io 2017](https://hardwear.io/the-hague-2017/speakers/johannes-vom-dorp.php) / [Slides](https://hardwear.io/document/hio.pdf)
- [Pass the salt 2019](https://2019.pass-the-salt.org/talks/71.html) / [Slides](https://2019.pass-the-salt.org/files/slides/04-FACT.pdf) / [Video](https://passthesalt.ubicast.tv/videos/improving-your-firmware-security-analysis-process-with-fact/)
- [Hardwear.io 2019](https://hardwear.io/netherlands-2019/speakers/johannes-vom-dorp-and-peter-weidenbach.php)

## License
```
    Firmware Analysis and Comparison Tool (FACT)
    Copyright (C) 2015-2019  Fraunhofer FKIE

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

