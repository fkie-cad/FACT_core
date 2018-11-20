# FACT plug-in - QEMU executable

This plugin determines whether a binary is executable with QEMU (including different architectures).

## Installation

Go to FACT's root directory and execute the following lines:

```sh
$ git submodule add https://git-sdn.caad.fkie.fraunhofer.de/FACT/analysis_plugin/plugin_qemu_exec.git src/plugins/analysis/qemu_exec
$ ./install.py -B
```
If you add more than one additional plug-in, ```./install.py -B``` must be run just once after you added the last plug-in.
