# FACT Plug-in - linter

A [FACT](https://github.com/fkie-cad/FACT_core) development plug-in.

```sh
$ git submodule add https://git-sdn.caad.fkie.fraunhofer.de/FACT/analysis_plugin/linter.git src/plugins/analysis/linter
$ ./install.py -B
``` 

If you add more than one additional plug-in, ```./install.py -B``` must be run just once after you added the last plug-in.


### Use case

This plugin tries to analyze present scripts in a firmware to find potential critical flaws by using a variety of linters.
Currently these scirpting languages are supported:

 * .sh
 * .py
 * .js
 * .lua

In future releases the following scripting languages will be supported eventually:

 * .php
 * .perl
 * .rb


