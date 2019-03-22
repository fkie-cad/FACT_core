# FACT_analysis_plugin_template
Download this Hello World template if you want to write your own FACT analysis plug-in.
All content of this Repo must be copied to src/plugins/analysis/PLUGIN_NAME.
Change PLUGIN_NAME to the desired name of your plug-in

This repository provides a minimal functional plug-in.

A minimal README template can be found below.

----------8<----------8<----------8<----------8<----------

# FACT Plug-in - Hello World 

A [FACT](https://github.com/fkie-cad/FACT_core) development demo plug-in.

```sh
$ git submodule add https://github.com/fkie-cad/FACT_analysis_plugin_template.git src/plugins/analysis/hello_world
$ ./install.py -B
``` 

If you add more than one additional plug-in, ```./install.py -B``` must be run just once after you added the last plug-in.
