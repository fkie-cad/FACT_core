# Input Vectors

This analysis plugin indentifies potential attack surfaces of a binary file (in the following 'input vectors'). It detects input vectors such as file input, command line input, or direct system call communication. Internally, it is based on radare2. There is a companion docker container `input-vectors` with an analysis script (using r2pipe to communicate with radare2).

The following input vectors are detected:
- file
- network
- random numbers
- time
- environment
- stdin
- signal
- shell
- usb
- ipc

You can configure the individual classes via the `internal/config.json` configuration file.
