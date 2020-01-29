# tun2socks[WIP]

## Introduction

The `tun2socks` is a tool which intercepts all traffic at ip layer and reassembles packets to a tcp stream and sends it to a SOCKS5 proxy.

Only work on Windows and Linux and still under heavy development now. Everything may be changed in the future.

Any kind of contributions is highly welcome. You can also join the development on the Telegram. [Telegram Group Link](https://t.me/joinchat/HFFokxdMTSOdbL2bKIVhnw).

## Build

### Linux

Take Debian as an example.

```
apt install libboost-all-dev -y
mkdir build
cd build
cmake ..
make
```

**Note: The version of boost should be higher than 1.66.0.**

## Usage

```
Usage: tun2socks [options] 

Optional arguments:
-h --help               show this help message and exit
-tip --tunIP            The IP address of the TUN interface.
-tmask --tunMask        The mask of the TUN interface.
-sip --socks5IP         The IP address of your socks5 server.
-sport --socks5Port     The port of your socks5 server.
-u --username           SOCKS5 username. Leave it blank if no authentication.
-p --password           SOCKS5 password. Leave it blank if no authentication.
-l --level              Set logging level. 0(Off), 1(Error), 2(Critical), 3(Warning), 4(Info), 5(Debug), 6(Trace).
-f --log-file           The path to log file. Logs are printed by default.
```

## Status

Okay, I rewrite almost all the logic of tun2socks. Although there exists some bugs, but the new structure should work well.

## TODO

- Fix LwIP running out of memoery.
- Port to Windows and MacOS.
- Real time statistics.
- Profile the program to ensure its performance.

## Known Bugs

- Huge network traffic cause LwIP to run out of memory.
- Race condition when stopping the program.

Working on these problems 💪.

## Credits

- [tun2socks](https://github.com/zhuhaow/tun2socks): It provides some basic ideas about how to reassemble packets to a tcp stream.
- [libtuntap](https://github.com/LaKabane/libtuntap): A good example about how to design tuntap API.
