# tun2socks[WIP]

## Introduction

The `tun2socks` is a tool which intercepts all traffic at ip layer and reassembles packets to a tcp stream and sends it to a SOCKS5 proxy.

Only work in Windows and still under heavy development now. Everything may be changed in the future.

Any kind of contributions is highly welcome. You can also join the development on the Telegram. [Telegram Group Link](https://t.me/joinchat/HFFokxdMTSOdbL2bKIVhnw).

## Build

Currently the project is a Visual Studio 2017 project and uses `vcpkg` as the package manager.

Firstly, install all dependencies

```
vcpkg install boost
```

Then compile and run it.

## Usage

The `tun2socks-core` is the core library of the project and is designed to only provide basic functions, so you can construct any interface you like.

Here I provide a sample `tun2socks-cli` to show how to use `tun2socks-core`.

## TODO

- Port to MacOS and Linux.
- Support DNS spoofing and PAC parsing.
- Profile the program to ensure its performace.

## Credits

[tun2socks](https://github.com/zhuhaow/tun2socks)
