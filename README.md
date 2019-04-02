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

```C++
int main()
{
	TUNAdapter adapters[32];
	auto size = get_tuns(adapters, 32); // get all tap drivers in the system. This step is only needed on Windows.
	if (size == 0)
		return 0;
	else {
		auto adapter = open_tun(&adapters[0]); // open the adapter.
		adapter->ip = inet_addr(tap_ip);
		adapter->mask = inet_addr(tap_mask);
		adapter->network = inet_addr(tap_network);
		tun2socks_start(adapter); // start tun2socks.
	}
}
```

On Windows you should download [Tap Driver](http://build.openvpn.net/downloads/releases/latest/) frist.

## TODO

- Configurable SOCKS5 proxy address.
- Support UDP.
- User-friendly API design.
- Port to MacOS and Linux.
- Support DNS spoofing and PAC parsing.
- Profile the program to ensure its performace.

## Credits

[tun2socks](https://github.com/zhuhaow/tun2socks)
