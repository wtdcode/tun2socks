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

The `tun2socks-core` is the core library of the project and is designed to only provide basic functions with C compatibility, so you can construct any interface you like.

Here I provide a sample `tun2socks-cli` to show how to use `tun2socks-core`.

```C++
int main()
{
	// get a tun adapter instance.
	auto adapter = open_tun(); 
	// set its addresses.
	adapter->ip = inet_addr(tap_ip);
	adapter->mask = inet_addr(tap_mask);
	// usually equals to `ip & mask`.
	adapter->network = inet_addr(tap_network); 
	// we construct a tun2socks config with no-authentication socks proxy.
	SOCKS5NoAuth auth;
	auto config = make_config_with_socks5_no_auth(adapter, socks5_address, strlen(socks5_address), 1080, &auth);
	// start tun2socks.
	tun2socks_start(config);
	// clean.
	delete_tun(adapter);
	delete_config(config);
}
```

On Windows you should download [Tap Driver](http://build.openvpn.net/downloads/releases/latest/) frist.

## TODO

- Support UDP.
- User-friendly API design.
- Port to MacOS and Linux.
- Robust error handling.
- Support DNS spoofing and PAC parsing.
- Profile the program to ensure its performace.
- Real time statistics.

## Credits

- [tun2socks](https://github.com/zhuhaow/tun2socks): It provides some basic ideas about how to reassemble packets to a tcp stream.
