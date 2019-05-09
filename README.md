# tun2socks[WIP]

## Introduction

The `tun2socks` is a tool which intercepts all traffic at ip layer and reassembles packets to a tcp stream and sends it to a SOCKS5 proxy.

Only work in Windows and still under heavy development now. Everything may be changed in the future.

Any kind of contributions is highly welcome. You can also join the development on the Telegram. [Telegram Group Link](https://t.me/joinchat/HFFokxdMTSOdbL2bKIVhnw).

## Build

Note: The project is being migrated to cmake. It won't depend on the Visual Studio in the future since I'm going to make a cross-platform tun2socks. However, for now, the Visual Studio can still be used to manage the project for various reasons.

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
#include "tun2socks.h"

static const char* tap_ip = "10.2.3.1";
static const char* tap_network = "10.2.3.0";
static const char* tap_mask = "255.255.255.252";

static const char* socks5_address = "127.0.0.1";
static const uint16_t socks5_port = 1080;
static const uint32_t udp_timeout = 60000; // 60000 ms

int main()
{
	// open a tun adapter.
	// Note: On windows, you need to install a tap driver first.
	auto adapter = open_tun();
	// set the address of the adapter.
	adapter->ip = inet_addr(tap_ip);
	adapter->mask = inet_addr(tap_mask);
	adapter->network = inet_addr(tap_network);
	// no authentication
	SOCKS5NoAuth auth{ NO_AUTH };
	auto config = make_config_with_socks5_no_auth(
		adapter, 
		socks5_address, 
		strlen(socks5_address), 
		socks5_port, 
		udp_timeout, 
		&auth);
	// start tun2socks
	tun2socks_start(config);
	// clean
	delete_tun(adapter);
	delete_config(config);
}
```

On Windows you should download [Tap Driver](http://build.openvpn.net/downloads/releases/latest/) frist.

## TODO

- User-friendly API design.
- Port to MacOS and Linux.
- Robust error handling.
- Support DNS spoofing and PAC parsing.
- Profile the program to ensure its performace.
- Real time statistics.

## Known Bugs

- x64 target won't build
- sometimes crash due to memory allocation failure

Working on these problems 💪.

## Credits

- [tun2socks](https://github.com/zhuhaow/tun2socks): It provides some basic ideas about how to reassemble packets to a tcp stream.
- [libtuntap](https://github.com/LaKabane/libtuntap): A good example about how to design tuntap API.