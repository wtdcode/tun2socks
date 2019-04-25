#include "tun2socks.h"

static const char* tap_ip = "10.2.3.1";
static const char* tap_network = "10.2.3.0";
static const char* tap_mask = "255.255.255.252";

static const char* socks5_address = "127.0.0.1";
static const uint16_t socks5_port = 1080;
static const uint32_t udp_timeout = 60000;

int main()
{
	auto adapter = open_tun();
	adapter->ip = inet_addr(tap_ip);
	adapter->mask = inet_addr(tap_mask);
	adapter->network = inet_addr(tap_network);
	SOCKS5NoAuth auth{ NO_AUTH};
	auto config = make_config_with_socks5_no_auth(
		adapter, 
		socks5_address, 
		strlen(socks5_address), 
		socks5_port, 
		udp_timeout, 
	&auth);
	tun2socks_start(config);
	delete_tun(adapter);
	delete_config(config);
}