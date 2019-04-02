#include <iostream>
#include <string>
#include <cstdlib>
#include <Windows.h>
#include "tun2socks.h"

static const char* tap_ip = "10.2.3.1";
static const char* tap_network = "10.2.3.0";
static const char* tap_mask = "255.255.255.252";

int main()
{
	TUNAdapter adapters[32];
	auto size = get_tuns(adapters, 32);
	if (size == 0)
		return 0;
	else {
		auto adapter = open_tun(&adapters[0]);
		adapter->ip = inet_addr(tap_ip);
		adapter->mask = inet_addr(tap_mask);
		adapter->network = inet_addr(tap_network);
		tun2socks_start(adapter);
	}
}