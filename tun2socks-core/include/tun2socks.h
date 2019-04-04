#pragma once

#ifdef USE_DLL
#ifdef COMPILE_DLL	
#define DECLSPEC extern "C" __declspec(dllexport)
#else
#define DECLSPEC extern "C" __declspec(dllimport)
#endif
#else
#define DECLSPEC extern "C"
#endif

#include <cstdint>

#ifdef __WIN32__
#include <Windows.h>

typedef HANDLE TUNHANDLE;

#define TUN_INVALID_HANDLE INVALID_HANDLE_VALUE;
#define MAX_LEN 256

#endif

typedef uint32_t IPADDR;

struct TUNAdapter {
	TUNHANDLE hd;
#ifdef __WIN32__
	char dev_id[MAX_LEN + 1];
	DWORD index;
#endif
	char dev_name[MAX_LEN + 1];
	IPADDR ip;
	IPADDR mask;
	uint32_t network;
};

#ifdef __WIN32__
DECLSPEC
size_t get_tuns(TUNAdapter*, size_t);
#endif

DECLSPEC
TUNAdapter* open_tun(TUNAdapter* = NULL);

DECLSPEC
void delete_tun(TUNAdapter*);

DECLSPEC
void tun2socks_start(const TUNAdapter*);