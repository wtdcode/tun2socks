#pragma once

#include <Windows.h>

#ifdef USE_DLL
#ifdef COMPILE_DLL	
#define DECLSPEC extern "C" __declspec(dllexport)
#else
#define DECLSPEC extern "C" __declspec(dllimport)
#endif
#else
#define DECLSPEC extern "C"
#endif

typedef unsigned long IPADDR;

DECLSPEC
void tun2socks_start(const char*, size_t);