#include "lwip/sys.h"

#include <time.h>
#include <Windows.h>

static LARGE_INTEGER freq, sys_start_time;

void sys_init(void) {
	QueryPerformanceFrequency(&freq);
	QueryPerformanceCounter(&sys_start_time);
}

static LONGLONG
sys_get_ms_longlong(void)
{
	LONGLONG ret;
	LARGE_INTEGER now;
	if (freq.QuadPart == 0) {
		sys_init();
	}
	QueryPerformanceCounter(&now);
	ret = now.QuadPart - sys_start_time.QuadPart;
	return (u32_t)(((ret) * 1000) / freq.QuadPart);
}

u32_t
sys_jiffies(void)
{
	return (u32_t)sys_get_ms_longlong();
}

u32_t
sys_now(void)
{
	return (u32_t)sys_get_ms_longlong();
}
