#include <iostream>
#include <string>
#include <cstdlib>
#include <Windows.h>

#include "tun2socks.h"

static const char* debug_instance_id = "{AADF77E3-D6C6-4E23-8F97-C0EA19168CC1}";

std::string get_message(int errorMessageID) {
	if (errorMessageID == 0)
		return std::string(); //No error message has been recorded

	LPSTR messageBuffer = nullptr;
	size_t size = FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL, errorMessageID, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)&messageBuffer, 0, NULL);

	std::string message(messageBuffer, size);

	//Free the buffer.
	LocalFree(messageBuffer);

	return message;
}

int main()
{
	tun2socks_start(debug_instance_id, strlen(debug_instance_id));
}