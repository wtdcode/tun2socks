#include <tuntap.h>
#include <tap-windows.h>

#undef IP_STATS
#undef ICMP_STATS
#undef TCP_STATS
#undef UDP_STATS
#undef IP6_STATS
#include <iphlpapi.h>

BOOL _synchronized_deviceiocontrol(
	_In_ HANDLE hDevice,
	_In_ DWORD dwIoControlCode,
	_In_reads_bytes_opt_(nInBufferSize) LPVOID lpInBuffer,
	_In_ DWORD nInBufferSize,
	_Out_writes_bytes_to_opt_(nOutBufferSize, *lpBytesReturned) LPVOID lpOutBuffer,
	_In_ DWORD nOutBufferSize,
	_Out_opt_ LPDWORD lpBytesReturned
) {
	BOOL result = false;
	OVERLAPPED overlapped{ 0 };
	overlapped.hEvent = CreateEventA(NULL, false, false, NULL);
	if (!DeviceIoControl(hDevice, dwIoControlCode, lpInBuffer, nInBufferSize, lpOutBuffer, nOutBufferSize, lpBytesReturned, &overlapped)) {
		if (GetLastError() == ERROR_IO_PENDING) {
			WaitForSingleObject(overlapped.hEvent, INFINITE);
			CloseHandle(overlapped.hEvent);
			result = (overlapped.Internal == ERROR_SUCCESS);
		}
		else
			result = false;
	}
	else
		result = true;
	CloseHandle(overlapped.hEvent);
	return result;
}

namespace tun2socks {
	TUNDevice::TUNDevice(boost::asio::io_context& ctx, const TUNAdapter& adapter)
		: _ctx(ctx), _tun_handle(adapter.hd), _adapter(adapter) {}

	int TUNDevice::tap_set_address() {
		int up = 1;
		int out_len;
		if (!_synchronized_deviceiocontrol(_tun_handle, TAP_WIN_IOCTL_SET_MEDIA_STATUS, &up, 4, &up, 4, (LPDWORD)&out_len))
			return GetLastError();
		IPADDR address[3] = {
			_adapter.ip,
			_adapter.network,
			_adapter.mask
		};
		if (!_synchronized_deviceiocontrol(_tun_handle, TAP_WIN_IOCTL_CONFIG_TUN, &address, sizeof(address), &address, sizeof(address), (LPDWORD)&out_len))
			return GetLastError();
		char cmd[1024];
		// To achieve this with Windows API is too painful :(.
		// May change in the future?
		snprintf(cmd, 1024, "netsh interface ip set address %d static %s %s", _adapter.index, get_address_string(_adapter.ip).c_str(), get_address_string(_adapter.mask).c_str());
		return system(cmd);
	}

	void TUNDevice::start_read(std::function<void(std::shared_ptr<Request>)> success, std::function<void(const boost::system::error_code&)> fail) {
		auto q = std::make_shared<Request>();
		memset(&q->overlapped, 0, sizeof(OVERLAPPED));
		q->overlapped.hEvent = CreateEventA(NULL, false, false, NULL);
		auto obj_handle = std::make_shared <boost::asio::windows::object_handle>(_ctx, q->overlapped.hEvent);
		q->buf = pbuf_alloc(pbuf_layer::PBUF_RAW, 1500, pbuf_type::PBUF_RAM);
		ReadFile(_tun_handle, q->buf->payload, 1500, &q->transfered, &q->overlapped);
		obj_handle->async_wait([this, obj_handle, q, fail, success](const boost::system::error_code& err) {
			if (!err) {
				start_read(success, fail);
				if(success != nullptr)
					success(q);
				//LWIPStack::getInstance().strand_ip_input(q->buf, [](err_t err) {});
			}
			else {
				if(fail != nullptr)
					fail(err);
				//printf("tun read:%s\n", err.message().c_str());
			}
		});
	}

	void TUNDevice::do_write(std::unique_ptr<u_char[]>&& buffer, size_t len, std::function<void()> success, std::function<void(const boost::system::error_code&)> fail) {
		DWORD transfered;
		auto poverlapped = std::make_shared<OVERLAPPED>(OVERLAPPED{ 0 });
		std::shared_ptr<u_char[]> shared_buffer = std::move(buffer);
		poverlapped->hEvent = CreateEventA(NULL, false, false, NULL);
		auto obj_handle = std::make_shared<boost::asio::windows::object_handle>(_ctx, poverlapped->hEvent);
		WriteFile(_tun_handle, shared_buffer.get(), len, &transfered, poverlapped.get());
		obj_handle->async_wait([this,shared_buffer, poverlapped, obj_handle, success, fail](const boost::system::error_code& err) {
			if (!err) {
				// do nothing.
				if (success != nullptr)
					success();
			}
			else {
				if (fail != nullptr)
					fail(err);
			}
		});
	}
}

std::vector<std::string> search_instance_id(std::function<bool(const std::string_view&)>&& istap) {
	std::vector<std::string> result;
	auto close_key_deleter = [](HKEY* p) {RegCloseKey(*p); };
	HKEY adapters_key;
	if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, ADAPTER_KEY, NULL, KEY_ENUMERATE_SUB_KEYS | KEY_QUERY_VALUE, &adapters_key))
		return result;
	DWORD max_subkey_len;
	DWORD nsubkeys;
	std::unique_ptr<HKEY, decltype(close_key_deleter)> p_adapters_key(&adapters_key, close_key_deleter);
	if (RegQueryInfoKeyA(adapters_key, NULL, NULL, NULL, &nsubkeys, &max_subkey_len, NULL, NULL, NULL, NULL, NULL, NULL))
		return result;
	auto subkey_buffer = std::make_unique<u_char[]>(max_subkey_len);
	for (DWORD i = 0; i < nsubkeys; i++) {
		if (RegEnumKeyA(*p_adapters_key, i, (LPSTR)(subkey_buffer.get()), max_subkey_len))
			continue;
		HKEY subkey;
		std::unique_ptr<HKEY, decltype(close_key_deleter)> p_subkey(&subkey, close_key_deleter);
		if (RegOpenKeyExA(*p_adapters_key, (LPSTR)(subkey_buffer.get()), NULL, KEY_QUERY_VALUE, p_subkey.get()))
			continue;
		DWORD max_value_len;
		if (RegQueryInfoKeyA(*p_subkey, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, &max_value_len, NULL, NULL))
			continue;
		auto value_buffer = std::make_unique<u_char[]>(max_value_len);
		DWORD bytes_read;
		if (!RegGetValueA(*p_subkey, NULL, "ComponentId", RRF_RT_REG_SZ, NULL, value_buffer.get(), &bytes_read)) {
			std::string_view cid((char*)(value_buffer.get()));
			if (istap(cid)) {
				bytes_read = max_value_len;
				if (!RegGetValueA(*p_subkey, NULL, "NetCfgInstanceId", RRF_RT_REG_SZ, NULL, value_buffer.get(), &bytes_read)) {
					result.emplace_back((char*)(value_buffer.get()));
				}
			}
		}
	}
	return result;
}

std::vector<TUNAdapter> get_adpaters(const std::vector<std::string>& ids) {
	std::vector<TUNAdapter> result;
	ULONG buffer_len = sizeof(IP_ADAPTER_INFO);
	auto buffer = std::make_unique<char[]>(sizeof(IP_ADAPTER_INFO));
	if (GetAdaptersInfo((PIP_ADAPTER_INFO)(buffer.get()), &buffer_len)) {
		buffer.reset();
		buffer = std::make_unique<char[]>(buffer_len);
	}
	if (GetAdaptersInfo((PIP_ADAPTER_INFO)(buffer.get()), &buffer_len))
		return result;
	auto padapter = (PIP_ADAPTER_INFO)buffer.get();
	while (padapter) {
		auto it = std::find(ids.begin(), ids.end(), padapter->AdapterName);
		if (it != ids.end()) {
			result.emplace_back();
			auto& adapter = *(result.rbegin());
			adapter.hd = TUN_INVALID_HANDLE;
			memcpy(adapter.dev_id, it->c_str(), it->length() + 1);
			memcpy(adapter.dev_name, padapter->Description, strlen(padapter->Description) + 1);
			adapter.ip = inet_addr(padapter->IpAddressList.IpAddress.String);
			adapter.mask = inet_addr(padapter->IpAddressList.IpMask.String);
			adapter.network = adapter.mask & adapter.ip;
			adapter.index = padapter->Index;
		}
		padapter = padapter->Next;
	}
	return result;
}

size_t get_tuns(TUNAdapter* buffer, size_t len) {
	auto taps_id = search_instance_id([](const std::string_view& tap_name) {return tap_name.compare(0, 3, "tap") == 0; });
	auto adapters = get_adpaters(taps_id);
	if (adapters.size() > len)
		return -1;
	else {
		for (size_t i = 0; i < adapters.size(); i++)
			buffer[i] = adapters[i];
		return adapters.size();
	}
}

TUNAdapter* open_tun(TUNAdapter* adapter) {
	if (adapter == NULL) {
		TUNAdapter tuns[32];
		auto size = get_tuns(tuns, 32);
		if (size == 0)
			return NULL;
		else
			adapter = &tuns[0];
	}
	std::stringstream ss;
	ss << USERMODEDEVICEDIR;
	ss << adapter->dev_id;
	ss << TAP_WIN_SUFFIX;
	adapter->hd = CreateFileA(
		ss.str().c_str(),
		GENERIC_READ | GENERIC_WRITE,
		NULL,
		NULL,
		OPEN_ALWAYS,
		FILE_FLAG_OVERLAPPED | FILE_ATTRIBUTE_SYSTEM,
		NULL);
	return new TUNAdapter(*adapter);
}

void delete_tun(TUNAdapter* adapter) {
	if (adapter != NULL)
		delete adapter;
}