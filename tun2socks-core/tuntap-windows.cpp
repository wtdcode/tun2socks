#include <tuntap.h>

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
	TUNDevice::TUNDevice(boost::asio::io_context& ctx, const std::string& instance_id)
		: _ctx(ctx),_instance_id(instance_id), _tun_handle(INVALID_HANDLE_VALUE){}
	int TUNDevice::tap_set_address(const DeviceAddress&& addr) {
		int up = 1;
		int out_len;
		if (!_synchronized_deviceiocontrol(_tun_handle, TAP_WIN_IOCTL_SET_MEDIA_STATUS, &up, 4, &up, 4, (LPDWORD)&out_len))
			return GetLastError();
		IPADDR address[3] = {
			addr.ip,
			addr.network,
			addr.mask
		};
		if (!_synchronized_deviceiocontrol(_tun_handle, TAP_WIN_IOCTL_CONFIG_TUN, &address, sizeof(address), &address, sizeof(address), (LPDWORD)&out_len))
			return GetLastError();
		return 0;
	}
	int TUNDevice::open_tun() {
		std::stringstream ss;
		ss << USERMODEDEVICEDIR;
		ss << _instance_id;
		ss << TAP_WIN_SUFFIX;
		_tun_handle = CreateFileA(
			ss.str().c_str(),
			GENERIC_READ | GENERIC_WRITE,
			NULL,
			NULL,
			OPEN_ALWAYS,
			FILE_FLAG_OVERLAPPED | FILE_ATTRIBUTE_SYSTEM,
			NULL);
		return GetLastError();
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