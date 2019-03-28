#pragma once

#include <boost/asio.hpp>
#include <boost/bind.hpp>
#include <tap-windows.h>
#include <lwipstack.h>

typedef uint32_t IPADDR;

namespace tun2socks {
	enum TUNSTATE {
		CLOSE = 0,
		OPEN,
		OPEN_FAILURE
	};

	struct DeviceAddress {
		IPADDR ip;
		IPADDR network;
		IPADDR mask;
	};

	struct Request {
		OVERLAPPED overlapped;
		pbuf* buf;
		DWORD transfered;
	};

	class TUNDevice {
		
	public:
		TUNDevice(boost::asio::io_context&, const std::string&);

		int tap_set_address(const DeviceAddress&&);

		int open_tun();

		void start_read(std::function<void(std::shared_ptr<Request>)>, std::function<void(const boost::system::error_code&)>);

		void do_write(std::unique_ptr<u_char[]>&&, size_t, std::function<void()>, std::function<void(const boost::system::error_code&)>);

	private:
		std::string _instance_id;
		HANDLE _tun_handle;
		boost::asio::io_context& _ctx;
	};
}