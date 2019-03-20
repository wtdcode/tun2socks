#include <cstring>
#include <memory>
#include <cstdio>
#include <thread>
#include <string>
#include <memory>
#include <cctype>
#include <array>
#include <deque>
#include <sstream>
#include <mutex>
#include <boost/asio.hpp>
#include <boost/enable_shared_from_this.hpp>
#include <boost/bind.hpp>

#include "tun2socks.h"
#include "tap-windows.h"
#include "lwip/tcp.h"
#include "lwip/init.h"

struct TUNContext;

static const char* tap_ip = "10.2.3.1";
static const char* lwip_ip = "10.2.3.2";
static const char* tap_network = "10.2.3.0";
static const char* tap_mask = "255.255.255.252";

static HANDLE g_tap_handle = INVALID_HANDLE_VALUE;
static bool to_read = true;
static std::shared_ptr<TUNContext> tctx;

enum SOCKS5STATE {
	INITIAL = 0,
	HELLO_SENT,
	REPLY_RECEIVED,
	PROXY_CONNECTED,
	AUTH_FAILURE
};

enum SOCKS5METHOD {
	NO_AUTH = 0,
	USER_PASSWORD = 2
};

enum TUNSTATE {
	CLOSE = 0,
	OPEN,
	OPEN_FAILURE
};


std::string debug_get_message(int errorMessageID) {
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


IPADDR inet_network(const char* cp) {
	return ntohl(inet_addr(cp));
}

std::string get_address_string(u32_t ip) {
	char buf[160];
	sprintf_s(buf, 16, "%d.%d.%d.%d", ip & 0xFF, (ip>>8) & 0xFF, (ip>>16) & 0xFF, (ip>>24) & 0xFF);
	return std::string(buf);
}

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




struct Socks5Context : public std::enable_shared_from_this<Socks5Context> {

	typedef void send_handler(const boost::system::error_code&, std::size_t);
	typedef void recv_handler(const boost::system::error_code&, std::size_t);

	SOCKS5STATE state;
	std::string proxy_ip;
	unsigned int proxy_port;
	SOCKS5METHOD method;
	size_t buffer_index;
	std::array<u_char, 256> buffer;
	boost::asio::ip::tcp::socket socket;
	boost::asio::ip::tcp::resolver resolver;
	boost::asio::io_service::strand _strand;
	bool _close;
	Socks5Context(boost::asio::io_context& ctx) : socket(ctx), resolver(ctx), _strand(ctx), _close(false){
		state = INITIAL;
		proxy_ip = "127.0.0.1";
		proxy_port = 1080;
		method = NO_AUTH;
		_connect();
	}

	void _connect() {
		boost::asio::ip::tcp::resolver::query q(proxy_ip.c_str(), "1080");
		try {
			auto results = resolver.resolve(q);
			for (auto& it : results)
				printf("%s %s\n", it.host_name().c_str(), it.service_name().c_str());
			socket.connect(*(results.begin()));
			u_char hello_msg[3] = { '\x05', '\x01', (u_char)method };
			socket.send(boost::asio::buffer(hello_msg, 3));
			u_char recv_msg[2];
			socket.receive(boost::asio::buffer(recv_msg, 2));
			assert(recv_msg[0] == '\x05' && recv_msg[1] == (u_char)method);
		}
		catch (const std::exception& e) {
			printf("%s\n", e.what());
		}
	}

	void send(std::shared_ptr<u_char> buffer, size_t len, std::function<send_handler> handler) {
		socket.async_send(boost::asio::buffer(buffer.get(), len), _strand.wrap(handler));
	}

	void recv(u_char* buffer, size_t len,std::function<recv_handler> handler) {
		socket.async_receive(boost::asio::buffer(buffer, len), _strand.wrap(handler));
	}

	void close() {
		if (!_close) {
			_close = true;
			auto self = shared_from_this();
			_strand.post([this, self]() {
				boost::system::error_code ec;
				socket.shutdown(boost::asio::ip::tcp::socket::shutdown_both, ec);
				socket.close();
			});
		}
	}

	bool connect(const std::string& domain, unsigned int port) {
		if (port > 65535)
			return false;
		u_char buffer[1600];
		buffer[0] = '\x05';
		buffer[1] = '\x01';
		buffer[2] = '\x00';
		buffer[3] = '\x03';
		buffer[4] = (u_char)domain.length();
		memcpy(buffer + 5, domain.c_str(), domain.length());
		auto port_n = htons(port);
		memcpy(buffer + 5 + domain.length(), &port_n, 2);
		socket.send(boost::asio::buffer(buffer, 5 + domain.length() + 2));
		try {
			socket.receive(boost::asio::buffer(buffer, 1600));
		}
		catch (std::exception& e) {
			printf("socks5 connect recv:%s\n", e.what());
		}
		if (buffer[1] == 0)
			return true;
		else
			return false;
	}

	void on_resolve(const boost::system::error_code& error, boost::asio::ip::tcp::resolver::results_type results) {
		for (auto& it : results) 
			printf("%s %s %s %d\n", it.host_name().c_str(), it.service_name().c_str(), it.endpoint().address().to_string().c_str(), it.endpoint().port());
	}

	~Socks5Context() {
		printf("smjb\n");
	}
};

struct LWIPStack {

	boost::asio::io_context::strand* _strand;
	netif* _loopback;

	static LWIPStack& getInstance() {
		static LWIPStack _stack;
		return _stack;
	}

	static tcp_pcb* lwip_tcp_new() {
		return tcp_new();
	}

	static err_t lwip_tcp_bind(struct tcp_pcb *pcb, const ip_addr_t *ipaddr, u16_t port) {
		return tcp_bind(pcb, ipaddr, port);
	}

	static tcp_pcb* lwip_tcp_listen(tcp_pcb* pcb) {
		return tcp_listen(pcb);
	}

	static void lwip_tcp_arg(tcp_pcb* pcb, void* arg) {
		return tcp_arg(pcb, arg);
	}

	static void lwip_tcp_accept(struct tcp_pcb *pcb, tcp_accept_fn accept) {
		return tcp_accept(pcb, accept);
	}

	static void lwip_tcp_receive(struct tcp_pcb* pcb, std::function<std::remove_pointer<tcp_recv_fn>::type> receive) {
		return tcp_recv(pcb, receive);
	}

	static void lwip_tcp_recved(tcp_pcb* pcb, u16_t len) {
		return tcp_recved(pcb, len);
	}

	static tcp_pcb* listen_any() {
		auto pcb = lwip_tcp_new();
		auto any = ip_addr_any;
		lwip_tcp_bind(pcb, &any, 0);
		return lwip_tcp_listen(pcb);
	}

	static err_t lwip_tcp_write(struct tcp_pcb *pcb, std::shared_ptr<void> arg, u16_t len, u8_t apiflags) {
		return tcp_write(pcb, arg.get(), len, apiflags);
	}

	static u32_t lwip_tcp_sndbuf(tcp_pcb* pcb) {
		return tcp_sndbuf(pcb);
	}

	static err_t lwip_tcp_output(tcp_pcb* pcb) {
		return tcp_output(pcb);
	}

	static err_t lwip_tcp_close(tcp_pcb* pcb) {
		return tcp_close(pcb);
	}

	void init(boost::asio::io_context& ctx) {
		lwip_init();
		_strand = new boost::asio::io_context::strand(ctx);
		_loopback = netif_list;
	}

	void strand_tcp_write(struct tcp_pcb *pcb, std::shared_ptr<void> arg, u16_t len, u8_t apiflags, std::function<void(err_t)> cb) {
		_strand->post([pcb, arg, len, apiflags, cb]() {
			auto err = LWIPStack::lwip_tcp_write(pcb, arg, len, apiflags); 
			if (cb != nullptr)
				cb(err);
		});
	}

	void strand_ip_input(pbuf* p, std::function<void(err_t)> cb) {
		_strand->post([p, cb, this]() {
			auto err = _loopback->input(p, _loopback);
			if (cb != nullptr)
				cb(err);
		});
	}

	void strand_tcp_close(tcp_pcb* pcb, std::function<void(err_t)> cb) {
		_strand->post([pcb, cb]() {
			auto err = tcp_close(pcb);
			if (cb != nullptr)
				cb(err);
		});
	}

	void strand_tcp_output(tcp_pcb* pcb, std::function<void(err_t)> cb) {
		_strand->post([pcb, cb]() {
			auto err = tcp_output(pcb);
			if (cb != nullptr)
				cb(err);
		});
	}

	void strand_tcp_recved(tcp_pcb* pcb, u16_t len) {
		_strand->post(boost::bind(&LWIPStack::lwip_tcp_recved, pcb, len));
	}

	void set_output_function(netif_output_fn f) {
		_loopback->output = f;
	}


	~LWIPStack() {
		if (_strand != nullptr)
			delete _strand;
	}

private:
	LWIPStack() :_strand(nullptr), _loopback(nullptr) {}
};

struct query {
	OVERLAPPED overlapped;
	pbuf* buf;
};

struct TUNContext {
	TUNSTATE state;
	std::string instance_id;
	IPADDR tun_ip;
	IPADDR tun_network;
	IPADDR tun_mask;
	HANDLE tun_handle;
	boost::asio::io_context& ctx;

	TUNContext(boost::asio::io_context& ioctx, const std::string& instance) : ctx(ioctx), instance_id(instance) {
		tun_ip = inet_addr(tap_ip);
		tun_network = inet_addr(tap_network);
		tun_mask = inet_addr(tap_mask);
	}

	int tap_set_address() {
		int up = 1;
		int out_len;
		if (!_synchronized_deviceiocontrol(tun_handle, TAP_WIN_IOCTL_SET_MEDIA_STATUS, &up, 4, &up, 4, (LPDWORD)&out_len))
			return GetLastError();
		IPADDR address[3] = {
			tun_ip,
			tun_network,
			tun_mask
		};
		if (!_synchronized_deviceiocontrol(tun_handle, TAP_WIN_IOCTL_CONFIG_TUN, &address, sizeof(address), &address, sizeof(address), (LPDWORD)&out_len))
			return GetLastError();
		return 0;
	}

	int open_tun() {
		std::stringstream ss;
		ss << USERMODEDEVICEDIR;
		ss << instance_id;
		ss << TAP_WIN_SUFFIX;
		tun_handle = CreateFileA(
			ss.str().c_str(),
			GENERIC_READ | GENERIC_WRITE,
			NULL,
			NULL,
			OPEN_ALWAYS,
			FILE_FLAG_OVERLAPPED | FILE_ATTRIBUTE_SYSTEM,
			NULL);
		return GetLastError();
	}

	void do_read() {
		DWORD transfered;
		auto q = std::make_shared<query>();
		memset(&q->overlapped, 0, sizeof(OVERLAPPED));
		q->overlapped.hEvent = CreateEventA(NULL, false, false, NULL);
		auto obj_handle = std::make_shared <boost::asio::windows::object_handle>(ctx, q->overlapped.hEvent);
		q->buf = pbuf_alloc(pbuf_layer::PBUF_RAW, 1500, pbuf_type::PBUF_RAM);
		ReadFile(tun_handle, q->buf->payload, 1500, &transfered, &q->overlapped);
		obj_handle->async_wait([this, obj_handle, q](const boost::system::error_code& err) {
			//printf("%d\n", *ptr);
			if (!err) {
				do_read();
				LWIPStack::getInstance().strand_ip_input(q->buf, [](err_t err) {});
			}
			else {
				printf("tun read:%s\n", err.message().c_str());
			}
		});
	}

	void do_write(pbuf* buf) {
		if (buf->len != buf->tot_len) {
			printf("pbuf: %d != %d", buf->len, buf->tot_len);
			return;
		}
		DWORD transfered;
		auto poverlapped = std::make_shared<OVERLAPPED>(OVERLAPPED{ 0 });
		poverlapped->hEvent = CreateEventA(NULL, false, false, NULL);
		auto obj_handle = std::make_shared<boost::asio::windows::object_handle>(ctx, poverlapped->hEvent);
		WriteFile(tun_handle, buf->payload, buf->len, &transfered, poverlapped.get());
		obj_handle->async_wait([this, poverlapped, obj_handle](const boost::system::error_code& err){
			if (!err) {
				// do nothing.
			}
			else {
				printf("tun write:%s\n", err.message().c_str());
			}
		});
	}


	int start() {
		do_read();
		return 0;
	}
};


struct LogicConnection{
	tcp_pcb* _lwip_pcb;
	std::shared_ptr<Socks5Context> _sctx;
};

err_t on_recv(std::shared_ptr<Socks5Context> ctx, struct tcp_pcb *tpcb, struct pbuf *p, err_t err) {
	if (err != ERR_OK || p == nullptr) { // p == NULL indicates EOF
		if (tpcb == nullptr)
			return ERR_VAL;
		else {
			LWIPStack::getInstance().strand_tcp_close(tpcb, [](err_t err) {});
			return ERR_OK;
		}
	}
	auto buffer = std::shared_ptr<u_char>(new u_char[p->tot_len], [](u_char* p) {
		delete[] p;
	});
	auto tp = buffer.get();
	pbuf_copy_partial(p, tp, p->tot_len, 0);
	ctx->send(buffer, p->tot_len, [ctx, tpcb](const boost::system::error_code& err, std::size_t sz) {
		if (err) {
			printf("socksctx send:%s\n", err.message().c_str());
			ctx->close();
			return;
		}
		printf("send: %d\n", sz);
	});
	LWIPStack::getInstance().strand_tcp_recved(tpcb, p->tot_len);
	return ERR_OK;
}

err_t on_accept(void *arg, struct tcp_pcb *newpcb, err_t err) {
	if (err != ERR_OK || newpcb == nullptr) {
		return ERR_VAL;
	}
	auto ioctx = (boost::asio::io_context*)arg;
	auto sctx = std::make_shared<Socks5Context>(*ioctx);
	sctx->connect(get_address_string(newpcb->local_ip.addr), newpcb->local_port);
	LWIPStack::lwip_tcp_receive(newpcb, [sctx](void* arg, struct tcp_pcb *tpcb, struct pbuf *p, err_t err) {return on_recv(sctx, tpcb, p, err); });
	auto handler = std::make_shared<std::function<Socks5Context::recv_handler>>();
	auto recv_buffer_len = (u32_t)TCP_SND_BUF;
	auto recv_buffer = std::shared_ptr<u_char>(new u_char[recv_buffer_len], [](u_char* p) {
		delete[] p;
	});
	*handler = std::function <Socks5Context::recv_handler>(
		[newpcb, recv_buffer, recv_buffer_len, sctx, handler](const boost::system::error_code& err, std::size_t sz) mutable {
		if (err) {
			printf("socks5ctx recv:%s\n", err.message().c_str());
			sctx->close();
			return;
		}
		printf("recv: %d\n", sz);
		std::shared_ptr<void> bf(new u_char[sz], [](void* p) {
			delete[](u_char*)p;
		});
		memcpy(bf.get(), recv_buffer.get(), sz);
		LWIPStack::getInstance().strand_tcp_write(newpcb, bf, sz, TCP_WRITE_FLAG_COPY, [newpcb, recv_buffer, recv_buffer_len, sctx, handler](err_t err) {
			if (err == ERR_OK) {
				LWIPStack::getInstance().strand_tcp_output(newpcb, [](err_t err) {});
				auto new_len = std::min(LWIPStack::lwip_tcp_sndbuf(newpcb), recv_buffer_len);
				sctx->recv(recv_buffer.get(), new_len, *handler);
			}
			else {
				LWIPStack::getInstance().strand_tcp_close(newpcb, [](err_t err) {});
			}
		});
	});
	sctx->recv(recv_buffer.get(), recv_buffer_len, *handler);
	return ERR_OK;
}



void tun2socks_start(const char* instance_id, size_t len) {
	boost::asio::io_context ioctx;
	boost::asio::io_context::work work(ioctx);
	LWIPStack::getInstance().init(ioctx);
	auto pcb = LWIPStack::listen_any();	
	LWIPStack::lwip_tcp_arg(pcb, (void*)(&ioctx));
	LWIPStack::lwip_tcp_accept(pcb, on_accept);
	LWIPStack::getInstance().set_output_function([](struct netif *netif, struct pbuf *p, const ip4_addr_t *ipaddr)->err_t {
		tctx->do_write(p);
		return ERR_OK;
	});
	tctx = std::make_shared<TUNContext>(ioctx, instance_id);
	tctx->open_tun();
	tctx->tap_set_address();
	tctx->start();
	ioctx.run();
	printf("Shouldn't reach here.\n");
}