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
#include "lwipstack.h"
#include "socks5.h"
#include "tuntap.h"

using namespace tun2socks;

static const char* tap_ip = "10.2.3.1";
static const char* lwip_ip = "10.2.3.2";
static const char* tap_network = "10.2.3.0";
static const char* tap_mask = "255.255.255.252";

static HANDLE g_tap_handle = INVALID_HANDLE_VALUE;
static bool to_read = true;


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

err_t on_recv(std::shared_ptr<Socks5Socket> ctx, struct tcp_pcb *tpcb, struct pbuf *p, err_t err) {
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
	ctx->async_send(buffer, p->tot_len, [ctx, tpcb](const boost::system::error_code& err, std::size_t sz) {
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
	auto s5socket = std::make_shared<Socks5Socket>(*ioctx, "127.0.0.1", 1080, std::move(std::make_unique<NoAuth>(NoAuth{})));
	if (!s5socket->connectProxy())
		return ERR_ABRT;
	s5socket->connect(get_address_string(newpcb->local_ip.addr), newpcb->local_port);
	LWIPStack::lwip_tcp_receive(newpcb, [s5socket](void* arg, struct tcp_pcb *tpcb, struct pbuf *p, err_t err) {return on_recv(s5socket, tpcb, p, err); });
	auto handler = std::make_shared<std::function<Socks5Socket::recv_handler>>();
	auto recv_buffer_len = (u32_t)TCP_SND_BUF;
	auto recv_buffer = std::shared_ptr<u_char>(new u_char[recv_buffer_len], [](u_char* p) {
		delete[] p;
	});
	*handler = std::function <Socks5Socket::recv_handler>(
		[newpcb, recv_buffer, recv_buffer_len, s5socket, handler](const boost::system::error_code& err, std::size_t sz) mutable {
		if (err) {
			printf("socks5socket recv:%s\n", err.message().c_str());
			s5socket->close();
			return;
		}
		std::shared_ptr<void> bf(new u_char[sz], [](void* p) {
			delete[](u_char*)p;
		});
		memcpy(bf.get(), recv_buffer.get(), sz);
		LWIPStack::getInstance().strand_tcp_write(newpcb, bf, sz, TCP_WRITE_FLAG_COPY, [newpcb, recv_buffer, recv_buffer_len, s5socket, handler](err_t err) {
			if (err == ERR_OK) {
				LWIPStack::getInstance().strand_tcp_output(newpcb, [](err_t err) {});
				auto new_len = std::min(LWIPStack::lwip_tcp_sndbuf(newpcb), recv_buffer_len);
				s5socket->async_recv(recv_buffer, new_len, *handler);
			}
			else {
				LWIPStack::getInstance().strand_tcp_close(newpcb, [](err_t err) {});
			}
		});
	});
	s5socket->async_recv(recv_buffer, recv_buffer_len, *handler);
	return ERR_OK;
}

void tun2socks_start(const char* instance_id, size_t len) {
	boost::asio::io_context ioctx;
	boost::asio::io_context::work work(ioctx);
	auto tctx = std::make_shared<TUNDevice>(ioctx, instance_id);
	LWIPStack::getInstance().init(ioctx);
	auto pcb = LWIPStack::listen_any();	
	LWIPStack::lwip_tcp_arg(pcb, (void*)(&ioctx));
	LWIPStack::lwip_tcp_accept(pcb, on_accept);
	LWIPStack::getInstance().set_output_function([tctx](struct netif *netif, struct pbuf *p, const ip4_addr_t *ipaddr)->err_t {
		auto buffer = std::make_unique<u_char[]>(p->tot_len);
		pbuf_copy_partial(p, buffer.get(), p->tot_len, 0);
		tctx->do_write(std::move(buffer), p->tot_len, nullptr, nullptr);
		return ERR_OK;
	});
	tctx->open_tun();
	tctx->tap_set_address(DeviceAddress{inet_addr(tap_ip), inet_addr(tap_network), inet_addr(tap_mask)});
	tctx->start_read([](std::shared_ptr<Request> q) {LWIPStack::getInstance().strand_ip_input(q->buf, [](err_t err) {
		if(err != ERR_OK)
			printf("%d\n", err);
	}); },
		[](const boost::system::error_code& err) {
		printf("tctx failed:%s\n", err.message().c_str());
	});
	ioctx.run();
	printf("Shouldn't reach here.\n");
}