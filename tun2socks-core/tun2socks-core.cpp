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
#include "lwipstack.h"
#include "socks5.h"
#include "tuntap.h"

using namespace tun2socks;

static HANDLE g_tap_handle = INVALID_HANDLE_VALUE;
static bool to_read = true;
static const TUN2SOCKSConfig* g_config;

std::unique_ptr<AuthMethod> get_auth_method(const BaseAuth* auth) {
	auto method = auth->method;
	if (method == SOCKS5METHOD::NO_AUTH)
		return std::make_unique<NoAuth>();
	else if (method == SOCKS5METHOD::USERNAME_PASSWORD) {
		auto pw_auth = (PSOCKS5UsernamePassword)auth;
		std::string username(pw_auth->username, pw_auth->username_length);
		std::string password(pw_auth->password, pw_auth->password_length);
		return std::make_unique<PasswordAuth>(std::move(username), std::move(password));
	}
	else
		return nullptr;
}

err_t tcp_on_recv(std::shared_ptr<Socks5Socket> ctx, struct tcp_pcb *tpcb, struct pbuf *p, err_t err) {
	if (err != ERR_OK || p == nullptr || tpcb == nullptr) { // p == NULL indicates EOF
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

err_t tcp_on_accept(void *arg, struct tcp_pcb *newpcb, err_t err) {
	if (err != ERR_OK || newpcb == nullptr) {
		return ERR_VAL;
	}
	auto ioctx = (boost::asio::io_context*)arg;
	auto auth = get_auth_method(g_config->socks5_auth);
	std::string proxy_ip(g_config->socks5_address, g_config->socks5_address_length);
	auto proxy_port = g_config->socks5_port;
	auto s5socket = std::make_shared<Socks5Socket>(*ioctx, std::move(auth));
	if (!s5socket->connectProxy(proxy_ip, proxy_port))
		return ERR_ABRT;
	s5socket->connect(get_address_string(newpcb->local_ip.addr), newpcb->local_port);
	LWIPStack::lwip_tcp_receive(newpcb, [s5socket](void* arg, struct tcp_pcb *tpcb, struct pbuf *p, err_t err) {return tcp_on_recv(s5socket, tpcb, p, err); });
	auto handler = std::make_shared<std::function<Socks5Socket::recv_handler>>();
	auto recv_buffer_len = (u32_t)TCP_SND_BUF;
	std::shared_ptr<u_char> recv_buffer(new u_char[recv_buffer_len], [](u_char* p) {
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
		// it seems that we don't need extra buffer because the original won't be modified before the next call to async_recv.
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

err_t udp_on_recv(std::shared_ptr<Socks5Socket> s5socket, struct udp_pcb* pcb, struct pbuf* p, const ip_addr_t *addr, u16_t port) {
	if (p == nullptr) {
		if (pcb == nullptr)
			return ERR_VAL;
		else {
			LWIPStack::getInstance().strand_udp_remove(pcb);
			return ERR_OK;
		}
	}
	// should be same to mtu.
	std::shared_ptr<u_char> buffer(new u_char[p->tot_len], [](u_char* _p) {delete[] _p; });
	pbuf_copy_partial(p, buffer.get(), p->tot_len, 0);
	s5socket->async_sendto(buffer, p->tot_len, pcb->local_ip.addr, htons(pcb->local_port), [s5socket](const boost::system::error_code& err, std::size_t len) {
		if (err) {
			printf("udp recv close: %s\n", err.message().c_str());
			s5socket->async_udp_close();
			return;
		}
	});
	return ERR_OK;
}

void new_udp_connection(struct udp_pcb* npcb, boost::asio::io_context& ctx) {
	printf("new conn %s:%d => %s:%d\n",
		boost::asio::ip::address_v4(ntohl(npcb->remote_ip.addr)).to_string().c_str(),
		npcb->remote_port,
		boost::asio::ip::address_v4(ntohl(npcb->local_ip.addr)).to_string().c_str(),
		npcb->local_port
		);
	auto auth = get_auth_method(g_config->socks5_auth);
	auto s5socket = std::make_shared<Socks5Socket>(ctx, std::move(auth));
	auto timeout = g_config->udp_timeout;
	LWIPStack::lwip_udp_set_timeout(npcb, timeout);
	std::string proxy_ip(g_config->socks5_address, g_config->socks5_address_length);
	auto proxy_port = g_config->socks5_port;
	if (!s5socket->connectProxy(proxy_ip, proxy_port) || !s5socket->associateUDP(npcb->local_ip.addr, npcb->local_port))
		return;
	LWIPStack::lwip_udp_timeout(npcb, [s5socket](struct udp_pcb* pcb) {
		printf("timeout %s:%d => %s:%d\n",
			boost::asio::ip::address_v4(ntohl(pcb->remote_ip.addr)).to_string().c_str(),
			pcb->remote_port,
			boost::asio::ip::address_v4(ntohl(pcb->local_ip.addr)).to_string().c_str(),
			pcb->local_port
		);
		s5socket->async_close();
		return;
	});
	LWIPStack::lwip_udp_recv(npcb, [s5socket](void*, struct udp_pcb* pcb, struct pbuf* p, const ip_addr_t* addr, u16_t port) {
		udp_on_recv(s5socket, pcb, p, addr, port);
		return;
	});
	// should be same to the mtu?
	const auto recv_len = 1600;
	std::shared_ptr<pbuf> p(
		pbuf_alloc(pbuf_layer::PBUF_TRANSPORT, recv_len, pbuf_type::PBUF_RAM), 
		[](pbuf* _p) {
			pbuf_free(_p);
		});
	auto _handler = std::make_shared<std::function<Socks5Socket::recv_handler>>();
	*_handler = [_handler, p, s5socket, npcb, recv_len](const boost::system::error_code& err, std::size_t len) {
		if (err) {
			printf("%s\n", err.message().c_str());
			s5socket->async_close();
			return;
		}
		p->tot_len = len;
		p->len = len;
		LWIPStack::getInstance().strand_udp_send(npcb, p, [s5socket, p, _handler, recv_len, npcb](err_t err) {
			if (err == ERR_OK) {
				s5socket->async_recvfrom((u_char*)(p->payload), recv_len, *_handler);
			}
			else {
				LWIPStack::getInstance().strand_udp_remove(npcb);
			}
		});
	};
	s5socket->async_recvfrom((u_char*)(p->payload), recv_len, *_handler);
}

void tun2socks_start(const TUN2SOCKSConfig* config) {
	boost::asio::io_context ioctx;
	boost::asio::io_context::work work(ioctx);
	g_config = config;
	auto tctx = std::make_shared<TUNDevice>(ioctx, *(config->adapter));
	LWIPStack::getInstance().init(ioctx, *config);
	auto t_pcb = LWIPStack::tcp_listen_any();
	auto u_pcb = LWIPStack::udp_listen_any();
	LWIPStack::lwip_tcp_arg(t_pcb, (void*)(&ioctx));
	LWIPStack::lwip_tcp_accept(t_pcb, tcp_on_accept);
	LWIPStack::lwip_udp_create([ &ioctx](struct udp_pcb* pcb) {
		new_udp_connection(pcb, ioctx); 
	});
	LWIPStack::getInstance().set_output_function([tctx](struct netif *netif, struct pbuf *p, const ip4_addr_t *ipaddr)->err_t {
		auto buffer = std::make_unique<u_char[]>(p->tot_len);
		pbuf_copy_partial(p, buffer.get(), p->tot_len, 0);
		tctx->do_write(std::move(buffer), p->tot_len, nullptr, nullptr);
		return ERR_OK;
	});
	tctx->tap_set_address();
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


template<class T>
PTUN2SOCKSConfig make_config(
	const TUNAdapter* adapter,
	const char* address, size_t address_length,
	uint16_t port,
	uint32_t timeout,
	const T* auth
){
	if (address_length > 256)
		return NULL;
	auto config = new TUN2SOCKSConfig();
	config->adapter = new TUNAdapter();
	memcpy(config->adapter, adapter, sizeof(decltype(*adapter)));
	memcpy(config->socks5_address, address, address_length);
	config->socks5_address_length = address_length;
	config->socks5_port = port;
	config->socks5_auth = (PBaseAuth)new T(*auth);
	return config;
}

PTUN2SOCKSConfig make_config_with_socks5_no_auth(
	const TUNAdapter* adapter,
	const char* address, size_t address_length,
	uint16_t port,
	uint32_t timeout,
	const SOCKS5NoAuth* auth
) {
	return make_config(adapter, address, address_length, port, timeout, auth);
}

PTUN2SOCKSConfig make_config_with_socks5_password_auth(
	const TUNAdapter* adapter,
	const char* address, size_t address_length,
	uint16_t port,
	uint32_t timeout,
	const SOCKS5UsernamePassword* auth
) {
	if (auth->username_length >= 256 || auth->password_length >= 256)
		return NULL;
	return make_config(adapter, address, address_length, port, timeout, auth);
}

void delete_config(PTUN2SOCKSConfig config) {
	if (config != NULL) {
		if (config->adapter != NULL)
			delete config->adapter;
		if (config->socks5_auth != NULL)
			delete config->socks5_auth;
		delete config;
	}
	g_config = nullptr;
}