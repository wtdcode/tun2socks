#pragma once

#include <lwip/tcp.h>
#include <lwip/netif.h>
#include <lwip/init.h>
#include <boost/asio.hpp>
#include <boost/bind.hpp>
#include <memory>

namespace tun2socks {
	class LWIPStack {
	public:
		boost::asio::io_context::strand* _strand;
		netif* _loopback;

		inline static LWIPStack& getInstance() {
			static LWIPStack _stack;
			return _stack;
		}

		inline static tcp_pcb* lwip_tcp_new() {
			return tcp_new();
		}

		inline static err_t lwip_tcp_bind(struct tcp_pcb *pcb, const ip_addr_t *ipaddr, u16_t port) {
			return tcp_bind(pcb, ipaddr, port);
		}

		inline static tcp_pcb* lwip_tcp_listen(tcp_pcb* pcb) {
			return tcp_listen(pcb);
		}

		inline static void lwip_tcp_arg(tcp_pcb* pcb, void* arg) {
			return tcp_arg(pcb, arg);
		}

		inline static void lwip_tcp_accept(struct tcp_pcb *pcb, tcp_accept_fn accept) {
			return tcp_accept(pcb, accept);
		}

		inline static void lwip_tcp_receive(struct tcp_pcb* pcb, std::function<std::remove_pointer<tcp_recv_fn>::type> receive) {
			return tcp_recv(pcb, receive);
		}

		inline static void lwip_tcp_recved(tcp_pcb* pcb, u16_t len) {
			return tcp_recved(pcb, len);
		}

		inline static tcp_pcb* listen_any() {
			auto pcb = lwip_tcp_new();
			auto any = ip_addr_any;
			lwip_tcp_bind(pcb, &any, 0);
			return lwip_tcp_listen(pcb);
		}

		inline static err_t lwip_tcp_write(struct tcp_pcb *pcb, std::shared_ptr<void> arg, u16_t len, u8_t apiflags) {
			return tcp_write(pcb, arg.get(), len, apiflags);
		}

		inline static u32_t lwip_tcp_sndbuf(tcp_pcb* pcb) {
			return tcp_sndbuf(pcb);
		}

		inline static err_t lwip_tcp_output(tcp_pcb* pcb) {
			return tcp_output(pcb);
		}

		inline static err_t lwip_tcp_close(tcp_pcb* pcb) {
			return tcp_close(pcb);
		}

		inline void init(boost::asio::io_context& ctx) {
			lwip_init();
			_strand = new boost::asio::io_context::strand(ctx);
			_loopback = netif_list;
		}

		inline void strand_tcp_write(struct tcp_pcb *pcb, std::shared_ptr<void> arg, u16_t len, u8_t apiflags, std::function<void(err_t)> cb) {
			_strand->post([pcb, arg, len, apiflags, cb]() {
				auto err = LWIPStack::lwip_tcp_write(pcb, arg, len, apiflags);
				if (cb != nullptr)
					cb(err);
			});
		}

		inline void strand_ip_input(pbuf* p, std::function<void(err_t)> cb) {
			_strand->post([p, cb, this]() {
				auto err = _loopback->input(p, _loopback);
				if (cb != nullptr)
					cb(err);
			});
		}

		inline void strand_tcp_close(tcp_pcb* pcb, std::function<void(err_t)> cb) {
			_strand->post([pcb, cb]() {
				auto err = tcp_close(pcb);
				if (cb != nullptr)
					cb(err);
			});
		}

		inline void strand_tcp_output(tcp_pcb* pcb, std::function<void(err_t)> cb) {
			_strand->post([pcb, cb]() {
				auto err = tcp_output(pcb);
				if (cb != nullptr)
					cb(err);
			});
		}

		inline void strand_tcp_recved(tcp_pcb* pcb, u16_t len) {
			_strand->post(boost::bind(&LWIPStack::lwip_tcp_recved, pcb, len));
		}

		inline void set_output_function(std::function<std::remove_pointer<netif_output_fn>::type> f) {
			_loopback->output = f;
		}


		inline ~LWIPStack() {
			if (_strand != nullptr)
				delete _strand;
		}

	private:
		inline LWIPStack() :_strand(nullptr), _loopback(nullptr) {}
	};
}