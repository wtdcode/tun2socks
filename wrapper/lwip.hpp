#ifndef TUN2SOCKS_LWIP_HPP
#define TUN2SOCKS_LWIP_HPP

#include <mutex>
#include "lwip/init.h"
#include "lwip/ip.h"
#include "lwip/netif.h"
#include "lwip/tcp.h"

#define CORE_LOCK std::lock_guard gurad(this->core_mtx_)

namespace toys {
namespace wrapper {
/*
 * According to documents of LwIP, the TCP/IP stack should be protected by a
 * lock. But it seems that the pbuf functions are safe to re-enter and be called
 * concurrently.
 *
 */
class LwIP {
   public:
    static LwIP& Instance() {
        static LwIP instance;
        return instance;
    }

    std::recursive_mutex& GetLock() { return this->core_mtx_; }

    void lwip_init() {
        CORE_LOCK;
        return ::lwip_init();
    }

    tcp_pcb* tcp_new() {
        CORE_LOCK;
        return ::tcp_new();
    }

    void tcp_arg(tcp_pcb* pcb, void* arg) {
        CORE_LOCK;
        return ::tcp_arg(pcb, arg);
    }

    void tcp_recv(tcp_pcb* pcb, tcp_recv_fn recv) {
        CORE_LOCK;
        return ::tcp_recv(pcb, recv);
    }

    void tcp_sent(tcp_pcb* pcb, tcp_sent_fn sent) {
        CORE_LOCK;
        return ::tcp_sent(pcb, sent);
    }

    void tcp_err(tcp_pcb* pcb, tcp_err_fn err) {
        CORE_LOCK;
        return ::tcp_err(pcb, err);
    }

    void tcp_accept(tcp_pcb* pcb, tcp_accept_fn accept) {
        CORE_LOCK;
        return ::tcp_accept(pcb, accept);
    }

    void tcp_poll(tcp_pcb* pcb, tcp_poll_fn poll, u8_t interval) {
        CORE_LOCK;
        return ::tcp_poll(pcb, poll, interval);
    }

    void tcp_recved(tcp_pcb* pcb, u16_t len) {
        CORE_LOCK;
        return ::tcp_recved(pcb, len);
    }

    err_t tcp_bind(tcp_pcb* pcb, const ip_addr_t* ipaddr, u16_t port) {
        CORE_LOCK;
        return ::tcp_bind(pcb, ipaddr, port);
    }

    void tcp_bind_netif(tcp_pcb* pcb, const netif* netif) {
        CORE_LOCK;
        return ::tcp_bind_netif(pcb, netif);
    }

    err_t tcp_connect(tcp_pcb* pcb,
                      const ip_addr_t* ipaddr,
                      u16_t port,
                      tcp_connected_fn connected) {
        CORE_LOCK;
        return ::tcp_connect(pcb, ipaddr, port, connected);
    }

    tcp_pcb* tcp_listen_with_backlog_and_err(tcp_pcb* pcb,
                                             u8_t backlog,
                                             err_t* err) {
        CORE_LOCK;
        return ::tcp_listen_with_backlog_and_err(pcb, backlog, err);
    }

    tcp_pcb* tcp_listen_with_backlog(tcp_pcb* pcb, u8_t backlog) {
        CORE_LOCK;
        return ::tcp_listen_with_backlog(pcb, backlog);
    }

    tcp_pcb* tcp_listen_wrapper(tcp_pcb* pcb) {
        CORE_LOCK;
        return ::tcp_listen_with_backlog(pcb, TCP_DEFAULT_LISTEN_BACKLOG);
    }

    void tcp_abort(tcp_pcb* pcb) {
        CORE_LOCK;
        return ::tcp_abort(pcb);
    }

    err_t tcp_close(tcp_pcb* pcb) {
        CORE_LOCK;
        return ::tcp_close(pcb);
    }

    err_t tcp_shutdown(tcp_pcb* pcb, int shut_rx, int shut_tx) {
        CORE_LOCK;
        return ::tcp_shutdown(pcb, shut_rx, shut_tx);
    }

    err_t tcp_write(tcp_pcb* pcb,
                    const void* dataptr,
                    u16_t len,
                    u8_t apiflags) {
        CORE_LOCK;
        return ::tcp_write(pcb, dataptr, len, apiflags);
    }

    void tcp_setprio(tcp_pcb* pcb, u8_t prio) {
        CORE_LOCK;
        return ::tcp_setprio(pcb, prio);
    }

    err_t tcp_output(tcp_pcb* pcb) {
        CORE_LOCK;
        return ::tcp_output(pcb);
    }

    err_t tcp_tcp_get_tcp_addrinfo(tcp_pcb* pcb,
                                   int local,
                                   ip_addr_t* addr,
                                   u16_t* port) {
        CORE_LOCK;
        return ::tcp_tcp_get_tcp_addrinfo(pcb, local, addr, port);
    }

   private:
    LwIP() : core_mtx_(){};

   private:
    std::recursive_mutex core_mtx_;
};
}  // namespace wrapper
}  // namespace toys

#endif  // TUN2SOCKS_LWIP_HPP
