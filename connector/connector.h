#ifndef TUN2SOCKS_CONNECTOR_H
#define TUN2SOCKS_CONNECTOR_H

#include <boost/bind.hpp>
#include <cstdint>
#include <functional>
#include <list>
#include <utility>
#include "allocator/allocator.hpp"
#include "connector/connector_table.hpp"
#include "socks5/socks5_auth.h"
#include "socks5/socks5_client.h"
#include "tuntap/tuntap.h"
#include "wrapper/lwip.hpp"

namespace toys {
namespace connector {
class Connector : public toys::socks5::SOCKS5Client::Delegate {
   public:
    class Delegate {
       public:
        virtual void OnConnectorError(uint32_t id,
                                      const boost::system::system_error& err) {}
    };

   public:
    Connector(Delegate* delegate,
              boost::asio::io_context& ctx,
              boost::asio::ip::tcp::endpoint server_endpoint,
              boost::asio::ip::tcp::endpoint destination_endpoint,
              std::shared_ptr<toys::socks5::AuthMethod> auth_method,
              toys::tuntap::TunTap& tun,
              tcp_pcb* npcb)
        : delegate_(delegate),
          strand_(ctx),
          client_(ctx,
                  this,
                  std::move(server_endpoint),
                  std::move(destination_endpoint),
                  std::move(auth_method),
                  boost::bind(&Connector::allocateBuffer,
                              this,
                              boost::placeholders::_1)),
          tun_(tun),
          tpcb_(npcb),
          id_(++counter_),
          send_queue_(),
          closed(false) {}

    void Start();
    void Stop();

    virtual void OnTCPReceived(
        const std::shared_ptr<boost::asio::mutable_buffer>& data,
        std::size_t len);
    virtual void OnError(const boost::system::system_error&);

    uint32_t GetID() { return id_; }

    virtual ~Connector();

   private:
    static err_t OnLWIPTCPReceivedWrapper(void* arg,
                                          struct tcp_pcb* tpcb,
                                          struct pbuf* p,
                                          err_t err);
    static void OnLWIPTCPErrorWrapper(void* arg, err_t err);

    static err_t OnLWIPTCPSentWrapper(void* arg,
                                      struct tcp_pcb* tpcb,
                                      u16_t len);
    err_t OnLWIPTCPReceived(void* arg,
                            struct tcp_pcb* tpcb,
                            struct pbuf* p,
                            err_t err);
    void OnLWIPTCPError(void* arg, err_t err);
    err_t OnLWIPTCPSent(void* arg, struct tcp_pcb* tpcb, u16_t len);
    void mayCallOnError(const boost::system::system_error&);
    std::shared_ptr<boost::asio::mutable_buffer> allocateBuffer(
        std::size_t suggest);
    void tryClearQueue();
    void doCallOnError(const boost::system::system_error&);
    void doSOCKS5TCPReceived(
        boost::asio::yield_context y,
        const std::shared_ptr<boost::asio::mutable_buffer>& data,
        std::size_t len);
    void doClose();

   private:
    Delegate* delegate_;
    boost::asio::io_context::strand strand_;
    toys::socks5::SOCKS5Client client_;
    toys::tuntap::TunTap& tun_;
    tcp_pcb* tpcb_;
    uint32_t id_;
    std::list<
        std::pair<std::shared_ptr<boost::asio::mutable_buffer>, std::size_t>>
        send_queue_;
    bool closed;
    static uint32_t counter_;
};
}  // namespace connector
}  // namespace toys

#endif
