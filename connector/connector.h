#ifndef TUN2SOCKS_CONNECTOR_H
#define TUN2SOCKS_CONNECTOR_H

#include <cstdint>

#include <boost/bind.hpp>
#include "allocator/allocator.hpp"
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
        virtual void OnConnectorError(uint64_t id,
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
          closed(false),
          id_(++counter_) {}

    void Start();
    void Stop();

    virtual void OnTCPReceived(
        const std::shared_ptr<boost::asio::mutable_buffer>& data,
        std::size_t len);
    virtual void OnError(const boost::system::system_error&);

    uint64_t GetID() { return id_; }

   private:
    static err_t OnLWIPTCPReceived(void* arg,
                                   struct tcp_pcb* tpcb,
                                   struct pbuf* p,
                                   err_t err);
    static void OnLWIPTCPError(void* arg, err_t err);

    void mayCallOnError(const boost::system::system_error&);
    std::shared_ptr<boost::asio::mutable_buffer> allocateBuffer(
        std::size_t suggest);
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
    uint64_t id_;
    bool closed;
    static uint64_t counter_;
};
}  // namespace connector
}  // namespace toys

#endif
