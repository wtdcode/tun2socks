#ifndef TUN2SOCKS_CORE_H
#define TUN2SOCKS_CORE_H

#include <memory>
#include <mutex>
#include <unordered_map>
#include "connector/connector_table.hpp"
#include "core/config.h"
#include "pool/pool.hpp"
#include "tuntap/tuntap.h"
#include "wrapper/lwip.hpp"

namespace toys {
namespace core {
class Core : public toys::tuntap::TunTap::Delegate,
             public toys::connector::Connector::Delegate {
   public:
    Core(TUN2SOCKSConfig config)
        : config_(std::move(config)),
          pool_(),
          tuntap_(),
          loopback_(NULL),
          tlpcb_(NULL) {}

    virtual void OnReceived(const uint8_t* data, std::size_t data_len);
    virtual void OnSent(const uint8_t* data, std::size_t data_len);
    virtual void OnConnectorError(uint32_t id,
                                  const boost::system::system_error& err);
    int Run();

   private:
    static err_t onLWIPOutput(struct netif* netif,
                              struct pbuf* p,
                              const ip4_addr_t* ipaddr);
    static err_t onLWIPTCPAccept(void* arg, struct tcp_pcb* newpcb, err_t err);

    void Stop();

   private:
    TUN2SOCKSConfig config_;
    toys::pool::IOContextPool<1, 8> pool_;
    std::unique_ptr<toys::tuntap::TunTap> tuntap_;
    netif* loopback_;
    tcp_pcb* tlpcb_;
};
}  // namespace core
}  // namespace toys

#endif
