#ifndef TUN2SOCKS_TUNTAP_H
#define TUN2SOCKS_TUNTAP_H

#include <error/error_code.h>
#include <cstdint>
#include <string>
#include <vector>

namespace toys {
namespace tuntap {
class TunTap {
   public:
    class Delegate {
       public:
        virtual void OnUp(){};
        virtual void OnDown(){};
        virtual void OnReceived(const uint8_t* data, std::size_t data_len){};
        virtual void OnSent(const uint8_t* data, std::size_t data_len){};
        virtual void OnTunTapError(const boost::system::error_code&){};
    };

   public:
    TunTap(Delegate* delegate) : delegate_(delegate) {}

    virtual bool Write(const std::vector<uint8_t>& data) = 0;
    virtual bool StartRead() = 0;
    virtual bool SetAddress(uint32_t ip, uint32_t mask) = 0;
    virtual bool Up() = 0;
    virtual bool Down() = 0;
    virtual bool Stop() = 0;

   protected:
    virtual void OnUp();
    virtual void OnDown();
    virtual void OnReadComplete(const uint8_t* data, std::size_t data_len);
    virtual void OnWriteComplete(const uint8_t* data, std::size_t data_len);
    virtual void OnError(const boost::system::error_code&);

   private:
    Delegate* delegate_;
};
}  // namespace tuntap
}  // namespace toys

#endif
