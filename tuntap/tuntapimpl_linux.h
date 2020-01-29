#ifndef TUN2SOCKS_TUNTAPIMPL_LINUX_H
#define TUN2SOCKS_TUNTAPIMPL_LINUX_H

#ifndef BOOST_COROUTINES_NO_DEPRECATION_WARNING
#define BOOST_COROUTINES_NO_DEPRECATION_WARNING
#endif

#include <net/if.h>
#include <boost/asio.hpp>
#include <boost/asio/spawn.hpp>
#include <vector>
#include "tuntap.h"

namespace toys {
namespace tuntap {
class TunTapImpl : public TunTap {
   public:
    static TunTapImpl* Create(Delegate* delegate, boost::asio::io_context& ctx);

    virtual bool Write(const std::vector<uint8_t>& data);
    virtual bool StartRead();
    virtual bool SetAddress(uint32_t ip, uint32_t mask);
    virtual bool Up();
    virtual bool Down();
    virtual bool Stop();
    virtual bool GetFlags(short&);
    // Can we achieve this on Windows?
    virtual bool SetInterfaceName(const std::string& ifname);
    virtual bool GetInterfaceName(std::string&);

   private:
    TunTapImpl(Delegate* delegate,
               int fd,
               int ctl_skt,
               boost::asio::io_context& ctx)
        : TunTap(delegate),
          fd_(fd),
          ctl_skt_(ctl_skt),
          stream_(ctx, fd),
          strand_(ctx) {}

    void startReadOnTunTapThread(boost::asio::yield_context y);
    void doWriteData(boost::asio::yield_context y,
                     const std::vector<uint8_t>& data);
    void doClose();

   private:
    int fd_;
    int ctl_skt_;
    boost::asio::posix::stream_descriptor stream_;
    boost::asio::io_context::strand strand_;
};
}  // namespace tuntap
}  // namespace toys

#endif
