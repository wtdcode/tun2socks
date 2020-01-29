#include "tuntapimpl_linux.h"
#include <fcntl.h>
#include <linux/if_tun.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <boost/bind.hpp>
#include <cstring>

namespace toys {
namespace tuntap {

TunTapImpl* TunTapImpl::Create(TunTap::Delegate* delegate,
                               boost::asio::io_context& ctx) {
    int fd;
    int ctl_skt;
    ifreq ifr{0};
    const char* ifname = "tun2socks";
    if ((fd = open("/dev/net/tun", O_RDWR)) == -1)
        return NULL;
    ifr.ifr_flags = IFF_TUN;
    ifr.ifr_flags |= IFF_NO_PI;
    memcpy(ifr.ifr_name, ifname, strlen(ifname) + 1);
    if (ioctl(fd, TUNSETIFF, &ifr) == -1)
        return NULL;
    ctl_skt = socket(AF_INET, SOCK_DGRAM, 0);
    if (ctl_skt == -1)
        return NULL;
    return new TunTapImpl(delegate, fd, ctl_skt, ctx);
}

bool TunTapImpl::Write(const std::vector<uint8_t>& data) {
    boost::asio::spawn(this->strand_,
                       boost::bind(&TunTapImpl::doWriteData, this,
                                   boost::placeholders::_1, data));
    return true;
}

bool TunTapImpl::StartRead() {
    boost::asio::spawn(this->strand_,
                       boost::bind(&TunTapImpl::startReadOnTunTapThread, this,
                                   boost::placeholders::_1));
    return true;
}

// See http://man7.org/linux/man-pages/man7/netdevice.7.html
bool TunTapImpl::SetAddress(uint32_t ip, uint32_t mask) {
    ifreq ifr{0};
    sockaddr_in mask_struct{0};
    std::string dev_name;
    if (!GetInterfaceName(dev_name))
        return false;
    memcpy(&(((struct sockaddr_in*)&ifr.ifr_addr)->sin_addr), &ip,
           sizeof(struct in_addr));
    memcpy(ifr.ifr_name, dev_name.c_str(), dev_name.size() + 1);
    ifr.ifr_addr.sa_family = AF_INET;
    if (ioctl(this->ctl_skt_, SIOCSIFADDR, &ifr) == -1) {
        return false;
    }
    memset(&ifr.ifr_addr, 0, sizeof ifr.ifr_addr);
    memset(&mask_struct, 0, sizeof mask);
    mask_struct.sin_family = AF_INET;
    mask_struct.sin_addr.s_addr = mask;
    memcpy(&ifr.ifr_netmask, &mask_struct, sizeof ifr.ifr_netmask);
    return ioctl(this->ctl_skt_, SIOCSIFNETMASK, &ifr) != -1;
}

bool TunTapImpl::Up() {
    ifreq ifr{0};
    if (ioctl(this->fd_, TUNGETIFF, &ifr) == -1)
        return false;
    ifr.ifr_flags |= IFF_UP;
    bool result = (ioctl(this->ctl_skt_, SIOCSIFFLAGS, &ifr) != -1);
    if (result)
        this->OnUp();
    // TODO: Call delegate->OnTunTapError
    return result;
}

bool TunTapImpl::Down() {
    ifreq ifr{0};
    if (ioctl(this->fd_, TUNGETIFF, &ifr) == -1)
        return false;
    ifr.ifr_flags &= ~IFF_UP;
    bool result = (ioctl(this->ctl_skt_, SIOCSIFFLAGS, &ifr) != -1);
    if (result)
        this->OnDown();
    // TODO: Call delegate->OnTunTapError
    return result;
}

bool TunTapImpl::Stop() {
    this->doClose();
    return true;
}

bool TunTapImpl::GetFlags(short& flags) {
    ifreq ifr{0};
    if (ioctl(this->fd_, TUNGETIFF, &ifr) == -1)
        return false;
    flags = ifr.ifr_flags;
    return true;
}

bool TunTapImpl::SetInterfaceName(const std::string& ifname) {
    if (ifname.size() >= IF_NAMESIZE)
        return false;
    ifreq ifr{0};
    std::string old_name;
    if (!GetInterfaceName(old_name))
        return false;
    memcpy(ifr.ifr_name, old_name.c_str(), old_name.size() + 1);
    memcpy(ifr.ifr_newname, ifname.c_str(), ifname.size() + 1);
    return ioctl(this->ctl_skt_, SIOCSIFNAME, &ifr) != -1;
}

bool TunTapImpl::GetInterfaceName(std::string& ifname) {
    ifreq ifr{0};
    if (ioctl(this->fd_, TUNGETIFF, &ifr) == -1)
        return false;
    auto len = strlen(ifr.ifr_name);
    if (len >= IF_NAMESIZE)
        return false;
    ifname.assign(ifr.ifr_name, len);
    return true;
}

void TunTapImpl::startReadOnTunTapThread(boost::asio::yield_context y) {
    while (true) {
        try {
            // TODO: We should allow custom allocators (also in SOCKS5 impl).
            uint8_t buffer[1600];
            auto sz = this->stream_.async_read_some(
                boost::asio::buffer(buffer, 1600), y);
            this->OnReadComplete(buffer, sz);
        } catch (boost::system::error_code& ec) {
            // TODO: delegate->OnTunTapError
            break;
        }
    }
}

void TunTapImpl::doWriteData(boost::asio::yield_context y,
                             const std::vector<uint8_t>& data) {
    try {
        boost::asio::async_write(this->stream_, boost::asio::buffer(data), y);
    } catch (boost::system::error_code& ec) {
        // TODO: Call delegate->OnTunTapError
    }
}

void TunTapImpl::doClose() {
    this->stream_.close();
}

}  // namespace tuntap
}