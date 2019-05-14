#include <tuntap.h>
#include <cstring>
#include <memory>

#include <linux/if_tun.h>

namespace tun2socks {
    TUNDevice::TUNDevice(boost::asio::io_context& ctx, const TUNAdapter& adapter)
            : _ctx(ctx), _tun_handle(adapter.hd), _adapter(adapter), _stream(ctx, adapter.hd) {}

    int TUNDevice::tap_set_address() {
        ifreq ifr{0};
        sockaddr_in mask;
        memcpy(&(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr), &_adapter.ip, sizeof(struct in_addr));
        memcpy(ifr.ifr_name, _adapter.dev_name, strlen(_adapter.dev_name) + 1);
        ifr.ifr_addr.sa_family = AF_INET;
        if (ioctl(_adapter.ctrl_socket, SIOCSIFADDR, &ifr) == -1) {
            perror("");
            return -1;
        }
        memset(&ifr.ifr_addr, 0, sizeof ifr.ifr_addr);
        memset(&mask, '\0', sizeof mask);
        mask.sin_family = AF_INET;
        mask.sin_addr.s_addr = _adapter.mask;
        memcpy(&ifr.ifr_netmask, &mask, sizeof ifr.ifr_netmask);
        if (ioctl(_adapter.ctrl_socket, SIOCSIFNETMASK, &ifr) == -1)
            return -1;
        memset(&ifr.ifr_addr, 0, sizeof ifr.ifr_addr);
        ifr.ifr_flags = _adapter.flags | IFF_UP;
        if (ioctl(_adapter.ctrl_socket, SIOCSIFFLAGS, &ifr) == -1)
            return -1;
        _adapter.flags = ifr.ifr_flags;
        return 0;
    }

    void TUNDevice::start_read(const std::function<void(std::shared_ptr<Request>)>& success,const std::function<void(const boost::system::error_code&)>& fail) {
        auto q = std::make_shared<Request>();
        q->buf = pbuf_alloc(pbuf_layer::PBUF_RAW, 1500, pbuf_type::PBUF_RAM);
        // Note: read_some means the read operation won't read all of the requested numbers.
        //       the handler will be called as soon as the read operation finishes, which means our device receive a new packet.
        _stream.async_read_some(boost::asio::buffer(q->buf->payload, q->buf->tot_len), [this, q, success, fail](const boost::system::error_code& err, size_t transferred){
            q->transfered = transferred;
            if(!err){
                start_read(success, fail);
                if(success != nullptr)
                    success(q);
            }else{
                if(fail != nullptr)
                    fail(err);
            }
        });
    }

    void TUNDevice::do_write(std::unique_ptr<u_char[]>&& buffer, size_t len, std::function<void()> success, std::function<void(const boost::system::error_code&)> fail) {
        std::shared_ptr<u_char[]> shared_buffer = std::move(buffer);
        boost::asio::async_write(_stream, boost::asio::buffer(shared_buffer.get(), len), [shared_buffer, success, fail](const boost::system::error_code& err, size_t transferred){
            if (!err) {
                if (success != nullptr)
                    success();
            }
            else {
                if (fail != nullptr)
                    fail(err);
            }
        });
    }
}


TUNAdapter* open_tun(TUNAdapter* adapter) {
    int fd;
    int skt_fd;
    ifreq ifr{0};
    const char* ifname = "tun2socks";
    if(adapter != NULL){
        // On linux, there is no need to select a specified device as we can on Windows.
        // TODO: Maybe TUNConfig is a good idea.
        return NULL;
    }
    if((fd = open("/dev/net/tun", O_RDWR))==-1)
        return NULL;
    ifr.ifr_flags = IFF_TUN;
    ifr.ifr_flags |= IFF_NO_PI;
    memcpy(ifr.ifr_name, ifname, strlen(ifname) + 1);
    if(ioctl(fd, TUNSETIFF, &ifr) ==-1)
        return NULL;
    skt_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if(skt_fd == -1)
        return NULL;
    if(ioctl(skt_fd, SIOCGIFFLAGS, &ifr) == -1)
        return NULL;
    auto result = new TUNAdapter();
    memset(result, 0, sizeof(TUNAdapter));
    result->hd = fd;
    result->ctrl_socket = skt_fd;
    memcpy(result->dev_name, ifr.ifr_name, sizeof ifr.ifr_name);
    result->flags = ifr.ifr_flags;
    return result;
}

void delete_tun(TUNAdapter* adapter) {
    // TODO: Change signature to TUNAdapter** and set pointer to NULL.
    close(adapter->hd);
    close(adapter->ctrl_socket);
    if (adapter != NULL)
        delete adapter;
}