#include <tuntap.h>

namespace tun2socks {
    TUNDevice::TUNDevice(boost::asio::io_context& ctx, const TUNAdapter& adapter)
            : _ctx(ctx), _tun_handle(adapter.hd), _adapter(adapter) {}

    int TUNDevice::tap_set_address() {

    }

    void TUNDevice::start_read(std::function<void(std::shared_ptr<Request>)> success, std::function<void(const boost::system::error_code&)> fail) {

    }

    void TUNDevice::do_write(std::unique_ptr<u_char[]>&& buffer, size_t len, std::function<void()> success, std::function<void(const boost::system::error_code&)> fail) {

    }
}


TUNAdapter* open_tun(TUNAdapter* adapter) {

}

void delete_tun(TUNAdapter* adapter) {
    if (adapter != NULL)
        delete adapter;
}