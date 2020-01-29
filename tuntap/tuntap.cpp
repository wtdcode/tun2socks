#include "tuntap.h"

namespace toys {
namespace tuntap {

void TunTap::OnUp() {
    if (this->delegate_)
        this->delegate_->OnUp();
}

void TunTap::OnDown() {
    if (this->delegate_)
        this->delegate_->OnDown();
}

void TunTap::OnReadComplete(const uint8_t* data, std::size_t data_len) {
    if (this->delegate_)
        this->delegate_->OnReceived(data, data_len);
}

void TunTap::OnWriteComplete(const uint8_t* data, std::size_t data_len) {
    if (this->delegate_)
        this->delegate_->OnSent(data, data_len);
}

void TunTap::OnError(const boost::system::error_code& err) {
    if (this->delegate_)
        this->delegate_->OnTunTapError(err);
}
}  // namespace tuntap
}