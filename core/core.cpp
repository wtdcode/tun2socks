#include "core/core.h"
#include <spdlog/spdlog.h>
#include "error/error_code.h"
#ifdef LINUX
#include "tuntap/tuntapimpl_linux.h"
#endif

namespace toys {
namespace core {

void Core::OnReceived(const uint8_t* data, std::size_t data_len) {
    if (data_len == 0)  // Does that mean EOF???
        return;
    std::vector<uint8_t> buffer;
    buffer.assign(data, data + data_len);
    auto p = pbuf_alloc(pbuf_layer::PBUF_RAW, data_len, pbuf_type::PBUF_REF);
    p->payload = &buffer[0];
    spdlog::trace("Receive {} bytes from TUN.", p->tot_len);
    {
        std::lock_guard<std::recursive_mutex> guard(
            wrapper::LwIP::Instance().GetLock());
        this->loopback_->input(p, this->loopback_);
    }
}

void Core::OnSent(const uint8_t* data, std::size_t data_len) {}

void Core::OnConnectorError(uint32_t id,
                            const boost::system::system_error& err) {
    auto code = err.code();
    if (code == TUN2SOCKSErrorCode::SOCKS5_WRONG_VERSION ||
        code == TUN2SOCKSErrorCode::SOCKS5_CONNECT_COMMAND_FAILED ||
        code == TUN2SOCKSErrorCode::SOCKS5_BAD_USERNAME_OR_PASSWORD ||
        code == TUN2SOCKSErrorCode::SOCKS5_USR_PWD_AUTH_FAILED ||
        code == TUN2SOCKSErrorCode::SOCKS5_AUTH_METHOD_NOT_SUPPORTED ||
        code == TUN2SOCKSErrorCode::SOCKS5_BAD_USR_PWD_AUTH_VERSION ||
        code == boost::system::errc::not_enough_memory) {
        spdlog::critical("Critical error : {}, program exits.", err.what());
        this->Stop();
    } else {
        connector::ConnectorTable::Instance().EraseConnector(id);
    }
}

int Core::Run() {
    lwip_init();
    this->loopback_ = netif_list;
    this->loopback_->callback_arg = (void*)this;
    this->loopback_->output = &Core::onLWIPOutput;
    auto tuntap =
        toys::tuntap::TunTapImpl::Create(this, this->pool_.getIOContext());
    if (tuntap == NULL) {
        spdlog::info("Fail to create TUN device. Are you root?");
        return -1;
    }
    this->tuntap_.reset(tuntap);
    auto isup = this->tuntap_->Up();
    auto isset = this->tuntap_->SetAddress(
        boost::asio::detail::socket_ops::host_to_network_long(
            this->config_.tunNetwork.address().to_uint()),
        boost::asio::detail::socket_ops::host_to_network_long(
            this->config_.tunNetwork.netmask().to_uint()));
    auto isstarted = this->tuntap_->StartRead();
    if (!isup || !isset || !isstarted) {
        spdlog::info("Fail to set up TUN device. Are you root?");
        return -1;
    }
    auto pcb = wrapper::LwIP::Instance().tcp_new();
    auto any = ip_addr_any;
    wrapper::LwIP::Instance().tcp_bind(pcb, &any, 0);
    this->tlpcb_ = wrapper::LwIP::Instance().tcp_listen_wrapper(pcb);
    wrapper::LwIP::Instance().tcp_arg(this->tlpcb_, (void*)this);
    wrapper::LwIP::Instance().tcp_accept(this->tlpcb_, &Core::onLWIPTCPAccept);
    wrapper::LwIP::Instance().tcp_bind_netif(this->tlpcb_, this->loopback_);
    this->pool_.Start();
    this->pool_.Wait();
    return 0;
}

err_t Core::onLWIPOutput(struct netif* netif,
                         struct pbuf* p,
                         const ip4_addr_t* ipaddr) {
    std::vector<uint8_t> buffer;
    auto core = (Core*)netif->callback_arg;
    buffer.resize(p->tot_len);
    pbuf_copy_partial(p, &buffer[0], p->tot_len, 0);
    spdlog::trace("Send {} bytes to TUN.", p->tot_len);
    core->tuntap_->Write(buffer);
    return ERR_OK;
}

err_t Core::onLWIPTCPAccept(void* arg, struct tcp_pcb* newpcb, err_t err) {
    if (err != ERR_OK || newpcb == NULL)
        return ERR_ABRT;
    // IP addresses are always in network order.
    boost::asio::ip::address_v4 dest_ip(
        boost::asio::detail::socket_ops::network_to_host_long(
            newpcb->local_ip.addr));
    boost::asio::ip::address_v4 src_ip(
        boost::asio::detail::socket_ops::network_to_host_long(
            newpcb->remote_ip.addr));
    // Ports are always in host byte order.
    auto src_port = newpcb->remote_port;
    auto dest_port = newpcb->local_port;
    auto core = (Core*)arg;
    boost::asio::ip::tcp::endpoint src(src_ip, src_port);
    boost::asio::ip::tcp::endpoint dest(dest_ip, dest_port);
    // For tcp_route.
    wrapper::LwIP::Instance().tcp_bind_netif(newpcb, core->loopback_);
    auto connector = connector::ConnectorTable::MakeConnector(
        core, core->pool_.getIOContext(), core->config_.socks5Endpoint, dest,
        core->config_.method, *core->tuntap_, newpcb);
    spdlog::debug("Accept a new connection: {}:{} -> {}:{} with ID = {}",
                  src.address().to_string(), src.port(),
                  dest.address().to_string(), dest.port(), connector->GetID());
    connector->Start();
    return ERR_OK;
}

void Core::Stop() {
    wrapper::LwIP::Instance().tcp_accept(this->tlpcb_, NULL);
    wrapper::LwIP::Instance().tcp_close(this->tlpcb_);
    connector::ConnectorTable::Instance().ClearConnectors();
    this->tuntap_->Stop();
    this->pool_.Stop();
}

}  // namespace core
}