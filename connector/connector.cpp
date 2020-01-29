#include "connector.h"

#include <spdlog/spdlog.h>
#include <functional>
#include "wrapper/pbuf.hpp"

namespace toys {
namespace connector {

uint64_t Connector::counter_ = 0;

void Connector::Start() {
    this->client_.Start();
    tcp_arg(this->tpcb_, (void*)this);
    tcp_recv(this->tpcb_, &Connector::OnLWIPTCPReceived);
    tcp_err(this->tpcb_, &Connector::OnLWIPTCPError);
}

void Connector::Stop() {
    this->doClose();
}

void Connector::OnTCPReceived(
    const std::shared_ptr<boost::asio::mutable_buffer>& data,
    std::size_t len) {
    boost::asio::spawn(this->strand_,
                       boost::bind(&Connector::doSOCKS5TCPReceived, this,
                                   boost::placeholders::_1, data, len));
}

void Connector::OnError(const boost::system::system_error& err) {
    this->mayCallOnError(err);
}

err_t Connector::OnLWIPTCPReceived(void* arg,
                                   struct tcp_pcb* tpcb,
                                   struct pbuf* p,
                                   err_t err) {
    auto connector = (Connector*)arg;
    if (p == NULL) {
        connector->mayCallOnError(
            boost::asio::error::make_error_code(boost::asio::error::eof));
        return ERR_OK;
    }
    std::vector<uint8_t> buffer;
    buffer.resize(p->tot_len);
    pbuf_copy_partial(p, &buffer[0], p->tot_len, 0);
    spdlog::trace("Send {} bytes to SOCKS5 client.", p->tot_len);
    connector->client_.SendTCPData(std::move(buffer));
    wrapper::LwIP::Instance().tcp_recved(connector->tpcb_, p->tot_len);
    return ERR_OK;
}

void Connector::OnLWIPTCPError(void* arg, err_t err) {
    auto connector = (Connector*)arg;
    boost::system::error_code code;
    switch (err) {
        case ERR_ABRT:
            code = boost::asio::error::make_error_code(
                boost::asio::error::connection_aborted);
            break;
        case ERR_CONN:
        case ERR_CLSD:
            code = boost::asio::error::make_error_code(boost::asio::error::eof);
            break;
        case ERR_RST:
            code = boost::asio::error::make_error_code(
                boost::asio::error::connection_reset);
            break;
        case ERR_MEM:
            spdlog::critical("LwIP runs out of memory...");
            code = boost::system::errc::make_error_code(
                boost::system::errc::not_enough_memory);
            break;
        case ERR_OK:
            spdlog::warn("We are required to handle ERR_OK.");
            return;
        default:
            spdlog::warn("Unhandled LwIP error: {}", err);
            return;
    }
    connector->mayCallOnError(code);
}

void Connector::mayCallOnError(const boost::system::system_error& err) {
    boost::asio::post(this->strand_,
                      boost::bind(&Connector::doCallOnError, this, err));
}

std::shared_ptr<boost::asio::mutable_buffer> Connector::allocateBuffer(
    std::size_t suggest) {
    if (!this->tpcb_)
        return nullptr;
    auto p = pbuf_alloc(pbuf_layer::PBUF_TRANSPORT, this->tpcb_->mss,
                        pbuf_type::PBUF_RAM);
    if (p == NULL)
        return nullptr;
    return {new wrapper::pbuf_buffer(p),
            [&p](boost::asio::mutable_buffer* buffer) {
                delete (wrapper::pbuf_buffer*)buffer;
            }};
}

void Connector::doCallOnError(const boost::system::system_error& err) {
    auto code = err.code();
    if (code == boost::asio::error::eof ||
        code == boost::asio::error::connection_refused ||
        code == boost::asio::error::connection_aborted ||
        code == boost::asio::error::connection_reset) {
        if (this->delegate_)
            this->delegate_->OnConnectorError(this->id_, err);
    } else if (code == boost::system::errc::not_enough_memory) {
        if (this->delegate_)
            this->delegate_->OnConnectorError(this->id_, err);
    } else if (code == boost::asio::error::operation_aborted) {
        // do nothing
    } else {
        spdlog::warn("Unhandled connector error: {}.", err.what());
    }
}

void Connector::doSOCKS5TCPReceived(
    boost::asio::yield_context y,
    const std::shared_ptr<boost::asio::mutable_buffer>& data,
    std::size_t len) {
    if (this->closed)
        return;
    auto err = wrapper::LwIP::Instance().tcp_write(this->tpcb_, data->data(),
                                                   len, TCP_WRITE_FLAG_COPY);
    if (err != ERR_OK)
        this->OnLWIPTCPError(this, err);
    spdlog::trace("Write {} bytes to LwIP TCP.", len);
    err = wrapper::LwIP::Instance().tcp_output(this->tpcb_);
    if (err != ERR_OK)
        this->OnLWIPTCPError(this, err);
}

void Connector::doClose() {
    if (this->closed)
        return;
    this->closed = true;
    this->client_.Stop();
    wrapper::LwIP::Instance().tcp_err(this->tpcb_, NULL);
    wrapper::LwIP::Instance().tcp_sent(this->tpcb_, NULL);
    wrapper::LwIP::Instance().tcp_recv(this->tpcb_, NULL);
    wrapper::LwIP::Instance().tcp_close(this->tpcb_);
    this->tpcb_ = NULL;
}
}  // namespace connector
}