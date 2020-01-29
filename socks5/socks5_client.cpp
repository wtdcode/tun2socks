#include "socks5/socks5_client.h"
#include <spdlog/spdlog.h>
#include <boost/bind.hpp>
#include <vector>
#include "error/error_code.h"

namespace toys {
namespace socks5 {

using boost::system::make_error_code;

std::vector<uint8_t> ConstructRequest(RequestCommand cmd,
                                      AddressType type,
                                      const uint8_t* address,
                                      size_t address_len,
                                      uint16_t port) {
    Request req{5, cmd, 0, type};
    std::vector<uint8_t> buffer;
    buffer.resize(sizeof(Request) + address_len + 2);
    auto next = std::copy((uint8_t*)&req, (uint8_t*)(&req) + sizeof(Request),
                          buffer.begin());
    next = std::copy(address, address + address_len, next);
    std::copy((uint8_t*)&port, (uint8_t*)(&port) + 2, next);
    return buffer;
}

std::vector<uint8_t> ConstructRequest(RequestCommand cmd,
                                      AddressType type,
                                      const std::vector<uint8_t>& address,
                                      uint16_t port) {
    return ConstructRequest(cmd, type, &address[0], address.size(), port);
}

std::vector<uint8_t> ConstructRequest(RequestCommand cmd,
                                      const std::string& address,
                                      uint16_t port) {
    std::vector<uint8_t> address_buffer;
    address_buffer.resize(1 + address.size());
    address_buffer[0] = address.size();
    std::copy(address.begin(), address.end(), &address_buffer[1]);
    return ConstructRequest(cmd, AddressType::DOMAINNAME, address_buffer, port);
}

void SOCKS5Client::Start() {
    boost::asio::spawn(this->strand_,
                       boost::bind(&SOCKS5Client::startOnSOCKS5Thread, this,
                                   boost::placeholders::_1));
}

void SOCKS5Client::Stop() {
    this->doClose();
}

void SOCKS5Client::SendTCPData(std::vector<uint8_t> data) {
    if (this->closed)
        return;
    auto dataToSend = std::make_shared<std::vector<uint8_t>>(std::move(data));
    boost::asio::post(this->strand_, [this, dataToSend]() {
        if (!this->ready_to_send_tcp_data_) {
            spdlog::trace("{} bytes data queued.", dataToSend->size());
            this->write_queue_.emplace_back(std::move(*dataToSend));
        } else {
            boost::asio::spawn(
                this->strand_,
                boost::bind(&SOCKS5Client::doSendTCPData, this,
                            boost::placeholders::_1, dataToSend));
        }
    });
}

void SOCKS5Client::startOnSOCKS5Thread(boost::asio::yield_context y) {
    auto connect_result = this->connectServer(y);
    if (!connect_result) {
        this->read_stopped_.set_value();
        return;
    }
    auto auth_result = this->authClient(y);
    if (!auth_result) {
        this->read_stopped_.set_value();
        return;
    }
    auto destination_connect_result = this->connectDestination(y);
    if (!destination_connect_result) {
        this->read_stopped_.set_value();
        return;
    }
    this->ready_to_send_tcp_data_ = true;
    boost::asio::spawn(
        this->strand_,
        boost::bind(&SOCKS5Client::clearQueue, this, boost::placeholders::_1));
    while (this->ready_to_send_tcp_data_) {
        try {
            auto buffer = this->allocator_(1600);
            if (!buffer) {
                this->wait_timer_.expires_from_now(
                    boost::posix_time::seconds(10));
                boost::system::error_code ec;
                this->wait_timer_.async_wait(y[ec]);  // yield.
                continue;
            }
            auto sz = this->tcp_socket_.async_receive(*buffer, y);
            if (this->delegate_)
                this->delegate_->OnTCPReceived(buffer, sz);
        } catch (const boost::system::system_error& err) {
            spdlog::debug("Fail to receive more data with error: {}.",
                          err.what());
            this->mayCallOnError(err);
            break;
        }
    }
    this->read_stopped_.set_value();
}

bool SOCKS5Client::connectServer(boost::asio::yield_context& y) {
    try {
        this->tcp_socket_.async_connect(this->server_endpoint_, y);
        auto method = this->auth_method_->Type();
        ClientHello client_hello{5, 1, method};
        ServerHello server_hello;
        boost::asio::async_write(
            this->tcp_socket_,
            boost::asio::buffer((void*)&client_hello, sizeof(ClientHello)), y);
        boost::asio::async_read(
            this->tcp_socket_, boost::asio::buffer((void*)&server_hello, 2), y);
        if (server_hello.version != 5) {
            if (this->delegate_)
                this->mayCallOnError(
                    make_error_code(TUN2SOCKSErrorCode::SOCKS5_WRONG_VERSION));
            return false;
        }
        if (server_hello.method != method) {
            this->mayCallOnError(make_error_code(
                TUN2SOCKSErrorCode::SOCKS5_AUTH_METHOD_NOT_SUPPORTED));
            return false;
        }
    } catch (const boost::system::system_error& err) {
        spdlog::critical("Fail to connect to SOCKS5 server with error: {}.",
                         err.what());
        this->mayCallOnError(err);
        return false;
    }
    if (this->delegate_)
        this->delegate_->OnServerConnected();
    return true;
}

bool SOCKS5Client::connectDestination(boost::asio::yield_context& y) {
    try {
        auto req_data = ConstructRequest(
            RequestCommand::CONNECT,
            this->destination_endpoint_.address().to_string(),
            boost::asio::detail::socket_ops::host_to_network_short(
                this->destination_endpoint_.port()));
        Reply reply;
        boost::asio::async_write(this->tcp_socket_,
                                 boost::asio::buffer(req_data), y);
        boost::asio::async_read(
            this->tcp_socket_,
            boost::asio::buffer((void*)&reply, sizeof(Reply)), y);
        if (reply.version != 5 || reply.reserved != 0) {
            if (this->delegate_)
                this->delegate_->OnError(
                    make_error_code(TUN2SOCKSErrorCode::SOCKS5_WRONG_VERSION));
            return false;
        }
        if (reply.reply != ReplyField::SUCCEED) {
            if (this->delegate_)
                this->delegate_->OnError(make_error_code(
                    TUN2SOCKSErrorCode::SOCKS5_CONNECT_COMMAND_FAILED));
            return false;
        }
        int32_t bytesToIgnore = 0;
        switch (reply.address_type) {
            case AddressType::IPV4:
                bytesToIgnore = 4;
                break;
            case AddressType::IPV6:
                bytesToIgnore = 16;
                break;
            case AddressType::DOMAINNAME:
                boost::asio::async_read(
                    this->tcp_socket_,
                    boost::asio::buffer((void*)&bytesToIgnore, 1), y);
                break;
        }
        bytesToIgnore += 2;  // BND.PORT
        std::vector<uint8_t> tmp;
        tmp.resize(bytesToIgnore);
        boost::asio::async_read(this->tcp_socket_, boost::asio::buffer(tmp), y);
        if (this->delegate_)
            this->delegate_->OnDestinationConnected();
        return true;
    } catch (const boost::system::system_error& err) {
        spdlog::critical("SOCKS5 CONNECT failed with error: {].", err.what());
        this->mayCallOnError(err);
        return false;
    }
}

bool SOCKS5Client::authClient(boost::asio::yield_context& y) {
    try {
        auto method = this->auth_method_->Type();
        switch (method) {
            case Method::NOAUTH:
                if (this->delegate_)
                    this->delegate_->OnAuthed();
                return true;
            case Method::USRNAME_PASSWORD: {
                auto usr_pwd_auth = dynamic_cast<UsernamePasswordAuth*>(
                    this->auth_method_.get());
                auto username = usr_pwd_auth->Username();
                auto password = usr_pwd_auth->Password();
                std::vector<uint8_t> buffer;
                auto username_len = username.size();
                auto password_len = password.size();
                USRPWDReply reply;
                if (username_len > 256 || password_len > 256) {
                    if (this->delegate_)
                        this->delegate_->OnError(make_error_code(
                            TUN2SOCKSErrorCode::
                                SOCKS5_BAD_USERNAME_OR_PASSWORD));
                    return false;
                }
                buffer.resize(3 + username.size() + password.size());
                buffer[0] = 1;
                buffer[1] = (uint8_t)username_len;
                auto next = std::copy(username.begin(), username.end(),
                                      buffer.begin() + 2);
                buffer[username_len + 2] = (uint8_t)password_len;
                next = std::copy(password.begin(), password.end(), next + 1);
                boost::asio::async_write(this->tcp_socket_,
                                         boost::asio::buffer(buffer), y);
                boost::asio::async_read(
                    this->tcp_socket_,
                    boost::asio::buffer((void*)&reply, sizeof(USRPWDReply)), y);
                if (reply.version != 1) {
                    if (this->delegate_)
                        this->delegate_->OnError(make_error_code(
                            TUN2SOCKSErrorCode::
                                SOCKS5_BAD_USR_PWD_AUTH_VERSION));
                    return false;
                }
                if (reply.status != 0) {
                    if (this->delegate_)
                        this->delegate_->OnError(make_error_code(
                            TUN2SOCKSErrorCode::
                                SOCKS5_BAD_USERNAME_OR_PASSWORD));
                    return false;
                }
                if (this->delegate_)
                    this->delegate_->OnAuthed();
                return true;
            }
            case Method::NO_ACCEPTABLE_METHODS:
                return false;
        }
    } catch (const boost::system::system_error& err) {
        spdlog::critical("Authentication failed with error: {}.", err.what());
        this->mayCallOnError(err);
        return false;
    }
    return true;
}

void SOCKS5Client::mayCallOnError(const boost::system::system_error& err) {
    if (err.code() == boost::asio::error::operation_aborted)
        return;
    if (this->delegate_)
        this->delegate_->OnError(err);
}

void SOCKS5Client::clearQueue(boost::asio::yield_context y) {
    while (!this->write_queue_.empty()) {
        spdlog::trace("Clearing SOCKS5 queue, size: {}.",
                      this->write_queue_.size());
        auto& queuedData = this->write_queue_.front();
        try {
            boost::asio::async_write(this->tcp_socket_,
                                     boost::asio::buffer(queuedData), y);
        } catch (const boost::system::system_error& err) {
            this->mayCallOnError(err);
            return;
        }
        this->write_queue_.pop_front();
    }
}

void SOCKS5Client::doSendTCPData(
    boost::asio::yield_context y,
    const std::shared_ptr<std::vector<uint8_t>>& data) {
    if (!this->ready_to_send_tcp_data_)
        return;
    if (!this->write_queue_.empty())
        this->clearQueue(y);
    try {
        spdlog::trace("Write {} bytes to SOCKS5.", data->size());
        boost::asio::async_write(this->tcp_socket_, boost::asio::buffer(*data),
                                 y);
    } catch (const boost::system::system_error& err) {
        this->mayCallOnError(err);
        return;
    }
}

void SOCKS5Client::doClose() {
    // https://www.boost.org/doc/libs/1_72_0/doc/html/boost_asio/tutorial/tutdaytime7/src.html
    // let the socket be closed when the object is deconstructed.
    if (this->closed)
        return;
    this->closed = true;
    this->ready_to_send_tcp_data_ = false;
    this->wait_timer_.cancel();
    if (this->tcp_socket_.is_open())
        this->tcp_socket_.close();
    if (this->udp_socket_.is_open())
        this->udp_socket_.close();
    this->read_stopped_.get_future().wait();
}
}  // namespace socks5
}