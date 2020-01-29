#ifndef TUN2SOCKS_CONFIG_H
#define TUN2SOCKS_CONFIG_H

#include <fmt/core.h>
#include <boost/asio/ip/address_v4.hpp>
#include <boost/asio/ip/network_v4.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <memory>
#include "socks5/socks5_auth.h"

namespace toys {
namespace core {

struct TUN2SOCKSConfig {
    boost::asio::ip::network_v4 tunNetwork;
    boost::asio::ip::tcp::endpoint socks5Endpoint;
    std::shared_ptr<toys::socks5::AuthMethod> method;

    std::string to_string() const {
        std::string methodString;
        if (this->method->Type() == socks5::NOAUTH)
            methodString = "No authentication";
        else if (this->method->Type() == socks5::USRNAME_PASSWORD)
            methodString = "Username/Password authentication";
        return fmt::format("TUN IP: {}, SOCKS5: {}:{}, Auth: {}",
                           this->tunNetwork.to_string(),
                           this->socks5Endpoint.address().to_string(),
                           this->socks5Endpoint.port(), methodString);
    }
};
}  // namespace core
}  // namespace toys

#endif
