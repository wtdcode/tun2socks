#ifndef LIBSOCKS5_SOCKS5_H
#define LIBSOCKS5_SOCKS5_H

#include <cstdint>

namespace toys {
namespace socks5 {

// From https://tools.ietf.org/html/rfc1928

enum RequestCommand : uint8_t { CONNECT = 1, BIND = 2, UDPASSOCIATE = 3 };

enum AddressType : uint8_t { IPV4 = 1, DOMAINNAME = 3, IPV6 = 4 };

enum Method : uint8_t {
    NOAUTH = 0,
    USRNAME_PASSWORD = 2,
    NO_ACCEPTABLE_METHODS = 0xFF
};

enum ReplyField : uint8_t {
    SUCCEED = 0,
    GENERAL_FAILURE = 1,
    NOT_ALLOWED = 2,
    NETWORK_UNREACHABLE = 3,
    HOST_UNREACHABLE = 4,
    CONNECTION_REFUSED = 5,
    TTL_EXPIRED = 6,
    COMMAND_NOT_SUPPORTED = 7,
    ADDRESS_TYPE_NOT_SUPPORTED = 8
};

#pragma pack(push, 1)
struct ClientHello {
    uint8_t version;
    uint8_t nmethods;
    Method methods[1];
};
#pragma pack(pop)

#pragma pack(push, 1)
struct ServerHello {
    uint8_t version;
    Method method;
};
#pragma pack(pop)

#pragma pack(push, 1)
struct Request {
    uint8_t version;
    RequestCommand cmd;
    uint8_t reserved;
    AddressType address_type;
};
#pragma pack(pop)

#pragma pack(push, 1)
struct UDPRequest {
    uint16_t reserved;
    uint8_t fragment_number;
    AddressType address_type;
};
#pragma pack(pop)

#pragma pack(push, 1)
struct Reply {
    uint8_t version;
    ReplyField reply;
    uint8_t reserved;
    AddressType address_type;
};
#pragma pack(pop)

#pragma pack(push, 1)
struct AddressIPV4 {
    uint32_t ipv4;
};
#pragma pack(pop)

#pragma pack(push, 1)
struct AddressDomain {
    uint8_t length;
    uint8_t domain[1];
};
#pragma pack(pop)

#pragma pack(push, 1)
struct AddressIPV6 {
    uint8_t ipv6[16];
};
#pragma pack(pop)

#pragma pack(push, 1)
struct USRPWDRequest {
    uint8_t version;
};
#pragma pack(pop)

#pragma pack(push, 1)
struct UsernameField {
    uint8_t length;
    uint8_t str[1];
};
#pragma pack(pop)

typedef UsernameField PasswordField;

#pragma pack(push, 1)
struct USRPWDReply {
    uint8_t version;
    uint8_t status;
};
#pragma pack(pop)

}  // namespace socks5
}  // namespace toys

#endif  // LIBSOCKS5_SOCKS5_H
