#ifndef LIBSOCKS5_ERROR_CODE_H
#define LIBSOCKS5_ERROR_CODE_H

// Copy from
// https://www.boost.org/doc/libs/1_71_0/libs/outcome/doc/html/motivation/plug_error_code2.html

#include <boost/system/error_code.hpp>  // bring in boost::system::error_code et al
#include <iostream>
#include <string>  // for string printing

// This is the custom error code enum
enum class TUN2SOCKSErrorCode {
    SOCKS5_WRONG_VERSION = 1,
    SOCKS5_AUTH_METHOD_NOT_SUPPORTED = 2,
    SOCKS5_USR_PWD_AUTH_FAILED = 3,
    SOCKS5_BAD_USERNAME_OR_PASSWORD = 4,
    SOCKS5_BAD_USR_PWD_AUTH_VERSION = 5,
    SOCKS5_CONNECT_COMMAND_FAILED = 6
};

namespace boost {
namespace system {
// Tell the C++ 11 STL metaprogramming that enum ConversionErrc
// is registered with the standard error code system
template <>
struct is_error_code_enum<TUN2SOCKSErrorCode> : std::true_type {};
}  // namespace system
}  // namespace boost

namespace detail {
// Define a custom error code category derived from
// boost::system::error_category
class TUN2SOCKSErrorCode_category : public boost::system::error_category {
   public:
    // Return a short descriptive name for the category
    virtual const char* name() const noexcept override final {
        return "TUN2SOCKSError";
    }
    // Return what each enum means in text
    virtual std::string message(int c) const override final {
        switch (static_cast<TUN2SOCKSErrorCode>(c)) {
            case TUN2SOCKSErrorCode::SOCKS5_WRONG_VERSION:
                return "Wrong SOCKS5 version.";
            case TUN2SOCKSErrorCode::SOCKS5_AUTH_METHOD_NOT_SUPPORTED:
                return "The auth method is not supported by the SOCKS5 server.";
            case TUN2SOCKSErrorCode::SOCKS5_USR_PWD_AUTH_FAILED:
                return "Username/Password authentication failed.";
            case TUN2SOCKSErrorCode::SOCKS5_BAD_USERNAME_OR_PASSWORD:
                return "Bad username/password for authentication.";
            case TUN2SOCKSErrorCode::SOCKS5_BAD_USR_PWD_AUTH_VERSION:
                return "Bad username/password authentication version.";
            case TUN2SOCKSErrorCode::SOCKS5_CONNECT_COMMAND_FAILED:
                return "Failed with CONNECT request.";
            default:
                return "unknown";
        }
    }
    // OPTIONAL: Allow generic error conditions to be compared to me
    virtual boost::system::error_condition default_error_condition(int c) const
        noexcept override final {
        switch (static_cast<TUN2SOCKSErrorCode>(c)) {
            default:
                // I have no mapping for this code
                return boost::system::error_condition(c, *this);
        }
    }
};
}  // namespace detail

inline const detail::TUN2SOCKSErrorCode_category& TUN2SOCKSCategory() {
    static detail::TUN2SOCKSErrorCode_category c;
    return c;
}

// Overload the global make_error_code() free function with our
// custom enum. It will be found via ADL by the compiler if needed.
inline boost::system::error_code make_error_code(TUN2SOCKSErrorCode e) {
    return {static_cast<int>(e), TUN2SOCKSCategory()};
}

#endif  // LIBSOCKS5_ERROR_CODE_H
