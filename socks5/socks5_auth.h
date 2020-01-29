#ifndef LIBSOCKS5_SOCKS5_AUTH_H
#define LIBSOCKS5_SOCKS5_AUTH_H

#include <string>
#include <utility>
#include "socks5/socks5.h"

namespace toys {
namespace socks5 {
class AuthMethod {
   public:
    AuthMethod(Method method) : method_(method) {}
    Method Type() { return method_; }
    virtual ~AuthMethod() {}

   protected:
    Method method_;
};

struct NoAuth : public AuthMethod {
    NoAuth() : AuthMethod(Method::NOAUTH) {}
};

struct UsernamePasswordAuth : public AuthMethod {
   public:
    friend void swap(UsernamePasswordAuth& lhs, UsernamePasswordAuth& rhs);

    UsernamePasswordAuth(std::string username, std::string password)
        : AuthMethod(Method::USRNAME_PASSWORD),
          username_(std::move(username)),
          password_(std::move(password)) {}
    UsernamePasswordAuth(const UsernamePasswordAuth& o)
        : UsernamePasswordAuth(o.username_, o.password_) {}
    UsernamePasswordAuth(UsernamePasswordAuth&& o) : AuthMethod(o.method_) {
        swap(*this, o);
    }
    UsernamePasswordAuth& operator=(UsernamePasswordAuth o) {
        swap(*this, o);
        return *this;
    }
    virtual ~UsernamePasswordAuth() {}

    std::string Username() { return username_; }
    std::string Password() { return password_; }

   private:
    std::string username_;
    std::string password_;
};

inline void swap(UsernamePasswordAuth& lhs, UsernamePasswordAuth& rhs) {
    using std::swap;
    swap(lhs.method_, rhs.method_);
    swap(lhs.username_, rhs.username_);
    swap(lhs.password_, rhs.password_);
}
}  // namespace socks5
}  // namespace toys
#endif  // LIBSOCKS5_SOCKS5_AUTH_H
