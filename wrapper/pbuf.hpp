#ifndef TUN2SOCKS_PBUF_HPP
#define TUN2SOCKS_PBUF_HPP

#include <boost/asio/buffer.hpp>
#include <cstdint>
#include "lwip/pbuf.h"

namespace toys {
namespace wrapper {

class pbuf_buffer : public boost::asio::mutable_buffer {
   public:
    pbuf_buffer(pbuf* p)
        : boost::asio::mutable_buffer(p->payload, p->len), p_(p) {}

   private:
    pbuf* p_;
};

}  // namespace wrapper
}  // namespace toys

namespace boost {
namespace asio {
inline const toys::wrapper::pbuf_buffer* buffer_sequence_begin(
    const toys::wrapper::pbuf_buffer& pb) {
    return &pb;
}

inline const toys::wrapper::pbuf_buffer* buffer_sequence_end(
    const toys::wrapper::pbuf_buffer& pb) {
    return &pb;
}
}  // namespace asio
};  // namespace boost

#endif  // TUN2SOCKS_PBUF_HPP
