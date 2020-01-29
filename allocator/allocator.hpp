#ifndef TUN2SOCKS_ALLOCATOR_HPP
#define TUN2SOCKS_ALLOCATOR_HPP

#include <boost/asio.hpp>
#include <functional>
#include <memory>

namespace toys {
namespace allocator {

typedef std::shared_ptr<boost::asio::mutable_buffer> (*allocator_ptr)(
    std::size_t suggestSize);

typedef std::function<std::remove_pointer_t<allocator_ptr>> allocator_fn;
}  // namespace allocator
}  // namespace toys

#endif  // TUN2SOCKS_ALLOCATOR_HPP
