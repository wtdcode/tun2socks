#ifndef LIBSOCKS5_SOCKS5_CLIENT_H
#define LIBSOCKS5_SOCKS5_CLIENT_H

#ifndef BOOST_COROUTINES_NO_DEPRECATION_WARNING
#define BOOST_COROUTINES_NO_DEPRECATION_WARNING
#endif

#include <boost/asio.hpp>
#include <boost/asio/spawn.hpp>
#include <cstdint>
#include <deque>
#include <functional>
#include <future>
#include <memory>
#include "allocator/allocator.hpp"
#include "socks5/socks5_auth.h"

namespace toys {
namespace socks5 {

class SOCKS5Client {
   public:
    class Delegate {
       public:
        virtual void OnServerConnected() {}
        virtual void OnAuthed() {}
        virtual void OnDestinationConnected() {}
        virtual void OnTCPSent() {}
        virtual void OnTCPReceived(
            const std::shared_ptr<boost::asio::mutable_buffer>& data,
            std::size_t len) {}
        virtual void OnUDPAssociated() {}
        virtual void OnUDPSent() {}
        virtual void OnUDPReceived() {}
        virtual void OnError(const boost::system::system_error&) {}
    };

   public:
    SOCKS5Client(boost::asio::io_context& ctx,
                 Delegate* delegate,
                 boost::asio::ip::tcp::endpoint server_endpoint,
                 boost::asio::ip::tcp::endpoint destination_endpoint,
                 std::shared_ptr<AuthMethod> auth_method,
                 allocator::allocator_fn allocator)
        : tcp_socket_(ctx),
          server_endpoint_(std::move(server_endpoint)),
          destination_endpoint_(std::move(destination_endpoint)),
          udp_socket_(ctx),
          strand_(ctx),
          delegate_(delegate),
          auth_method_(std::move(auth_method)),
          write_queue_(),
          allocator_(std::move(allocator)),
          wait_timer_(ctx),
          read_stopped_(),
          ready_to_send_tcp_data_(false),
          closed(false) {}

    void Start();
    void Stop();

    // Passing by value allows us to manage the life of the data.
    void SendTCPData(std::vector<uint8_t> data);
    // void SendUDPData(std::vector<uint8_t> data);

    boost::asio::ip::tcp::endpoint GetTCPDestination() {
        return this->destination_endpoint_;
    }

   private:
    void startOnSOCKS5Thread(boost::asio::yield_context y);
    bool connectServer(boost::asio::yield_context& y);
    bool connectDestination(boost::asio::yield_context& y);
    bool authClient(boost::asio::yield_context& y);
    void mayCallOnError(const boost::system::system_error& err);
    void clearQueue(boost::asio::yield_context y);
    void doSendTCPData(boost::asio::yield_context y,
                       const std::shared_ptr<std::vector<uint8_t>>& data);
    void doClose();

   private:
    boost::asio::ip::tcp::socket tcp_socket_;
    boost::asio::ip::tcp::endpoint server_endpoint_;
    boost::asio::ip::tcp::endpoint destination_endpoint_;
    boost::asio::ip::udp::socket udp_socket_;
    boost::asio::io_context::strand strand_;
    Delegate* delegate_;
    std::shared_ptr<AuthMethod> auth_method_;
    std::deque<std::vector<uint8_t>> write_queue_;
    allocator::allocator_fn allocator_;
    boost::asio::deadline_timer wait_timer_;
    std::promise<void> read_stopped_;
    bool ready_to_send_tcp_data_;
    bool closed;
};
}  // namespace socks5
}  // namespace toys

#endif  // LIBSOCKS5_SOCKS5_CLIENT_H
