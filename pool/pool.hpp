#ifndef TUN2SOCKS_POOL_HPP
#define TUN2SOCKS_POOL_HPP

#include <array>
#include <thread>
#include "boost/asio/io_context.hpp"

namespace toys {
namespace pool {
template <int ContextNumbers, int ThreadPerContext>
class IOContextPool {
   public:
    IOContextPool() : ctxs_(), threads_(), toStop_(false) {}
    void Start() {
        for (int i = 0; i < ContextNumbers; i++) {
            auto& ctx = this->ctxs_[i];
            for (int j = 0; j < ThreadPerContext; j++) {
                std::thread t(
                    std::bind(&IOContextPool<ContextNumbers,
                                             ThreadPerContext>::ThreadFunc,
                              this, std::ref(ctx)));
                this->threads_[i * ThreadPerContext + j] = std::move(t);
            }
        }
    }
    void Wait() {
        for (auto& thread : this->threads_)
            if (thread.joinable())
                thread.join();
    }
    void Stop() {
        this->toStop_ = true;
        for (auto& ctx : this->ctxs_)
            ctx.stop();
    }
    boost::asio::io_context& getIOContext() {
        static int next = 0;
        auto old_next = next;
        next = (next + 1) % this->ctxs_.size();
        return this->ctxs_[old_next];
    }
    ~IOContextPool() {
        if (!this->toStop_)
            Stop();
    }

   private:
    void ThreadFunc(boost::asio::io_context& ctx) {
        // 1. If there is no more work to do, the io_context::run() will stop
        // and return.
        // 2. When an io_context object is stopped, calls to run(), run_one(),
        // poll() or poll_one() will return immediately without invoking any
        // handlers.
        while (!this->toStop_) {
            boost::asio::executor_work_guard<
                boost::asio::io_context::executor_type>
                guard = boost::asio::make_work_guard(ctx);
            try {
                ctx.restart();
                ctx.run();
            } catch (const boost::system::system_error& err) {
                // let it go ...
            }
        }
    }

   private:
    std::array<boost::asio::io_context, ContextNumbers> ctxs_;
    std::array<std::thread, ContextNumbers * ThreadPerContext> threads_;
    bool toStop_;
};
}  // namespace pool
}  // namespace toys

#endif
