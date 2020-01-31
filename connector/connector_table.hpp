#ifndef TUN2SOCKS_CONNECTOR_TABLE_HPP
#define TUN2SOCKS_CONNECTOR_TABLE_HPP

#include <cstdint>
#include <memory>
#include <mutex>
#include <unordered_map>
#include <utility>
#include "connector/connector.h"

namespace toys {
namespace connector {

// TODO: Break the circular dependency.
class Connector;

class ConnectorTable {
   public:
    static ConnectorTable& Instance() {
        static ConnectorTable table;
        return table;
    }

    std::shared_ptr<Connector> GetConnector(uint32_t id) {
        std::lock_guard<std::recursive_mutex> guard(this->mtx_);
        auto result = this->connections_.find(id);
        if (result == this->connections_.end())
            return {};
        return result->second;
    }

    void EraseConnector(uint32_t id) {
        std::lock_guard<std::recursive_mutex> guard(this->mtx_);
        auto result = this->connections_.find(id);
        if (result == this->connections_.end())
            return;
        this->connections_.erase(result);
    }

    void ClearConnectors() {
        std::lock_guard<std::recursive_mutex> guard(this->mtx_);
        this->connections_.clear();
    }

    template <class... U>
    static std::shared_ptr<Connector> MakeConnector(U&&... u) {
        auto& table = ConnectorTable::Instance();
        std::lock_guard<std::recursive_mutex> guard(table.mtx_);
        auto connector = std::make_shared<Connector>(std::forward<U>(u)...);
        auto id = connector->GetID();
        table.connections_[id] = connector;
        return connector;
    }

   private:
    ConnectorTable() : mtx_(), connections_() {}

   private:
    std::recursive_mutex mtx_;
    std::unordered_map<uint32_t, std::shared_ptr<Connector>> connections_;
};
}  // namespace connector
}  // namespace toys

#endif  // TUN2SOCKS_CONNECTOR_TABLE_HPP
