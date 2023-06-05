#pragma once
#include <chrono>
#include <future>
#include <shared_mutex>
#include <span>
#include <string>
#include <utility>
#include <variant>
#include <vector>

#include "data.hpp"

namespace bighorn {

using asio::ip::udp;
using namespace std::chrono_literals;

enum class ServerConnMethod { Udp };

struct DnsServer {
    std::variant<Ipv4Type, Ipv6Type> ip;
    int port = 53;
    ServerConnMethod conn_method;
    bool recursive;
    bool operator==(const DnsServer&) const = default;
};

struct Resolution {
    std::vector<Rr> records;
    ResponseCode rcode;
};

class Resolver {
   public:
    virtual asio::awaitable<Resolution> resolve(
        Labels labels, DnsType qtype, DnsClass qclass, bool recursion_desired,
        std::chrono::milliseconds timeout) = 0;
};

class BasicResolver : public Resolver {
   public:
    explicit BasicResolver(asio::io_context& io,
                           std::vector<DnsServer> servers = {})
        : io_(io),
          slist_(std::move(servers)),
          slist_mutex_(std::make_unique<std::shared_mutex>()) {}

    asio::awaitable<Resolution> resolve(
        Labels labels, DnsType qtype, DnsClass qclass, bool recursion_desired,
        std::chrono::milliseconds timeout) override;

   private:
    asio::io_context& io_;
    std::vector<DnsServer> slist_;
    std::unique_ptr<std::shared_mutex> slist_mutex_;

    template <class CompletionToken>
    auto async_query_server(const DnsServer& server, Message query,
                            std::chrono::milliseconds timeout,
                            CompletionToken&& token);
};

}  // namespace bighorn