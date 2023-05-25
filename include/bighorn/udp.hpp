#pragma once
#include <asio.hpp>
#include <memory>

#include "responder.hpp"

namespace bighorn {

class UdpNameServer {
   public:
    UdpNameServer(asio::io_service &io, int port, Responder &&responder)
        : socket_(io, asio::ip::udp::endpoint(asio::ip::udp::v4(), port)),
          responder_(std::move(responder)) {
        port_ = socket_.local_endpoint().port();
    }

    asio::awaitable<void> start();

    int port() { return port_; }

   private:
    asio::ip::udp::socket socket_;
    Responder responder_;
    asio::ip::udp::endpoint remote_endpoint_;
    std::array<char, 512> data_;
    int port_;

    asio::awaitable<void> handle_recv();
};

}  // namespace bighorn