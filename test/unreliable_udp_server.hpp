#pragma once

#include <asio.hpp>
#include <chrono>
#include <bighorn/lookup.hpp>

class UnreliableUdpNameServer {
   public:
    UnreliableUdpNameServer(asio::io_service &io, int port)
        : socket_(io, asio::ip::udp::endpoint(asio::ip::udp::v6(), port)) {
        std::error_code ignore_err;
        socket_.set_option(asio::ip::v6_only(false), ignore_err);
    }

    asio::awaitable<void> start() {
        try {
            while (true) {
                co_await handle_recv();
            }
        } catch (const std::exception &e) {
            std::cerr << "Exception caught: " << e.what() << "\n";
        }
    }

    int port() { return socket_.local_endpoint().port(); }

   private:
    asio::ip::udp::socket socket_;
    asio::ip::udp::endpoint remote_endpoint_;
    std::array<uint8_t, 512> data_;

    asio::awaitable<void> handle_recv() {
        auto bytes_recv = co_await socket_.async_receive_from(
            asio::buffer(data_), remote_endpoint_, asio::use_awaitable);
        std::error_code err;
        bighorn::DataBuffer buffer(data_);
        buffer.limit(bytes_recv);

        bighorn::Header header;
        err = read_header(buffer, header);
        if (err) {
            header.rcode = bighorn::ResponseCode::FormatError;
            bighorn::Message response{.header = header};
            co_await socket_.async_send_to(asio::buffer(response.bytes()),
                                           remote_endpoint_,
                                           asio::use_awaitable);
            co_return;
        }
        std::vector<bighorn::Question> question_rrs;
        for (int i = 0; i < header.qdcount; ++i) {
            bighorn::Question question;
            err = read_question(buffer, question);
            if (err) {
                header.rcode = bighorn::ResponseCode::FormatError;
                bighorn::Message response{.header = header};
                co_await socket_.async_send_to(asio::buffer(response.bytes()),
                                               remote_endpoint_,
                                               asio::use_awaitable);
                co_return;
            }
            question_rrs.push_back(std::move(question));
        }
        bighorn::Message request{.header = header,
                                  .questions = std::move(question_rrs)};
        asio::io_context io;
        asio::steady_timer timer(io);
        timer.expires_from_now(std::chrono::hours(1));
        io.run();
    }
};