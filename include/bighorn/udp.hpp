#pragma once
#include <asio.hpp>
#include <iostream>
#ifndef NDEBUG
#include <format>
#endif

#include "responder.hpp"

namespace bighorn {

template <std::derived_from<Lookup> L>
class UdpNameServer {
   public:
    UdpNameServer(asio::io_service &io, int port, Responder<L> responder)
        : socket_(io, asio::ip::udp::endpoint(asio::ip::udp::v6(), port)),
          responder_(std::move(responder)) {
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
    Responder<L> responder_;
    asio::ip::udp::endpoint remote_endpoint_;
    std::array<uint8_t, 512> data_{};

    asio::awaitable<void> handle_recv() {
        auto bytes_recv = co_await socket_.async_receive_from(
            asio::buffer(data_), remote_endpoint_, asio::use_awaitable);
        std::error_code err;
        DataBuffer buffer(data_);
        buffer.limit(bytes_recv);

        Header header;
        err = read_header(buffer, header);
        if (err) {
            header.rcode = ResponseCode::FormatError;
            Message response = Message{.header = header};
            co_await socket_.async_send_to(asio::buffer(response.bytes()),
                                           remote_endpoint_,
                                           asio::use_awaitable);
            co_return;
        }
        std::vector<Question> question_rrs;
        for (int i = 0; i < header.qdcount; ++i) {
            Question question;
            err = read_question(buffer, question);
            if (err) {
                header.rcode = ResponseCode::FormatError;
                Message response = Message{.header = header};
                co_await socket_.async_send_to(asio::buffer(response.bytes()),
                                               remote_endpoint_,
                                               asio::use_awaitable);
                co_return;
            }
            question_rrs.push_back(std::move(question));
        }
        Message request{.header = header, .questions = std::move(question_rrs)};
#ifndef NDEBUG
        std::cout << "Received request\n";
        std::cout << "- Header:\n";
        std::cout << std::format("   QR={} OP={} AA={} TC={} RD={}\n",
                                 static_cast<uint8_t>(request.header.qr),
                                 static_cast<uint8_t>(request.header.opcode),
                                 static_cast<uint8_t>(request.header.aa),
                                 static_cast<uint8_t>(request.header.tc),
                                 static_cast<uint8_t>(request.header.rd));
        if (request.questions.empty()) {
            std::cout << "- No question\n";
        } else {
            auto question = request.questions[0];
            std::cout << "- Question:\n";
            std::cout << std::format("    {}\n",
                                     labels_to_string(question.labels));
            std::cout << std::format("    CLS={} TYPE={}\n",
                                     static_cast<uint8_t>(question.qclass),
                                     static_cast<uint8_t>(question.qtype));
        }
#endif
        Message response = co_await responder_.respond(std::move(request));
        auto response_bytes = response.bytes();
        if (response_bytes.size() > 512) {
            response.header.tc = 1;
            response_bytes.resize(512);
        }
        co_await socket_.async_send_to(asio::buffer(response_bytes),
                                       remote_endpoint_, asio::use_awaitable);
    }
};

}  // namespace bighorn