#include <buffer.hpp>
#include <format>
#include <functional>
#include <iostream>
#include <memory>
#include <system_error>
#include <udp.hpp>
using asio::ip::udp;

namespace bighorn {

asio::awaitable<void> UdpNameServer::start() {
    try {
        while (true) {
            co_await handle_recv();
        }
    } catch (std::exception e) {
        std::cerr << "Exception caught: " << e.what() << "\n";
    }
}

asio::awaitable<void> UdpNameServer::handle_recv() {
    auto bytes_recv = co_await socket_.async_receive_from(
        asio::buffer(data_), remote_endpoint_, asio::use_awaitable);
    std::error_code err;
    DataBuffer buffer(&data_);
    buffer.limit(bytes_recv);

    Header header;
    err = read_header(buffer, header);
    if (err) {
        std::cerr << "Could not read header\n";
        co_return;
    }
    std::vector<Question> question_rrs;
    for (int i = 0; i < header.qdcount; ++i) {
        Question question;
        err = read_question(buffer, question);
        if (err) {
            std::cerr << "Could not read question";
            co_return;
        }
        question_rrs.push_back(std::move(question));
    }
    Message request{.header = header, .questions = std::move(question_rrs)};
    Message response = responder_.respond(std::move(request));
    auto response_bytes = response.bytes();
    co_await socket_.async_send_to(asio::buffer(response_bytes),
                                   remote_endpoint_, asio::use_awaitable);
}

}  // namespace bighorn