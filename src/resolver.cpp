#include "resolver.hpp"

#include <atomic>
#include <format>
#include <mutex>
#include <optional>
#include <utility>

namespace bighorn {

using asio::ip::udp;

const int MaxSendCount = 3;

template <class CompletionToken>
auto BasicResolver::async_query_server(const DnsServer& server, Message query,
                                       std::chrono::milliseconds timeout,
                                       CompletionToken&& token) {
    auto init = [&](asio::completion_handler_for<void(
                        Message, std::error_code)> auto completion_handler,
                    const DnsServer& server, Message query) {
        query.header.rd = server.recursive;

        udp::socket socket(io_);
        udp::endpoint endpoint;
        if (std::holds_alternative<Ipv4Type>(server.ip)) {
            endpoint = udp::endpoint(
                asio::ip::address_v4(std::get<Ipv4Type>(server.ip)),
                server.port);
            socket.open(udp::v4());
        } else if (std::holds_alternative<Ipv6Type>(server.ip)) {
            endpoint = udp::endpoint(
                asio::ip::address_v6(std::get<Ipv6Type>(server.ip)),
                server.port);
            socket.open(udp::v6());
        } else {
            throw std::runtime_error("Unknown IP type");
        }

        Message empty_message;
        auto send_future = socket.async_send_to(asio::buffer(query.bytes()),
                                                endpoint, asio::use_future);
        if (send_future.wait_for(timeout) != std::future_status::ready) {
            completion_handler(empty_message, ResolutionError::Timeout);
            return;
        }
        std::array<uint8_t, 512> response{};
        auto read_future = socket.async_receive_from(
            asio::buffer(response), endpoint, asio::use_future);
        if (read_future.wait_for(timeout) != std::future_status::ready) {
            completion_handler(empty_message, ResolutionError::Timeout);
            return;
        }
        auto received_bytes = read_future.get();

        DataBuffer data_buf(response, received_bytes);
        Message message;
        auto err = read_message(data_buf, message);
        if (err) {
            completion_handler(empty_message, err);
            return;
        }
        if (!message.header.qr) {
            completion_handler(empty_message, ResolutionError::InvalidResponse);
            return;
        }
        if (message.header.rcode == ResponseCode::ServerFailure) {
            const std::unique_lock slist_lock(*slist_mutex_);
            auto i = std::find(slist_.begin(), slist_.end(), server);
            slist_.erase(i);

            completion_handler(empty_message, ResolutionError::RemoteFailure);
            return;
        }
        completion_handler(message, std::error_code{});
    };
    return asio::async_initiate<CompletionToken,
                                void(Message, std::error_code)>(init, token,
                                                                server, query);
}

asio::awaitable<Resolution> BasicResolver::resolve(
    std::vector<std::string> labels, RrType qtype, RrClass qclass,
    bool request_recursion, std::chrono::milliseconds timeout) {
    std::vector<Rr> records;

    Question question{.labels = labels, .qtype = qtype, .qclass = qclass};
    Message query{
        .header = Header{.id = 1,
                         .qr = 0,
                         .opcode = Opcode::Query,
                         .aa = 0,
                         .tc = 0,
                         .rd = request_recursion ? static_cast<uint8_t>(1)
                                                 : static_cast<uint8_t>(0),
                         .ra = 0},
        .questions = {question}};

    Message current_query = query;
    DnsServer answering_server;
    int switches_left = 10;
new_cname:
    if (switches_left == 0) {
        throw std::runtime_error("Recursion limit hit");
    }

    std::optional<Message> result;
    std::mutex result_mutex;

    for (int send_count = 0; send_count < MaxSendCount; ++send_count) {
        asio::cancellation_signal found_signal;
        int start_count = 0;
        std::atomic_int finish_count = 0;
        std::atomic_int success_count = 0;
        {
            std::shared_lock const slist_lock(*slist_mutex_);
            for (auto& server : slist_) {
                ++start_count;
                async_query_server(
                    server, current_query, timeout,
                    asio::bind_cancellation_slot(
                        found_signal.slot(),
                        [&](const Message& message, std::error_code err) {
                            ++finish_count;
                            if (err) {
                                return;
                            }
                            std::unique_lock const result_lock(result_mutex);
                            if (result.has_value()) {
                                return;
                            }
                            found_signal.emit(
                                asio::cancellation_type::terminal);
                            result = message;
                            ++success_count;
                        }));
            }
        }
        while (start_count != finish_count && success_count == 0) {
            if (success_count > 0) {
                goto finished;
            }
            asio::steady_timer timer(io_);
            timer.expires_from_now(10ms);
            co_await timer.async_wait(asio::use_awaitable);
        }
    }
finished:
    if (!result.has_value()) {
        throw std::runtime_error("Resolution failed");
    }
    auto message = result.value();
    for (auto& answer : message.answers) {
        if (answer.rtype == RrType::Cname) {
            Labels cname;
            DataBuffer buffer(answer.rdata);
            auto err = read_labels(buffer, cname);
            if (err) {
                throw std::runtime_error("Server returned invalid labels");
            }
            if (current_query.questions.at(0).labels != cname) {
                current_query.questions.at(0).labels = std::move(cname);
            }
            --switches_left;
            goto new_cname;
        }
    }
    std::copy(message.answers.begin(), message.answers.end(),
              std::back_inserter(records));
    co_return Resolution{.records = records, .rcode = message.header.rcode};
}

}  // namespace bighorn