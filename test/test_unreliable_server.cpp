#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <asio.hpp>
#include <bighorn/recursive_lookup.hpp>
#include <bighorn/resolver.hpp>
#include <bighorn/udp.hpp>
#include <thread>

#include "unreliable_udp_server.hpp"

TEST(UnreliableServerTest, VerySlowServer) {
    asio::io_context io;
    UnreliableUdpNameServer unreliable_server(io, 0);
    asio::cancellation_signal cancel_server;
    std::jthread t1([&] {
        asio::co_spawn(
            io, unreliable_server.start(),
            asio::bind_cancellation_slot(cancel_server.slot(), asio::detached));
        io.run();
    });

    auto server = bighorn::DnsServer{
        .ip = asio::ip::address_v4::from_string("127.0.0.1").to_uint(),
        .port = unreliable_server.port(),
        .conn_method = bighorn::ServerConnMethod::Udp};
    bighorn::RecursiveLookup<bighorn::BasicResolver> test_lookup(
        io, bighorn::BasicResolver(io, {server}),
        std::chrono::milliseconds(100));
    bighorn::Responder<decltype(test_lookup)> responder(
        std::move(test_lookup));
    bighorn::Question question{.labels = {"a", "com"},
                                .qtype = bighorn::DnsType::A,
                                .qclass = bighorn::DnsClass::In};
    bighorn::Message query{
        .header = {.id = 100, .opcode = bighorn::Opcode::Query, .rd = 1},
        .questions = {question}};
    asio::co_spawn(io, responder.respond(query), [&](std::exception_ptr, auto) {
        cancel_server.emit(asio::cancellation_type::terminal);
    });
    io.run();
}