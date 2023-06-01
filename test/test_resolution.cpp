#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <asio.hpp>
#include <functional>
#include <bighorn/resolver.hpp>
#include <bighorn/udp.hpp>
#include <memory>
#include <thread>

using asio::ip::tcp;
using namespace std::chrono_literals;

bool is_a_record(const bighorn::Rr& record) {
    return record.dtype == bighorn::DnsType::A;
}
bool is_aaaa_record(const bighorn::Rr& record) {
    return record.dtype == bighorn::DnsType::Aaaa;
}

using ServerType = bighorn::UdpNameServer<bighorn::StaticLookup>;

ServerType make_dns_server(asio::io_context& io,
                           std::vector<bighorn::Rr> records) {
    bighorn::StaticLookup lookup;
    for (auto& record : records) {
        lookup.add_record(record);
    }
    bighorn::Responder responder(std::move(lookup));
    ServerType server(io, 0, std::move(responder));
    return server;
}

TEST(ResolutionTest, Simple) {
    auto example_ipv4_record =
        bighorn::Rr::a_record({"abcd", "com"}, 0x01020304, 86400);
    auto example_ipv6_record = bighorn::Rr::aaaa_record(
        {"abcd", "com"}, {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
        86400);
    asio::io_context io;
    auto server =
        make_dns_server(io, {example_ipv4_record, example_ipv6_record});
    asio::cancellation_signal cancel_server;
    std::jthread thread([&] {
        asio::co_spawn(
            io, server.start(),
            asio::bind_cancellation_slot(cancel_server.slot(), asio::detached));
        io.run();
    });

    auto server_ref = bighorn::DnsServer{
        .ip = asio::ip::address_v4::from_string("127.0.0.1").to_uint(),
        .port = server.port(),
        .conn_method = bighorn::ServerConnMethod::Udp};
    bighorn::BasicResolver test_resolver(io, {server_ref});
    bighorn::Labels example{"abcd", "com"};
    asio::co_spawn(io,
                   test_resolver.resolve(example, bighorn::DnsType::All,
                                         bighorn::DnsClass::In),
                   [&](std::exception_ptr, auto records) {
                       std::vector<bighorn::Rr> a_records;
                       std::copy_if(records.begin(), records.end(),
                                    std::back_inserter(a_records), is_a_record);
                       EXPECT_THAT(a_records, testing::UnorderedElementsAre(
                                                  example_ipv4_record));
                       cancel_server.emit(asio::cancellation_type::terminal);
                   });
    io.run();
}

TEST(ResolutionTest, CnameSwitch) {
    auto cname_record =
        bighorn::Rr::cname_record({"alias", "com"}, {"example", "com"}, 86400);
    auto example_record =
        bighorn::Rr::a_record({"example", "com"}, 0x01020304, 86400);
    asio::io_context io;
    auto example_server = make_dns_server(io, {example_record, cname_record});

    asio::cancellation_signal cancel_server;
    std::jthread t([&] {
        asio::co_spawn(
            io, example_server.start(),
            asio::bind_cancellation_slot(cancel_server.slot(), asio::detached));
        io.run();
    });

    auto server = bighorn::DnsServer{
        .ip = asio::ip::address_v4::from_string("127.0.0.1").to_uint(),
        .port = example_server.port(),
        .conn_method = bighorn::ServerConnMethod::Udp};
    bighorn::BasicResolver test_resolver(io, {server});
    bighorn::Labels example{"alias", "com"};
    asio::co_spawn(io,
                   test_resolver.resolve(example, bighorn::DnsType::All,
                                         bighorn::DnsClass::In),
                   [&](std::exception_ptr, auto records) {
                       std::vector<bighorn::Rr> a_records;
                       std::copy_if(records.begin(), records.end(),
                                    std::back_inserter(a_records), is_a_record);
                       EXPECT_THAT(a_records, testing::UnorderedElementsAre(
                                                  example_record));
                       cancel_server.emit(asio::cancellation_type::terminal);
                   });
    io.run();
}

TEST(ResolutionTest, NoInfiniteRecursion) {
    asio::io_context io;
    bighorn::StaticLookup lookup;
    auto cname_a =
        bighorn::Rr::cname_record({"a", "com"}, {"b", "com"}, 86400);
    auto cname_b =
        bighorn::Rr::cname_record({"b", "com"}, {"a", "com"}, 86400);
    auto example_server = make_dns_server(io, {cname_a, cname_b});
    asio::cancellation_signal cancel_server;

    std::jthread t([&] {
        asio::co_spawn(
            io, example_server.start(),
            asio::bind_cancellation_slot(cancel_server.slot(), asio::detached));
        io.run();
    });

    auto server = bighorn::DnsServer{
        .ip = asio::ip::address_v4::from_string("127.0.0.1").to_uint(),
        .port = example_server.port(),
        .conn_method = bighorn::ServerConnMethod::Udp};
    bighorn::BasicResolver test_resolver(io, {server});
    bighorn::Labels example{"a", "com"};
    asio::co_spawn(io,
                   test_resolver.resolve(example, bighorn::DnsType::All,
                                         bighorn::DnsClass::In),
                   [&](std::exception_ptr, auto) {
                       cancel_server.emit(asio::cancellation_type::terminal);
                   });
    io.run();
}

TEST(ResolutionTest, ResponderWithRecursiveLookup) {
    asio::io_context io;
    bighorn::StaticLookup lookup;
    auto cname_a =
        bighorn::Rr::cname_record({"a", "com"}, {"b", "com"}, 86400);
    auto b_record = bighorn::Rr::a_record({"b", "com"}, 0x01020304, 86400);
    auto example_server = make_dns_server(io, {cname_a, b_record});

    asio::cancellation_signal cancel_server;
    std::jthread t1([&] {
        asio::co_spawn(
            io, example_server.start(),
            asio::bind_cancellation_slot(cancel_server.slot(), asio::detached));
        io.run();
    });

    auto server = bighorn::DnsServer{
        .ip = asio::ip::address_v4::from_string("127.0.0.1").to_uint(),
        .port = example_server.port(),
        .conn_method = bighorn::ServerConnMethod::Udp};
    bighorn::RecursiveLookup<bighorn::BasicResolver> test_lookup(
        io, bighorn::BasicResolver(io, {server}));
    bighorn::Responder<decltype(test_lookup)> responder(
        std::move(test_lookup));
    bighorn::Question question{.labels = {"a", "com"},
                                .qtype = bighorn::DnsType::A,
                                .qclass = bighorn::DnsClass::In};
    bighorn::Message query{
        .header = {.id = 100, .opcode = bighorn::Opcode::Query, .rd = 1},
        .questions = {question}};
    asio::co_spawn(
        io, responder.respond(query), [&](std::exception_ptr, auto message) {
            cancel_server.emit(asio::cancellation_type::terminal);
            EXPECT_THAT(message.header.ra, 1);
            EXPECT_THAT(message.answers, testing::ElementsAre(b_record));
        });
    io.run();
}

TEST(ResolutionTest, RecursionNotSupportedByLookup) {
    asio::io_context io;
    bighorn::StaticLookup lookup;
    bighorn::Responder responder(std::move(lookup));

    bighorn::Question question{.labels = {"a", "com"},
                                .qtype = bighorn::DnsType::A,
                                .qclass = bighorn::DnsClass::In};
    bighorn::Message query{
        .header = {.id = 100, .opcode = bighorn::Opcode::Query, .rd = 1},
        .questions = {question}};
    asio::co_spawn(io, responder.respond(query),
                   [&](std::exception_ptr, auto message) {
                       EXPECT_EQ(message.header.ra, 0);
                       EXPECT_EQ(message.header.rcode,
                                 bighorn::ResponseCode::NotImplemented);
                   });
    io.run();
}

// TODO Test one unreliable server timeout
// TODO Test only one server selected