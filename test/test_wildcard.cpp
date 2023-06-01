#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <bighorn/responder.hpp>

TEST(WildcardTest, Basic) {
    bighorn::StaticLookup lookup;
    lookup.add_record(
        bighorn::Rr::a_record({"*", "example", "com"}, 0x00000000, 86400));
    auto responder =
        bighorn::Responder<bighorn::StaticLookup>(std::move(lookup));
    bighorn::Question question{.labels = {"a", "example", "com"},
                                .qtype = bighorn::DnsType::A,
                                .qclass = bighorn::DnsClass::In};
    bighorn::Message msg{.header = {.id = 1,
                                     .qr = 0,
                                     .opcode = bighorn::Opcode::Query,
                                     .aa = 0,
                                     .tc = 0,
                                     .rd = 0,
                                     .ra = 0},
                          .questions = {question}};
    asio::io_context io;
    auto future = asio::co_spawn(io, responder.respond(msg), asio::use_future);
    io.run();
    future.wait();
    auto result = future.get();
    EXPECT_EQ(result.header.opcode, bighorn::Opcode::Query);
    EXPECT_EQ(result.header.qr, 1);
    EXPECT_EQ(result.header.aa, 1);
    EXPECT_EQ(result.header.rcode, bighorn::ResponseCode::Ok);
    EXPECT_EQ(result.header.ancount, 1);
    ASSERT_THAT(result.answers[0].labels,
                testing::ElementsAre("*", "example", "com"));
}

TEST(WildcardTest, MustMatchClass) {
    bighorn::StaticLookup lookup;
    lookup.add_record(bighorn::Rr::mx_record({"*", "example", "com"}, 0,
                                              {"example", "com"}, 86400,
                                              bighorn::DnsClass::Ch));
    auto responder =
        bighorn::Responder<bighorn::StaticLookup>(std::move(lookup));
    bighorn::Question question{.labels = {"a", "example", "com"},
                                .qtype = bighorn::DnsType::Mx,
                                .qclass = bighorn::DnsClass::In};
    bighorn::Message msg{.header = {.id = 1,
                                     .qr = 0,
                                     .opcode = bighorn::Opcode::Query,
                                     .aa = 0,
                                     .tc = 0,
                                     .rd = 0,
                                     .ra = 0},
                          .questions = {question}};
    asio::io_context io;
    auto future = asio::co_spawn(io, responder.respond(msg), asio::use_future);
    io.run();
    future.wait();
    auto result = future.get();
    EXPECT_EQ(result.header.rcode, bighorn::ResponseCode::NameError);
    EXPECT_EQ(result.header.ancount, 0);
}

TEST(WildcardTest, MustMatchType) {
    bighorn::StaticLookup lookup;
    lookup.add_record(bighorn::Rr::mx_record({"*", "example", "com"}, 0,
                                              {"example", "com"}, 86400,
                                              bighorn::DnsClass::In));
    auto responder =
        bighorn::Responder<bighorn::StaticLookup>(std::move(lookup));
    bighorn::Question question{.labels = {"a", "example", "com"},
                                .qtype = bighorn::DnsType::Hinfo,
                                .qclass = bighorn::DnsClass::In};
    bighorn::Message msg{.header = {.id = 1,
                                     .qr = 0,
                                     .opcode = bighorn::Opcode::Query,
                                     .aa = 0,
                                     .tc = 0,
                                     .rd = 0,
                                     .ra = 0},
                          .questions = {question}};
    asio::io_context io;
    auto future = asio::co_spawn(io, responder.respond(msg), asio::use_future);
    io.run();
    future.wait();
    auto result = future.get();
    EXPECT_EQ(result.header.rcode, bighorn::ResponseCode::Ok);
    EXPECT_EQ(result.header.ancount, 0);
}

TEST(WildcardTest, MultipleLabelMatch) {
    bighorn::StaticLookup lookup;
    lookup.add_record(
        bighorn::Rr::a_record({"*", "example", "com"}, 0x00000000, 86400));
    auto responder =
        bighorn::Responder<bighorn::StaticLookup>(std::move(lookup));
    bighorn::Question question{
        .labels = {"a", "b", "c", "d", "example", "com"},
        .qtype = bighorn::DnsType::A,
        .qclass = bighorn::DnsClass::In};
    bighorn::Message msg{.header = {.id = 1,
                                     .qr = 0,
                                     .opcode = bighorn::Opcode::Query,
                                     .aa = 0,
                                     .tc = 0,
                                     .rd = 0,
                                     .ra = 0},
                          .questions = {question}};
    asio::io_context io;
    auto future = asio::co_spawn(io, responder.respond(msg), asio::use_future);
    io.run();
    future.wait();
    auto result = future.get();
    EXPECT_EQ(result.header.opcode, bighorn::Opcode::Query);
    EXPECT_EQ(result.header.qr, 1);
    EXPECT_EQ(result.header.aa, 1);
    EXPECT_EQ(result.header.rcode, bighorn::ResponseCode::Ok);
    EXPECT_EQ(result.header.ancount, 1);
    ASSERT_THAT(result.answers[0].labels,
                testing::ElementsAre("*", "example", "com"));
}