#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <bighorn/responder.hpp>
#include <bighorn/static_lookup.hpp>

// See section 6.2 of RFC 1034

std::vector<bighorn::Rr> get_test_records() {
    std::vector<bighorn::Rr> records{};
    // Example 6.2.1 && Example 6.2.3
    records.push_back(
        bighorn::Rr::a_record({"sri-nic", "arpa"}, 0x1a000049, 86400));
    records.push_back(
        bighorn::Rr::a_record({"sri-nic", "arpa"}, 0x0a000033, 86400));

    // Example 6.2.2 && Example 6.2.3
    records.push_back(bighorn::Rr::mx_record({"sri-nic", "arpa"}, 0,
                                              {"sri-nic", "arpa"}, 86400));

    // Example 6.2.2
    records.push_back(bighorn::Rr::hinfo_record({"sri-nic", "arpa"},
                                                 "DEC-2060", "TOPS20", 86400));

    return records;
}

std::vector<bighorn::DomainAuthority> get_test_authorities() {
    std::vector<bighorn::DomainAuthority> authorities{};
    // Example 6.2.6
    auto sri_nic = bighorn::DomainAuthority{.domain = {"mil"},
                                             .name = {"sri-nic", "arpa"},
                                             .ips = {0x1A000049, 0x0A000033},
                                             .ttl = 86400};
    auto a_isi = bighorn::DomainAuthority{.domain = {"mil"},
                                           .name = {"a", "isi", "edu"},
                                           .ips = {0x1A030067},
                                           .ttl = 86400};
    return std::vector<bighorn::DomainAuthority>{sri_nic, a_isi};
}

bighorn::Responder<bighorn::StaticLookup> get_resolver() {
    bighorn::StaticLookup lookup;
    for (auto& record : get_test_records()) {
        lookup.add_record(record);
    }
    for (auto& authority : get_test_authorities()) {
        lookup.add_authority(authority);
    }
    return bighorn::Responder<bighorn::StaticLookup>(std::move(lookup));
}

TEST(StandardQueryTest, Example621) {
    auto test_records = get_test_records();
    auto resolver = get_resolver();

    bighorn::Question question{.labels = {"sri-nic", "arpa"},
                                .qtype = bighorn::RrType::A,
                                .qclass = bighorn::RrClass::In};
    bighorn::Message msg{.header = {.id = 621,
                                     .qr = 0,
                                     .opcode = bighorn::Opcode::Query,
                                     .aa = 0,
                                     .tc = 0,
                                     .rd = 0,
                                     .ra = 0},
                          .questions = {question}};
    asio::io_context io;
    auto future = asio::co_spawn(io, resolver.respond(msg), asio::use_future);
    io.run();
    future.wait();
    auto result = future.get();
    EXPECT_EQ(result.header.opcode, bighorn::Opcode::Query);
    EXPECT_EQ(result.header.qr, 1);
    EXPECT_EQ(result.header.aa, 1);
    EXPECT_EQ(result.header.rcode, bighorn::ResponseCode::Ok);
    std::vector<bighorn::Rr> answers;
    answers.push_back(test_records[0]);
    answers.push_back(test_records[1]);
    EXPECT_EQ(result.answers, answers);
}

TEST(StandardQueryTest, Example622) {
    auto resolver = get_resolver();
    auto test_records = get_test_records();

    bighorn::Question question{.labels = {"sri-nic", "arpa"},
                                .qtype = bighorn::RrType::All,
                                .qclass = bighorn::RrClass::In};
    bighorn::Message msg{.header = {.id = 622,
                                     .qr = 0,
                                     .opcode = bighorn::Opcode::Query,
                                     .aa = 0,
                                     .tc = 0,
                                     .rd = 0,
                                     .ra = 0},
                          .questions = {question}};
    asio::io_context io;
    auto future = asio::co_spawn(io, resolver.respond(msg), asio::use_future);
    io.run();
    future.wait();
    auto result = future.get();
    EXPECT_EQ(result.header.opcode, bighorn::Opcode::Query);
    EXPECT_EQ(result.header.qr, 1);
    EXPECT_EQ(result.header.aa, 1);
    EXPECT_EQ(result.header.rcode, bighorn::ResponseCode::Ok);
    std::vector<bighorn::Rr> answers;
    answers.push_back(test_records[0]);
    answers.push_back(test_records[1]);
    answers.push_back(test_records[2]);
    answers.push_back(test_records[3]);
    EXPECT_THAT(result.answers, testing::UnorderedElementsAreArray(answers));
}

TEST(StandardQueryTest, Example623) {
    auto resolver = get_resolver();
    auto test_records = get_test_records();

    bighorn::Question question{.labels = {"sri-nic", "arpa"},
                                .qtype = bighorn::RrType::Mx,
                                .qclass = bighorn::RrClass::In};
    bighorn::Message msg{.header = {.id = 623,
                                     .qr = 0,
                                     .opcode = bighorn::Opcode::Query,
                                     .aa = 0,
                                     .tc = 0,
                                     .rd = 0,
                                     .ra = 0},
                          .questions = {question}};
    asio::io_context io;
    auto future = asio::co_spawn(io, resolver.respond(msg), asio::use_future);
    io.run();
    future.wait();
    auto result = future.get();
    EXPECT_EQ(result.header.opcode, bighorn::Opcode::Query);
    EXPECT_EQ(result.header.qr, 1);
    EXPECT_EQ(result.header.aa, 1);
    EXPECT_EQ(result.header.rcode, bighorn::ResponseCode::Ok);
    std::vector<bighorn::Rr> answers;
    answers.push_back(test_records[2]);
    EXPECT_EQ(result.answers, answers);
    std::vector<bighorn::Rr> additional;
    additional.push_back(test_records[0]);
    additional.push_back(test_records[1]);
    EXPECT_EQ(result.additional, additional);
}

TEST(StandardQueryTest, Example624) {
    auto resolver = get_resolver();
    auto test_records = get_test_records();

    bighorn::Question question{.labels = {"sri-nic", "arpa"},
                                .qtype = bighorn::RrType::Ns,
                                .qclass = bighorn::RrClass::In};
    bighorn::Message msg{.header = {.id = 624,
                                     .qr = 0,
                                     .opcode = bighorn::Opcode::Query,
                                     .aa = 0,
                                     .tc = 0,
                                     .rd = 0,
                                     .ra = 0},
                          .questions = {question}};
    asio::io_context io;
    auto future = asio::co_spawn(io, resolver.respond(msg), asio::use_future);
    io.run();
    future.wait();
    auto result = future.get();
    EXPECT_EQ(result.header.opcode, bighorn::Opcode::Query);
    EXPECT_EQ(result.header.qr, 1);
    EXPECT_EQ(result.header.aa, 1);
    EXPECT_EQ(result.header.rcode, bighorn::ResponseCode::Ok);
    EXPECT_EQ(result.answers, std::vector<bighorn::Rr>{});
    EXPECT_EQ(result.authorities, std::vector<bighorn::Rr>{});
    EXPECT_EQ(result.additional, std::vector<bighorn::Rr>{});
}

TEST(StandardQueryTest, Example625) {
    // Note: not including negative caching response as this is an optional
    // feature that should be tested separately.

    auto resolver = get_resolver();
    auto test_records = get_test_records();

    bighorn::Question question{.labels = {"sir-nic", "arpa"},
                                .qtype = bighorn::RrType::A,
                                .qclass = bighorn::RrClass::In};
    bighorn::Message msg{.header = {.id = 625,
                                     .qr = 0,
                                     .opcode = bighorn::Opcode::Query,
                                     .aa = 0,
                                     .tc = 0,
                                     .rd = 0,
                                     .ra = 0},
                          .questions = {question}};
    asio::io_context io;
    auto future = asio::co_spawn(io, resolver.respond(msg), asio::use_future);
    io.run();
    future.wait();
    auto result = future.get();
    EXPECT_EQ(result.header.opcode, bighorn::Opcode::Query);
    EXPECT_EQ(result.header.qr, 1);
    EXPECT_EQ(result.header.aa, 1);
    EXPECT_EQ(result.header.rcode, bighorn::ResponseCode::NameError);
    EXPECT_EQ(result.answers, std::vector<bighorn::Rr>{});
    EXPECT_EQ(result.authorities, std::vector<bighorn::Rr>{});
    EXPECT_EQ(result.additional, std::vector<bighorn::Rr>{});
}

TEST(StandardQueryTest, Example626) {
    auto resolver = get_resolver();
    auto labels = std::vector<std::string>{"brl", "mil"};
    bighorn::Question question{.labels = labels,
                                .qtype = bighorn::RrType::A,
                                .qclass = bighorn::RrClass::In};
    bighorn::Message msg{.header = {.id = 626,
                                     .qr = 0,
                                     .opcode = bighorn::Opcode::Query,
                                     .aa = 0,
                                     .tc = 0,
                                     .rd = 0,
                                     .ra = 0},
                          .questions = {question}};

    asio::io_context io;
    auto future = asio::co_spawn(io, resolver.respond(msg), asio::use_future);
    io.run();
    future.wait();
    auto result = future.get();
    ASSERT_EQ(result.header.aa, 0);

    auto ns_records = std::vector<bighorn::Rr>{
        bighorn::Rr::ns_record({"mil"}, {"sri-nic", "arpa"}, 86400),
        bighorn::Rr::ns_record({"mil"}, {"a", "isi", "edu"}, 86400),
    };
    auto a_records = std::vector<bighorn::Rr>{
        bighorn::Rr::a_record({"a", "isi", "edu"}, 0x1A030067, 0),
        bighorn::Rr::a_record({"sri-nic", "arpa"}, 0x1A000049, 0),
        bighorn::Rr::a_record({"sri-nic", "arpa"}, 0x0A000033, 0),
    };
    EXPECT_EQ(result.authorities.size(), 2);
    ASSERT_THAT(result.authorities,
                testing::UnorderedElementsAreArray(ns_records));
    EXPECT_EQ(result.additional.size(), 3);
    ASSERT_THAT(result.additional,
                testing::UnorderedElementsAreArray(a_records));
}