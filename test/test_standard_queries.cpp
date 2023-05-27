#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <bighorn/responder.hpp>

// See section 6.2 of RFC 1034

std::vector<bighorn::Rr> get_test_records() {
    std::vector<bighorn::Rr> records{};
    // Example 6.2.1 && Example 6.2.3
    records.push_back({.labels = {"sri-nic", "arpa"},
                       .type = bighorn::DnsType::A,
                       .cls = bighorn::DnsClass::In,
                       .ttl = 86400,
                       .rdata = "\x1a\x00\x00\x49"});

    records.push_back({.labels = {"sri-nic", "arpa"},
                       .type = bighorn::DnsType::A,
                       .cls = bighorn::DnsClass::In,
                       .ttl = 86400,
                       .rdata = "\x0a\x00\x00\x33"});
    // Example 6.2.2 && Example 6.2.3
    records.push_back({.labels = {"sri-nic", "arpa"},
                       .type = bighorn::DnsType::Mx,
                       .cls = bighorn::DnsClass::In,
                       .ttl = 86400,
                       .rdata = "\x00\x00\x07sri-nic\x04arpa\x00"});
    // Example 6.2.2
    records.push_back({.labels = {"sri-nic", "arpa"},
                       .type = bighorn::DnsType::Hinfo,
                       .cls = bighorn::DnsClass::In,
                       .ttl = 86400,
                       .rdata = "\"DEC-2060.\"TOPS20."});

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
    auto lookup =
        bighorn::StaticLookup(get_test_records(), get_test_authorities());
    return bighorn::Responder<bighorn::StaticLookup>(std::move(lookup));
}

TEST(StandardQueryTest, Example621) {
    auto test_records = get_test_records();
    auto resolver = get_resolver();

    bighorn::Question question{.labels = {"sri-nic", "arpa"},
                                .qtype = bighorn::DnsType::A,
                                .qclass = bighorn::DnsClass::In};
    bighorn::Message msg{.header = {.id = 621,
                                     .qr = 0,
                                     .opcode = bighorn::Opcode::Query,
                                     .aa = 0,
                                     .tc = 0,
                                     .rd = 0,
                                     .ra = 0},
                          .questions = {question}};
    auto result = resolver.respond(msg);
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
                                .qtype = bighorn::DnsType::All,
                                .qclass = bighorn::DnsClass::In};
    bighorn::Message msg{.header = {.id = 622,
                                     .qr = 0,
                                     .opcode = bighorn::Opcode::Query,
                                     .aa = 0,
                                     .tc = 0,
                                     .rd = 0,
                                     .ra = 0},
                          .questions = {question}};
    auto result = resolver.respond(msg);
    EXPECT_EQ(result.header.opcode, bighorn::Opcode::Query);
    EXPECT_EQ(result.header.qr, 1);
    EXPECT_EQ(result.header.aa, 1);
    EXPECT_EQ(result.header.rcode, bighorn::ResponseCode::Ok);
    std::vector<bighorn::Rr> answers;
    answers.push_back(test_records[0]);
    answers.push_back(test_records[1]);
    answers.push_back(test_records[2]);
    answers.push_back(test_records[3]);
    EXPECT_EQ(result.answers, answers);
}

TEST(StandardQueryTest, Example623) {
    auto resolver = get_resolver();
    auto test_records = get_test_records();

    bighorn::Question question{.labels = {"sri-nic", "arpa"},
                                .qtype = bighorn::DnsType::Mx,
                                .qclass = bighorn::DnsClass::In};
    bighorn::Message msg{.header = {.id = 623,
                                     .qr = 0,
                                     .opcode = bighorn::Opcode::Query,
                                     .aa = 0,
                                     .tc = 0,
                                     .rd = 0,
                                     .ra = 0},
                          .questions = {question}};
    auto result = resolver.respond(msg);
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
                                .qtype = bighorn::DnsType::Ns,
                                .qclass = bighorn::DnsClass::In};
    bighorn::Message msg{.header = {.id = 624,
                                     .qr = 0,
                                     .opcode = bighorn::Opcode::Query,
                                     .aa = 0,
                                     .tc = 0,
                                     .rd = 0,
                                     .ra = 0},
                          .questions = {question}};
    auto result = resolver.respond(msg);
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
                                .qtype = bighorn::DnsType::A,
                                .qclass = bighorn::DnsClass::In};
    bighorn::Message msg{.header = {.id = 625,
                                     .qr = 0,
                                     .opcode = bighorn::Opcode::Query,
                                     .aa = 0,
                                     .tc = 0,
                                     .rd = 0,
                                     .ra = 0},
                          .questions = {question}};
    auto result = resolver.respond(msg);
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
                                .qtype = bighorn::DnsType::A,
                                .qclass = bighorn::DnsClass::In};
    bighorn::Message msg{.header = {.id = 626,
                                     .qr = 0,
                                     .opcode = bighorn::Opcode::Query,
                                     .aa = 0,
                                     .tc = 0,
                                     .rd = 0,
                                     .ra = 0},
                          .questions = {question}};

    auto result = resolver.respond(msg);
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