#include <gtest/gtest.h>

#include <bighorn/resolver.hpp>

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
TEST(StandardQueryTest, Example621) {
    bighorn::Question question{.labels = {"sri-nic", "arpa"},
                                .qtype = bighorn::DnsType::A,
                                .qclass = bighorn::DnsClass::In};
    auto test_records = get_test_records();
    bighorn::Resolver resolver(test_records);
    bighorn::Message msg{.header = {.opcode = bighorn::Opcode::Query},
                          .questions = {question}};
    auto result = resolver.resolve(msg);
    EXPECT_EQ(result.header.opcode, bighorn::Opcode::Query);
    EXPECT_EQ(result.header.qr, 1);
    EXPECT_EQ(result.header.aa, 1);
    std::vector<bighorn::Rr> answers;
    answers.push_back(test_records[0]);
    answers.push_back(test_records[1]);
    EXPECT_EQ(result.answers, answers);
}

TEST(StandardQueryTest, Example622) {
    bighorn::Question question{.labels = {"sri-nic", "arpa"},
                                .qtype = bighorn::DnsType::All,
                                .qclass = bighorn::DnsClass::In};
    auto test_records = get_test_records();
    bighorn::Resolver resolver(test_records);
    bighorn::Message msg{.header = {.opcode = bighorn::Opcode::Query},
                          .questions = {question}};
    auto result = resolver.resolve(msg);
    EXPECT_EQ(result.header.opcode, bighorn::Opcode::Query);
    EXPECT_EQ(result.header.qr, 1);
    EXPECT_EQ(result.header.aa, 1);
    std::vector<bighorn::Rr> answers;
    answers.push_back(test_records[0]);
    answers.push_back(test_records[1]);
    answers.push_back(test_records[2]);
    answers.push_back(test_records[3]);
    EXPECT_EQ(result.answers, answers);
}

TEST(StandardQueryTest, Example623) {
    bighorn::Question question{.labels = {"sri-nic", "arpa"},
                                .qtype = bighorn::DnsType::Mx,
                                .qclass = bighorn::DnsClass::In};
    auto test_records = get_test_records();
    bighorn::Resolver resolver(test_records);
    bighorn::Message msg{.header = {.opcode = bighorn::Opcode::Query},
                          .questions = {question}};
    auto result = resolver.resolve(msg);
    EXPECT_EQ(result.header.opcode, bighorn::Opcode::Query);
    EXPECT_EQ(result.header.qr, 1);
    EXPECT_EQ(result.header.aa, 1);
    std::vector<bighorn::Rr> answers;
    answers.push_back(test_records[2]);
    EXPECT_EQ(result.answers, answers);
    std::vector<bighorn::Rr> additional;
    additional.push_back(test_records[0]);
    additional.push_back(test_records[1]);
    EXPECT_EQ(result.additional, additional);
}