#include <gtest/gtest.h>
#include <bighorn/resolver.hpp>

// See section 6.2 of RFC 1034

TEST(StandardQueryTest, Example621)
{
    bighorn::Question question{
        .labels = {"sri-nic", "arpa"}, .qtype = bighorn::DnsType::A, .qclass = bighorn::DnsClass::In};
    bighorn::Rr answer1{.labels = {"sri-nic", "arpa"},
                         .type = bighorn::DnsType::A,
                         .cls = bighorn::DnsClass::In,
                         .ttl = 86400,
                         .rdata = "\x1a\x00\x00\x49"};
    bighorn::Rr answer2{.labels = {"sri-nic", "arpa"},
                         .type = bighorn::DnsType::A,
                         .cls = bighorn::DnsClass::In,
                         .ttl = 86400,
                         .rdata = "\x0a\x00\x00\x33"};
    std::vector<bighorn::Rr> answers{answer1, answer2};
    bighorn::Resolver resolver(answers);
    bighorn::Message msg{.header = {.opcode = bighorn::Opcode::Query}, .questions = {question}};
    auto result = resolver.resolve(msg);
    EXPECT_EQ(result.header.opcode, bighorn::Opcode::Query);
    EXPECT_EQ(result.header.qr, 1);
    EXPECT_EQ(result.header.aa, 1);
    EXPECT_EQ(result.answers, answers);
}