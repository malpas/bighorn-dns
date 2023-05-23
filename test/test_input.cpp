#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <asio.hpp>
#include <bighorn/data.hpp>
#include <istream>
#include <ostream>
#include <sstream>

#include "stream_tester.hpp"

static std::vector<uint8_t> example_rr = {
    '\7', 'e',   'x',    'a',  'm',  'p',  'l',  'e',  '\3',
    'c',  'o',   'm',    '\0', '\0', '\1', '\0', '\1', '\0',
    '\0', '\xe', '\x10', '\0', '\4', '\1', '\2', '\3', '\4'};

static std::vector<uint8_t> example_header = {
    '\0', '\1', 0x86, 0x12, '\0', '\1', '\0',
    '\1', '\0', '\1', '\0', '\1'};  // ID=1, QR=1, OP=0, AA=1, TC=1, RD=0, RA=0,
                                    // Z=1, RCODE=2

TEST(InputTest, EmptyRr) {
    bighorn::Rr rr;
    StreamTester stream_tester({});

    auto err = bighorn::read_rr(stream_tester, rr);
    ASSERT_EQ(err, asio::error::eof);
}

TEST(InputTest, CutShortRr) {
    bighorn::Rr rr;
    StreamTester stream_tester({'\4', 'e', 'x', 'a'});

    auto err = bighorn::read_rr(stream_tester, rr);
    ASSERT_EQ(err, asio::error::eof);
}

TEST(InputTest, FullSimpleRr) {
    bighorn::Rr rr;
    StreamTester stream_tester(example_rr);

    auto err = bighorn::read_rr(stream_tester, rr);
    ASSERT_FALSE(err);
    ASSERT_THAT(rr.labels, testing::ElementsAre("example", "com"));
    EXPECT_EQ(rr.type, bighorn::DnsType::A);
    EXPECT_EQ(rr.cls, bighorn::DnsClass::In);
    EXPECT_EQ(rr.ttl, 3600);
    EXPECT_EQ(rr.rdata, "\1\2\3\4");
}

TEST(InputTest, FullHeader) {
    StreamTester stream_tester(example_header);

    bighorn::Header header;
    auto err = bighorn::read_header(stream_tester, header);
    ASSERT_FALSE(err);
    EXPECT_EQ(header.id, 1);
    EXPECT_EQ(header.qr, 1);
    EXPECT_EQ(header.opcode, bighorn::Opcode::Query);
    EXPECT_EQ(header.aa, 1);
    EXPECT_EQ(header.tc, 1);
    EXPECT_EQ(header.rd, 0);
    EXPECT_EQ(header.ra, 0);
    EXPECT_EQ(header.z, 1);
    EXPECT_EQ(header.rcode, bighorn::ResponseCode::ServerFailure);
}