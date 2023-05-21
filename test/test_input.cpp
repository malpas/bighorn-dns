#include <asio.hpp>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <bighorn/rr.hpp>
#include <istream>
#include <ostream>
#include <sstream>

#include "stream_tester.hpp"

static std::vector<uint8_t> example1 = {'\7', 'e',   'x',    'a',  'm',  'p',  'l',  'e',  '\3',
                                        'c',  'o',   'm',    '\0', '\0', '\1', '\0', '\1', '\0',
                                        '\0', '\xe', '\x10', '\0', '\4', '\1', '\2', '\3', '\4'};

TEST(RrTest, EmptyRr)
{
    bighorn::Rr rr;
    StreamTester stream_tester({});

    auto err = bighorn::read_rr(stream_tester, rr);
    ASSERT_EQ(err, asio::error::eof);
}

TEST(RrTest, CutShort)
{
    bighorn::Rr rr;
    StreamTester stream_tester({'e', 'x', 'a'});

    auto err = bighorn::read_rr(stream_tester, rr);
    ASSERT_EQ(err, asio::error::eof);
}

TEST(RrTest, FullSimple)
{
    bighorn::Rr rr;
    StreamTester stream_tester(example1);

    auto err = bighorn::read_rr(stream_tester, rr);
    ASSERT_FALSE(err);
    ASSERT_THAT(rr.labels, testing::ElementsAre("example", "com"));
    EXPECT_EQ(rr.type, bighorn::RrType::HostAddress);
    EXPECT_EQ(rr.cls, bighorn::RrClass::Internet);
    EXPECT_EQ(rr.ttl, 3600);
    EXPECT_EQ(rr.rdata, "\1\2\3\4");
}