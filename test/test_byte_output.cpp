
#include "stream_tester.hpp"
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <bighorn/data.hpp>

static bighorn::Rr example_rr = {.labels = {"example", "com"},
                                  .type = bighorn::RrType::HostAddress,
                                  .cls = bighorn::RrClass::Internet,
                                  .ttl = 3600,
                                  .rdata = ""};

static bighorn::Header example_header = {
    .id = 1, .qr = 1, .opcode = 1, .aa = 1, .tc = 1, .rd = 0, .ra = 0, .z = 1, .rcode = 2};

TEST(ByteOutputTest, HeaderInOut)
{
    StreamTester stream_tester(example_header.bytes());

    bighorn::Header header;
    auto err = bighorn::read_header(stream_tester, header);
    ASSERT_FALSE(err);
    EXPECT_EQ(header.id, example_header.id);
    EXPECT_EQ(header.qr, example_header.qr);
    EXPECT_EQ(header.opcode, example_header.opcode);
    EXPECT_EQ(header.aa, example_header.aa);
    EXPECT_EQ(header.tc, example_header.tc);
    EXPECT_EQ(header.rd, example_header.rd);
    EXPECT_EQ(header.ra, example_header.ra);
    EXPECT_EQ(header.z, example_header.z);
    EXPECT_EQ(header.rcode, example_header.rcode);
}

TEST(ByteOutputTest, RrInOut)
{
    StreamTester stream_tester(example_rr.bytes());

    bighorn::Rr rr;
    auto err = bighorn::read_rr(stream_tester, rr);
    ASSERT_FALSE(err);
    ASSERT_THAT(rr.labels, testing::ElementsAreArray(example_rr.labels));
    EXPECT_EQ(rr.cls, example_rr.cls);
    EXPECT_EQ(rr.ttl, example_rr.ttl);
    EXPECT_EQ(rr.rdata, example_rr.rdata);
}