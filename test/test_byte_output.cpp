
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <bighorn/data.hpp>

#include "stream_tester.hpp"

static bighorn::Rr example_rr = {.labels = {"example", "com"},
                                  .type = bighorn::DnsType::A,
                                  .cls = bighorn::DnsClass::In,
                                  .ttl = 3600,
                                  .rdata = ""};

static bighorn::Header example_header = {.id = 1,
                                          .qr = 1,
                                          .opcode = bighorn::Opcode::Query,
                                          .aa = 1,
                                          .tc = 1,
                                          .rd = 0,
                                          .ra = 0,
                                          .z = 1,
                                          .rcode = bighorn::ResponseCode::Ok};

TEST(ByteOutputTest, HeaderInOut) {
    StreamTester stream_tester(example_header.bytes());

    bighorn::Header header;
    auto err = bighorn::read_header(stream_tester, header);
    ASSERT_FALSE(err);
    ASSERT_EQ(header, example_header);
}

TEST(ByteOutputTest, RrInOut) {
    StreamTester stream_tester(example_rr.bytes());

    bighorn::Rr rr;
    auto err = bighorn::read_rr(stream_tester, rr);
    ASSERT_FALSE(err);
    ASSERT_EQ(rr, example_rr);
}