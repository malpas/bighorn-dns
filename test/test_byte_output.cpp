
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <bighorn/data.hpp>

static bighorn::Rr example_rr =
    bighorn::Rr::a_record({"example", "com"}, 0x7F000001, 3600);

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
    auto bytes = example_header.bytes();
    bighorn::DataBuffer buffer(bytes);

    bighorn::Header header;
    auto err = bighorn::read_header(buffer, header);
    ASSERT_FALSE(err);
    ASSERT_EQ(header, example_header);
}

TEST(ByteOutputTest, RrInOut) {
    auto bytes = example_rr.bytes();
    bighorn::DataBuffer buffer(bytes);

    bighorn::Rr rr;
    auto err = bighorn::read_rr(buffer, rr);
    ASSERT_FALSE(err);
    ASSERT_EQ(rr, example_rr);
}

TEST(ByteOutputTest, ALabel) {
    std::vector<uint8_t> expected_bytes{
        7, 'e', 'x', 'a', 'm',    'p',  'l', 'e',  3,    'c',  'o', 'm',
        0, 1,   0,   1,   0b1110, 0x10, 4,   0x7F, 0x00, 0x00, 0x01};
    auto bytes = example_rr.bytes();
    bighorn::DataBuffer buffer(bytes);

    bighorn::Rr rr;
    auto err = bighorn::read_rr(buffer, rr);
    ASSERT_FALSE(err);
    ASSERT_EQ(rr, example_rr);
}