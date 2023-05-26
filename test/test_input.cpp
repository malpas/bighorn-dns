#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <asio.hpp>
#include <bighorn/buffer.hpp>
#include <bighorn/data.hpp>
#include <istream>
#include <ostream>
#include <sstream>

static const std::vector<uint8_t> example_rr = {
    7, 'e', 'x', 'a', 'm', 'p',    'l',    'e', 3, 'c', 'o', 'm', 0, 0,
    1, 0,   1,   0,   0,   '\x0e', '\x10', 0,   4, 1,   2,   3,   4};

static const std::vector<uint8_t> example_header = {
    0, 1, 0x86, 0x12, 0, 1,
    0, 1, 0,    1,    0, 1};  // ID=1, QR=1, OP=0, AA=1, TC=1, RD=0, RA=0,
                              // Z=1, RCODE=2

TEST(InputTest, EmptyRr) {
    std::vector<uint8_t> empty_data;
    bighorn::DataBuffer buffer(&empty_data);

    bighorn::Rr rr;
    auto err = bighorn::read_rr(buffer, rr);
    ASSERT_EQ(err, bighorn::MessageError::ReadError);
}

TEST(InputTest, CutShortRr) {
    std::vector<uint8_t> data{'\4', 'e', 'x', 'a'};
    bighorn::DataBuffer buffer(&data);

    bighorn::Rr rr;
    auto err = bighorn::read_rr(buffer, rr);
    ASSERT_EQ(err, bighorn::MessageError::ReadError);
}

TEST(InputTest, FullSimpleRr) {
    bighorn::Rr rr;
    bighorn::DataBuffer buffer(&example_rr);

    auto err = bighorn::read_rr(buffer, rr);
    ASSERT_FALSE(err);
    ASSERT_THAT(rr.labels, testing::ElementsAre("example", "com"));
    EXPECT_EQ(rr.type, bighorn::DnsType::A);
    EXPECT_EQ(rr.cls, bighorn::DnsClass::In);
    EXPECT_EQ(rr.ttl, 3600);
    EXPECT_EQ(rr.rdata, "\1\2\3\4");
}

TEST(InputTest, FullHeader) {
    bighorn::DataBuffer buffer(&example_header);

    bighorn::Header header;
    auto err = bighorn::read_header(buffer, header);
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

TEST(InputTest, LabelTooLong) {
    static std::vector<uint8_t> long_label = {64};
    for (int i = 0; i < 64; ++i) {
        long_label.push_back('a');
    }
    bighorn::DataBuffer buffer(&long_label);

    std::vector<std::string> labels;
    auto err = bighorn::read_labels(buffer, labels);
    ASSERT_EQ(err, bighorn::MessageError::LabelTooLong);
}

TEST(InputTest, NameTooLong) {
    static std::vector<uint8_t> long_name;
    for (int i = 0; i < 256; ++i) {
        long_name.push_back(1);
        long_name.push_back('a');
    }
    bighorn::DataBuffer buffer(&long_name);

    std::vector<std::string> labels;
    auto err = bighorn::read_labels(buffer, labels);
    ASSERT_EQ(err, bighorn::MessageError::NameTooLong);
}

TEST(InputTest, LabelStartingWithSymbol) {
    static std::vector<uint8_t> invalid_label{4, '-', 'a', 'b', 'c', 0};
    bighorn::DataBuffer buffer(&invalid_label);

    std::vector<std::string> labels;
    auto err = bighorn::read_labels(buffer, labels);
    ASSERT_EQ(err, bighorn::MessageError::InvalidLabelChar);
}

TEST(InputTest, LabelWithInvalidSymbol) {
    static std::vector<uint8_t> invalid_label{4, 'a', '#', 'b', 'c', 0};
    bighorn::DataBuffer buffer(&invalid_label);

    std::vector<std::string> labels;
    auto err = bighorn::read_labels(buffer, labels);
    ASSERT_EQ(err, bighorn::MessageError::InvalidLabelChar);
}

TEST(InputTest, LabelCanHaveNumbers) {
    static std::vector<uint8_t> invalid_label{4, '1', '2', '3', 'a', 0};
    bighorn::DataBuffer buffer(&invalid_label);

    std::vector<std::string> labels;
    auto err = bighorn::read_labels(buffer, labels);
    ASSERT_FALSE(err);
}

TEST(InputTest, LabelCanHaveDash) {
    static std::vector<uint8_t> invalid_label{3, 'a', '-', 'b', 0};
    bighorn::DataBuffer buffer(&invalid_label);

    std::vector<std::string> labels;
    auto err = bighorn::read_labels(buffer, labels);
    ASSERT_FALSE(err);
}

TEST(InputTest, LabelMustEndInAlnum) {
    static std::vector<uint8_t> invalid_label{3, 'a', 'a', '-', 0};
    bighorn::DataBuffer buffer(&invalid_label);

    std::vector<std::string> labels;
    auto err = bighorn::read_labels(buffer, labels);
    ASSERT_EQ(err, bighorn::MessageError::InvalidLabelChar);
}