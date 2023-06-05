#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <asio.hpp>
#include <bighorn/buffer.hpp>
#include <bighorn/data.hpp>

TEST(PointerTest, ReadPointerToQuestion) {
    std::vector<uint8_t> pre_bytes{'#', '#', '#', '#'};
    bighorn::Question question{.labels = {"example", "com"},
                                .qtype = bighorn::RrType::A,
                                .qclass = bighorn::RrClass::In};
    auto question_bytes = question.bytes();

    std::vector<uint8_t> message_bytes = pre_bytes;
    std::copy(question_bytes.begin(), question_bytes.end(),
              std::back_inserter(message_bytes));

    std::vector<uint8_t> data = message_bytes;
    data.push_back(0b11000000);  // We'll be reading a pointer that skips the
    data.push_back(4);           // initial "####"

    bighorn::DataBuffer buffer(message_bytes);
    buffer.seek(pre_bytes.size());
    bighorn::Labels labels;
    auto err = bighorn::read_labels(buffer, labels);
    EXPECT_FALSE(err);
    EXPECT_THAT(labels, testing::ElementsAre("example", "com"));
}

TEST(PointerTest, InfinitePointerLoop) {
    std::vector<uint8_t> bytes{0b11000000, 0, 1, 'a', 1, 'b', 0};
    bighorn::Labels labels;
    bighorn::DataBuffer buffer(bytes);
    auto err = bighorn::read_labels(buffer, labels);
    EXPECT_EQ(err, bighorn::MessageError::JumpLimit);
}