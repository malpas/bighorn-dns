#include <gtest/gtest.h>

#include <bighorn/hostname_parser.hpp>

TEST(HostnameParserTest, EmptyString) {
    bighorn::Hostname domain;
    EXPECT_EQ(bighorn::parse_hostname("", domain),
              bighorn::HostnameError::Empty);
}

TEST(HostnameParserTest, InvalidSymbol) {
    bighorn::Hostname domain;
    EXPECT_EQ(bighorn::parse_hostname("abc#", domain),
              bighorn::HostnameError::InvalidCharacter);
}

TEST(HostnameParserTest, OnlyPeriod) {
    bighorn::Hostname domain;
    auto err = bighorn::parse_hostname(".", domain);
    EXPECT_EQ(err, bighorn::HostnameError::InvalidCharacter);
}

TEST(HostnameParserTest, CutOff) {
    bighorn::Hostname domain;
    auto err = bighorn::parse_hostname("example.", domain);
    EXPECT_EQ(err, bighorn::HostnameError::InvalidCharacter);
}

TEST(HostnameParserTest, OneWord) {
    bighorn::Hostname domain;
    auto err = bighorn::parse_hostname("domain", domain);
    ASSERT_FALSE(err);
}

TEST(HostnameParserTest, LengthLimit) {
    bighorn::Hostname domain;
    auto err = bighorn::parse_hostname(std::string(24, 'a'), domain);
    ASSERT_FALSE(err);

    err = bighorn::parse_hostname(std::string(25, 'a'), domain);
    ASSERT_EQ(err, bighorn::HostnameError::TooLong);
}

TEST(HostnameParserTest, CannotStartWithHyphen) {
    bighorn::Hostname domain;
    auto err = bighorn::parse_hostname("-test.com", domain);
    ASSERT_EQ(err, bighorn::HostnameError::InvalidCharacter);
}

TEST(HostnameParserTest, ExampleCom) {
    bighorn::Hostname domain;
    auto err = bighorn::parse_hostname("example.com", domain);
    ASSERT_FALSE(err);
    ASSERT_EQ(domain.labels.size(), 2);
    EXPECT_EQ(domain.labels.at(0), "example");
    EXPECT_EQ(domain.labels.at(1), "com");
}