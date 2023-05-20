#include <gtest/gtest.h>
#include <bighorn/hostname_parser.hpp>

TEST(HostnameParserTest, EmptyString)
{
    bighorn::Hostname domain;
    EXPECT_EQ(bighorn::parse_hostname("", domain), bighorn::HostnameError::Empty);
}

TEST(HostnameParserTest, InvalidSymbol)
{
    bighorn::Hostname domain;
    EXPECT_EQ(bighorn::parse_hostname("#", domain), bighorn::HostnameError::InvalidCharacter);
}

TEST(HostnameParserTest, Simple)
{
    bighorn::Hostname domain;
    auto err = bighorn::parse_hostname("example.com", domain);
    ASSERT_FALSE(err);
    ASSERT_EQ(domain.subdomains.size(), 2);
    ASSERT_EQ(domain.subdomains.at(0), "example");
    ASSERT_EQ(domain.subdomains.at(1), "com");
}