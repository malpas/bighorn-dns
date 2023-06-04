#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <asio.hpp>
#include <functional>
#include <bighorn/resolver.hpp>
#include <bighorn/responder.hpp>
#include <bighorn/static_lookup.hpp>

using namespace bighorn;

TEST(ResponderTest, RecursionNotSupportedByLookup) {
    asio::io_context io;
    StaticLookup lookup;
    Responder responder(std::move(lookup));

    Question question{
        .labels = {"a", "com"}, .qtype = DnsType::A, .qclass = DnsClass::In};
    Message query{.header = {.id = 100, .opcode = Opcode::Query, .rd = 1},
                  .questions = {question}};
    asio::co_spawn(
        io, responder.respond(query), [&](std::exception_ptr, auto message) {
            EXPECT_EQ(message.header.ra, 0);
            EXPECT_EQ(message.header.rcode, ResponseCode::NotImplemented);
        });
    io.run();
}

class RefusalLookup : public Lookup {
   public:
    asio::awaitable<FoundRecords> find_records(
        std::span<std::string const> /*labels*/, DnsType /*qtype*/,
        DnsClass /*qclass*/, bool /*recursive*/ = false) {
        co_return FoundRecords{.records = {},
                               .err = ResolutionError::RemoteRefused};
    }
    std::vector<DomainAuthority> find_authorities(
        std::span<std::string const> /*labels*/,
        DnsClass /*dclass*/ = DnsClass::In) {
        return {};
    };

    bool supports_recursion() { return true; }
};

TEST(ResponderTest, LookupReturnedRefused) {
    asio::io_context io;
    RefusalLookup lookup;
    bighorn::Responder responder(lookup);

    bighorn::Question question{.labels = {"a", "com"},
                                .qtype = bighorn::DnsType::A,
                                .qclass = bighorn::DnsClass::In};
    bighorn::Message query{
        .header = {.id = 100, .opcode = bighorn::Opcode::Query, .rd = 1},
        .questions = {question}};
    asio::co_spawn(
        io, responder.respond(query), [&](std::exception_ptr, auto message) {
            EXPECT_EQ(message.header.rcode, bighorn::ResponseCode::Refused);
        });
    io.run();
}