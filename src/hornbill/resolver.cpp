#include <resolver.hpp>

namespace bighorn
{

Message bighorn::Resolver::resolve(const Message &query)
{
    Message response = query;
    response.header.qr = 1;
    response.header.aa = 1;
    bighorn::Rr answer1{.labels = {"sri-nic", "arpa"},
                         .type = bighorn::DnsType::A,
                         .cls = bighorn::DnsClass::In,
                         .ttl = 86400,
                         .rdata = "\x1a\x00\x00\x49"};
    bighorn::Rr answer2{.labels = {"sri-nic", "arpa"},
                         .type = bighorn::DnsType::A,
                         .cls = bighorn::DnsClass::In,
                         .ttl = 86400,
                         .rdata = "\x0a\x00\x00\x33"};
    std::vector<bighorn::Rr> answers{answer1, answer2};
    response.answers = std::move(answers);
    return response;
}

} // namespace bighorn