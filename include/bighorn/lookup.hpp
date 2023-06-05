#pragma once
#include <span>

#include "data.hpp"
#include "resolver.hpp"

namespace bighorn {

struct DomainAuthority {
    Labels domain;
    Labels name;
    DnsClass dclass = DnsClass::In;
    std::vector<uint32_t> ips;
    uint32_t ttl;

    auto operator<=>(const DomainAuthority &) const = default;
};

bool is_label_match(std::span<std::string const> labels, const Rr &candidate);

bool is_authority_match(std::span<std::string const> labels,
                        const DomainAuthority &authority,
                        DnsClass dclass = DnsClass::In);

struct FoundRecords {
    std::vector<Rr> records;
    std::error_code err;
};

class Lookup {
   public:
    virtual asio::awaitable<FoundRecords> find_records(
        std::span<std::string const> labels, DnsType qtype, DnsClass qclass,
        bool recursive) = 0;
    virtual std::vector<DomainAuthority> find_authorities(
        std::span<std::string const> labels, DnsClass dclass) = 0;
    virtual bool supports_recursion() = 0;
};

}  // namespace bighorn