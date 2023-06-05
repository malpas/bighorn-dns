#pragma once
#include <span>

#include "data.hpp"
#include "resolver.hpp"

namespace bighorn {

struct DomainAuthority {
    Labels domain;
    Labels name;
    RrClass rclass = RrClass::In;
    std::vector<uint32_t> ips;
    uint32_t ttl;

    auto operator<=>(const DomainAuthority &) const = default;
};

bool is_label_match(std::span<std::string const> labels, const Rr &candidate);

bool is_authority_match(std::span<std::string const> labels,
                        const DomainAuthority &authority,
                        RrClass rclass = RrClass::In);

struct FoundRecords {
    std::vector<Rr> records;
    std::error_code err;
};

class Lookup {
   public:
    virtual asio::awaitable<FoundRecords> find_records(
        std::span<std::string const> labels, RrType qtype, RrClass qclass,
        bool recursive) = 0;
    virtual std::vector<DomainAuthority> find_authorities(
        std::span<std::string const> labels, RrClass rclass) = 0;
    virtual bool supports_recursion() = 0;
};

}  // namespace bighorn