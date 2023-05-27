#pragma once
#include <memory>
#include <optional>
#include <ranges>
#include <span>
#include <unordered_set>

#include "data.hpp"

namespace bighorn {

struct DomainAuthority {
    Labels domain;
    Labels name;
    DnsClass dclass = DnsClass::In;
    std::vector<uint32_t> ips;
    uint32_t ttl;

    auto operator<=>(const DomainAuthority &) const = default;
};

bool is_wildcard(const std::string &s);

bool is_label_match(std::span<std::string const> labels, const Rr &candidate);

bool is_authority_match(std::span<std::string const> labels,
                        const DomainAuthority &authority,
                        DnsClass dclass = DnsClass::In);

class Lookup {
   public:
    virtual std::vector<Rr> find_records(std::span<std::string const> labels,
                                         DnsType qtype, DnsClass qclass) = 0;
    virtual std::vector<DomainAuthority> find_authorities(
        std::span<std::string const> labels,
        DnsClass dclass = DnsClass::In) = 0;
};

class StaticLookup : public Lookup {
   public:
    StaticLookup() {}
    std::vector<Rr> find_records(std::span<std::string const> labels,
                                 DnsType qtype, DnsClass qclass);
    std::vector<DomainAuthority> find_authorities(
        std::span<std::string const> labels, DnsClass dclass = DnsClass::In);
    bool use_recursive = false;

    void add_record(Rr record) {
        records_[labels_to_string(record.labels)].push_back(record);
    }

    void add_authority(DomainAuthority authority) {
        authorities_.push_back(authority);
    }

   private:
    std::unordered_map<std::string, std::vector<Rr>> records_;
    std::vector<DomainAuthority> authorities_;
};

}  // namespace bighorn