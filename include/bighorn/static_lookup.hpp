#pragma once
#include "lookup.hpp"

namespace bighorn {
class StaticLookup : public Lookup {
   public:
    StaticLookup() = default;
    asio::awaitable<FoundRecords> find_records(
        std::span<std::string const> labels, DnsType qtype, DnsClass qclass,
        bool recursive) override;
    std::vector<DomainAuthority> find_authorities(
        std::span<std::string const> labels, DnsClass dclass) override;

    void add_record(Rr record) {
        records_[labels_to_string(record.labels)].push_back(record);
        if (record.labels.at(0) == "*" && record.labels.size() >= 2) {
            wildcard_records_[labels_to_string(record.labels)].push_back(
                record);
        }
    }

    void add_authority(const DomainAuthority& authority) {
        authorities_.push_back(authority);
    }

    bool supports_recursion() override { return false; }

   private:
    std::unordered_map<std::string, std::vector<Rr>> records_;
    std::unordered_map<std::string, std::vector<Rr>> wildcard_records_;
    std::vector<DomainAuthority> authorities_;

    void match_wildcards(std::span<std::string const> labels, DnsType qtype,
                         DnsClass qclass, std::vector<Rr>& matching_records);
};
}  // namespace bighorn