#pragma once
#include <asio/experimental/awaitable_operators.hpp>
#include <memory>
#include <optional>
#include <ranges>
#include <span>
#include <unordered_set>

#include "data.hpp"
#include "resolver.hpp"

namespace bighorn {

using namespace std::chrono_literals;
using namespace asio::experimental::awaitable_operators;

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

class Lookup {
   public:
    virtual asio::awaitable<std::vector<Rr>> find_records(
        std::span<std::string const> labels, DnsType qtype, DnsClass qclass,
        bool recursive = false) = 0;
    virtual std::vector<DomainAuthority> find_authorities(
        std::span<std::string const> labels,
        DnsClass dclass = DnsClass::In) = 0;
    virtual bool supports_recursion() = 0;
};

class StaticLookup : public Lookup {
   public:
    StaticLookup() {}
    asio::awaitable<std::vector<Rr>> find_records(
        std::span<std::string const> labels, DnsType qtype, DnsClass qclass,
        bool recursive = false);
    std::vector<DomainAuthority> find_authorities(
        std::span<std::string const> labels, DnsClass dclass = DnsClass::In);

    void add_record(Rr record) {
        records_[labels_to_string(record.labels)].push_back(record);
        if (record.labels.at(0) == "*" && record.labels.size() >= 2) {
            wildcard_records_[labels_to_string(record.labels)].push_back(
                record);
        }
    }

    void add_authority(DomainAuthority authority) {
        authorities_.push_back(authority);
    }

    bool supports_recursion() { return false; }

   private:
    std::unordered_map<std::string, std::vector<Rr>> records_;
    std::unordered_map<std::string, std::vector<Rr>> wildcard_records_;
    std::vector<DomainAuthority> authorities_;

    void match_wildcards(std::span<std::string const> labels, DnsType qtype,
                         DnsClass qclass, std::vector<Rr> &matching_records);
};

template <std::derived_from<Resolver> R>
class RecursiveLookup : public Lookup {
   public:
    RecursiveLookup(asio::io_context &io, R resolver,
                    std::chrono::milliseconds timeout = 5s)
        : io_(io), resolver_(std::move(resolver)), timeout_(timeout) {}

    asio::awaitable<std::vector<Rr>> find_records(
        std::span<std::string const> labels, DnsType qtype, DnsClass qclass,
        bool recursive = false);

    std::vector<DomainAuthority> find_authorities(std::span<std::string const>,
                                                  DnsClass) {
        return {};
    }

    bool supports_recursion() { return true; }

   private:
    asio::io_context &io_;
    R resolver_;
    std::chrono::milliseconds timeout_;
};

template <std::derived_from<Resolver> R>
inline asio::awaitable<std::vector<Rr>> RecursiveLookup<R>::find_records(
    std::span<std::string const> labels, DnsType qtype, DnsClass qclass,
    bool recursive) {
    Labels label_vec(labels.begin(), labels.end());
    return resolver_.resolve(label_vec, qtype, qclass, recursive, timeout_);
}

}  // namespace bighorn