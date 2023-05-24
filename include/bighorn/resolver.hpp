#pragma once
#include <asio.hpp>
#include <unordered_map>
#include <vector>

#include "data.hpp"

namespace bighorn {

struct DomainAuthority {
    Labels domain;
    Labels name;
    std::vector<uint32_t> ips;
    uint32_t ttl;

    auto operator<=>(const DomainAuthority &) const = default;
};

class Resolver {
   public:
    Resolver(std::vector<Rr> records, std::vector<DomainAuthority> authorities)
        : records_(records), authorities_(authorities) {}
    Message resolve(const Message &query);

   private:
    std::vector<Rr> records_;
    std::vector<DomainAuthority> authorities_;
    std::vector<Rr> resolve_question(const Question &);
    void add_additional_records_for_mx(const std::vector<std::string> &labels,
                                       Message &response);
    void check_authorities(const Question &question, Message &response);
};

}  // namespace bighorn