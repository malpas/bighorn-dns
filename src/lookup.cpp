#include <lookup.hpp>
#include <set>

namespace bighorn {

bool is_wildcard(const std::string &s) { return s == "*"; }

bool is_label_match(std::span<std::string const> labels, const Rr &candidate) {
    if (labels.size() != candidate.labels.size()) {
        return false;
    }
    for (size_t i = 0; i < labels.size(); ++i) {
        if (labels[i] != candidate.labels[i] && !is_wildcard(labels[i])) {
            return false;
        }
    }
    return true;
}

bool is_authority_match(const std::span<std::string const> labels,
                        const DomainAuthority &authority,
                        const DnsClass dclass) {
    bool match = false;
    if (authority.dclass != dclass) {
        return false;
    }
    if (authority.domain.size() > labels.size()) {
        return false;
    }
    int i = 0;
    for (auto l = authority.domain.rbegin(); l < authority.domain.rend(); ++l) {
        if (*l != labels[labels.size() - 1 - i]) {
            return false;
        }
        ++i;
    }
    match = true;
    return match;
}

std::vector<Rr> StaticLookup::find_records(std::span<std::string const> labels,
                                           DnsType qtype, DnsClass qclass) {
    std::vector<Rr> matching_records;
    for (auto &candidate : records_) {
        if (qtype != candidate.type && qtype != DnsType::All) {
            continue;
        }
        if (qclass != candidate.cls) {
            continue;
        }
        if (!is_label_match(labels, candidate)) {
            continue;
        }
        matching_records.push_back(candidate);
    }
    return matching_records;
}
std::vector<DomainAuthority> StaticLookup::find_authorities(
    std::span<std::string const> labels, DnsClass dclass) {
    std::set<DomainAuthority> unique_auths;
    for (auto &authority : authorities_) {
        if (is_authority_match(labels, authority, dclass) &&
            std::find(unique_auths.begin(), unique_auths.end(), authority) ==
                unique_auths.end()) {
            unique_auths.insert(authority);
        }
    }
    return std::vector(unique_auths.begin(), unique_auths.end());
}

}  // namespace bighorn