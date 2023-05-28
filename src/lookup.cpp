#include <lookup.hpp>
#include <set>

namespace bighorn {

bool is_label_match(std::span<std::string const> labels, const Rr &candidate) {
    if (labels.size() != candidate.labels.size()) {
        return false;
    }
    for (size_t i = 0; i < labels.size(); ++i) {
        if (labels[i] != candidate.labels[i]) {
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
    for (auto &candidate : records_[labels_to_string(labels)]) {
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
    if (labels.size() >= 2 && wildcard_records_.size() > 0) {
        match_wildcards(labels, qtype, qclass, matching_records);
    }
    return matching_records;
}

void StaticLookup::match_wildcards(std::span<std::string const> labels,
                                   DnsType qtype, DnsClass qclass,
                                   std::vector<Rr> &matching_records) {
    for (size_t i = 1; i < labels.size(); ++i) {
        std::stringstream wild_label;
        wild_label << "*.";
        for (size_t j = i; j < labels.size() - 1; ++j) {
            wild_label << labels[j];
            wild_label << '.';
        }
        wild_label << labels.back();
        auto possible_records = wildcard_records_.find(wild_label.str());
        if (possible_records == wildcard_records_.end()) {
            continue;
        }
        auto record_vec = (*possible_records).second;
        std::copy_if(
            record_vec.begin(), record_vec.end(),
            std::back_inserter(matching_records), [&](auto record) {
                return (record.type == qtype || qtype == DnsType::All) &&
                       record.cls == qclass;
            });
    }
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