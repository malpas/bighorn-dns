#include <static_lookup.hpp>

namespace bighorn {

asio::awaitable<FoundRecords> StaticLookup::find_records(
    std::span<std::string const> labels, DnsType qtype, DnsClass qclass,
    bool use_recursion) {
    std::vector<Rr> matching_records;
    if (use_recursion) {
        co_return matching_records;
    }
    for (auto &candidate : records_[labels_to_string(labels)]) {
        if (qtype != candidate.dtype && qtype != DnsType::All) {
            if (qtype != DnsType::A || candidate.dtype != DnsType::Cname) {
                continue;
            }
        }
        if (qclass != candidate.dclass) {
            continue;
        }
        if (!is_label_match(labels, candidate)) {
            continue;
        }
        matching_records.push_back(candidate);
    }
    if (labels.size() >= 2 && !wildcard_records_.empty()) {
        match_wildcards(labels, qtype, qclass, matching_records);
    }
    co_return FoundRecords{.records = matching_records, .err = {}};
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
                return (record.dtype == qtype || qtype == DnsType::All) &&
                       record.dclass == qclass;
            });
    }
}

std::vector<DomainAuthority> StaticLookup::find_authorities(
    std::span<std::string const> labels, DnsClass dclass) {
    std::vector<DomainAuthority> unique_auths;
    for (auto &authority : authorities_) {
        if (is_authority_match(labels, authority, dclass) &&
            std::find(unique_auths.begin(), unique_auths.end(), authority) ==
                unique_auths.end()) {
            unique_auths.push_back(authority);
        }
    }
    return {unique_auths.begin(), unique_auths.end()};
}

}  // namespace bighorn