#include <static_lookup.hpp>

namespace bighorn {

asio::awaitable<FoundRecords> StaticLookup::find_records(
    std::span<std::string const> labels, RrType qtype, RrClass qclass,
    bool use_recursion) {
    std::vector<Rr> matching_records;
    if (use_recursion) {
        co_return matching_records;
    }
    for (auto &candidate : records_[labels_to_string(labels)]) {
        if (qtype != candidate.rtype && qtype != RrType::All) {
            if (qtype != RrType::A || candidate.rtype != RrType::Cname) {
                continue;
            }
        }
        if (qclass != candidate.rclass) {
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
                                   RrType qtype, RrClass qclass,
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
                return (record.rtype == qtype || qtype == RrType::All) &&
                       record.rclass == qclass;
            });
    }
}

std::vector<DomainAuthority> StaticLookup::find_authorities(
    std::span<std::string const> labels, RrClass rclass) {
    std::vector<DomainAuthority> unique_auths;
    for (auto &authority : authorities_) {
        if (is_authority_match(labels, authority, rclass) &&
            std::find(unique_auths.begin(), unique_auths.end(), authority) ==
                unique_auths.end()) {
            unique_auths.push_back(authority);
        }
    }
    return {unique_auths.begin(), unique_auths.end()};
}

}  // namespace bighorn