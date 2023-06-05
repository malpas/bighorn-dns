#include <lookup.hpp>

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
    return true;
}

}  // namespace bighorn