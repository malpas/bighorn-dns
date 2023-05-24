#include <algorithm>
#include <responder.hpp>
#include <set>

namespace bighorn {

bool is_wildcard(const std::string &s) { return s == "*"; }

bool is_label_match(const Labels &labels, const Rr &candidate) {
    if (labels.size() != candidate.labels.size()) {
        return false;
    }
    for (int i = 0; i < labels.size(); ++i) {
        if (labels[i] != candidate.labels[i] && !is_wildcard(labels[i])) {
            return false;
        }
    }
    return true;
}

bool is_authority_match(const Labels &labels,
                        const DomainAuthority &authority) {
    bool match = false;
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

Message bighorn::Responder::respond(const Message &query) {
    Message response;
    response.header = query.header;
    response.header.qr = 1;
    response.header.aa = 1;
    for (auto &question : query.questions) {
        auto records = resolve_question(question);
        std::copy(records.begin(), records.end(),
                  std::back_inserter(response.answers));
        if (question.qtype == DnsType::Mx) {
            add_additional_records_for_mx(question.labels, response);
        }
        if (records.size() == 0) {
            check_authorities(question, response);
        }
        if (records.size() == 0) {
            bool name_exists =
                std::any_of(records_.begin(), records_.end(),
                            std::bind(is_label_match, question.labels,
                                      std::placeholders::_1));
            if (!name_exists) {
                response.header.rcode = ResponseCode::NameError;
            }
        }
    }
    return response;
}

std::vector<Rr> Responder::resolve_question(const Question &question) {
    std::vector<Rr> matching_records;
    for (auto &candidate : records_) {
        if (question.qtype != candidate.type &&
            question.qtype != DnsType::All) {
            continue;
        }
        if (!is_label_match(question.labels, candidate)) {
            continue;
        }
        matching_records.push_back(candidate);
    }
    return matching_records;
}

void Responder::add_additional_records_for_mx(
    const std::vector<std::string> &labels, Message &response) {
    for (auto &record : records_) {
        if (is_label_match(record.labels, record) &&
            record.type == DnsType::A) {
            response.additional.push_back(record);
        }
    }
}

void bighorn::Responder::check_authorities(const Question &question,
                                            Message &response) {
    std::set<DomainAuthority> unique_auths;
    for (auto &authority : authorities_) {
        if (is_authority_match(question.labels, authority) &&
            std::find(unique_auths.begin(), unique_auths.end(), authority) ==
                unique_auths.end()) {
            unique_auths.insert(authority);
        }
    }
    for (auto &authority : unique_auths) {
        auto ns_record =
            Rr::ns_record(authority.domain, authority.name, authority.ttl);
        response.authorities.push_back(ns_record);
        for (auto &ip : authority.ips) {
            auto a_record = Rr::a_record(authority.name, ip, 0);
            response.additional.push_back(a_record);
        }
    }
    if (unique_auths.size() != 0) {
        response.header.aa = 0;
    }
}

}  // namespace bighorn