#include <algorithm>
#include <resolver.hpp>

namespace bighorn {

bool is_wildcard(const std::string &s) { return s == "*"; }

bool is_label_match(const std::vector<std::string> &labels,
                    const Rr &candidate) {
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

Message bighorn::Resolver::resolve(const Message &query) {
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

std::vector<Rr> Resolver::resolve_question(const Question &question) {
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

void Resolver::add_additional_records_for_mx(
    const std::vector<std::string> &labels, Message &response) {
    for (auto &record : records_) {
        if (is_label_match(record.labels, record) &&
            record.type == DnsType::A) {
            response.additional.push_back(record);
        }
    }
}

}  // namespace bighorn