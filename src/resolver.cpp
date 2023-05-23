#include <algorithm>
#include <resolver.hpp>

namespace bighorn {

Message bighorn::Resolver::resolve(const Message &query) {
    Message response;
    response.header = query.header;
    response.header.qr = 1;
    response.header.aa = 1;
    for (auto &question : query.questions) {
        auto records_ = resolve_question(question);
        std::copy(records_.begin(), records_.end(),
                  std::back_inserter(response.answers));
    }
    return response;
}

bool is_wildcard(std::string s) { return s != "*"; }

std::vector<Rr> Resolver::resolve_question(const Question &question) {
    std::vector<Rr> matching_records;
    for (auto &record : records_) {
        if (record.labels.size() != question.labels.size()) {
            continue;
        }
        for (int i = 0; i < question.labels.size(); ++i) {
            if (record.labels[i] != question.labels[i] &&
                !is_wildcard(record.labels[i])) {
                goto no_match;
            }
        }
        matching_records.push_back(record);
    no_match:;
    }
    return matching_records;
}

}  // namespace bighorn