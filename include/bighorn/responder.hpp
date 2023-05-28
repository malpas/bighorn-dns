#pragma once
#include <asio.hpp>

#include "data.hpp"
#include "lookup.hpp"

namespace bighorn {

template <std::derived_from<Lookup> L>
class Responder {
   public:
    Responder(L &&lookup) : lookup_(std::move(lookup)) {}

    Message respond(const Message &query) {
        Message response;
        response.questions = query.questions;
        response.header = query.header;
        response.header.qr = 1;
        response.header.aa = 1;
        for (auto &question : query.questions) {
            auto records = lookup_.find_records(question.labels, question.qtype,
                                                question.qclass);
            std::copy(records.begin(), records.end(),
                      std::back_inserter(response.answers));
            if (question.qtype == DnsType::Mx) {
                add_additional_records_for_mx(question.labels, response);
            }
            if (records.size() == 0) {
                check_authorities(question, response);
            }
            if (response.authorities.size() == 0) {
                auto all_related_records = lookup_.find_records(
                    question.labels, DnsType::All, question.qclass);
                if (all_related_records.size() == 0) {
                    response.header.rcode = ResponseCode::NameError;
                }
            }
        }
        response.header.ancount = response.answers.size();
        response.header.arcount = response.additional.size();
        response.header.qdcount = response.questions.size();
        response.header.nscount = response.authorities.size();
        return response;
    }

   private:
    L lookup_;
    void add_additional_records_for_mx(std::span<std::string const> labels,
                                       Message &response) {
        auto records = lookup_.find_records(labels, DnsType::A, DnsClass::In);
        for (auto &record : records) {
            response.additional.push_back(record);
        }
    }

    void check_authorities(const Question &question, Message &response) {
        auto authorities =
            lookup_.find_authorities(question.labels, question.qclass);
        for (auto &authority : authorities) {
            auto ns_record =
                Rr::ns_record(authority.domain, authority.name, authority.ttl);
            response.authorities.push_back(ns_record);
            for (auto &ip : authority.ips) {
                auto a_record = Rr::a_record(authority.name, ip, 0);
                response.additional.push_back(a_record);
            }
        }
        if (authorities.size() != 0) {
            response.header.aa = 0;
        }
    }
};

}  // namespace bighorn