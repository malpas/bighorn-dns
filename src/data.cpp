#include "data.hpp"

#include <algorithm>
#include <sstream>
#include <utility>

namespace bighorn {

const int PointerJumpLimit = 100;

std::vector<uint8_t> Header::bytes() const {
    uint16_t const meta = qr << 15 | static_cast<uint16_t>(opcode) << 11 |
                          aa << 10 | tc << 9 | rd << 8 | ra << 7 | z << 4 |
                          static_cast<uint16_t>(rcode);

    std::vector<uint8_t> bytes(12);
    auto *data = reinterpret_cast<uint16_t *>(bytes.data());
    data[0] = htons(id);
    data[1] = htons(meta);
    data[2] = htons(qdcount);
    data[3] = htons(ancount);
    data[4] = htons(nscount);
    data[5] = htons(arcount);
    return bytes;
}

std::vector<uint8_t> Rr::bytes() const {
    std::vector<uint8_t> bytes;
    size_t required_size = 0;
    for (const auto &label : labels) {
        required_size += 1 + label.length();
    }
    required_size += 10;
    required_size += rdata.size();
    bytes.reserve(required_size);
    for (const auto &label : labels) {
        bytes.push_back(static_cast<uint8_t>(label.length()));
        for (const auto &c : label) {
            bytes.push_back(c);
        }
    }
    bytes.push_back(0);

    auto utype = htons(static_cast<uint16_t>(rtype));
    auto ucls = htons(static_cast<uint16_t>(rclass));
    bytes.push_back(utype & 0xFF);
    bytes.push_back(utype >> 8);
    bytes.push_back(ucls & 0xFF);
    bytes.push_back(ucls >> 8);

    uint32_t const uttl = htonl(ttl);
    bytes.push_back(uttl & 0xFF);
    bytes.push_back(uttl >> 8 & 0xFF);
    bytes.push_back(uttl >> 16 & 0xFF);
    bytes.push_back(uttl >> 24);

    uint16_t const rdlength = htons(static_cast<uint16_t>(rdata.size()));
    bytes.push_back(rdlength & 0xFF);
    bytes.push_back(rdlength >> 8);
    for (const auto &c : rdata) {
        bytes.push_back(c);
    }
    return bytes;
}

Rr Rr::a_record(Labels labels, uint32_t ip, uint32_t ttl) {
    std::vector<uint8_t> rdata;
    rdata.push_back(static_cast<char>(ip >> 24 & 0xFF));
    rdata.push_back(static_cast<char>(ip >> 16 & 0xFF));
    rdata.push_back(static_cast<char>(ip >> 8 & 0xFF));
    rdata.push_back(static_cast<char>(ip & 0xFF));
    return Rr{.labels = std::move(labels),
              .rtype = RrType::A,
              .rclass = RrClass::In,
              .ttl = ttl,
              .rdata = rdata};
}

Rr Rr::aaaa_record(Labels labels, std::array<uint8_t, 16> ip, uint32_t ttl) {
    return Rr{.labels = std::move(labels),
              .rtype = RrType::Aaaa,
              .rclass = RrClass::In,
              .ttl = ttl,
              .rdata = std::vector<uint8_t>(ip.begin(), ip.end())};
}

Rr Rr::mx_record(Labels labels, uint16_t preference, Labels exchange,
                 uint32_t ttl, RrClass rclass) {
    std::vector<uint8_t> data;
    preference = htons(preference);
    data.push_back(preference & 0xFF);
    data.push_back(preference >> 8 & 0xFF);
    for (auto &ex_label : exchange) {
        data.push_back(ex_label.size());
        std::copy(ex_label.begin(), ex_label.end(), std::back_inserter(data));
    }
    data.push_back(0);
    return Rr{.labels = std::move(labels),
              .rtype = RrType::Mx,
              .rclass = rclass,
              .ttl = ttl,
              .rdata = data};
}

Rr Rr::ns_record(Labels labels, Labels authority_labels, uint32_t ttl,
                 RrClass rclass) {
    std::vector<uint8_t> rdata;
    for (std::string &label : authority_labels) {
        rdata.push_back(static_cast<char>(label.length()));
        std::copy(label.begin(), label.end(), std::back_inserter(rdata));
    }
    rdata.push_back(0);
    return Rr{.labels = std::move(labels),
              .rtype = RrType::Ns,
              .rclass = rclass,
              .ttl = ttl,
              .rdata = rdata};
}

Rr Rr::cname_record(Labels labels, Labels cname, uint32_t ttl, RrClass rclass) {
    std::vector<uint8_t> rdata;
    for (std::string &label : cname) {
        rdata.push_back(static_cast<char>(label.length()));
        std::copy(label.begin(), label.end(), std::back_inserter(rdata));
    }
    rdata.push_back(0);
    return Rr{.labels = std::move(labels),
              .rtype = RrType::Cname,
              .rclass = rclass,
              .ttl = ttl,
              .rdata = rdata};
}

Rr Rr::hinfo_record(Labels labels, std::string cpu, std::string os,
                    uint32_t ttl, RrClass rclass) {
    std::vector<uint8_t> rdata;
    rdata.push_back(static_cast<uint8_t>(cpu.length()));
    std::copy(cpu.begin(), cpu.end(), std::back_inserter(rdata));
    rdata.push_back(static_cast<uint8_t>(os.length()));
    std::copy(os.begin(), os.end(), std::back_inserter(rdata));
    return Rr{.labels = std::move(labels),
              .rtype = RrType::Hinfo,
              .rclass = rclass,
              .ttl = ttl,
              .rdata = rdata};
}

std::vector<uint8_t> Question::bytes() const {
    std::vector<uint8_t> bytes;
    size_t required_size = 0;
    for (const auto &label : labels) {
        required_size += 1 + label.length();
    }
    required_size += 8;
    bytes.reserve(required_size);
    for (const auto &label : labels) {
        bytes.push_back(static_cast<uint8_t>(label.length()));
        for (const auto &c : label) {
            bytes.push_back(c);
        }
    }
    bytes.push_back(0);

    uint16_t const utype = htons(static_cast<uint16_t>(qtype));
    uint16_t const ucls = htons(static_cast<uint16_t>(qclass));
    bytes.push_back(utype & 0xFF);
    bytes.push_back(utype >> 8);
    bytes.push_back(ucls & 0xFF);
    bytes.push_back(ucls >> 8);
    return bytes;
}

std::vector<uint8_t> Message::bytes() const {
    Header counted_header = header;
    counted_header.qdcount = questions.size();
    counted_header.ancount = answers.size();
    counted_header.nscount = authorities.size();
    counted_header.arcount = additional.size();

    auto bytes = std::vector<uint8_t>();
    auto header_bytes = counted_header.bytes();
    std::copy(header_bytes.begin(), header_bytes.end(),
              std::back_inserter(bytes));
    for (const auto &question : questions) {
        auto question_bytes = question.bytes();
        std::copy(question_bytes.begin(), question_bytes.end(),
                  std::back_inserter(bytes));
    }
    for (const auto &answer : answers) {
        auto answer_bytes = answer.bytes();
        std::copy(answer_bytes.begin(), answer_bytes.end(),
                  std::back_inserter(bytes));
    }
    for (const auto &authority : authorities) {
        auto auth_bytes = authority.bytes();
        std::copy(auth_bytes.begin(), auth_bytes.end(),
                  std::back_inserter(bytes));
    }
    for (const auto &add : additional) {
        auto add_bytes = add.bytes();
        std::copy(add_bytes.begin(), add_bytes.end(),
                  std::back_inserter(bytes));
    }
    return bytes;
}

std::string labels_to_string(std::span<std::string const> labels) {
    if (labels.empty()) {
        return "";
    }
    std::stringstream ss;
    for (size_t i = 0; i < labels.size() - 1; ++i) {
        ss << labels[i];
        ss << ".";
    }
    ss << labels.back();
    return ss.str();
}

std::error_code check_label(const std::string &label) {
    if (std::isalnum(label[0]) == 0) {
        return MessageError::InvalidLabelChar;
    }
    if (std::isalnum(label[label.size() - 1]) == 0) {
        return MessageError::InvalidLabelChar;
    }
    if (std::any_of(label.begin(), label.end(),
                    [](char c) { return std::isalnum(c) == 0 && c != '-'; })) {
        return MessageError::InvalidLabelChar;
    }
    return {};
}

std::error_code read_labels(DataBuffer &buffer,
                            std::vector<std::string> &labels) {
    int total_len = 0;
    int jumps = 0;
    uint8_t label_len = 0;
    size_t buffer_end_i = buffer.pos();
    do {
        if (jumps > PointerJumpLimit) {
            return MessageError::JumpLimit;
        }
        auto err = buffer.read_byte(label_len);
        if (err) {
            return err;
        }
        if (jumps == 0) {
            buffer_end_i += 1;
        }
        if (label_len >> 6 == 0b11) {  // Next byte is continuation of pointer
            uint16_t offset = (label_len & 0b00111111) << 8;
            uint8_t second_byte;
            err = buffer.read_byte(second_byte);
            if (err) {
                return err;
            }
            offset |= second_byte;
            buffer.seek(offset);
            ++jumps;
            buffer_end_i += 1;
            continue;
        }
        total_len += label_len;
        if (label_len == 0) {
            break;
        }

        if (label_len > 63) {
            return MessageError::LabelTooLong;
        }
        if (total_len > 255) {
            return MessageError::NameTooLong;
        }
        std::string label(label_len, '\0');
        err = buffer.read_n(label_len, label.data());
        if (jumps == 0) {
            buffer_end_i += label_len;
        }
        if (err) {
            return err;
        }
        err = check_label(label);
        if (err) {
            return err;
        }
        labels.push_back(label);
    } while (label_len > 0);

    buffer.seek(buffer_end_i);
    return {};
}

std::error_code read_rr(DataBuffer &buffer, Rr &rr) {
    std::error_code err;

    err = read_labels(buffer, rr.labels);
    if (err) {
        return err;
    }

    uint16_t bytes = 0;
    err = buffer.read_number(bytes);
    if (err) {
        return err;
    }
    rr.rtype = static_cast<RrType>(bytes);

    err = buffer.read_number(bytes);
    if (err) {
        return err;
    }
    rr.rclass = static_cast<RrClass>(bytes);

    err = buffer.read_number(rr.ttl);
    if (err) {
        return err;
    }

    uint16_t rdlength = 0;
    err = buffer.read_number(rdlength);
    rr.rdata.resize(rdlength);
    if (err) {
        return err;
    }
    err = buffer.read_n(rdlength, rr.rdata.data());
    return err;
}

std::error_code read_header(DataBuffer &stream, Header &header) {
    std::error_code err;
    err = stream.read_number(header.id);
    if (err) {
        return err;
    }

    uint16_t meta = 0;
    err = stream.read_number(meta);
    if (err) {
        return err;
    }
    header.qr = meta >> 15 & 1;
    header.opcode = static_cast<Opcode>(meta >> 11 & 0b1111);
    header.aa = meta >> 10 & 1;
    header.tc = meta >> 9 & 1;
    header.rd = meta >> 8 & 1;
    header.ra = meta >> 7 & 1;
    header.z = meta >> 4 & 0b111;
    header.rcode = static_cast<ResponseCode>(meta & 0b1111);

    err = stream.read_number(header.qdcount);
    if (err) {
        return err;
    }
    err = stream.read_number(header.ancount);
    if (err) {
        return err;
    }
    err = stream.read_number(header.nscount);
    if (err) {
        return err;
    }
    err = stream.read_number(header.arcount);
    if (err) {
        return err;
    }
    return {};
}

std::error_code read_question(DataBuffer &buffer, Question &question) {
    std::vector<std::string> labels;
    auto err = read_labels(buffer, labels);
    if (err) {
        return err;
    }
    uint16_t qtype = 0;
    uint16_t qclass = 0;
    err = buffer.read_number(qtype);
    if (err) {
        return err;
    }
    err = buffer.read_number(qclass);
    if (err) {
        return err;
    }
    question = Question{.labels = std::move(labels),
                        .qtype = static_cast<RrType>(qtype),
                        .qclass = static_cast<RrClass>(qclass)};
    return {};
}

std::error_code read_message(DataBuffer &buffer, Message &message) {
    auto err = read_header(buffer, message.header);
    if (err) {
        return err;
    }
    auto qdcount = message.header.qdcount;
    for (size_t i = 0; i < qdcount; ++i) {
        Question q;
        err = read_question(buffer, q);
        if (err) {
            return err;
        }
        message.questions.push_back(q);
    }
    for (size_t i = 0; i < message.header.ancount; ++i) {
        Rr rr;
        err = read_rr(buffer, rr);
        if (err) {
            return err;
        }
        message.answers.push_back(rr);
    }
    for (size_t i = 0; i < message.header.nscount; ++i) {
        Rr rr;
        err = read_rr(buffer, rr);
        if (err) {
            return err;
        }
        message.authorities.push_back(rr);
    }
    for (size_t i = 0; i < message.header.arcount; ++i) {
        Rr rr;
        err = read_rr(buffer, rr);
        if (err) {
            return err;
        }
        message.additional.push_back(rr);
    }
    return {};
}

}  // namespace bighorn