#include "data.hpp"

#include <algorithm>
#include <sstream>

namespace bighorn {

std::vector<uint8_t> Header::bytes() const {
    uint16_t meta = qr << 15 | static_cast<uint16_t>(opcode) << 11 | aa << 10 |
                    tc << 9 | rd << 8 | ra << 7 | z << 4 |
                    static_cast<uint16_t>(rcode);

    std::vector<uint8_t> bytes(12);
    uint16_t *data = reinterpret_cast<uint16_t *>(bytes.data());
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
    for (auto &label : labels) {
        required_size += 1 + label.length();
    }
    required_size += 10;
    required_size += rdata.length();
    bytes.reserve(required_size);
    for (auto &label : labels) {
        bytes.push_back(static_cast<uint8_t>(label.length()));
        for (auto &c : label) {
            bytes.push_back(c);
        }
    }
    bytes.push_back(0);

    uint16_t utype = htons(static_cast<uint16_t>(type));
    uint16_t ucls = htons(static_cast<uint16_t>(cls));
    bytes.push_back(utype & 0xFF);
    bytes.push_back(utype >> 8);
    bytes.push_back(ucls & 0xFF);
    bytes.push_back(ucls >> 8);

    uint32_t uttl = htonl(ttl);
    bytes.push_back(uttl & 0xFF);
    bytes.push_back(uttl >> 8 & 0xFF);
    bytes.push_back(uttl >> 16 & 0xFF);
    bytes.push_back(uttl >> 24);

    uint16_t rdlength = htons(static_cast<uint16_t>(rdata.length()));
    bytes.push_back(rdlength & 0xFF);
    bytes.push_back(rdlength >> 8);
    for (auto &c : rdata) {
        bytes.push_back(c);
    }

    return bytes;
}

Rr Rr::a_record(Labels labels, uint32_t ip, uint32_t ttl) {
    std::string rdata(4, 0);
    rdata[0] = static_cast<char>(ip >> 24 & 0xFF);
    rdata[1] = static_cast<char>(ip >> 16 & 0xFF);
    rdata[2] = static_cast<char>(ip >> 8 & 0xFF);
    rdata[3] = static_cast<char>(ip & 0xFF);
    return Rr{.labels = labels,
              .type = DnsType::A,
              .cls = DnsClass::In,
              .ttl = ttl,
              .rdata = rdata};
}

Rr Rr::aaaa_record(Labels labels, std::array<uint8_t, 16> ip, uint32_t ttl) {
    std::string rdata(16, 0);
    std::memcpy(rdata.data(), ip.data(), 16);
    return Rr{.labels = labels,
              .type = DnsType::Aaaa,
              .cls = DnsClass::In,
              .ttl = ttl,
              .rdata = rdata};
}

Rr Rr::ns_record(Labels labels, Labels authority_labels, uint32_t ttl,
                 DnsClass cls) {
    std::stringstream rdata;
    for (std::string &label : authority_labels) {
        rdata << static_cast<char>(label.length());
        rdata << label;
    }
    rdata << static_cast<char>(0);
    return Rr{.labels = labels,
              .type = DnsType::Ns,
              .cls = cls,
              .ttl = ttl,
              .rdata = std::move(rdata.str())};
}

std::vector<uint8_t> Question::bytes() const {
    std::vector<uint8_t> bytes;
    size_t required_size = 0;
    for (auto &label : labels) {
        required_size += 1 + label.length();
    }
    required_size += 8;
    bytes.reserve(required_size);
    for (auto &label : labels) {
        bytes.push_back(static_cast<uint8_t>(label.length()));
        for (auto &c : label) {
            bytes.push_back(c);
        }
    }
    bytes.push_back(0);

    uint16_t utype = htons(static_cast<uint16_t>(qtype));
    uint16_t ucls = htons(static_cast<uint16_t>(qclass));
    bytes.push_back(utype & 0xFF);
    bytes.push_back(utype >> 8);
    bytes.push_back(ucls & 0xFF);
    bytes.push_back(ucls >> 8);
    return bytes;
}

std::vector<uint8_t> Message::bytes() const {
    auto bytes = std::vector<uint8_t>();
    auto header_bytes = header.bytes();
    std::copy(header_bytes.begin(), header_bytes.end(),
              std::back_inserter(bytes));
    for (auto &question : questions) {
        auto question_bytes = question.bytes();
        std::copy(question_bytes.begin(), question_bytes.end(),
                  std::back_inserter(bytes));
    }
    for (auto &answer : answers) {
        auto answer_bytes = answer.bytes();
        std::copy(answer_bytes.begin(), answer_bytes.end(),
                  std::back_inserter(bytes));
    }
    return bytes;
}

std::error_code read_labels(DataBuffer &buffer,
                            std::vector<std::string> &labels) {
    int total_len = 0;
    uint8_t label_len = 0;
    do {
        auto err = buffer.read_byte(label_len);
        if (err) {
            return err;
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
        if (err) {
            return err;
        }
        if (!std::isalnum(label[0])) {
            return MessageError::InvalidLabelChar;
        }
        if (!std::all_of(label.begin(), label.end(),
                         [](char c) { return std::isalnum(c) || c == '-'; })) {
            return MessageError::InvalidLabelChar;
        }
        if (!std::isalnum(label[label.size() - 1])) {
            return MessageError::InvalidLabelChar;
        }
        labels.push_back(label);
    } while (label_len > 0);
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
    rr.type = static_cast<DnsType>(bytes);

    err = buffer.read_number(bytes);
    if (err) {
        return err;
    }
    rr.cls = static_cast<DnsClass>(bytes);

    err = buffer.read_number(rr.ttl);
    if (err) {
        return err;
    }

    uint16_t rdlength = 0;
    err = buffer.read_number(rdlength);
    rr.rdata = std::string(rdlength, '\0');
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
                        .qtype = static_cast<DnsType>(qtype),
                        .qclass = static_cast<DnsClass>(qclass)};
    return {};
}

}  // namespace bighorn