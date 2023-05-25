#pragma once
#include <arpa/inet.h>
#include <stdint.h>

#include <array>
#include <asio.hpp>
#include <istream>
#include <memory>
#include <sstream>
#include <string>

#include "buffer.hpp"
#include "error.hpp"
#include "hostname_parser.hpp"

namespace bighorn {

enum class DnsType : uint16_t {
    A = 1,
    Ns = 2,
    Md = 3,
    Mf = 4,
    Cname = 5,
    Soa = 6,
    Mb = 7,
    Mg = 8,
    Mr = 9,
    Null = 10,
    Wks = 11,
    Ptr = 12,
    Hinfo = 13,
    Minfo = 14,
    Mx = 15,
    Txt = 16,
    Axfr = 252,   // QTYPE
    Mailb = 253,  // QTYPE
    MailA = 254,  // QTYPE
    All = 255,    // QTYPE
};

enum class DnsClass : uint16_t { In = 1, Cs = 2, Ch = 3, Hs = 4 };

enum class ResponseCode : uint8_t {
    Ok = 0,
    FormatError = 1,
    ServerFailure = 2,
    NameError = 3,
    NotImplemented = 4,
    Refused = 5
};

using Labels = std::vector<std::string>;

struct Rr {
    std::vector<std::string> labels;
    DnsType type;
    DnsClass cls;
    uint32_t ttl;
    std::string rdata;

    std::vector<uint8_t> bytes() const;
    bool operator==(const Rr &) const = default;

    static Rr a_record(Labels labels, uint32_t ip, uint32_t ttl);
    static Rr ns_record(Labels labels, Labels authority_labels, uint32_t ttl,
                        DnsClass cls = DnsClass::In);
};

template <typename T>
[[nodiscard]] std::error_code read_labels(DataBuffer<T> &buffer,
                                          std::vector<std::string> &labels) {
    uint8_t label_len;
    do {
        auto err = buffer.read_byte(label_len);
        if (err) {
            return err;
        }
        if (label_len == 0) {
            break;
        }
        std::string label(label_len, '\0');
        err = buffer.read_n(label_len, label.data());
        if (err) {
            return err;
        }
        labels.push_back(label);
    } while (label_len > 0);
    return {};
}

template <typename T>
[[nodiscard]] std::error_code read_rr(DataBuffer<T> &buffer, Rr &rr) {
    std::error_code err;

    err = read_labels(buffer, rr.labels);
    if (err) {
        return err;
    }

    uint16_t bytes;
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

    uint16_t rdlength;
    err = buffer.read_number(rdlength);
    rr.rdata = std::string(rdlength, '\0');
    err = buffer.read_n(rdlength, rr.rdata.data());
    return {};
}

enum class Opcode : uint8_t { Query = 0, Iquery = 1, Status = 2 };

struct Header {
    uint16_t id;

    uint16_t qr : 1;
    Opcode opcode : 4;
    uint16_t aa : 1;
    uint16_t tc : 1;
    uint16_t rd : 1;
    uint16_t ra : 1;
    uint16_t z : 3;
    ResponseCode rcode : 4;

    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;

    std::vector<uint8_t> bytes() const;
    bool operator==(const Header &) const = default;
};

template <typename T>
[[nodiscard]] std::error_code read_header(DataBuffer<T> &stream,
                                          Header &header) {
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

struct Question {
    std::vector<std::string> labels;
    DnsType qtype;
    DnsClass qclass;
    auto operator<=>(const Question &) const = default;
    std::vector<uint8_t> bytes() const;
};

template <typename T>
std::error_code read_question(DataBuffer<T> &buffer, Question &question) {
    std::vector<std::string> labels;
    auto err = read_labels(buffer, labels);
    if (err) {
        return err;
    }
    uint16_t qtype;
    uint16_t qclass;
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

struct Message {
    Header header;
    std::vector<Question> questions;
    std::vector<Rr> answers;
    std::vector<Rr> authorities;
    std::vector<Rr> additional;
    bool operator==(const Message &) const = default;
    std::vector<uint8_t> bytes() const;
};

}  // namespace bighorn
