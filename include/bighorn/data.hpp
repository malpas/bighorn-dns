#pragma once
#include <arpa/inet.h>
#include <stdint.h>

#include <array>
#include <asio.hpp>
#include <istream>
#include <memory>
#include <sstream>
#include <string>

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

struct Rr {
    std::vector<std::string> labels;
    DnsType type;
    DnsClass cls;
    uint32_t ttl;
    std::string rdata;

    std::vector<uint8_t> bytes();
    bool operator==(const Rr &) const = default;
};

namespace {

template <typename SyncReadStream>
[[nodiscard]] std::error_code read_n(SyncReadStream &stream,
                                     asio::streambuf &buf, int n, char *out) {
    if (buf.in_avail() < n) {
        std::error_code asio_err;
        asio::read(stream, buf, asio::transfer_at_least(n - buf.in_avail()),
                   asio_err);
        if (asio_err) {
            return asio_err;
        }
    }
    buf.sgetn(out, n);
    return {};
}

template <typename SyncReadStream>
[[nodiscard]] std::error_code read_byte(SyncReadStream &stream,
                                        asio::streambuf &buf, uint8_t &out) {
    auto err = read_n(stream, buf, 1, reinterpret_cast<char *>(&out));
    if (err) {
        return err;
    }
    return {};
}

template <typename SyncReadStream, typename T>
[[nodiscard]] std::error_code read_number(SyncReadStream &stream,
                                          asio::streambuf &buf, T &out) {
    auto err = read_n(stream, buf, sizeof(T), reinterpret_cast<char *>(&out));
    if (err) {
        return err;
    }
    if constexpr (sizeof(T) == 2) {
        out = ntohs(out);
    } else {
        out = ntohl(out);
    }
    return {};
}

}  // namespace

template <typename SyncReadStream>
[[nodiscard]] std::error_code read_rr(SyncReadStream &stream, Rr &rr) {
    std::error_code asio_err;
    asio::streambuf buf;
    buf.prepare(512);

    uint8_t label_len;
    rr.labels = std::vector<std::string>{};
    do {
        asio_err = read_byte(stream, buf, label_len);
        if (asio_err) {
            return asio_err;
        }
        if (label_len == 0) {
            break;
        }
        std::string label(label_len, '\0');
        asio_err = read_n(stream, buf, label_len, label.data());
        if (asio_err) {
            return asio_err;
        }
        rr.labels.push_back(label);
    } while (label_len > 0);

    uint16_t bytes;
    asio_err = read_number(stream, buf, bytes);
    if (asio_err) {
        return asio_err;
    }
    rr.type = static_cast<DnsType>(bytes);

    asio_err = read_number(stream, buf, bytes);
    if (asio_err) {
        return asio_err;
    }
    rr.cls = static_cast<DnsClass>(bytes);

    asio_err = read_number(stream, buf, rr.ttl);
    if (asio_err) {
        return asio_err;
    }

    uint16_t rdlength;
    asio_err = read_number(stream, buf, rdlength);
    rr.rdata = std::string(rdlength, '\0');
    asio_err = read_n(stream, buf, rdlength, rr.rdata.data());
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

    std::vector<uint8_t> bytes();
    bool operator==(const Header &) const = default;
};

template <typename SyncReadStream>
[[nodiscard]] std::error_code read_header(SyncReadStream &stream,
                                          Header &header) {
    std::error_code asio_err;
    asio::streambuf buf;
    buf.prepare(512);
    asio_err = read_number(stream, buf, header.id);
    if (asio_err) {
        return asio_err;
    }

    uint16_t meta = 0;
    asio_err = read_number(stream, buf, meta);
    if (asio_err) {
        return asio_err;
    }
    header.qr = meta >> 15 & 1;
    header.opcode = static_cast<Opcode>(meta >> 11 & 0b1111);
    header.aa = meta >> 10 & 1;
    header.tc = meta >> 9 & 1;
    header.rd = meta >> 8 & 1;
    header.ra = meta >> 7 & 1;
    header.z = meta >> 4 & 0b111;
    header.rcode = static_cast<ResponseCode>(meta & 0b1111);

    asio_err = read_number(stream, buf, header.qdcount);
    if (asio_err) {
        return asio_err;
    }
    asio_err = read_number(stream, buf, header.ancount);
    if (asio_err) {
        return asio_err;
    }
    asio_err = read_number(stream, buf, header.nscount);
    if (asio_err) {
        return asio_err;
    }
    asio_err = read_number(stream, buf, header.arcount);
    if (asio_err) {
        return asio_err;
    }
    return {};
}

struct Question {
    std::vector<std::string> labels;
    DnsType qtype;
    DnsClass qclass;
    auto operator<=>(const Question &) const = default;
};

struct Message {
    Header header;
    std::vector<Question> questions;
    std::vector<Rr> answers;
    std::vector<Rr> authorities;
    std::vector<Rr> additional;
    bool operator==(const Message &) const = default;
};

}  // namespace bighorn
