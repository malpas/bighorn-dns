#pragma once

#ifdef _WIN32
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#endif

#include <array>
#include <asio.hpp>
#include <cstdint>
#include <sstream>
#include <string>

#include "buffer.hpp"
#include "error.hpp"

namespace bighorn {

enum class RrType : uint16_t {
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
    Aaaa = 28,
    Axfr = 252,   // QTYPE
    Mailb = 253,  // QTYPE
    MailA = 254,  // QTYPE
    All = 255,    // QTYPE
};

enum class RrClass : uint16_t { In = 1, Cs = 2, Ch = 3, Hs = 4 };

enum class ResponseCode : uint8_t {
    Ok = 0,
    FormatError = 1,
    ServerFailure = 2,
    NameError = 3,
    NotImplemented = 4,
    Refused = 5
};

using Labels = std::vector<std::string>;

using Ipv4Type = uint32_t;
using Ipv6Type = std::array<uint8_t, 16>;
using IpType = std::variant<Ipv4Type, Ipv6Type>;

std::string labels_to_string(std::span<std::string const> labels);

struct Rr {
    std::vector<std::string> labels;
    RrType rtype;
    RrClass rclass;
    uint32_t ttl;
    std::vector<uint8_t> rdata;

    [[nodiscard]] std::vector<uint8_t> bytes() const;
    bool operator==(const Rr &) const = default;

    static Rr a_record(Labels labels, uint32_t ip, uint32_t ttl);
    static Rr aaaa_record(Labels labels, std::array<uint8_t, 16> ip,
                          uint32_t ttl);
    static Rr mx_record(Labels labels, uint16_t preference, Labels exchange,
                        uint32_t ttl, RrClass rclass = RrClass::In);
    static Rr ns_record(Labels labels, Labels authority_labels, uint32_t ttl,
                        RrClass rclass = RrClass::In);
    static Rr cname_record(Labels labels, Labels cname, uint32_t ttl,
                           RrClass rclass = RrClass::In);
    static Rr hinfo_record(Labels labels, std::string cpu, std::string os,
                           uint32_t ttl, RrClass rclass = RrClass::In);
};

[[nodiscard]] std::error_code read_labels(DataBuffer &buffer,
                                          std::vector<std::string> &labels);

[[nodiscard]] std::error_code read_rr(DataBuffer &buffer, Rr &rr);

enum class Opcode : uint8_t { Query = 0, Iquery = 1, Status = 2 };

struct Header {
    uint16_t id;

    uint16_t qr : 1 = 0;
    Opcode opcode : 4;
    uint16_t aa : 1 = 0;
    uint16_t tc : 1 = 0;
    uint16_t rd : 1;
    uint16_t ra : 1 = 0;
    uint16_t z : 3 = 0;
    ResponseCode rcode : 4 = ResponseCode::Ok;

    uint16_t qdcount = 0;
    uint16_t ancount = 0;
    uint16_t nscount = 0;
    uint16_t arcount = 0;

    [[nodiscard]] std::vector<uint8_t> bytes() const;
    bool operator==(const Header &) const = default;
};

[[nodiscard]] std::error_code read_header(DataBuffer &stream, Header &header);

struct Question {
    std::vector<std::string> labels;
    RrType qtype;
    RrClass qclass;
    auto operator<=>(const Question &) const = default;
    [[nodiscard]] std::vector<uint8_t> bytes() const;
};

[[nodiscard]] std::error_code read_question(DataBuffer &buffer,
                                            Question &question);

struct Message {
    Header header;
    std::vector<Question> questions{};
    std::vector<Rr> answers{};
    std::vector<Rr> authorities{};
    std::vector<Rr> additional{};
    bool operator==(const Message &) const = default;
    [[nodiscard]] std::vector<uint8_t> bytes() const;
};

[[nodiscard]] std::error_code read_message(DataBuffer &buffer,
                                           Message &message);

}  // namespace bighorn
