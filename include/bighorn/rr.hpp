#pragma once
#include "error.hpp"
#include "hostname_parser.hpp"

#include <arpa/inet.h>
#include <array>
#include <asio.hpp>
#include <istream>
#include <memory>
#include <sstream>
#include <stdint.h>
#include <string>

namespace bighorn
{

enum class RrType : uint16_t
{
    HostAddress = 1,
    AuthoritativeNameServer = 2,
    MailDestination = 3,
    MailForwarder = 4,
    CanonicalAlias = 5,
    ZoneStart = 6,
    MailboxDomain = 7,
    MailGroupMember = 8,
    MailRenameDomain = 9,
    Null = 10,
    WellKnownService = 11,
    DomainNamePointer = 12,
    HostInformation = 13,
    Mailbox = 14,
    MailExchange = 15,
    TextStrings = 16
};

enum class RrClass : uint16_t
{
    Internet = 1,
    Csnet = 2,
    Chaos = 3,
    Hesiod = 4
};

struct Rr
{
    std::vector<std::string> labels;
    RrType type;
    RrClass cls;
    uint32_t ttl;
    std::string rdata;
};

namespace
{

template <typename SyncReadStream>
[[nodiscard]] std::error_code read_n(SyncReadStream &stream, asio::streambuf &buf, int n, char *out)
{
    if (buf.in_avail() >= n)
    {
        buf.commit(n);
    }
    else
    {
        std::error_code asio_err;
        auto count = asio::read(stream, buf, asio::transfer_at_least(n), asio_err);
        if (asio_err)
        {
            return asio_err;
        }
        buf.commit(count);
    }
    buf.sgetn(out, n);
    return {};
}

template <typename SyncReadStream>
[[nodiscard]] std::error_code read_byte(SyncReadStream &stream, asio::streambuf &buf, uint8_t &out)
{
    auto err = read_n(stream, buf, 1, reinterpret_cast<char *>(&out));
    if (err)
    {
        return err;
    }
    return {};
}

template <typename SyncReadStream, typename T>
[[nodiscard]] std::error_code read_number(SyncReadStream &stream, asio::streambuf &buf, T &out)
{
    auto err = read_n(stream, buf, sizeof(T), reinterpret_cast<char *>(&out));
    if (err)
    {
        return err;
    }
    if constexpr (sizeof(T) == 2)
    {
        out = ntohs(out);
    }
    else
    {
        out = ntohl(out);
    }
    return {};
}

} // namespace

template <typename SyncReadStream> [[nodiscard]] std::error_code read_rr(SyncReadStream &stream, Rr &rr)
{
    std::error_code asio_err;
    asio::streambuf buf;
    buf.prepare(512);

    uint8_t label_len;
    rr.labels = std::vector<std::string>{};
    do
    {
        asio_err = read_byte(stream, buf, label_len);
        if (asio_err)
        {
            return asio_err;
        }
        if (label_len == 0)
        {
            break;
        }
        std::string label(label_len, '\0');
        asio_err = read_n(stream, buf, label_len, label.data());
        if (asio_err)
        {
            return asio_err;
        }
        rr.labels.push_back(label);
    } while (label_len > 0);

    uint16_t bytes;
    asio_err = read_number(stream, buf, bytes);
    if (asio_err)
    {
        return asio_err;
    }
    rr.type = static_cast<RrType>(bytes);

    asio_err = read_number(stream, buf, bytes);
    if (asio_err)
    {
        return asio_err;
    }
    rr.cls = static_cast<RrClass>(bytes);

    asio_err = read_number(stream, buf, rr.ttl);
    if (asio_err)
    {
        return asio_err;
    }

    uint16_t rdlength;
    asio_err = read_number(stream, buf, rdlength);
    rr.rdata = std::string(rdlength, '\0');
    asio_err = read_n(stream, buf, rdlength, rr.rdata.data());
    return {};
}

} // namespace bighorn