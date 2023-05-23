#include "data.hpp"

namespace bighorn
{

std::vector<uint8_t> Header::bytes()
{
    uint16_t meta =
        qr << 15 | static_cast<uint16_t>(opcode) << 11 | aa << 10 | tc << 9 | rd << 8 | ra << 7 | z << 4 | rcode;

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

std::vector<uint8_t> Rr::bytes()
{
    std::vector<uint8_t> bytes;
    size_t required_size = 0;
    for (auto &label : labels)
    {
        required_size += 1 + label.length();
    }
    required_size += 10;
    required_size += rdata.length();
    bytes.reserve(required_size);
    for (auto &label : labels)
    {
        bytes.push_back(static_cast<uint8_t>(label.length()));
        for (auto &c : label)
        {
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
    for (auto &c : rdata)
    {
        bytes.push_back(c);
    }

    return bytes;
}

} // namespace bighorn