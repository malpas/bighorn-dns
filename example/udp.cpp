#include <asio.hpp>
#include <format>
#include <bighorn/udp.hpp>
#include <iostream>

using asio::ip::tcp;

int main() {
    asio::io_service io;

    bighorn::StaticLookup lookup;
    lookup.add_record(
        bighorn::Rr::a_record({"abcdef", "abcdef"}, 0x7F000001, 86400));
    lookup.add_record(bighorn::Rr::aaaa_record(
        {"abcdef", "abcdef"}, {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
        84600));
    lookup.add_authority(
        bighorn::DomainAuthority{.domain = {"com"},
                                  .name = {"a", "root-servers", "net"},
                                  .ips = {0xC6290004},
                                  .ttl = 86400});
    bighorn::Responder<bighorn::StaticLookup> responder(std::move(lookup));
    bighorn::UdpNameServer server(io, 0, std::move(responder));

    asio::co_spawn(io, server.start(), asio::detached);
    std::cout << "Started server on port " << server.port() << "\n";
    io.run();
    return 0;
}