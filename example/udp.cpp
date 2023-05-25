#include <asio.hpp>
#include <format>
#include <bighorn/udp.hpp>
#include <iostream>

using asio::ip::tcp;

std::vector<bighorn::Rr> get_example_records(asio::io_service& io);

int main() {
    asio::io_service io;

    bighorn::Responder responder(get_example_records(io),
                                  std::vector<bighorn::DomainAuthority>{});
    bighorn::UdpNameServer server(io, 0, std::move(responder));
    asio::co_spawn(io, server.start(), asio::detached);
    std::cout << "Started server on port " << server.port() << "\n";
    io.run();
    return 0;
}

std::vector<bighorn::Rr> get_example_records(asio::io_service& io) {
    tcp::resolver resolver(io);
    std::vector<bighorn::Rr> records;

    auto example_endpoints = resolver.resolve("example.com", "80");
    for (auto& endpoint : example_endpoints) {
        if (!endpoint.endpoint().address().is_v4()) {
            continue;
        }
        std::vector<std::string> labels;
        std::stringstream ss(endpoint.host_name());
        std::string label;
        while (std::getline(ss, label, '.')) {
            labels.push_back(label);
        }
        records.push_back(bighorn::Rr::a_record(
            labels, endpoint.endpoint().address().to_v4().to_uint(), 0));
    }
    return records;
}