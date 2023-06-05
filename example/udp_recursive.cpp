#include <asio.hpp>
#include <bighorn/recursive_lookup.hpp>
#include <bighorn/udp.hpp>
#include <iostream>
#include <thread>

int main() {
    asio::io_context io;
    auto cloudflare_server =
        bighorn::DnsServer{.ip = 0x01010101U,
                            .conn_method = bighorn::ServerConnMethod::Udp,
                            .recursive = true};
    bighorn::BasicResolver resolver(io, {cloudflare_server});
    bighorn::RecursiveLookup lookup(io, std::move(resolver));
    bighorn::Responder responder(std::move(lookup));

    bighorn::UdpNameServer server(io, 0, std::move(responder));
    asio::co_spawn(io, server.start(), asio::detached);
    std::cout << "Started server on port " << server.port() << "\n";

    uint const thread_count = std::max(1U, std::thread::hardware_concurrency());
    std::vector<std::thread> threads;
    for (uint i = 0; i < thread_count; ++i) {
        std::thread t([&io] { io.run(); });
        threads.push_back(std::move(t));
    }
    std::cout << "Started " << thread_count << " worker threads\n";
    io.run();
    for (auto& thread : threads) {
        thread.join();
    }
    return 0;
}