#include <argparse/argparse.hpp>
#include <asio.hpp>
#include <bighorn/recursive_lookup.hpp>
#include <bighorn/udp.hpp>
#include <iostream>
#include <thread>

void run_server(const bighorn::IpType& remote_ip, int port, int remote_port,
                bool no_rec);

bighorn::IpType parse_ip(std::string ip_str);

int main(int argc, char* argv[]) {
    argparse::ArgumentParser program("example_basic");
    program.add_argument("--port")
        .help("port to use (any port by default)")
        .scan<'i', int>()
        .metavar("PORT")
        .default_value(0);
    program.add_argument("--remote-ip")
        .help("remote DNS server use in queries")
        .metavar("IP")
        .default_value(std::string(
            "1.1.1.1"));  // Cloudflare's public DNS server, could use 127.0.0.1
    program.add_argument("--remote-port")
        .help("remote port to use")
        .scan<'i', int>()
        .metavar("PORT")
        .default_value(53);
    program.add_argument("--norec")
        .help("do not desire recursion from remote server")
        .implicit_value(true)
        .default_value(false);

    bighorn::IpType remote_ip;
    int port;
    int remote_port;
    bool no_rec;
    try {
        program.parse_args(argc, argv);
        remote_ip = parse_ip(program.get<std::string>("remote-ip"));
        port = program.get<int>("port");
        remote_port = program.get<int>("remote-port");
        no_rec = program.get<bool>("norec");
    } catch (const std::exception& err) {
        std::cerr << err.what() << '\n';
        std::cerr << program;
        return 1;
    }

    run_server(remote_ip, port, remote_port, no_rec);
    return 0;
}

void run_server(const bighorn::IpType& remote_ip, int port, int remote_port,
                bool no_rec) {
    asio::io_context io;
    auto cloudflare_server =
        bighorn::DnsServer{.ip = remote_ip,
                           .port = remote_port,
                           .conn_method = bighorn::ServerConnMethod::Udp,
                           .recursive = !no_rec};
    bighorn::DefaultResolver resolver(io, {cloudflare_server});
    bighorn::RecursiveLookup lookup(io, std::move(resolver));
    bighorn::Responder responder(std::move(lookup));

    bighorn::UdpNameServer server(io, port, std::move(responder));
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
}

bighorn::IpType parse_ip(std::string ip_str) {
    bighorn::IpType remote_ip;
    if (ip_str == "localhost") {
        remote_ip = 0x7F000001U;
    } else if (inet_pton(AF_INET, ip_str.data(), &remote_ip) == 0 &&
               inet_pton(AF_INET6, ip_str.data(), &remote_ip) == 0) {
        throw std::runtime_error("Remote IP must be an IPv4 or IPv6 address\n");
    }
    return remote_ip;
}