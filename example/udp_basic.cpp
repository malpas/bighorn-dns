#include <argparse/argparse.hpp>
#include <asio.hpp>
#include <bighorn/static_lookup.hpp>
#include <bighorn/udp.hpp>
#include <iostream>

void run_server(const argparse::ArgumentParser& program);

int main(int argc, char* argv[]) {
    argparse::ArgumentParser program("example_basic");
    program.add_argument("--port")
        .help("port to use (any port by default)")
        .scan<'i', int>()
        .metavar("PORT")
        .default_value(0);
    try {
        program.parse_args(argc, argv);
    } catch (const std::runtime_error& err) {
        std::cerr << err.what() << '\n';
        std::cerr << program;
        return 1;
    }

    run_server(program);
    return 0;
}
void run_server(const argparse::ArgumentParser& program) {
    asio::io_context io;
    bighorn::StaticLookup lookup;
    lookup.add_record(
        bighorn::Rr::a_record({"abcdef", "abcdef"}, 0x7F000001, 86400));
    lookup.add_record(bighorn::Rr::a_record({"*", "wildcard-example", "com"},
                                             0x7F000001, 86400));
    lookup.add_record(bighorn::Rr::aaaa_record(
        {"abcdef", "abcdef"}, {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
        84600));
    lookup.add_authority(
        bighorn::DomainAuthority{.domain = {"com"},
                                  .name = {"a", "root-servers", "net"},
                                  .ips = {0xC6290004},
                                  .ttl = 86400});
    bighorn::Responder const responder(lookup);
    bighorn::UdpNameServer server(io, program.get<int>("port"), responder);

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
