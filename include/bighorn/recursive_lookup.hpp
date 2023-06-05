#include "lookup.hpp"

namespace bighorn {

template <std::derived_from<Resolver> R>
class RecursiveLookup : public Lookup {
   public:
    RecursiveLookup(asio::io_context &io, R resolver,
                    std::chrono::milliseconds timeout = 5s)
        : io_(io), resolver_(std::move(resolver)), timeout_(timeout) {}

    asio::awaitable<FoundRecords> find_records(
        std::span<std::string const> labels, RrType qtype, RrClass qclass,
        bool recursive) override;

    std::vector<DomainAuthority> find_authorities(
        std::span<std::string const> /*labels*/, RrClass /*rclass*/) override {
        return {};
    }

    bool supports_recursion() override { return true; }

   private:
    asio::io_context &io_;
    R resolver_;
    std::chrono::milliseconds timeout_;
};

template <std::derived_from<Resolver> R>
inline asio::awaitable<FoundRecords> RecursiveLookup<R>::find_records(
    std::span<std::string const> labels, RrType qtype, RrClass qclass,
    bool /*recursive*/) {
    Labels label_vec(labels.begin(), labels.end());
    Resolution resolution =
        co_await resolver_.resolve(label_vec, qtype, qclass, true, timeout_);
    std::error_code err;
    if (resolution.rcode == ResponseCode::Refused) {
        err = ResolutionError::RemoteRefused;
    }
    co_return FoundRecords{.records = resolution.records, .err = err};
}

}  // namespace bighorn