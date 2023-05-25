#pragma once

#include <arpa/inet.h>

#include <cstdint>
#include <cstring>
#include <system_error>

#include "error.hpp"

namespace bighorn {

template <typename T>
concept Indexable = requires(T a, size_t i) {
    { a[i] } -> std::common_with<uint8_t>;
} && requires(T a) { a.size(); };

template <typename I>
    requires Indexable<I>
class DataBuffer {
   public:
    DataBuffer(const I *data) : data_(data), i_(0) {}
    DataBuffer(const DataBuffer &) = delete;

    template <typename T>
    [[nodiscard]] std::error_code read_n(int n, T *out) {
        if (i_ + n > data_->size() || i_ + n > limit_) {
            return MessageError::ReadError;
        }
        std::memcpy(out, &((*data_)[i_]), n);
        i_ += n;
        return {};
    }

    template <typename T>
    [[nodiscard]] std::error_code read_number(T &out) {
        auto err = read_n(sizeof(T), &out);
        if (err) {
            return err;
        }
        if constexpr (sizeof(T) == 2) {
            out = ntohs(out);
        } else if constexpr (sizeof(T) == 4) {
            out = ntohl(out);
        } else if constexpr (sizeof(T) == 1) {
        } else {
            static_assert(false);
        }
        return {};
    }

    [[nodiscard]] std::error_code read_byte(uint8_t &out) {
        if (i_ + 1 > data_->size()) {
            return MessageError::ReadError;
        }
        auto err = read_n(1, &out);
        return {};
    }

    void limit(uint8_t limit) { limit_ = limit; }

   private:
    size_t i_;
    size_t limit_;
    const I *data_;
};

}  // namespace bighorn