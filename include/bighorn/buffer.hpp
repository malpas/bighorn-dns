#pragma once

#include <arpa/inet.h>

#include <cstdint>
#include <cstring>
#include <span>
#include <system_error>

#include "error.hpp"

namespace bighorn {

class DataBuffer {
   public:
    DataBuffer(std::span<uint8_t const> data)
        : data_(data), i_(0), limit_(data.size_bytes()) {}
    DataBuffer(std::span<uint8_t const> data, size_t limit)
        : data_(data), i_(0), limit_(limit) {}
    DataBuffer(const DataBuffer &) = delete;

    template <typename T>
    [[nodiscard]] std::error_code read_n(int n, T *out) {
        if (i_ + n > data_.size_bytes() || i_ + n > limit_) {
            return MessageError::ReadError;
        }
        std::memcpy(out, &data_.data()[i_], n);
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
        if (i_ + 1 > data_.size()) {
            return MessageError::ReadError;
        }
        auto err = read_n(1, &out);
        return err;
    }

    size_t pos() { return i_; }
    void seek(size_t i) { i_ = i; }
    void limit(uint8_t limit) { limit_ = limit; }

   private:
    std::span<uint8_t const> data_;
    size_t i_;
    size_t limit_;
};

}  // namespace bighorn