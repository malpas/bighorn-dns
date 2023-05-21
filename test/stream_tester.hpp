#pragma once
#include <asio.hpp>
#include <cstdint>
#include <cstring>
#include <ostream>
#include <string>
#include <system_error>

class StreamTester
{
  public:
    StreamTester(std::vector<uint8_t> data) : data(data), is_read(false)
    {
    }

    template <typename MutableBufferSequence> size_t read_some(MutableBufferSequence mb)
    {
        return read_some(mb, std::error_code{});
    }

    template <typename MutableBufferSequence> size_t read_some(MutableBufferSequence mb, std::error_code &ec)
    {
        if (is_read)
        {
            ec = asio::error::eof;
            return 0;
        }
        is_read = true;
        size_t copy_size;
        for (auto it = asio::buffer_sequence_begin(mb); it != asio::buffer_sequence_end(mb); ++it)
        {
            asio::mutable_buffer const buffer = *it;
            copy_size = std::min(data.size(), buffer.size());
            std::memcpy(static_cast<uint8_t *>(buffer.data()), data.data(), copy_size);
        }
        ec = std::error_code{};
        return copy_size;
    }

  private:
    std::vector<uint8_t> data;
    bool is_read;
};