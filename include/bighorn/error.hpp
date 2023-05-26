#pragma once
#include <string>
#include <system_error>

namespace bighorn {

enum class HostnameError { Empty = 1, InvalidCharacter, LabelTooLong, TooLong };

struct HostnameErrorCategory : std::error_category {
    const char *name() const noexcept override;
    std::string message(int ev) const override;
};

const HostnameErrorCategory hostnameErrCategory{};

std::error_code make_error_code(bighorn::HostnameError e);

enum class MessageError { Eof = 1, ReadError, LabelTooLong, NameTooLong };

struct MessageErrorCategory : std::error_category {
    const char *name() const noexcept override;
    std::string message(int ev) const override;
};

const MessageErrorCategory msgErrCategory{};

std::error_code make_error_code(bighorn::MessageError e);

}  // namespace bighorn

namespace std {

template <>
struct is_error_code_enum<bighorn::HostnameError> : true_type {};

template <>
struct is_error_code_enum<bighorn::MessageError> : true_type {};

}  // namespace std
