#pragma once
#include <string>
#include <system_error>

namespace bighorn {

enum class MessageError {
    Eof = 1,
    ReadError,
    InvalidLabelChar,
    LabelTooLong,
    NameTooLong,
    JumpLimit
};

enum class ResolutionError {
    InvalidResponse = 1,
    Timeout,
    RecursionLimit,
    RemoteFailure,
    RemoteRefused,
};

struct MessageErrorCategory : std::error_category {
    const char *name() const noexcept override;
    std::string message(int ev) const override;
};

struct ResolutionErrorCategory : std::error_category {
    const char *name() const noexcept override;
    std::string message(int ev) const override;
};

const MessageErrorCategory msgErrCategory{};
const ResolutionErrorCategory resolutionErrCategory{};

std::error_code make_error_code(bighorn::MessageError e);
std::error_code make_error_code(bighorn::ResolutionError e);

}  // namespace bighorn

namespace std {

template <>
struct is_error_code_enum<bighorn::MessageError> : true_type {};

template <>
struct is_error_code_enum<bighorn::ResolutionError> : true_type {};

}  // namespace std
