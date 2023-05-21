#include <error.hpp>

namespace bighorn
{

const char *HostnameErrorCategory::name() const noexcept
{
    return "host_parse_error";
}

std::string HostnameErrorCategory::message(int ev) const
{
    switch (static_cast<HostnameError>(ev))
    {
    case HostnameError::Empty:
        return "empty host name";
    case HostnameError::InvalidCharacter:
        return "invalid character";
    case HostnameError::TooLong:
        return "too long";
    default:
        return "unknown error";
    }
}

std::error_code make_error_code(HostnameError e)
{
    return {static_cast<int>(e), hostnameErrCategory};
}

} // namespace bighorn