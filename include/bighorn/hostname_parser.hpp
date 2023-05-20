#pragma once
#include <string>
#include <system_error>
#include <vector>

#include "error.hpp"

namespace bighorn
{

struct Hostname
{
    std::vector<std::string> subdomains;
};

[[nodiscard]] std::error_code parse_hostname(const std::string &hostname, Hostname &domain);

} // namespace bighorn