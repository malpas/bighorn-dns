#include <cctype>
#include <error.hpp>
#include <hostname_parser.hpp>
#include <sstream>
#include <string>

namespace bighorn
{

bool valid_subdomain_char(char c)
{
    return (std::isalnum(c) != 0) || c == '-';
}

std::error_code parse_hostname(const std::string &hostname, Hostname &domain)
{
    if (hostname.length() == 0)
    {
        return HostnameError::Empty;
    }

    std::vector<std::string> subdomains;
    int i = 0;
    while (true)
    {
        std::stringstream ss;

        if (!valid_subdomain_char(hostname[i]))
        {
            return HostnameError::InvalidCharacter;
        }
        ss << hostname[i];
        ++i;

        while (i < hostname.length() && hostname[i] != '.')
        {
            if (!valid_subdomain_char(hostname[i]))
            {
                return HostnameError::InvalidCharacter;
            }
            ss << hostname[i];
            ++i;
        }
        subdomains.push_back(ss.str());
        if (i == hostname.size())
        {
            break;
        }
        ++i;
    }
    domain = Hostname{.subdomains = subdomains};
    return {};
}

} // namespace bighorn
