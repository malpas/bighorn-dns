#include <cctype>
#include <error.hpp>
#include <hostname_parser.hpp>
#include <sstream>
#include <string>

namespace bighorn
{

bool valid_subdomain_char(char c)
{
    return std::isalnum(c) || c == '-';
}

const int max_hostname_len = 24;

std::error_code parse_hostname(const std::string &hostname, Hostname &domain)
{
    if (hostname.length() == 0)
    {
        return HostnameError::Empty;
    }

    std::vector<std::string> labels;
    int i = 0;
    while (true)
    {
        std::stringstream ss;
        if (!std::isalpha(hostname[i]))
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
        labels.push_back(ss.str());
        if (i == hostname.size())
        {
            break;
        }
        ++i;
    }
    if (i > max_hostname_len)
    {
        return HostnameError::TooLong;
    }
    domain = Hostname{.labels = labels};
    return {};
}

} // namespace bighorn
