#pragma once
#include "data.hpp"
#include <asio.hpp>

namespace bighorn
{

class Resolver
{
  public:
    Message resolve(const Message &query);
};

} // namespace bighorn