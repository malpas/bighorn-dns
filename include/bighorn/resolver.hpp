#pragma once
#include "data.hpp"
#include <asio.hpp>
#include <vector>

namespace bighorn
{

class Resolver
{
  public:
    Resolver(std::vector<Rr> records) : records(records)
    {
    }
    Message resolve(const Message &query);

  private:
    std::vector<Rr> records;
    std::vector<Rr> resolve_question(const Question &);
};

} // namespace bighorn