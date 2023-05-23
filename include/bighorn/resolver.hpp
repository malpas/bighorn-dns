#pragma once
#include <asio.hpp>
#include <vector>

#include "data.hpp"

namespace bighorn {

class Resolver {
   public:
    Resolver(std::vector<Rr> records) : records_(records) {}
    Message resolve(const Message &query);

   private:
    std::vector<Rr> records_;
    std::vector<Rr> resolve_question(const Question &);
};

}  // namespace bighorn