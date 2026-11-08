#pragma once
#include <vector>
#include <cstdint>

#include "dns/Question.h"

namespace dns {
    std::vector<std::uint8_t> buildQuery(const Question& question, std::uint16_t id);
}