#pragma once

#include <vector>
#include <cstdint>
#include <string>

namespace dns
{
    std::vector<std::uint8_t> encodeDomainName(const std::string& domain);
};