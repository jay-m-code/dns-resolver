#pragma once

#include "Header.h"

#include <vector>
#include <cstdint>
#include <string>

namespace dns
{
    std::vector<std::uint8_t> encodeDomainName(const std::string& domain);
    std::vector<std::uint8_t> encodeHeader(const Header& header);
};