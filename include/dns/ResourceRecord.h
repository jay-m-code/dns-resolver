#pragma once

#include <string>
#include <cstdint>
#include <vector>

namespace dns {
    struct ResourceRecord
    {
        std::string name;
        std::uint16_t type = 0;
        std::uint16_t recordClass = 0;
        std::uint32_t ttl = 0;
        std::vector<std::uint8_t> rdata;
    };
    
}