#pragma once

#include "dns/ResourceRecord.h"

#include <cstdint>
#include <string>
#include <vector>
#include <variant>
#include <span>

namespace dns {
    struct IPv4 {
        std::uint8_t bytes[4] {};
    };
    struct IPv6 {
        std::uint8_t bytes[16] {};
    };
    struct DomainName {
        std::string name;
    };
    struct Unknown
    {
        std::vector<std::uint8_t> bytes;
    };
    struct InterpretedRecord {
        std::variant<
            IPv4,
            IPv6,
            DomainName,
            Unknown
        > result;
        std::string name;
        std::uint16_t type = 0;
        std::uint16_t recordClass = 0;
        std::uint32_t ttl = 0;
    };
    
    InterpretedRecord interpretRecord(const ResourceRecord& recordData, std::span<const std::uint8_t> packet);
    
}