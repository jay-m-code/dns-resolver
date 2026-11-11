#pragma once
#include <cstdint>

namespace dns {
    struct Header {
        bool operator==(const Header&) const = default;
        std::uint16_t id = 0;
        std::uint16_t flags = 0;
        std::uint16_t questionCount = 0;
        std::uint16_t answerCount = 0;
        std::uint16_t authorityCount = 0;
        std::uint16_t additionalCount = 0;
    };
}