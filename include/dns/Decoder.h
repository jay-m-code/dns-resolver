#pragma once
#include "dns/Header.h"
#include "dns/Question.h"

#include <string>
#include <span>

namespace dns
{
    Header decodeHeader(std::span<const std::uint8_t> packet);
    Question decodeQuestion(std::span<const std::uint8_t> packet);
    std::string decodeDomain(std::span<const std::uint8_t> packet);
};