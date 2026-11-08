#pragma once

#include "dns/Header.h"
#include "dns/Question.h"

#include <vector>
#include <cstdint>
#include <string>

namespace dns
{
    std::vector<std::uint8_t> encodeDomainName(const std::string& domain);
    std::vector<std::uint8_t> encodeHeader(const Header& header);
    std::vector<std::uint8_t> encodeQuestion(const Question& Question);
    std::vector<std::uint8_t> encodeQuery(const Header& header, const Question& question);
};