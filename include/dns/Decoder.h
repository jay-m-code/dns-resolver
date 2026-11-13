#pragma once

#include "dns/Header.h"
#include "dns/Question.h"
#include "dns/ResourceRecord.h"
#include "dns/DnsMessage.h"

#include <string>
#include <span>

namespace dns
{
    Header decodeHeader(std::span<const std::uint8_t> packet);
    Question decodeQuestion(std::span<const std::uint8_t> packet, std::size_t& offset);
    std::string decodeDomain(std::span<const std::uint8_t> packet, std::size_t& offset);
    ResourceRecord decodeResourceRecord(std::span<const std::uint8_t> packet, std::size_t& offset);

    DNSMessage decodeDNSMessage(std::span<const std::uint8_t> packet);
};