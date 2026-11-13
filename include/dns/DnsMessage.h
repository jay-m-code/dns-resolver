#pragma once

#include "dns/Header.h"
#include "dns/Question.h"
#include "dns/ResourceRecord.h"

#include <vector>
#include <span>
#include <cstdint>

namespace dns {
    struct DNSMessage {
        Header header;
        std::vector<Question> questions;
        std::vector<ResourceRecord> answers;
        std::vector<ResourceRecord> authorities;
        std::vector<ResourceRecord> additionals;

        std::vector<std::uint8_t> packet;
    };
}