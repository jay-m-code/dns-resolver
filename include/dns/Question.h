#pragma once
#include <cstdint>
#include <string>

namespace dns {
    enum class QType: std::uint16_t {
        A = 0x0001,
        NS = 0x0002,
        CNAME = 0x0005,
        MX = 0x000F,
        TXT = 0x0010,
        AAAA = 0x001C
    };

    enum class QClass: std::uint16_t {
        IN = 0x0001,
        CH = 0x0003,
        HS = 0x0004
    };

    struct Question {
        std::string domainName;
        QType qType;
        QClass qClass;

        Question(const std::string& domainName, QType qType, QClass qClass = QClass::IN): domainName(domainName), qType(qType), qClass(qClass) {}
    };
}