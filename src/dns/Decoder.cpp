#include "dns/Decoder.h"

#include <stdexcept>
#include <vector>

namespace {
    std::uint16_t toUint16from8BE(std::uint8_t byteOne, std::uint8_t byteTwo) {
        std::uint16_t bytes = byteOne << 8;
        bytes = bytes | byteTwo;

        return bytes;
    }
}

namespace dns{

Header decodeHeader(std::span<const std::uint8_t> packet) {
    if (packet.size() < 12) {
        throw std::invalid_argument("Packet size is too small!");
    }

    Header header; 
    header.id = toUint16from8BE(packet[0], packet[1]);
    header.flags = toUint16from8BE(packet[2], packet[3]);
    header.questionCount = toUint16from8BE(packet[4], packet[5]);
    header.answerCount = toUint16from8BE(packet[6], packet[7]);
    header.authorityCount = toUint16from8BE(packet[8], packet[9]);
    header.additionalCount = toUint16from8BE(packet[10], packet[11]);

    return header;
}

}