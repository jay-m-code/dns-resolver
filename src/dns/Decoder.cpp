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


std::string decodeDomain(std::span<const std::uint8_t> packet, std::size_t& offset) {
	std::size_t position = offset;
	bool jumped = false;

	std::string currentDomain;
	std::size_t lengthCounter = 0;

	while (true) {
		if (position >= packet.size()) {
			throw std::invalid_argument("Offset is beyond valid size");
		}

		std::uint8_t currentLength = packet[position];
		position++;

		if (currentLength == 0x00) {
			break;
		}

		if ((currentLength & 0xC0) == 0xC0) {
			if (position >= packet.size()) {
				throw std::invalid_argument("Truncated compression pointer");
			}

			std::uint16_t target = ((currentLength & 0x3F) << 8) | packet[position];

			if (target >= position - 1) {
				throw std::invalid_argument("Invalid compression pointer target");
			}

			if (!jumped) {
				offset = position + 1;
				jumped = true;
			}

			position = target;
			continue;
		}

		if ((currentLength & 0xC0) != 0) {
			throw std::invalid_argument("Unsupported DNS label type");
		}

		if (currentLength > packet.size() - position) {
			throw std::invalid_argument("Label goes beyond packet");
		}

		lengthCounter += currentLength + 1;

		if (lengthCounter > 254) {
			throw std::invalid_argument("Domain exceeds 255 bytes");
		}

		if (!currentDomain.empty()) {
			currentDomain += ".";
		}

		for (std::size_t i = 0; i < currentLength; i++) {
			currentDomain += static_cast<char>(packet[position]);
			position++;
		}
	}

	if (!jumped) {
		offset = position;
	}

	return currentDomain.empty() ? "." : currentDomain;
}


}