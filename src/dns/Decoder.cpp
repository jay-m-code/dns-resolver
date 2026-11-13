#include "dns/Decoder.h"

#include <stdexcept>
#include <vector>

namespace {
    std::uint16_t toUint16from8BE(std::uint8_t byteOne, std::uint8_t byteTwo) {
        std::uint16_t bytes = byteOne << 8;
        bytes = bytes | byteTwo;

        return bytes;
    }

	std::uint32_t toUint32from8BE(std::uint8_t byteOne, std::uint8_t byteTwo, std::uint8_t byteThree, std::uint8_t byteFour) {
        std::uint32_t bytes = static_cast<uint32_t>(byteOne) << 24;
        bytes = bytes | (byteTwo << 16);
		bytes = bytes | (byteThree << 8);
		bytes = bytes | (byteFour);

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


Question decodeQuestion(std::span<const std::uint8_t> packet, std::size_t& offset) {
	std::string domain = decodeDomain(packet, offset);

	if (offset > packet.size() || packet.size() - offset < 4) {
		throw std::invalid_argument("Truncated DNS question");
	}

	std::uint16_t qType = toUint16from8BE(packet[offset], packet[offset + 1]);
	offset += 2;
	std::uint16_t qClass = toUint16from8BE(packet[offset], packet[offset + 1]);
	offset += 2;


	return Question(domain, static_cast<QType>(qType), static_cast<QClass>(qClass));
}

ResourceRecord decodeResourceRecord(std::span<const std::uint8_t> packet, std::size_t& offset) {
	ResourceRecord record;
	record.name = decodeDomain(packet, offset);

	if (offset > packet.size() || packet.size() - offset < 10) {
		throw std::invalid_argument("Truncated DNS RR");
	}

	

	record.type = toUint16from8BE(packet[offset], packet[offset + 1]);
	offset += 2;
	record.recordClass = toUint16from8BE(packet[offset], packet[offset + 1]);
	offset += 2;

	record.ttl = toUint32from8BE(packet[offset], packet[offset + 1], packet[offset + 2], packet[offset + 3]);
	offset += 4;

	std::uint16_t rdLength = toUint16from8BE(packet[offset], packet[offset + 1]);
	offset += 2;
	
	if (offset > packet.size() || packet.size() - offset < rdLength) {
		throw std::invalid_argument("Not enough space for rdata?");
	}

	record.rdata.insert(record.rdata.end(), packet.begin() + offset, packet.begin() + offset + rdLength);

	offset += rdLength;

	return record;
}

}