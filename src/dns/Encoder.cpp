#include "dns/Encoder.h"
#include <string_view>
#include <stdexcept>

namespace {
    void appendUint16BE(std::vector<std::uint8_t>& bytes, std::uint16_t data) {
        std::uint8_t byteOne = data >> 8;
        std::uint8_t byteTwo = data;

        bytes.push_back(byteOne);
        bytes.push_back(byteTwo);
    }
}

std::vector<std::uint8_t> dns::encodeHeader(const Header& header) {
    std::vector<std::uint8_t> bytes;
    bytes.reserve(12);

    const std::uint16_t headArray[6] = {header.id, header.flags, header.questionCount, header.answerCount, header.authorityCount, header.additionalCount};

    for (std::uint16_t field : headArray) {
        appendUint16BE(bytes, field);
    }

    return bytes;
}

std::vector<std::uint8_t> dns::encodeQuestion(const Question& question) {
    std::vector<std::uint8_t> bytes = encodeDomainName(question.domainName);
    bytes.reserve(bytes.size() + 4);

    appendUint16BE(bytes, static_cast<std::uint16_t>(question.qType));
    appendUint16BE(bytes, static_cast<std::uint16_t>(question.qClass));

    return bytes;
}

std::vector<std::uint8_t>  dns::encodeDomainName(const std::string& domain) {
    std::vector<std::uint8_t> bytes;

    std::string_view domainView = domain;

    if (domainView.empty()) {
        throw std::invalid_argument("Inputted domain is empty");
    }

    if (domainView.back() == '.') {
        domainView.remove_suffix(1);
    }

    if (!domainView.empty() && domainView.back() == '.') {
        throw std::invalid_argument("Inputted domain has multiple trailing dots.");
    }

    if (domainView.length() > 253) {
        throw std::invalid_argument("Inputted domain is too long!");
    }



    while (!domainView.empty()) {
        std::size_t nextDot = domainView.find('.');
        std::string_view label = domainView.substr(0, nextDot);

        const std::size_t length = label.length();

        if (length == 0 or length > 63) {
            throw std::invalid_argument("Domain is invalid - Label is an invalid size");
        }

        bytes.push_back(length);

        for (char c : label) {
            bytes.push_back(static_cast<std::uint8_t>(c));
        }

        if (nextDot == std::string_view::npos) {
            break;
        }

        domainView.remove_prefix(nextDot + 1);
    };

    bytes.push_back(0);

    return bytes;
}