#include "dns/Encoder.h"
#include <string_view>
#include <stdexcept>

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