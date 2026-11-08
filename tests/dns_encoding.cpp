#include <gtest/gtest.h>
#include "dns/Encoder.h"

TEST(DNSNameEncoding, ValidDomain)
{
	std::vector<std::uint8_t> actual = dns::encodeDomainName("example.com");
	std::vector<std::uint8_t> expected {
		0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
		0x03, 'c', 'o', 'm',
		0x00
	};

	EXPECT_EQ(expected, actual);
}