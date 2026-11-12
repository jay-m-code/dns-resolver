#include <gtest/gtest.h>
#include "dns/Decoder.h"

TEST(DNSNameDecoding, DirectCompression)
{
	std::vector<std::uint8_t> encoded(12, 0x00);

    std::vector<std::uint8_t> domain {
		0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
		0x03, 'c', 'o', 'm', 0x00
	};

	encoded.insert(encoded.end(), domain.begin(), domain.end());

	encoded.insert(encoded.end(), {0xC0, 0x0C});

	std::size_t offset = 25;

	std::string actual = dns::decodeDomain(encoded, offset);

	EXPECT_EQ("example.com", actual);
	EXPECT_EQ(27, offset);
}

TEST(DNSNameDecoding, PartialCompression)
{
	std::vector<std::uint8_t> encoded(12, 0x00);

	std::vector<std::uint8_t> domain {
		0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
		0x03, 'c', 'o', 'm', 0x00
	};

	encoded.insert(encoded.end(), domain.begin(), domain.end());

	encoded.insert(encoded.end(), {
		0x03, 'w', 'w', 'w',
		0xC0, 0x0C
	});

	std::size_t offset = 25;

	std::string actual = dns::decodeDomain(encoded, offset);

	EXPECT_EQ("www.example.com", actual);
	EXPECT_EQ(31, offset);
}

TEST(DNSNameDecoding, TruncatedLabel)
{
	std::vector<std::uint8_t> encoded {
		0x03, 'a', 'b'
	};

	std::size_t offset = 0;

	EXPECT_THROW(
		dns::decodeDomain(encoded, offset),
		std::invalid_argument
	);
}

TEST(DNSNameDecoding, TruncatedPointer)
{
	std::vector<std::uint8_t> encoded {
		0xC0
	};

	std::size_t offset = 0;

	EXPECT_THROW(
		dns::decodeDomain(encoded, offset),
		std::invalid_argument
	);
}

TEST(DNSNameDecoding, SelfReferencingPointer)
{
	std::vector<std::uint8_t> encoded {
		0xC0, 0x00
	};

	std::size_t offset = 0;

	EXPECT_THROW(
		dns::decodeDomain(encoded, offset),
		std::invalid_argument
	);
}

TEST(DNSNameDecoding, UnsupportedLabelType)
{
	std::vector<std::uint8_t> encoded {
		0x40, 0x00
	};

	std::size_t offset = 0;

	EXPECT_THROW(
		dns::decodeDomain(encoded, offset),
		std::invalid_argument
	);
}

TEST(DNSNameDecoding, MaximumDomainLength)
{
	std::vector<std::uint8_t> encoded;

	for (std::size_t length : {63, 63, 63, 61}) {
		encoded.push_back(static_cast<std::uint8_t>(length));
		encoded.insert(encoded.end(), length, 'a');
	}

	encoded.push_back(0x00);

	std::size_t offset = 0;

	std::string actual = dns::decodeDomain(encoded, offset);

	EXPECT_EQ(253, actual.size());
	EXPECT_EQ(255, offset);
}

TEST(DNSNameDecoding, DomainTooLong)
{
	std::vector<std::uint8_t> encoded;

	for (std::size_t length : {63, 63, 63, 62}) {
		encoded.push_back(static_cast<std::uint8_t>(length));
		encoded.insert(encoded.end(), length, 'a');
	}

	encoded.push_back(0x00);

	std::size_t offset = 0;

	EXPECT_THROW(
		dns::decodeDomain(encoded, offset),
		std::invalid_argument
	);
}
