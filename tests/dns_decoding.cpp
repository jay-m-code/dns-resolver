
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

	EXPECT_THROW(dns::decodeDomain(encoded, offset), std::invalid_argument);
}

TEST(DNSNameDecoding, TruncatedPointer)
{
	std::vector<std::uint8_t> encoded {
		0xC0
	};

	std::size_t offset = 0;

	EXPECT_THROW(dns::decodeDomain(encoded, offset), std::invalid_argument);
}

TEST(DNSNameDecoding, SelfReferencingPointer)
{
	std::vector<std::uint8_t> encoded {
		0xC0, 0x00
	};

	std::size_t offset = 0;

	EXPECT_THROW(dns::decodeDomain(encoded, offset), std::invalid_argument);
}

TEST(DNSNameDecoding, UnsupportedLabelType)
{
	std::vector<std::uint8_t> encoded {
		0x40, 0x00
	};

	std::size_t offset = 0;

	EXPECT_THROW(dns::decodeDomain(encoded, offset), std::invalid_argument);
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

	EXPECT_THROW(dns::decodeDomain(encoded, offset), std::invalid_argument);
}

TEST(DNSQuestionDecoding, OrdinaryQuestion)
{
	std::vector<std::uint8_t> encoded {
		0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
		0x03, 'c', 'o', 'm', 0x00,
		0x00, 0x01,
		0x00, 0x01
	};

	std::size_t offset = 0;

	dns::Question actual = dns::decodeQuestion(encoded, offset);

	EXPECT_EQ("example.com", actual.domainName);
	EXPECT_EQ(dns::QType::A, actual.qType);
	EXPECT_EQ(dns::QClass::IN, actual.qClass);
	EXPECT_EQ(17, offset);
}

TEST(DNSQuestionDecoding, CompressedQuestion)
{
	std::vector<std::uint8_t> encoded(12, 0x00);

	std::vector<std::uint8_t> domain {
		0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
		0x03, 'c', 'o', 'm', 0x00
	};

	encoded.insert(encoded.end(), domain.begin(), domain.end());

	encoded.insert(encoded.end(), {
		0xC0, 0x0C,
		0x00, 0x1C,
		0x00, 0x01
	});

	std::size_t offset = 25;

	dns::Question actual = dns::decodeQuestion(encoded, offset);

	EXPECT_EQ("example.com", actual.domainName);
	EXPECT_EQ(dns::QType::AAAA, actual.qType);
	EXPECT_EQ(dns::QClass::IN, actual.qClass);
	EXPECT_EQ(31, offset);
}

TEST(DNSQuestionDecoding, TruncatedQuestion)
{
	std::vector<std::uint8_t> encoded {
		0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
		0x03, 'c', 'o', 'm', 0x00,
		0x00, 0x01
	};

	std::size_t offset = 0;

	EXPECT_THROW(dns::decodeQuestion(encoded, offset), std::invalid_argument);
}


TEST(DNSResourceRecordDecoding, ARecord)
{
	std::vector<std::uint8_t> encoded {
		0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
		0x03, 'c', 'o', 'm', 0x00,
		0x00, 0x01,
		0x00, 0x01,
		0x00, 0x00, 0x0E, 0x10,
		0x00, 0x04,
		0x5D, 0xB8, 0xD7, 0x0E
	};

	std::size_t offset = 0;

	dns::ResourceRecord actual = dns::decodeResourceRecord(encoded, offset);

	std::vector<std::uint8_t> expectedRData {
		0x5D, 0xB8, 0xD7, 0x0E
	};

	EXPECT_EQ("example.com", actual.name);
	EXPECT_EQ(1, actual.type);
	EXPECT_EQ(1, actual.recordClass);
	EXPECT_EQ(3600, actual.ttl);
	EXPECT_EQ(expectedRData, actual.rdata);
	EXPECT_EQ(27, offset);
}

TEST(DNSResourceRecordDecoding, AAAARecord)
{
	std::vector<std::uint8_t> encoded {
		0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
		0x03, 'c', 'o', 'm', 0x00,
		0x00, 0x1C,
		0x00, 0x01,
		0x00, 0x00, 0x01, 0x2C,
		0x00, 0x10,
		0x20, 0x01, 0x0D, 0xB8,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x01
	};

	std::size_t offset = 0;

	dns::ResourceRecord actual = dns::decodeResourceRecord(encoded, offset);

	std::vector<std::uint8_t> expectedRData {
		0x20, 0x01, 0x0D, 0xB8,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x01
	};

	EXPECT_EQ("example.com", actual.name);
	EXPECT_EQ(28, actual.type);
	EXPECT_EQ(1, actual.recordClass);
	EXPECT_EQ(300, actual.ttl);
	EXPECT_EQ(expectedRData, actual.rdata);
	EXPECT_EQ(39, offset);
}

TEST(DNSResourceRecordDecoding, CompressedName)
{
	std::vector<std::uint8_t> encoded(12, 0x00);

	std::vector<std::uint8_t> domain {
		0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
		0x03, 'c', 'o', 'm', 0x00
	};

	encoded.insert(encoded.end(), domain.begin(), domain.end());

	encoded.insert(encoded.end(), {
		0xC0, 0x0C,
		0x00, 0x01,
		0x00, 0x01,
		0x00, 0x00, 0x00, 0x3C,
		0x00, 0x04,
		0x7F, 0x00, 0x00, 0x01
	});

	std::size_t offset = 25;

	dns::ResourceRecord actual = dns::decodeResourceRecord(encoded, offset);

	std::vector<std::uint8_t> expectedRData {
		0x7F, 0x00, 0x00, 0x01
	};

	EXPECT_EQ("example.com", actual.name);
	EXPECT_EQ(1, actual.type);
	EXPECT_EQ(1, actual.recordClass);
	EXPECT_EQ(60, actual.ttl);
	EXPECT_EQ(expectedRData, actual.rdata);
	EXPECT_EQ(41, offset);
}

TEST(DNSResourceRecordDecoding, MaximumTTL)
{
	std::vector<std::uint8_t> encoded {
		0x00,
		0x00, 0x01,
		0x00, 0x01,
		0xFF, 0xFF, 0xFF, 0xFF,
		0x00, 0x00
	};

	std::size_t offset = 0;

	dns::ResourceRecord actual = dns::decodeResourceRecord(encoded, offset);

	EXPECT_EQ(".", actual.name);
	EXPECT_EQ(1, actual.type);
	EXPECT_EQ(1, actual.recordClass);
	EXPECT_EQ(0xFFFFFFFFu, actual.ttl);
	EXPECT_TRUE(actual.rdata.empty());
	EXPECT_EQ(11, offset);
}

TEST(DNSResourceRecordDecoding, EmptyRData)
{
	std::vector<std::uint8_t> encoded {
		0x00,
		0x00, 0x01,
		0x00, 0x01,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00
	};

	std::size_t offset = 0;

	dns::ResourceRecord actual = dns::decodeResourceRecord(encoded, offset);

	EXPECT_EQ(".", actual.name);
	EXPECT_EQ(1, actual.type);
	EXPECT_EQ(1, actual.recordClass);
	EXPECT_EQ(0, actual.ttl);
	EXPECT_TRUE(actual.rdata.empty());
	EXPECT_EQ(11, offset);
}

TEST(DNSResourceRecordDecoding, SingleByteRData)
{
	std::vector<std::uint8_t> encoded {
		0x00,
		0x00, 0x10,
		0x00, 0x01,
		0x00, 0x00, 0x00, 0x01,
		0x00, 0x01,
		0xAB
	};

	std::size_t offset = 0;

	dns::ResourceRecord actual = dns::decodeResourceRecord(encoded, offset);

	std::vector<std::uint8_t> expectedRData {
		0xAB
	};

	EXPECT_EQ(".", actual.name);
	EXPECT_EQ(16, actual.type);
	EXPECT_EQ(1, actual.recordClass);
	EXPECT_EQ(1, actual.ttl);
	EXPECT_EQ(expectedRData, actual.rdata);
	EXPECT_EQ(12, offset);
}

TEST(DNSResourceRecordDecoding, UnknownRecordType)
{
	std::vector<std::uint8_t> encoded {
		0x00,
		0xFF, 0xFE,
		0x12, 0x34,
		0x80, 0x00, 0x00, 0x01,
		0x00, 0x02,
		0xAA, 0xBB
	};

	std::size_t offset = 0;

	dns::ResourceRecord actual = dns::decodeResourceRecord(encoded, offset);

	std::vector<std::uint8_t> expectedRData {
		0xAA, 0xBB
	};

	EXPECT_EQ(".", actual.name);
	EXPECT_EQ(65534, actual.type);
	EXPECT_EQ(0x1234, actual.recordClass);
	EXPECT_EQ(0x80000001u, actual.ttl);
	EXPECT_EQ(expectedRData, actual.rdata);
	EXPECT_EQ(13, offset);
}

TEST(DNSResourceRecordDecoding, MaximumRDataLength)
{
	std::vector<std::uint8_t> encoded {
		0x00,
		0x00, 0x01,
		0x00, 0x01,
		0x00, 0x00, 0x00, 0x00,
		0xFF, 0xFF
	};

	encoded.insert(encoded.end(), 65535, 0xAB);

	std::size_t offset = 0;

	dns::ResourceRecord actual = dns::decodeResourceRecord(encoded, offset);

	EXPECT_EQ(".", actual.name);
	EXPECT_EQ(1, actual.type);
	EXPECT_EQ(65535, actual.rdata.size());
	EXPECT_EQ(0xAB, actual.rdata.front());
	EXPECT_EQ(0xAB, actual.rdata.back());
	EXPECT_EQ(65546, offset);
}

TEST(DNSResourceRecordDecoding, TruncatedFixedFields)
{
	for (std::size_t length = 0; length < 10; length++) {
		std::vector<std::uint8_t> encoded(1 + length, 0x00);

		std::size_t offset = 0;

		EXPECT_THROW(dns::decodeResourceRecord(encoded, offset), std::invalid_argument) << "Fixed field bytes: " << length;
	}
}

TEST(DNSResourceRecordDecoding, MinimumFixedFields)
{
	std::vector<std::uint8_t> encoded(11, 0x00);

	std::size_t offset = 0;

	dns::ResourceRecord actual = dns::decodeResourceRecord(encoded, offset);

	EXPECT_EQ(".", actual.name);
	EXPECT_EQ(0, actual.type);
	EXPECT_EQ(0, actual.recordClass);
	EXPECT_EQ(0, actual.ttl);
	EXPECT_TRUE(actual.rdata.empty());
	EXPECT_EQ(11, offset);
}

TEST(DNSResourceRecordDecoding, TruncatedRData)
{
	std::vector<std::uint8_t> encoded {
		0x00,
		0x00, 0x01,
		0x00, 0x01,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x04,
		0xAA, 0xBB, 0xCC
	};

	std::size_t offset = 0;

	EXPECT_THROW(dns::decodeResourceRecord(encoded, offset), std::invalid_argument);
}

TEST(DNSResourceRecordDecoding, RDataLengthBoundaries)
{
	for (std::size_t length = 0; length <= 4; length++) {
		std::vector<std::uint8_t> encoded {
			0x00,
			0x00, 0x01,
			0x00, 0x01,
			0x00, 0x00, 0x00, 0x00,
			0x00, 0x04
		};

		encoded.insert(encoded.end(), length, 0xAB);

		std::size_t offset = 0;

		if (length < 4) {
			EXPECT_THROW(dns::decodeResourceRecord(encoded, offset), std::invalid_argument) << "Available RDATA bytes: " << length;
		} else {
			dns::ResourceRecord actual = dns::decodeResourceRecord(encoded, offset);

			EXPECT_EQ(4, actual.rdata.size());
			EXPECT_EQ(15, offset);
		}
	}
}

TEST(DNSResourceRecordDecoding, MaximumRDataLengthTruncated)
{
	std::vector<std::uint8_t> encoded {
		0x00,
		0x00, 0x01,
		0x00, 0x01,
		0x00, 0x00, 0x00, 0x00,
		0xFF, 0xFF
	};

	encoded.insert(encoded.end(), 65534, 0xAB);

	std::size_t offset = 0;

	EXPECT_THROW(dns::decodeResourceRecord(encoded, offset), std::invalid_argument);
}

TEST(DNSResourceRecordDecoding, TruncatedDomain)
{
	std::vector<std::uint8_t> encoded {
		0x03, 'a', 'b'
	};

	std::size_t offset = 0;

	EXPECT_THROW(dns::decodeResourceRecord(encoded, offset), std::invalid_argument);
}

TEST(DNSResourceRecordDecoding, InvalidCompressionPointer)
{
	std::vector<std::uint8_t> encoded {
		0xC0, 0x00
	};

	std::size_t offset = 0;

	EXPECT_THROW(dns::decodeResourceRecord(encoded, offset), std::invalid_argument);
}

TEST(DNSResourceRecordDecoding, InvalidStartingOffset)
{
	std::vector<std::uint8_t> encoded {
		0x00
	};

	std::size_t offset = encoded.size();

	EXPECT_THROW(dns::decodeResourceRecord(encoded, offset), std::invalid_argument);
}

TEST(DNSResourceRecordDecoding, ConsecutiveRecords)
{
	std::vector<std::uint8_t> encoded {
		0x00,
		0x00, 0x01,
		0x00, 0x01,
		0x00, 0x00, 0x00, 0x3C,
		0x00, 0x04,
		0x7F, 0x00, 0x00, 0x01,
		0x00,
		0x00, 0x1C,
		0x00, 0x01,
		0x00, 0x00, 0x01, 0x2C,
		0x00, 0x00
	};

	std::size_t offset = 0;

	dns::ResourceRecord first = dns::decodeResourceRecord(encoded, offset);

	EXPECT_EQ(1, first.type);
	EXPECT_EQ(15, offset);

	dns::ResourceRecord second = dns::decodeResourceRecord(encoded, offset);

	EXPECT_EQ(28, second.type);
	EXPECT_EQ(300, second.ttl);
	EXPECT_TRUE(second.rdata.empty());
	EXPECT_EQ(encoded.size(), offset);
}

