
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


TEST(DNSMessageDecoding, QuestionAndAnswer)
{
	std::vector<std::uint8_t> encoded {
		0x12, 0x34, 0x81, 0x80,
		0x00, 0x01, 0x00, 0x01,
		0x00, 0x00, 0x00, 0x00,
		0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
		0x03, 'c', 'o', 'm', 0x00,
		0x00, 0x01, 0x00, 0x01,
		0xC0, 0x0C,
		0x00, 0x01, 0x00, 0x01,
		0x00, 0x00, 0x0E, 0x10,
		0x00, 0x04,
		0x5D, 0xB8, 0xD7, 0x0E
	};

	dns::DNSMessage actual = dns::decodeDNSMessage(encoded);

	std::vector<std::uint8_t> expectedRData {
		0x5D, 0xB8, 0xD7, 0x0E
	};

	EXPECT_EQ(0x1234, actual.header.id);
	EXPECT_EQ(0x8180, actual.header.flags);
	EXPECT_EQ(1, actual.questions.size());
	EXPECT_EQ(1, actual.answers.size());
	EXPECT_TRUE(actual.authorities.empty());
	EXPECT_TRUE(actual.additionals.empty());
	EXPECT_EQ("example.com", actual.questions[0].domainName);
	EXPECT_EQ(dns::QType::A, actual.questions[0].qType);
	EXPECT_EQ(dns::QClass::IN, actual.questions[0].qClass);
	EXPECT_EQ("example.com", actual.answers[0].name);
	EXPECT_EQ(1, actual.answers[0].type);
	EXPECT_EQ(1, actual.answers[0].recordClass);
	EXPECT_EQ(3600, actual.answers[0].ttl);
	EXPECT_EQ(expectedRData, actual.answers[0].rdata);
	EXPECT_EQ(41, actual.answers[0].rdataStart);
	EXPECT_EQ(encoded, actual.packet);
}

TEST(DNSMessageDecoding, MultipleAnswers)
{
	std::vector<std::uint8_t> encoded {
		0x12, 0x34, 0x81, 0x80,
		0x00, 0x01, 0x00, 0x02,
		0x00, 0x00, 0x00, 0x00,
		0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
		0x03, 'c', 'o', 'm', 0x00,
		0x00, 0x01, 0x00, 0x01,
		0xC0, 0x0C,
		0x00, 0x01, 0x00, 0x01,
		0x00, 0x00, 0x00, 0x3C,
		0x00, 0x04,
		0x7F, 0x00, 0x00, 0x01,
		0xC0, 0x0C,
		0x00, 0x01, 0x00, 0x01,
		0x00, 0x00, 0x01, 0x2C,
		0x00, 0x04,
		0x7F, 0x00, 0x00, 0x02
	};

	dns::DNSMessage actual = dns::decodeDNSMessage(encoded);

	std::vector<std::uint8_t> expectedFirst {
		0x7F, 0x00, 0x00, 0x01
	};

	std::vector<std::uint8_t> expectedSecond {
		0x7F, 0x00, 0x00, 0x02
	};

	EXPECT_EQ(1, actual.questions.size());
	EXPECT_EQ(2, actual.answers.size());
	EXPECT_EQ("example.com", actual.answers[0].name);
	EXPECT_EQ("example.com", actual.answers[1].name);
	EXPECT_EQ(60, actual.answers[0].ttl);
	EXPECT_EQ(300, actual.answers[1].ttl);
	EXPECT_EQ(expectedFirst, actual.answers[0].rdata);
	EXPECT_EQ(expectedSecond, actual.answers[1].rdata);
	EXPECT_EQ(41, actual.answers[0].rdataStart);
	EXPECT_EQ(57, actual.answers[1].rdataStart);
	EXPECT_EQ(encoded, actual.packet);
}

TEST(DNSMessageDecoding, AllSections)
{
	std::vector<std::uint8_t> encoded {
		0xAB, 0xCD, 0x81, 0x80,
		0x00, 0x01, 0x00, 0x01,
		0x00, 0x01, 0x00, 0x01,
		0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
		0x03, 'c', 'o', 'm', 0x00,
		0x00, 0x01, 0x00, 0x01,
		0xC0, 0x0C,
		0x00, 0x01, 0x00, 0x01,
		0x00, 0x00, 0x00, 0x3C,
		0x00, 0x04,
		0x7F, 0x00, 0x00, 0x01,
		0xC0, 0x0C,
		0x00, 0x02, 0x00, 0x01,
		0x00, 0x00, 0x01, 0x2C,
		0x00, 0x02,
		0xC0, 0x0C,
		0xC0, 0x0C,
		0x00, 0x01, 0x00, 0x01,
		0x00, 0x00, 0x00, 0x78,
		0x00, 0x04,
		0x7F, 0x00, 0x00, 0x02
	};

	dns::DNSMessage actual = dns::decodeDNSMessage(encoded);

	EXPECT_EQ(0xABCD, actual.header.id);
	EXPECT_EQ(1, actual.questions.size());
	EXPECT_EQ(1, actual.answers.size());
	EXPECT_EQ(1, actual.authorities.size());
	EXPECT_EQ(1, actual.additionals.size());
	EXPECT_EQ(1, actual.answers[0].type);
	EXPECT_EQ(2, actual.authorities[0].type);
	EXPECT_EQ(1, actual.additionals[0].type);
	EXPECT_EQ("example.com", actual.answers[0].name);
	EXPECT_EQ("example.com", actual.authorities[0].name);
	EXPECT_EQ("example.com", actual.additionals[0].name);
	EXPECT_EQ(41, actual.answers[0].rdataStart);
	EXPECT_EQ(57, actual.authorities[0].rdataStart);
	EXPECT_EQ(71, actual.additionals[0].rdataStart);
	EXPECT_EQ(encoded, actual.packet);
}

TEST(DNSMessageDecoding, HeaderOnly)
{
	std::vector<std::uint8_t> encoded {
		0x12, 0x34, 0x81, 0x80,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00
	};

	dns::DNSMessage actual = dns::decodeDNSMessage(encoded);

	EXPECT_EQ(0x1234, actual.header.id);
	EXPECT_EQ(0x8180, actual.header.flags);
	EXPECT_TRUE(actual.questions.empty());
	EXPECT_TRUE(actual.answers.empty());
	EXPECT_TRUE(actual.authorities.empty());
	EXPECT_TRUE(actual.additionals.empty());
	EXPECT_EQ(encoded, actual.packet);
}

TEST(DNSMessageDecoding, TruncatedHeader)
{
	for (std::size_t length = 0; length < 12; length++) {
		std::vector<std::uint8_t> encoded(length, 0x00);

		EXPECT_THROW(dns::decodeDNSMessage(encoded), std::invalid_argument) << "Header bytes: " << length;
	}
}

TEST(DNSMessageDecoding, TruncatedQuestion)
{
	std::vector<std::uint8_t> encoded {
		0x12, 0x34, 0x81, 0x80,
		0x00, 0x01, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
		0x03, 'c', 'o', 'm', 0x00,
		0x00, 0x01
	};

	EXPECT_THROW(dns::decodeDNSMessage(encoded), std::invalid_argument);
}

TEST(DNSMessageDecoding, TruncatedAnswer)
{
	std::vector<std::uint8_t> encoded {
		0x12, 0x34, 0x81, 0x80,
		0x00, 0x00, 0x00, 0x01,
		0x00, 0x00, 0x00, 0x00,
		0xC0, 0x0C,
		0x00, 0x01, 0x00, 0x01
	};

	EXPECT_THROW(dns::decodeDNSMessage(encoded), std::invalid_argument);
}

TEST(DNSMessageDecoding, MissingDeclaredAnswer)
{
	std::vector<std::uint8_t> encoded {
		0x12, 0x34, 0x81, 0x80,
		0x00, 0x00, 0x00, 0x01,
		0x00, 0x00, 0x00, 0x00
	};

	EXPECT_THROW(dns::decodeDNSMessage(encoded), std::invalid_argument);
}

TEST(DNSMessageDecoding, MissingDeclaredAuthority)
{
	std::vector<std::uint8_t> encoded {
		0x12, 0x34, 0x81, 0x80,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x01, 0x00, 0x00
	};

	EXPECT_THROW(dns::decodeDNSMessage(encoded), std::invalid_argument);
}

TEST(DNSMessageDecoding, MissingDeclaredAdditional)
{
	std::vector<std::uint8_t> encoded {
		0x12, 0x34, 0x81, 0x80,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x01
	};

	EXPECT_THROW(dns::decodeDNSMessage(encoded), std::invalid_argument);
}

TEST(DNSMessageDecoding, UnexpectedTrailingBytes)
{
	std::vector<std::uint8_t> encoded {
		0x12, 0x34, 0x81, 0x80,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0xAA
	};

	EXPECT_THROW(dns::decodeDNSMessage(encoded), std::invalid_argument);
}

TEST(DNSMessageDecoding, InvalidCompressedName)
{
	std::vector<std::uint8_t> encoded {
		0x12, 0x34, 0x81, 0x80,
		0x00, 0x01, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0xC0, 0x0C,
		0x00, 0x01, 0x00, 0x01
	};

	EXPECT_THROW(dns::decodeDNSMessage(encoded), std::invalid_argument);
}

TEST(DNSMessageDecoding, ZeroLengthRData)
{
	std::vector<std::uint8_t> encoded {
		0x12, 0x34, 0x81, 0x80,
		0x00, 0x00, 0x00, 0x01,
		0x00, 0x00, 0x00, 0x00,
		0x00,
		0x00, 0x10, 0x00, 0x01,
		0x00, 0x00, 0x00, 0x3C,
		0x00, 0x00
	};

	dns::DNSMessage actual = dns::decodeDNSMessage(encoded);

	EXPECT_EQ(1, actual.answers.size());
	EXPECT_EQ(".", actual.answers[0].name);
	EXPECT_EQ(16, actual.answers[0].type);
	EXPECT_TRUE(actual.answers[0].rdata.empty());
	EXPECT_EQ(23, actual.answers[0].rdataStart);
	EXPECT_EQ(encoded, actual.packet);
}

TEST(DNSMessageDecoding, MultipleQuestions)
{
	std::vector<std::uint8_t> encoded {
		0x12, 0x34, 0x01, 0x00,
		0x00, 0x02, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
		0x03, 'c', 'o', 'm', 0x00,
		0x00, 0x01, 0x00, 0x01,
		0xC0, 0x0C,
		0x00, 0x1C, 0x00, 0x01
	};

	dns::DNSMessage actual = dns::decodeDNSMessage(encoded);

	EXPECT_EQ(2, actual.questions.size());
	EXPECT_EQ("example.com", actual.questions[0].domainName);
	EXPECT_EQ("example.com", actual.questions[1].domainName);
	EXPECT_EQ(dns::QType::A, actual.questions[0].qType);
	EXPECT_EQ(dns::QType::AAAA, actual.questions[1].qType);
	EXPECT_TRUE(actual.answers.empty());
	EXPECT_EQ(encoded, actual.packet);
}
