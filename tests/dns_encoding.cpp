#include <gtest/gtest.h>
#include "dns/Encoder.h"

//	DNS NAME TEST //

// VALID TESTS

TEST(DNSNameEncoding, Domain)
{
	std::vector<std::uint8_t> actual = dns::encodeDomainName("example.com");
	std::vector<std::uint8_t> expected {
		0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
		0x03, 'c', 'o', 'm',
		0x00
	};

	EXPECT_EQ(expected, actual);
}

TEST(DNSNameEncoding, SubDomain)
{
	std::vector<std::uint8_t> actual = dns::encodeDomainName("www.example.com");
	std::vector<std::uint8_t> expected {
		0x03, 'w', 'w', 'w',
		0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
		0x03, 'c', 'o', 'm',
		0x00
	};

	EXPECT_EQ(expected, actual);
}

TEST(DNSNameEncoding, Root)
{
	std::vector<std::uint8_t> actual = dns::encodeDomainName(".");
	std::vector<std::uint8_t> expected {
		0x00
	};

	EXPECT_EQ(expected, actual);
}

TEST(DNSNameEncoding, SingleLabel)
{
	std::vector<std::uint8_t> actual = dns::encodeDomainName("localhost");
	std::vector<std::uint8_t> expected {
		0x09, 'l', 'o', 'c', 'a', 'l', 'h', 'o', 's', 't',
		0x00
	};

	EXPECT_EQ(expected, actual);
}

TEST(DNSNameEncoding, MultiSubDomain)
{
	std::vector<std::uint8_t> actual = dns::encodeDomainName("a.b.c.example.com");
	std::vector<std::uint8_t> expected {
		0x01, 'a',
		0x01, 'b',
		0x01, 'c',
		0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
		0x03, 'c', 'o', 'm',
		0x00
	};

	EXPECT_EQ(expected, actual);
}

TEST(DNSNameEncoding, EndRoot)
{
	std::vector<std::uint8_t> actual = dns::encodeDomainName("example.com.");
	std::vector<std::uint8_t> expected {
		0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
		0x03, 'c', 'o', 'm',
		0x00
	};

	EXPECT_EQ(expected, actual);
}

TEST(DNSNameEncoding, MaxLength)
{
	std::string domain =
		std::string(63, 'a') + "." +
		std::string(63, 'b') + "." +
		std::string(63, 'c') + "." +
		std::string(61, 'd');
	std::vector<std::uint8_t> actual = dns::encodeDomainName(domain);
	std::vector<std::uint8_t> expected;

	expected.push_back(63);
	expected.insert(expected.end(), 63, 'a');

	expected.push_back(63);
	expected.insert(expected.end(), 63, 'b');

	expected.push_back(63);
	expected.insert(expected.end(), 63, 'c');

	expected.push_back(61);
	expected.insert(expected.end(), 61, 'd');

	expected.push_back(0x00);

	EXPECT_EQ(expected, actual);
}

TEST(DNSNameEncoding, MaxLengthTrailingDot)
{
	std::string domain =
		std::string(63, 'a') + "." +
		std::string(63, 'b') + "." +
		std::string(63, 'c') + "." +
		std::string(61, 'd') + ".";
	std::vector<std::uint8_t> actual = dns::encodeDomainName(domain);
	std::vector<std::uint8_t> expected;

	expected.push_back(63);
	expected.insert(expected.end(), 63, 'a');

	expected.push_back(63);
	expected.insert(expected.end(), 63, 'b');

	expected.push_back(63);
	expected.insert(expected.end(), 63, 'c');

	expected.push_back(61);
	expected.insert(expected.end(), 61, 'd');

	expected.push_back(0x00);

	EXPECT_EQ(expected, actual);
}

TEST(DNSNameEncoding, ManyShortLabels)
{
	std::string domain;
	std::vector<std::uint8_t> expected;

	for (int i = 0; i < 127; i++) {
		if (i > 0) {
			domain += '.';
		}

		domain += 'a';

		expected.push_back(0x01);
		expected.push_back('a');
	}

	expected.push_back(0x00);

	EXPECT_EQ(253, domain.size());
	EXPECT_EQ(255, expected.size());
	EXPECT_EQ(expected, dns::encodeDomainName(domain));
}

// Preservation
TEST(DNSNameEncoding, Preservation)
{
	std::vector<std::uint8_t> actual = dns::encodeDomainName("_tcp.ex-AMPle2.com");
	std::vector<std::uint8_t> expected {
		0x04, '_', 't', 'c', 'p',
		0x09, 'e', 'x', '-', 'A', 'M', 'P', 'l', 'e', '2',
		0x03, 'c', 'o', 'm',
		0x00
	};

	EXPECT_EQ(expected, actual);
}

// Invalid
TEST(DNSNameEncoding, EmptyDomain) {
	EXPECT_THROW(
		dns::encodeDomainName(""),
		std::invalid_argument
	);
}

TEST(DNSNameEncoding, EmptyLabel) {
	EXPECT_THROW(
		dns::encodeDomainName("example..com"),
		std::invalid_argument
	);
}

TEST(DNSNameEncoding, LeadingDot) {
	EXPECT_THROW(
		dns::encodeDomainName(".example.com"),
		std::invalid_argument
	);
}

TEST(DNSNameEncoding, DoubleTrailingDot) {
	EXPECT_THROW(
		dns::encodeDomainName("example.com.."),
		std::invalid_argument
	);
}

TEST(DNSNameEncoding, OversizedLabel) {
	EXPECT_THROW(
		dns::encodeDomainName(std::string(64, 'a')),
		std::invalid_argument
	);
}

TEST(DNSNameEncoding, OversizedDomain) {
	std::string domain =
		std::string(63, 'a') + "." +
		std::string(63, 'b') + "." +
		std::string(63, 'c') + "." +
		std::string(62, 'd');

	EXPECT_THROW(
		dns::encodeDomainName(domain),
		std::invalid_argument
	);
}

TEST(DNSNameEncoding, TooManyLabels) {
	std::string domain;

	for (int i = 0; i < 128; i++) {
		if (i > 0) {
			domain += '.';
		}

		domain += 'a';
	}

	EXPECT_THROW(
		dns::encodeDomainName(domain),
		std::invalid_argument
	);
}

TEST(DNSNameEncoding, OversizedMiddleLabel)
{
	std::string domain = "a." + std::string(64, 'b') + ".com";

	EXPECT_THROW(
		dns::encodeDomainName(domain),
		std::invalid_argument
	);
}

/// DNS HEADER TEST ///

TEST(DNSHeaderEncoding, Default)
{
	dns::Header header;
	std::vector<std::uint8_t> actual = dns::encodeHeader(header);
	std::vector<std::uint8_t> expected {
		0x00, 0x00,
		0x00, 0x00,
		0x00, 0x00,
		0x00, 0x00,
		0x00, 0x00,
		0x00, 0x00
	};

	EXPECT_EQ(expected, actual);
}

TEST(DNSHeaderEncoding, Standard)
{
	dns::Header header;
	header.id = 0x1234;
	header.flags = 0x0100;
	header.questionCount = 0x0001;
	std::vector<std::uint8_t> actual = dns::encodeHeader(header);
	std::vector<std::uint8_t> expected {
		0x12, 0x34,
		0x01, 0x00,
		0x00, 0x01,
		0x00, 0x00,
		0x00, 0x00,
		0x00, 0x00
	};

	EXPECT_EQ(expected, actual);
}

TEST(DNSHeaderEncoding, AllFields)
{
	dns::Header header;
	header.id = 0xFFEE;
	header.flags = 0xDDCC;
	header.questionCount = 0xBBAA;
	header.answerCount = 0x9988;
	header.authorityCount = 0x7766;
	header.additionalCount = 0x5544;
	std::vector<std::uint8_t> actual = dns::encodeHeader(header);
	std::vector<std::uint8_t> expected {
		0xFF, 0xEE,
		0xDD, 0xCC,
		0xBB, 0xAA,
		0x99, 0x88,
		0x77, 0x66,
		0x55, 0x44
	};

	EXPECT_EQ(expected, actual);
}

/// QUESTION ENCODING ///
// Valid
TEST(DNSQuestionEncoding, Standard) {
	dns::Question question("example.com", dns::QType::A, dns::QClass::IN);
	std::vector<std::uint8_t> expected {
		0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
		0x03, 'c', 'o', 'm',
		0x00,
		0x00, 0x01,
		0x00, 0x01
	};
	std::vector<std::uint8_t> actual = dns::encodeQuestion(question);

	EXPECT_EQ(expected, actual);
}

TEST(DNSQuestionEncoding, Different) {
	dns::Question question("example.com", dns::QType::AAAA, dns::QClass::CH);
	std::vector<std::uint8_t> expected {
		0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
		0x03, 'c', 'o', 'm',
		0x00,
		0x00, 0x1C,
		0x00, 0x03
	};
	std::vector<std::uint8_t> actual = dns::encodeQuestion(question);

	EXPECT_EQ(expected, actual);
}

TEST(DNSQuestionEncoding, Custom) {
	dns::Question question("example.com", static_cast<dns::QType>(0xFEDC), static_cast<dns::QClass>(0xBA98));
	std::vector<std::uint8_t> expected {
		0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
		0x03, 'c', 'o', 'm',
		0x00,
		0xFE, 0xDC,
		0xBA, 0x98
	};
	std::vector<std::uint8_t> actual = dns::encodeQuestion(question);

	EXPECT_EQ(expected, actual);
}

// Invalid
TEST(DNSQuestionEncoding, InvalidDomain) {
	dns::Question question("example..com", dns::QType::AAAA, dns::QClass::CH);
	
	EXPECT_THROW(dns::encodeQuestion(question), std::invalid_argument);
}

/// QUERY TESTING ///
TEST(DNSQueryEncoding, Standard) {
	dns::Header header;
	header.id = 0xABCD;
	header.flags = 0x0100;
	header.questionCount = 0x0001;

	dns::Question question("example.com", dns::QType::A);

	std::vector<std::uint8_t> expected {
		0xAB, 0xCD, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x07, 0x65, 0x78, 0x61, 0x6D, 0x70, 0x6C, 0x65, 0x03, 0x63, 0x6F, 0x6D, 0x00, 0x00, 0x01, 0x00, 0x01
	};

	std::vector<std::uint8_t> actual = dns::encodeQuery(header, question);

	EXPECT_EQ(expected, actual);
}

TEST(DNSQueryEncoding, InvalidQDCount) {
	dns::Header header;
	header.id = 0xABCD;
	header.flags = 0x0100;
	header.questionCount = 0x0002;

	dns::Question question("example.com", dns::QType::A);

	EXPECT_THROW(dns::encodeQuery(header, question), std::invalid_argument);
}