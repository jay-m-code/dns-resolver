#include "dns/QueryBuilder.h"
#include "dns/Encoder.h"

std::vector<std::uint8_t> dns::buildQuery(const Question& question, std::uint16_t id) {
    dns::Header header;
    header.id = id;
    header.questionCount = 0x0001;
    header.flags = 0x0100;
    header.answerCount = header.authorityCount = header.additionalCount = 0;

    return dns::encodeQuery(header, question);
}