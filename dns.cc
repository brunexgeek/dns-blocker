#include "dns.hh"
#include <stdio.h>
#include <string>


dns_header_t::dns_header_t()
{
    id = fields = qdcount = ancount = nscount = arcount = 0;
}

dns_question_t::dns_question_t()
{
    type = clazz = 0;
}

dns_question_t::dns_question_t( const dns_question_t &obj )
{
    qname = obj.qname;
    type = obj.type;
    clazz = obj.clazz;
}

dns_record_t::dns_record_t()
{
    type = clazz = ttl = 0;
}

static void decodeHeader(
    BufferIO &bio,
    dns_header_t &header )
{
    header.id = bio.readU16();
    header.fields = bio.readU16();
    header.qdcount = bio.readU16();
    header.ancount = bio.readU16();
    header.nscount = bio.readU16();
    header.arcount = bio.readU16();
}


static void decodeQuestions(
    BufferIO &bio,
    int count,
    std::vector<dns_question_t> &output )
{
    output.resize(count);

    for (auto it = output.begin(); it != output.end(); ++it)
    {
        it->qname = bio.readQName();
        it->type = bio.readU16();
        it->clazz = bio.readU16();
    }
}


void dns_decode(
    BufferIO &bio,
    dns_message_t &message )
{
    message.questions.clear();
    message.answers.clear();

    decodeHeader(bio, message.header);
    decodeQuestions(bio, message.header.qdcount, message.questions);
}


static void encodeHeader(
    BufferIO &bio,
    dns_header_t &header )
{
    bio.writeU16(header.id);
    bio.writeU16(header.fields);
    bio.writeU16(header.qdcount);
    bio.writeU16(header.ancount);
    bio.writeU16(header.nscount);
    bio.writeU16(header.arcount);
}


static void encodeQuestions(
    BufferIO &bio,
    const std::vector<dns_question_t> &input )
{
    for (auto it = input.begin(); it != input.end(); ++it)
    {
        bio.writeQName(it->qname);
        bio.writeU16(it->type);
        bio.writeU16(it->clazz);
    }
}


static void encodeRecords(
    BufferIO &bio,
    const std::vector<dns_record_t> &input )
{
    for (auto it = input.begin(); it != input.end(); ++it)
    {
        bio.writeQName(it->qname);
        bio.writeU16(it->type);
        bio.writeU16(it->clazz);
        bio.writeU32(it->ttl);
        // TODO: use record fields to write data!
        bio.writeU16(4);
        bio.writeU32(0x7F0000FE);
    }
}

void dns_encode(
    BufferIO &bio,
    dns_message_t &message )
{
    message.header.qdcount = (uint16_t) message.questions.size();
    message.header.ancount = (uint16_t) message.answers.size();
    message.header.nscount = 0;
    message.header.arcount = 0;

    encodeHeader(bio, message.header);
    encodeQuestions(bio, message.questions);
    encodeRecords(bio, message.answers);
}