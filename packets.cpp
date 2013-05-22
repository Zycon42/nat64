/**
 * Projekt do predmetu ISA/2011
 *
 * @file packets.cpp
 * @author Jan Dušek <xdusek17@stud.fit.vutbr.cz>
 * @date 2011
 *
 * Packet structs ctors.
 */

#include "packets.h"

#include <stdexcept>

Ipv4Packet::Ipv4Packet() {
    version = 4;
    headerLen = 20;
}

Ipv4Packet::Ipv4Packet(const void* data, size_t len) {
    if (len < 20)
        throw std::runtime_error("Ipv4Packet::Ipv4Packet: packet must be minumum 20 bytes long.");

    // version is hiword of first byte in packet
    version = *(uint8_t*)data >> 4;
    if (version != 4)
        throw std::runtime_error("Ipv4Packet::Ipv4Packet: version field is not 4.");

    // in packet is actualy stored 4bit value representing num of 32bit words.
    headerLen = ((*(uint8_t*)data) & 0xf) * 4;
    if (headerLen < 20)
        throw std::runtime_error("Ipv4Packet::Ipv4Packet: headerLen.");

    tos = ((uint8_t*)data)[1];

    totalLen = ntohs(((uint16_t*)data)[1]);
    if (totalLen > len)
        throw std::runtime_error("Ipv4Packet::Ipv4Packet: totalLen in packet larger than source data len.");

    identification = ntohs(((uint16_t*)data)[2]);
    fragment = ntohs(((uint16_t*)data)[3]);
    ttl = ((uint8_t*)data)[8];
    protocol = ((uint8_t*)data)[9];
    srcAddr = ((in_addr*)data)[3];
    destAddr = ((in_addr*)data)[4];

    payload = (uint8_t*)data + headerLen;
    payloadLen = totalLen - headerLen;
}

Ipv6Packet::Ipv6Packet() {
    version = 6;
}

Ipv6Packet::Ipv6Packet(const void* data, size_t len) {
    if (len < 40)
        throw std::runtime_error("Ipv6Packet::Ipv6Packet: packet must be minumum 40 bytes long.");

    // version is hiword of first byte in packet
    version = *(uint8_t*)data >> 4;
    if (version != 6)
        throw std::runtime_error("Ipv6Packet::Ipv6Packet: version field is not 6.");

    // trafficClass is stored in bits 4-11 of first 16bit word
    trafficClass = (*(uint16_t*)data >> 4) & 0xff;
    flowLabel = 0;          //  TODO: add flow label support
    payloadLen = ntohs(((uint16_t*)data)[2]);
    nextHeader = ((uint8_t*)data)[6];
    hopLimit = ((uint8_t*)data)[7];

    // store addresses
    in6_addr* addrData = (in6_addr*)((uint8_t*)data + 8);
    srcAddr = addrData[0];
    destAddr = addrData[1];

    // ipv6 header has 40 bytes
    payload = (uint8_t*)data + 40;
}

