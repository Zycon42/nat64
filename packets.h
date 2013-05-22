/**
 * Projekt do predmetu ISA/2011
 *
 * @file packets.h
 * @author Jan Dušek <xdusek17@stud.fit.vutbr.cz>
 * @date 2011
 *
 * Packet structs
 */

#ifndef _PACKETS_H_
#define _PACKETS_H_

#include <stddef.h>
#include <stdint.h>

#include <arpa/inet.h>

/// Raw packet
struct Packet {
    /// data length
    size_t length;
    /// packet data
    const u_char* data;
};

/**
 * Ipv4 Packet
 */
struct Ipv4Packet
{
    Ipv4Packet();
    Ipv4Packet(const void* data, size_t len);

    uint8_t version;            /// Ip version must be 4
    uint8_t headerLen;          /// Header length
    uint8_t tos;                /// Type of service
    uint16_t totalLen;          /// Header + payload length
    uint16_t identification;    /// id of fragment
    uint16_t fragment;          /// first 3 bits are fragment frags rest is fragment offset
    uint8_t ttl;                /// Time to live
    uint8_t protocol;           /// Protocol type in payload
    in_addr srcAddr;            /// Source ip address
    in_addr destAddr;           /// Destination ip address

    const void* payload;        /// Payload data (just pointer this class does NOT own this data)
    uint16_t payloadLen;          /// Payload length(not part of header its computed as totalLen - headerLen)
};

struct Ipv6Packet
{
    Ipv6Packet();
    Ipv6Packet(const void* data, size_t len);

    uint8_t version;            /// Ip version must be 6
    uint8_t trafficClass;       /// Type of service
    uint32_t flowLabel;         /// Experimental
    uint16_t payloadLen;        /// Length of payload
    uint8_t nextHeader;         /// Protocol type in payload
    uint8_t hopLimit;           /// Time to live
    in6_addr srcAddr;           /// Source ip address
    in6_addr destAddr;          /// Dest ip address

    const void* payload;        /// Payload data (just pointer this class does NOT own this data)
};

#endif // _PACKETS_H_
