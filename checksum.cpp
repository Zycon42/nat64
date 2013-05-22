/**
 * Projekt do predmetu ISA/2011
 *
 * @file checksum.cpp
 * @author Jan Dušek <xdusek17@stud.fit.vutbr.cz>
 * @date 2011
 *
 * Internet checksum
 */

#include "checksum.h"

#include <arpa/inet.h>
#include <libnet.h>

static int computeChecksum(const uint16_t* data, int len) {
    int sum = 0;

    while (len > 1) {
        sum += *data++;
        len -= 2;
    }

    if (len == 1) {
        uint16_t lastByte = 0;
        *(uint8_t *)&lastByte = *(uint8_t *)data;
        sum += lastByte;
    }

    return sum;
}

bool setProtocolChecksum(uint8_t proto, void* data, size_t dataLen, PseudoHeader header) {
    switch (proto) {
        case IPPROTO_TCP: {
            libnet_tcp_hdr* hdr = (libnet_tcp_hdr*)data;
            hdr->th_sum = 0;            // zero checksum

            int sum = computeChecksum((const uint16_t*)header.srcAddr, header.addrLen);
            sum += computeChecksum((const uint16_t*)header.destAddr, header.addrLen);
            sum += ntohs(proto + dataLen);
            sum += computeChecksum((const uint16_t*)data, dataLen);

            while (sum >> 16)
                sum = (sum & 0xffff) + (sum >> 16);

            hdr->th_sum = ~sum;
            break;
        }
        case IPPROTO_UDP: {
            libnet_udp_hdr* hdr = (libnet_udp_hdr*)data;
            hdr->uh_sum = 0;

            int sum = computeChecksum((const uint16_t*)header.srcAddr, header.addrLen);
            sum += computeChecksum((const uint16_t*)header.destAddr, header.addrLen);
            sum += ntohs(proto + dataLen);
            sum += computeChecksum((const uint16_t*)data, dataLen);

            while (sum >> 16)
                sum = (sum & 0xffff) + (sum >> 16);

            hdr->uh_sum = ~sum;
            break;
        }
        default:
            return false;
    }
    return true;
}


