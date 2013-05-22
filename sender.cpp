/**
 * Projekt do predmetu ISA/2011
 *
 * @file sender.cpp
 * @author Jan Dušek <xdusek17@stud.fit.vutbr.cz>
 * @date 2011
 *
 * Trida Sender
 */

#include "sender.h"
#include "checksum.h"
#include "log.h"

#include <stdexcept>

using namespace std;

Sender::Sender(const char* dev, Sender::InjectionType type) {
    int injection = type == Sender::Ipv6 ? LIBNET_RAW6_ADV :
                    ( type == Sender::Ipv4 ? LIBNET_RAW4_ADV : -1 );

    char errBuf[LIBNET_ERRBUF_SIZE];
    context = libnet_init(injection, (char*)dev, errBuf);
    if (context == NULL)
        throw runtime_error(string("libnet_init: ") + errBuf);
}

Sender::~Sender() {
    libnet_destroy(context);
}

void Sender::send(const Ipv4Packet& pack) {
    PseudoHeader pshdr = { &pack.srcAddr, &pack.destAddr, sizeof(in_addr) };
    setProtocolChecksum(pack.protocol, (void*)pack.payload, pack.payloadLen, pshdr);

    libnet_ptag_t ret;
    ret = libnet_build_ipv4(pack.totalLen, pack.tos, pack.identification,
                            pack.fragment, pack.ttl, pack.protocol, 0,
                            pack.srcAddr.s_addr, pack.destAddr.s_addr, (uint8_t*)pack.payload,
                            pack.payloadLen, context, 0);

    if (ret == -1)
        throw runtime_error(string("libnet_build_ipv4: ") + libnet_geterror(context));

    if (libnet_write(context) == -1)
        throw runtime_error(string("libnet_write: ") + libnet_geterror(context));

    libnet_clear_packet(context);
}

void Sender::send(const Ipv6Packet& pack) {
    PseudoHeader pshdr = { &pack.srcAddr, &pack.destAddr, sizeof(in6_addr) };
    setProtocolChecksum(pack.nextHeader, (void*)pack.payload, pack.payloadLen, pshdr);

    libnet_in6_addr srcAddr, destAddr;
    memcpy(&srcAddr, &pack.srcAddr, sizeof(in6_addr));
    memcpy(&destAddr, &pack.destAddr, sizeof(in6_addr));

    libnet_ptag_t ret;
    ret = libnet_build_ipv6(pack.trafficClass, pack.flowLabel, pack.payloadLen,
                            pack.nextHeader, pack.hopLimit, srcAddr,
                            destAddr, (uint8_t*)pack.payload, pack.payloadLen, context, 0);

    if (ret == -1)
        throw runtime_error(string("libnet_build_ipv6: ") + libnet_geterror(context));

    if (libnet_write(context) == -1)
        throw runtime_error(string("libnet_write: ") + libnet_geterror(context));

    libnet_clear_packet(context);
}
