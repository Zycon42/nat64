/**
 * Projekt do predmetu ISA/2011
 *
 * @file nat.cpp
 * @author Jan Dušek <xdusek17@stud.fit.vutbr.cz>
 * @date 2011
 *
 * Implementace tridy nat
 */

#include "nat.h"
#include "snifferservice.h"
#include "log.h"
#include "exceptions.h"

#include <fstream>
#include <string>
#include <stdexcept>
#include <iostream>

#include <string.h>
#include <errno.h>

#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <net/if.h>

using namespace std;

Nat::Nat(const char* rulesFile, const char* inDev, const char* outDev) :
    inDev(inDev), outDev(outDev), inSender(inDev, Sender::Ipv6), outSender(outDev, Sender::Ipv4)
{
    loadRulesFile(rulesFile);
}

void Nat::loadRulesFile(const char* fileName) {
    ifstream file(fileName);

    char nl;
    string v6addr, v4addr;
    while (file >> noskipws >> v6addr >> ws >> v4addr >> nl && nl == '\n') {
        Rule rule;
        if (!inet_pton(AF_INET6, v6addr.c_str(), &rule.addr6))
            throw runtime_error("Bad rules file: some ipv6 address is not valid");
        if (!inet_pton(AF_INET, v4addr.c_str(), &rule.addr4))
            throw runtime_error("Bad rules file: some ipv4 address is not valid");

        table.insert(rule);
    }

    // if table empty
    if (table.getSize() == 0)
        throw runtime_error("Bad rules file: contains no rules");
}

void Nat::start() {
    Sniffer inSniffer(inDev);
    inSniffer.activate(false, true, 0, PCAP_D_IN);

    // only accept incoming ipv6 packets
    ether_addr inMac = getIfaceMacAddr(inDev);
    inSniffer.applyFilter((string("ip6 and not ether src ") + ether_ntoa(&inMac)).c_str());

    Sniffer outSniffer(outDev);
    outSniffer.activate(false, true, 0, PCAP_D_IN);

    // only accept incoming ipv4 packets
    ether_addr outMac = getIfaceMacAddr(outDev);
    outSniffer.applyFilter((string("ip and not ether src ") + ether_ntoa(&outMac)).c_str());

    // create service and register sniffers onto it.
    SnifferService service;
    service.registerSniffer(&inSniffer, PacketFunc::make(*this, &Nat::handleIpv6Packet));
    service.registerSniffer(&outSniffer, PacketFunc::make(*this, &Nat::handleIpv4Packet));

    service.start();
}

void Nat::handleIpv4Packet(Packet pack) {
    try {
        Ipv4Packet ipPacket(pack.data + ETHER_HDR_LEN, pack.length - ETHER_HDR_LEN);

        char srcAddr4Buf[16], destAddr4Buf[16];
        inet_ntop(AF_INET, &ipPacket.srcAddr, srcAddr4Buf, 16);
        inet_ntop(AF_INET, &ipPacket.destAddr, destAddr4Buf, 16);
        pLog() << "Captured ipv4 packet: src=" << srcAddr4Buf << " dest=" << destAddr4Buf << endl;

        Ipv6Packet tslPack = translateIpv4(ipPacket);

        char srcAddr6Buf[40], destAddr6Buf[40];
        inet_ntop(AF_INET6, &tslPack.srcAddr, srcAddr6Buf, 40);
        inet_ntop(AF_INET6, &tslPack.destAddr, destAddr6Buf, 40);
        pLog() << "Translated to ipv6 packet: src=" << srcAddr6Buf << " dest=" << destAddr6Buf << endl;

        inSender.send(tslPack);     // send translated packet

    } catch (runtime_error& e) {
        pLog() << e.what() << " Discarding packet." << endl;
    }
}

void Nat::handleIpv6Packet(Packet pack) {
    try {
        Ipv6Packet ipPacket(pack.data + ETHER_HDR_LEN, pack.length - ETHER_HDR_LEN);

        char srcAddr6Buf[40], destAddr6Buf[40];
        inet_ntop(AF_INET6, &ipPacket.srcAddr, srcAddr6Buf, 40);
        inet_ntop(AF_INET6, &ipPacket.destAddr, destAddr6Buf, 40);
        pLog() << "Captured ipv6 packet: src=" << srcAddr6Buf << " dest=" << destAddr6Buf << endl;

        Ipv4Packet tslPack = translateIpv6(ipPacket);

        char srcAddr4Buf[16], destAddr4Buf[16];
        inet_ntop(AF_INET, &tslPack.srcAddr, srcAddr4Buf, 16);
        inet_ntop(AF_INET, &tslPack.destAddr, destAddr4Buf, 16);
        pLog() << "Translated to ipv4 packet: src=" << srcAddr4Buf << " dest=" << destAddr4Buf << endl;

        outSender.send(tslPack);        // send translate packet

    } catch (runtime_error& e) {
        pLog() << e.what() << " Discarding packet." << endl;
    }
}

ether_addr Nat::getIfaceMacAddr(const char* ifaceName) {
    int s = socket(AF_INET, SOCK_DGRAM, 0);     // create socket used as ioctl target
    if (s == -1)
        throw system_error("socket:", errno);

    ifreq buffer;                       // input for ioctl
    strcpy(buffer.ifr_name, ifaceName);         // set interface name

    // call ioctl to get mac addr to buffer
    if (ioctl(s, SIOCGIFHWADDR, &buffer) == -1)
        throw system_error("ioctl:", errno);

    close(s);                   // close socket

    // store mac addr to result
    ether_addr res;
    for (int i = 0; i < ETH_ALEN; i++)
        res.ether_addr_octet[i] = buffer.ifr_hwaddr.sa_data[i];

    return res;
}

Ipv6Packet Nat::translateIpv4(const Ipv4Packet& pack) {
    Ipv6Packet res;
    res.trafficClass = pack.tos;
    res.flowLabel = 0;
    res.payloadLen = pack.totalLen - pack.headerLen;
    res.nextHeader = pack.protocol;
    if (res.nextHeader != IPPROTO_TCP && res.nextHeader != IPPROTO_UDP)
        throw runtime_error("Nat::translateIpv4: Only TCP and UDP protocols are supported.");

    res.hopLimit = pack.ttl - 1;          // decrement ttl cuz we are router.
    if (res.hopLimit == 0) {
        // TODO: according to rfc6145 we should send ICMPv4 "TTL Exceeded" message
        throw runtime_error("Nat::translateIpv4: TTL Exceeded.");
    }

    convertSrcIpv4Addr(res.srcAddr, pack.srcAddr);
    convertDestIpv4Addr(res.destAddr, pack.destAddr);

    res.payload = pack.payload;

    return res;
}

void Nat::convertSrcIpv4Addr(in6_addr& res, in_addr addr) {
    inet_pton(AF_INET6, "64:ff9b::", &res);
    res.s6_addr32[3] = addr.s_addr;
}

void Nat::convertDestIpv4Addr(in6_addr& res, in_addr addr) {
    if (!table.lookup(addr, res))
        throw runtime_error("Nat::convertDestIpv4Addr: Address not present in table.");
}

Ipv4Packet Nat::translateIpv6(const Ipv6Packet& pack) {
    Ipv4Packet res;
    res.headerLen = 20;
    res.tos = pack.trafficClass;
    res.totalLen = pack.payloadLen + res.headerLen;
    res.identification = 0;
    res.fragment = 0x4000;

    res.ttl = pack.hopLimit - 1;          // decrement ttl cuz we are router.
    if (res.ttl == 0) {
        // TODO: according to rfc6145 we should send ICMPv6 "Hop Limit Exceeded" message
        throw runtime_error("Nat::translateIpv6: Hop Limit Exceeded.");
    }

    res.protocol = pack.nextHeader;
    if (res.protocol != IPPROTO_TCP && res.protocol != IPPROTO_UDP)
        throw runtime_error("Nat::translateIpv4: Only TCP and UDP protocols are supported.");

    convertDestIpv6Addr(res.destAddr, pack.destAddr);
    convertSrcIpv6Addr(res.srcAddr, pack.srcAddr);

    res.payload = pack.payload;
    res.payloadLen = pack.payloadLen;

    return res;
}

void Nat::convertDestIpv6Addr(in_addr& res, const in6_addr& addr) {
    // check if we have well know prefix 64:ff9b::/96
    if (addr.s6_addr16[0] != 0x6400 || addr.s6_addr16[1] != 0x9bff || addr.s6_addr32[1] != 0 || addr.s6_addr32[2] != 0)
        throw runtime_error("Nat::convertDestIpv6Addr: Address doesnt have well known prefix.");

    res.s_addr = addr.s6_addr32[3];     // last 32b word is ipv4 address
}

void Nat::convertSrcIpv6Addr(in_addr& res, const in6_addr& addr) {
    if (!table.lookup(addr, res))
        throw runtime_error("Nat::convertDestIpv6Addr: Address not present in table.");
}
