/**
 * Projekt do predmetu ISA/2011
 *
 * @file nat.h
 * @author Jan Dušek <xdusek17@stud.fit.vutbr.cz>
 * @date 2011
 *
 * Trida Nat
 */

#ifndef _NAT_H_
#define _NAT_H_

#include "nattable.h"
#include "sniffer.h"
#include "sender.h"

#include <libnet.h>
#include <netinet/ether.h>

/// Static NAT64
class Nat
{
public:
    /**
     * Constructs static nat64 instance.
     * @param rulesFile file containing rules for v6 to v4 translation
     * @param inDev network interface connected to internal ipv6 network
     * @param outDev network interface connected to external ipv4 network
     */
    Nat(const char* rulesFile, const char* inDev, const char* outDev);

    /**
     * Starts nat.
     * Enters endless loop, where nat listens on given net interfaces
     * and translates addresses.
     */
    void start();
private:
    void loadRulesFile(const char* fileName);

    /**
     * Get network interface Mac(Hw) address.
     * @param ifaceName interface name (ex. eth0)
     * @return interface hw address in network byte order
     */
    ether_addr getIfaceMacAddr(const char* ifaceName);

    /// Function called by SnifferService when received ipv4 packet
    void handleIpv4Packet(Packet pack);
    /// Function called by SnifferService when received ipv4 packet
    void handleIpv6Packet(Packet pack);

    /**
     * Translates Ipv4 packet to Ipv6 packet.
     * See rfc6145 for details.
     * @param pack Ipv4 packet to translate
     * @return translated ipv6 packet
     */
    Ipv6Packet translateIpv4(const Ipv4Packet& pack);
    /**
     * Translates Ipv6 packet to Ipv4 packet.
     * See rfc6145 for details.
     * @param pack Ipv6 packet to translate
     * @return translated ipv4 packet
     */
    Ipv4Packet translateIpv6(const Ipv6Packet& pack);

    /**
     * Convert ipv4 to ipv6 address.
     * Adds well known prefix 64:ff9b::/96 (rfc6052) to ipv4 address.
     * @retval res converted ipv6 address
     * @param addr ipv4 address to convert
     */
    void convertSrcIpv4Addr(in6_addr& res, in_addr addr);
    /**
     * Convert ipv4 to ipv6 address.
     * Searches coresponding ipv6 address to given ipv4 address in nat table
     * Throws exception when not found.
     * @retval res converted ipv6 address
     * @param addr ipv4 address to convert
     */
    void convertDestIpv4Addr(in6_addr& res, in_addr addr);

    /**
     * Converts ipv6 to ipv4 address.
     * Searches coresponding ipv4 address to given ipv6 address in nat table
     * Throws exception when not found.
     * @retval res converted ipv4 address
     * @param addr ipv6 address to convert
     */
    void convertSrcIpv6Addr(in_addr& res, const in6_addr& addr);
    /**
     * Converts ip6 to ipv4 address.
     * Extracts last 32bits from ipv6 address as ipv4 address.
     * Check if ipv6 addr has well known prefix.
     * @retval res converted ipv4 address
     * @param addr ipv6 address to convert
     */
    void convertDestIpv6Addr(in_addr& res, const in6_addr& addr);

    /// Nat table for translating ip addresses
    NatTable table;

    /// Network interface connected to internal ipv6 network
    const char* inDev;
    /// Network interface connected to outer ipv4 network
    const char* outDev;

    /// Sender connected to internal ipv6 network
    Sender inSender;
    /// Sender connected to outer ipv4 network
    Sender outSender;
};

#endif // _NAT_H_
