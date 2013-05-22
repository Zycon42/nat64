/**
 * Projekt do predmetu ISA/2011
 *
 * @file sniffer.h
 * @author Jan Dušek <xdusek17@stud.fit.vutbr.cz>
 * @date 2011
 *
 * Trida Sniffer
 */

#ifndef SNIFFER_H
#define SNIFFER_H

#include "packets.h"

#include <pcap/pcap.h>

/**
 * Sniffes packets on network interface
 */
class Sniffer
{
public:
    /**
     * Constructs Sniffer.
     * @param dev network interface to sniff
     */
    explicit Sniffer(const char* dev);
    /// Destructor
    ~Sniffer();

    /**
     * Activates sniffer.
     * @param promisc flag to set device to promiscuote mode
     * @param nonblock flag to set device to nonblocking mode
     * @param timeout read timeout in miliseconds
     * @param dir direction that packets are being captured.
     */
    void activate(bool promisc, bool nonblock, int timeout, pcap_direction_t dir = PCAP_D_INOUT);
    /**
     * Apply filter to incoming packets.
     * @param filterStr see man pcap-filter(7) for details
     */
    void applyFilter(const char* filterStr);
    /**
     * Gets next packet on device.
     * @retval pack received packet
     * @return true if success false if timeout ran off or no packets in nonblocking mode
     */
    bool getNextPacket(Packet& pack);

    /**
     * Get file descriptor.
     * @return file descriptor from which packets are read. -1 when failed
     */
    int getFileno();
private:
    /// Prevent cpy ctor and assign operator
    Sniffer(const Sniffer&);
    Sniffer& operator=(const Sniffer&);

    /// pcap handle
    pcap_t* handle;
};

#endif // SNIFFER_H
