/**
 * Projekt do predmetu ISA/2011
 *
 * @file snifferservice.h
 * @author Jan Dušek <xdusek17@stud.fit.vutbr.cz>
 * @date 2011
 *
 * Trida SnifferService
 */

#ifndef _SNIFFERSERVICE_H_
#define _SNIFFERSERVICE_H_

#include "sniffer.h"
#include "callback.h"

#include <vector>

typedef CallBack<void, Packet> PacketFunc;

/**
 * Services multiple sniffers.
 * This service waits until some of registered sniffers has packet
 * and calls registered handler.
 */
class SnifferService
{
public:
    /// Ctor
    SnifferService();
    /**
     * Registers sniffer to service.
     * @param sniffer to register
     * @param func callback to method which will handle sniffered packet from sniffer
     */
    void registerSniffer(Sniffer* sniffer, PacketFunc func);
    /**
     * Starts service.
     * Waits in endless loop(uses select(3)) for incoming
     * packets in registered sniffers.
     * Exits when SIGTERM, SIGQUIT or SIGINT come.
     */
    void start();
private:
    int buildSelectSet();
    void readPackets();
    void registerSignals();

    std::vector<Sniffer*> sniffers;
    std::vector<PacketFunc> funcs;

    fd_set set;
};

#endif // _SNIFFERSERVICE_H_
