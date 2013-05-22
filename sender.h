/**
 * Projekt do predmetu ISA/2011
 *
 * @file sender.h
 * @author Jan Dušek <xdusek17@stud.fit.vutbr.cz>
 * @date 2011
 *
 * Trida Sender
 */

#ifndef _SENDER_H
#define _SENDER_H_

#include "packets.h"

#include <libnet.h>

class Sender
{
public:
    enum InjectionType {
        Ipv4,
        Ipv6
    };

    explicit Sender(const char* dev, InjectionType type);
    virtual ~Sender();

    void send(const Ipv4Packet& pack);
    void send(const Ipv6Packet& pack);
private:
    Sender(const Sender&);
    Sender& operator=(const Sender&);

    libnet_t* context;
};

#endif // _SENDER_H_
