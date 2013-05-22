/**
 * Projekt do predmetu ISA/2011
 *
 * @file sniffer.cpp
 * @author Jan Dušek <xdusek17@stud.fit.vutbr.cz>
 * @date 2011
 *
 * Trida Sniffer
 */

#include "sniffer.h"
#include <netpacket/packet.h>

#include <stdexcept>

using namespace std;

Sniffer::Sniffer(const char* dev) {
    char errBuf[PCAP_ERRBUF_SIZE];
    handle = pcap_create(dev, errBuf);
    if (handle == NULL)
        throw runtime_error(string("pcap_create: ") + errBuf);
}

Sniffer::~Sniffer() {
    pcap_close(handle);
}

void Sniffer::activate(bool promisc, bool nonblock, int timeout, pcap_direction_t dir) {
    char errBuf[PCAP_ERRBUF_SIZE];
    if (pcap_setnonblock(handle, (int)nonblock, errBuf) == -1)
        throw runtime_error(string("pcap_setnonblock: ") + errBuf);

    pcap_set_promisc(handle, (int)promisc);
    pcap_set_timeout(handle, timeout);

    int err = pcap_activate(handle);
    if (err == PCAP_WARNING || err == PCAP_WARNING_PROMISC_NOTSUP)
        pcap_perror(handle, (char*)"pcap_activate");    // hope that pcap_perror wont modify that string literal :)
    else if (err == PCAP_ERROR || err == PCAP_ERROR_ACTIVATED || err == PCAP_ERROR_NO_SUCH_DEVICE ||
        err == PCAP_ERROR_PERM_DENIED || err == PCAP_ERROR_RFMON_NOTSUP || err == PCAP_ERROR_IFACE_NOT_UP
    )
        throw runtime_error(string("pcap_activate: ") + pcap_geterr(handle));

    if (pcap_setdirection(handle, dir) == -1)
        throw runtime_error(string("pcap_setdirection: ") + pcap_geterr(handle));
}

void Sniffer::applyFilter(const char* filterStr) {
    bpf_program prog;
    if (pcap_compile(handle, &prog, filterStr, 0, 0) == -1)
        throw runtime_error(string("pcap_compile: ") + pcap_geterr(handle));

    if (pcap_setfilter(handle, &prog) == -1)
        throw runtime_error(string("pcap_setfilter: ") + pcap_geterr(handle));

    pcap_freecode(&prog);
}

bool Sniffer::getNextPacket(Packet& pack) {
    pcap_pkthdr* hdr;
    const u_char* pck;
    int err = pcap_next_ex(handle, &hdr, &pck);
    if (err == 1) {
        pack.length = hdr->caplen;
        pack.data = pck;
        return true;
    } else if (err == 0)
        return false;
    else
        throw runtime_error(string("pcap_next_ex: ") + pcap_geterr(handle));
}

int Sniffer::getFileno() {
    return pcap_fileno(handle);
}
