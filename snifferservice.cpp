/**
 * Projekt do predmetu ISA/2011
 *
 * @file snifferservice.cpp
 * @author Jan Dušek <xdusek17@stud.fit.vutbr.cz>
 * @date 2011
 *
 * Trida SnifferService
 */

#include "snifferservice.h"
#include "log.h"

#include <stdexcept>
#include <errno.h>
#include <string.h>
#include <signal.h>

/// Flag set by signal handler if we should terminate.
static volatile bool sTerminateFlag = false;

/// Terminate signal handler
static void termSignalHandler(int) {
    sTerminateFlag = true;              // set flag
}

SnifferService::SnifferService() {

}

void SnifferService::registerSniffer(Sniffer* sniffer, PacketFunc func) {
    sniffers.push_back(sniffer);
    funcs.push_back(func);
}

void SnifferService::start() {
    registerSignals();

    while (!sTerminateFlag) {
        int maxfd = buildSelectSet();
        int readfds = select(maxfd + 1, &set, NULL, NULL, NULL);

        if (readfds == -1) {
            if (errno != EINTR)
                throw std::runtime_error(std::string("select: ") + strerror(errno));
            else                    // actualy EINTR is not error so continue
                pLog() << "select(): interrupted" << std::endl;
        } else if (readfds == 0) {
            pLog() << "select(): returned 0" << std::endl;
        } else
            readPackets();
    }
    pLog() << "Caught terminating signal, cleaning up..." << std::endl;
}

int SnifferService::buildSelectSet() {
    int maxfd = 0;
    FD_ZERO(&set);
    // insert sniffers filenos to fd_set
    for (size_t i = 0; i < sniffers.size(); i++) {
        int fd = sniffers[i]->getFileno();
        FD_SET(fd, &set);
        if (fd > maxfd)
            maxfd = fd;
    }
    return maxfd;
}

void SnifferService::readPackets() {
    // for each sniffer check if its ready
    for (size_t i = 0; i < sniffers.size(); i++) {
        if (FD_ISSET(sniffers[i]->getFileno(), &set)) {
            Packet pack;
            if (sniffers[i]->getNextPacket(pack))   // read packet
                funcs[i](pack);
        }
    }
}

void SnifferService::registerSignals() {
    struct sigaction act;
    act.sa_handler = termSignalHandler;
    sigemptyset(&act.sa_mask);
    sigaction(SIGTERM, &act, NULL);
    sigaction(SIGINT, &act, NULL);
    sigaction(SIGQUIT, &act, NULL);
}
