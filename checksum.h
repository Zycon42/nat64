/**
 * Projekt do predmetu ISA/2011
 *
 * @file checksum.h
 * @author Jan Dušek <xdusek17@stud.fit.vutbr.cz>
 * @date 2011
 *
 * Internet checksum
 */

#ifndef _CHECKSUM_H_
#define _CHECKSUM_H_

#include <stdint.h>
#include <stdlib.h>

/// Pseudo header for checksum computing
struct PseudoHeader
{
    const void* srcAddr;
    const void* destAddr;
    size_t addrLen;
};

/**
 * Computes and sets checksum for protocol proto
 * Supports TCP and UDP protocols which requires pseudoheader
 * @param proto protocol(v4) or next header(v6) field in ip header
 * @param data protocol header + payload
 * @param dataLen size of data
 * @param header pseudo header containing ip addresses
 * @return if successful
 */
bool setProtocolChecksum(uint8_t proto, void* data, size_t dataLen, PseudoHeader header);

#endif  // _CHECKSUM_H_
