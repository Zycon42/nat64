/**
 * Projekt do predmetu ISA/2011
 *
 * @file nattable.cpp
 * @author Jan Dušek <xdusek17@stud.fit.vutbr.cz>
 * @date 2011
 *
 * Implementace NatTable
 */

#include "nattable.h"

static int cmpIpv6Addr(const in6_addr& addr1, const in6_addr& addr2) {
    for (int i = 0; i < 16; i++) {
        int d = addr2.s6_addr[i] - addr1.s6_addr[i];
        if (d != 0)
            return d;
    }
    return 0;
}

NatTable::NatTable() {
}

void NatTable::insert(const Rule& rule) {
    rules.push_back(rule);
}

bool NatTable::lookup(const in6_addr& addr, in_addr& res) {
    for (size_t i = 0; i < rules.size(); i++) {
        if (cmpIpv6Addr(rules[i].addr6, addr) == 0) {
            res = rules[i].addr4;
            return true;
        }
    }
    return false;
}

bool NatTable::lookup(const in_addr& addr, in6_addr& res) {
    for (size_t i = 0; i < rules.size(); i++) {
        if (rules[i].addr4.s_addr == addr.s_addr) {
            res = rules[i].addr6;
            return true;
        }
    }
    return false;
}
