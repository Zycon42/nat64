/**
 * Projekt do predmetu ISA/2011
 *
 * @file nattable.h
 * @author Jan Dušek <xdusek17@stud.fit.vutbr.cz>
 * @date 2011
 *
 * Rozhrani staticke natovaci tabulky
 */

#ifndef _NATTABLE_H_
#define _NATTABLE_H_

#include <vector>

#include <netinet/in.h>

/// rule in table
struct Rule {
    in6_addr addr6;
    in_addr addr4;
};

/**
 * Static nat table
 * Contains rules (turples v6 - v4 address)
 */
class NatTable
{
public:
    /// Ctor
    NatTable();

    /// Insert rule to table
    void insert(const Rule& rule);

    /// lookup in table for v4 address with v6 address as key
    bool lookup(const in6_addr& addr, in_addr& res);
    /// lookup in table for v6 address with v4 address as key
    bool lookup(const in_addr& addr, in6_addr& res);

    /// Get table size
    size_t getSize() const { return rules.size(); }
private:
    std::vector<Rule> rules;
};

#endif // _NATTABLE_H_
