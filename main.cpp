/**
 * Projekt do predmetu ISA/2011
 *
 * @file main.cpp
 * @author Jan Dušek <xdusek17@stud.fit.vutbr.cz>
 * @date 2011
 *
 * Funkce main a zpracovani parametru
 */

#include "nat.h"
#include "log.h"

#include <iostream>
#include <string>
#include <stdexcept>
#include <cstdlib>

using namespace std;

/// Parsed program arguments
struct Params {
    /// device connected to internal ipv6 network
    char* inDev;
    /// device connected to external ipv4 network
    char* outDev;
    /// name of file with static rules for 6to4 translation
    char* rulesFile;
};

static const char* USAGE = "nat64 -i INTERFACE -o INTERFACE -r FILE";
static const char* HELP = "Static NAT64 implementation see RFC6146 for details\n\n"
                          "     -i INTERFACE    Interface connected to ipv6 network\n"
                          "     -o INTERFACE    Interface connected to ipv4 network\n"
                          "     -r FILE         File with static rules for 6to4 translation\n";

void printHelp() {
    cout << USAGE << "\n" << HELP;
}

/**
 * Parse cmd-line arguments.
 * @param argc argument count
 * @param argv argument vector
 * @return parsed params
 */
Params parseParams(int argc, char** argv) {
    if (argc == 1 || (argc == 2 && string(argv[1]) == "-h")) {
        printHelp();
        exit(0);
    }

    if (argc != 7)
        throw runtime_error("Bad argument count");

    Params res;

    int opt = 1;
    while (opt < 7) {
        if (string(argv[opt]) == "-i") {
            res.inDev = argv[opt + 1];
            opt += 2;
        } else if (string(argv[opt]) == "-o") {
            res.outDev = argv[opt + 1];
            opt += 2;
        } else if (string(argv[opt]) == "-r") {
            res.rulesFile = argv[opt + 1];
            opt += 2;
        } else
            throw runtime_error(string(argv[opt]) + " is not option");
    }

    if (!res.inDev || !res.outDev || !res.rulesFile)
        throw runtime_error("Some option is missing");

    return res;
}

int main(int argc, char** argv) {

    try {
        Params params = parseParams(argc, argv);

        Nat nat(params.rulesFile, params.inDev, params.outDev);
        nat.start();
    } catch (exception& e) {
        pError() << e.what() << endl;
    }
}
