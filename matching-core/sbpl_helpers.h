#ifndef SBPL_HELPERS_H
#define SBPL_HELPERS_H

#include <set>
#include <string>
#include <cstdlib>
#include <array>

extern "C" {
    #include <simbple/src/platform_data/platforms.h>
    #include <simbple/src/sb/operations/data.h>
    #include <simbple/src/sb/operations/types.h>
}

#include <simbple/src/dependencies/sbpldump/convert.h>

namespace sbpl {
    /**
     * For any given operation, a couple of other operations
     * (mostly more general rules) also apply.
     * This function returns the set of names relevant operations
     * that need to be considered for matching purposes.
     */
    std::set<std::string> relevant_operations(const std::string &op);

    bool operation_default_action(const std::string &op);
}

#endif