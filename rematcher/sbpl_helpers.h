#ifndef SBPL_HELPERS_H
#define SBPL_HELPERS_H

#include <set>
#include <string>
#include <cstdlib>
#include <array>

#include "sb/operations/definition.h"
#include "sb/operations/helpers.h"
#include "sb/operations/types.h"

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