#ifndef RULESET_HELPERS_H
#define RULESET_HELPERS_H

#include <string>
#include <sstream>

#include <nlohmann/json.hpp>

using json = nlohmann::json;

namespace ruleset {

    json parse(const char *input);
    json from_file(const char *filename);
    const char *dump_scheme(const json &rulebase);
    json relevant_rules_only(const json &rulebase, const json &input);

    /**
     * Gets the default rule. In case of multiple default rules, the first
     * one is returned.
     */
    json get_default(const json &rulebase);

    /**
     * Sets a new default action.
     * Results in a rule of the form (action default)
     */
    json set_default(json rulebase, std::string action);

    /**
     * Removes the last rule and returns it to the caller.
     */
    json remove_last_rule(const json &rulebase, size_t *last_rule_idx, json *last_rule);

    /**
     * Gets the nth rule of a profile
     */
    json get_nth(const json &rulebase, const size_t n);

    /**
     * Searches for the rule `rule` in the rulebase
     * and returns the corresponding index.
     *
     * It is an error to call this function with a rule
     * that cannot be found in rulebase!
     */
    size_t index_for_rule(const json &rulebase, const json rule);
}

#endif