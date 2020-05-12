#include <simbple/src/dependencies/sbpldump/convert.h>

#include "ruleset_helpers.h"

static size_t file_size(FILE *f)
{
    fseek(f, 0, SEEK_END);
    size_t size = ftell(f);
    fseek(f, 0, SEEK_SET);

    return size;
}

namespace ruleset {

    json parse(const char *input)
    {
        return json::parse(input);
    }

    json from_file(const char *filename)
    {
        FILE *rule_file = fopen(filename, "rb");
        if (!rule_file) {
            return nullptr;
        }

        const size_t rule_file_size = file_size(rule_file);
        char *buffer = new char[rule_file_size+1];
        if (!buffer ||
            (rule_file_size != fread(buffer, 1, rule_file_size, rule_file))) {

            if (buffer) {
                delete[] buffer;
            }

            return nullptr;
        }
        // Make sure the last byte is NULL, otherwise parsing fails.
        buffer[rule_file_size] = '\0';

        json ruleset = parse(buffer);
        delete[] buffer;

        return ruleset;
    }

    const char *dump_scheme(const json &rulebase)
    {
        return sandbox_rules_dump_scheme(rulebase.dump().c_str());
    }

    /**
     * Gets the default rule. In case of multiple default rules, the first
     * one is returned.
     */
    json get_default(const json &rulebase)
    {
        for (const json &rule : rulebase) {
            for (const std::string &op : rule["operations"]) {
                if (op == "default") {
                    return rule;
                }
            }
        }

        return nullptr;
    }

    /**
     * Injects a new sandbox rule of the form
     *      (`action` default)
     * into the supplied rulebase, replacing any existing default rule or
     * creating a new one at the start of the ruleset.
     */
    json set_default(json rulebase, std::string action)
    {
        assert(action == "allow" || action == "deny");

        bool rule_changed = false;

        for (json &rule : rulebase) {
            for (const std::string &op : rule["operations"]) {
                if (op == "default") {
                    rule["action"] = action;

                    rule_changed = true;
                    break;
                }
            }

            if (rule_changed)
                break;
        }

        if (!rule_changed) {
            json default_rule = json::object();
            default_rule["action"] = action;
            default_rule["operations"].push_back("default");

            json output = json::array();
            output.push_back(default_rule);

            std::copy(rulebase.begin(), rulebase.end(), std::back_inserter(output));

            return output;
        } else {
            return rulebase;
        }
    }

    /**
     * Removes the last sandbox rule from the `rulebase`.
     *
     * Assigns the removed rule to the out-parameter `removed` and returns a
     * modified ruleset to the caller. This modified ruleset is missing the
     * removed rule.
     */
    json remove_last_rule(const json &rulebase, size_t *last_rule_idx, json *last_rule)
    {
        assert(rulebase.size() > 0);

        *last_rule_idx = rulebase.size() - 1;
        *last_rule = rulebase.back();

        json result = json::array();
        std::copy(rulebase.begin(), rulebase.end() - 1, std::back_inserter(result));

        return result;
    }

    /**
     * Gets the nth rule of a profile
     */
    json get_nth(const json &rulebase, const size_t n)
    {
        return rulebase[n];
    }

    /**
     * Searches for the rule `rule` in the rulebase
     * and returns the corresponding index.
     *
     * It is an error to call this function with a rule that does not exist!
     */
    size_t index_for_rule(const json &rulebase, const json rule)
    {
        for (size_t i = 0; i < rulebase.size(); ++i) {
            if (rulebase[i] == rule) {
                return i;
            }
        }

        // Should never happen
        assert(false);
        return ~0;
    }
}
