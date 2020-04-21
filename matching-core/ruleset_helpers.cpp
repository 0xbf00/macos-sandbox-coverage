#include "ruleset_helpers.h"
#include "sbpl_helpers.h"

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

    static std::string dump_scheme_modifier(const json &modifier_desc, size_t padding = 0)
    {
        std::string pad(padding, ' ');

        std::string mod_name = modifier_desc["name"];

        if (modifier_desc.find("argument") != modifier_desc.end()) {
        // Modifier with an argument
            if (modifier_desc["argument"].is_string()) {
                std::string mod_arg = modifier_desc["argument"];
                return pad +"(with " + mod_name + " \"" + mod_arg + "\")";
            } else {
                long mod_arg = modifier_desc["argument"];
                return pad + "(with " + mod_name + " " + std::to_string(mod_arg) + ")";
            }
        } else {
        // No argument modifier
            return pad + "(with " + mod_name + ")";
        }
    }

    static std::string dump_scheme_filter(const json &filter_desc, size_t padding = 0)
    {
        std::string pad(padding, ' ');

        std::ostringstream filter_out;

        const std::string filter_name = filter_desc["name"];
        if (    filter_name == "require-all" ||
            filter_name == "require-any" ||
            filter_name == "require-not") {
            filter_out << pad << "(" << filter_name << std::endl;
            for (const json &subfilter : filter_desc["subfilters"]) {
                filter_out << dump_scheme_filter(subfilter, padding + 4) << std::endl;
            }
            filter_out << pad << ")" << std::endl;
        } else {
            filter_out << pad << "(" << filter_name << " ";

            const json &arguments = filter_desc["arguments"];
            for (json::const_iterator it = arguments.cbegin(); it != arguments.cend(); ++it) {
                const json &argument = *it;

                if (argument.find("alias") != argument.end()) {
                    // Alias provided, use this one.
                    const std::string alias = argument["alias"];
                    filter_out << alias;
                } else {
                    if (argument["value"].is_string()) {
                        filter_out << argument["value"];
                    } else {
                        // TODO: Handle boolean values
                        const uint64_t int_value = argument["value"];
                        filter_out << int_value;
                    }
                }
                if (it == --arguments.cend()) {
                    // Currently processing last filter argument. Special handling
                    filter_out << ")";
                } else {
                    // Place each argument on its own line
                    filter_out << std::endl << pad << "    ";
                }
            }

            // Normal filter on first level (assuming 4 as default padding)
            if (padding == 4) {
                filter_out << std::endl;
            }
        }

        return filter_out.str();
    }

    static std::string dump_scheme_rule(const json &rule_desc)
    {
        std::ostringstream rule;

        rule_desc.dump(4);

        std::string action = rule_desc["action"];
        rule << "(" << action << std::endl;

        for (const std::string &op : rule_desc["operations"]) {
            rule << "    " << op << std::endl;
        }

        if (rule_desc.count("filters") > 0) {
            for (const json &filter : rule_desc["filters"]) {
                rule << dump_scheme_filter(filter, 4);
            }
        }

        if (rule_desc.count("modifiers") > 0) {
            for (const json &modifier : rule_desc["modifiers"]) {
                rule << dump_scheme_modifier(modifier, 4);
            }
        }
        rule << ")" << std::endl;

        return rule.str();
    }

    const char *dump_scheme(const json &rulebase)
    {
        std::ostringstream output;

        output << "(version 1)" << std::endl;

        for (const json &rule : rulebase) {
            output << dump_scheme_rule(rule);
        }

        std::string output_str = output.str();

        return strdup(output_str.c_str());
    }

    /**
     * For a given input, e.g the log entry
     *      "file-read-data /private/etc/hosts"
     * not every rule is relevant.
     *
     * A rule is only relevant iff
     * it governs the usage of the file-read-data operation.
     * This is either file-read-data directly or any fallback operations
     * that might be used.
     */
    json relevant_rules_only(const json &rulebase, const json &input)
    {
        std::string op_name = input["operation"];

        json output = json::array();

        auto relevant = sbpl::relevant_operations(op_name);
        for (const json &rule : rulebase) {
            for (const std::string &current_op : rule["operations"]) {
                if (relevant.find(current_op) != relevant.end()) {
                    output.emplace_back(rule);
                    break;
                }
            }
        }

        return output;
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
