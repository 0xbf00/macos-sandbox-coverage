/**
 * This program matches input log rules with a ruleset, figuring
 * out which rule in the ruleset matches with the given input.
 *
 * Here, we make use of sandbox interna:
 * We spawn processes, once process per rule, and check using
 * sandbox_check API whether the input is allowed or not. Afterwards,
 * the results of all calls are combined and the rule number given to
 * the user.
 *
 * Note that the input ruleset should be provided in JSON format,
 * which can be generated by the `sbpl` tool.
 */

#include <iostream>
#include <sstream>
#include <cstdlib>
#include <cstdint>
#include <string>
#include <set>
#include <algorithm>
#include <cassert>

#include <ctime>
#include <unistd.h>
#include <sys/mman.h>

extern "C" {
    #include "simbple/src/platform_data/platforms.h"
    #include "simbple/src/sb/operations/data.h"
    #include "simbple/src/sb/operations/types.h"
}

#include <nlohmann/json.hpp>

using json = nlohmann::json;

enum sandbox_match_status {
    SANDBOX_INCONSISTENT = 0,
    SANDBOX_CONSISTENT = 1,
    SANDBOX_EXTERNAL = 2
};

/**
 * Round up the `size` to the next largest size that
 * is aligned to `alignment`
 */
size_t align_to_pagesize(const size_t size)
{
    const size_t PAGESIZE = getpagesize();
    return ((size + PAGESIZE-1) & ~(PAGESIZE-1));
}

void usage(const char *program_name)
{
    std::cerr << "Usage: " << program_name
    << " ruleset.json log_entries.json"
    << std::endl;
}

size_t file_size(FILE *f)
{
    fseek(f, 0, SEEK_END);
    size_t size = ftell(f);
    fseek(f, 0, SEEK_SET);

    return size;
}

namespace sbpl {
    /**
     * For any given operation, a couple of other operations
     * (mostly more general rules) also apply.
     * This function returns the set of names relevant operations
     * that need to be considered for matching purposes.
     */
    std::set<std::string> relevant_operations(const std::string &op)
    {
        std::set<std::string> result;
        result.insert(op);

        const operation_info_t *op_info = operation_info_for_name(op.c_str());
        if (op_info->node_type == TERMINAL_NODE) {
            // Terminal nodes mean no other operation may interfere.
            return result;
        }

        while (true) {
            op_info = operation_info_for_idx(op_info->fallback_op);

            const size_t idx = operation_idx_for_operation_info(op_info);
            std::string op_name = operation_name_for_idx(idx);

            auto res = result.insert(op_name);
            
            // Stop if we have already processed this operation name
            if (!std::get<1>(res)) {
                break;
            }
        }

        return result;
    }

    bool operation_default_action(const std::string &op)
    {
        const operation_info_t *op_info = operation_info_for_name(op.c_str());
        return op_info->action;
    }
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
     * Searches for the rule `rule` in the rulebase and returns the corresponding
     * index.
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

extern "C" {
    // Forward declare SPI from sandbox/private.h.
    enum sandbox_filter_type {
      SANDBOX_FILTER_NONE,
      SANDBOX_FILTER_PATH,
      SANDBOX_FILTER_GLOBAL_NAME,
      SANDBOX_FILTER_LOCAL_NAME,
      SANDBOX_FILTER_APPLEEVENT_DESTINATION,
      SANDBOX_FILTER_RIGHT_NAME,
      SANDBOX_FILTER_PREFERENCE_DOMAIN,
      SANDBOX_FILTER_KEXT_BUNDLE_ID,
      SANDBOX_FILTER_INFO_TYPE,
      SANDBOX_FILTER_NOTIFICATION,
      // Custom type
      SANDBOX_FILTER_UNKNOWN,
    };
    extern const enum sandbox_filter_type SANDBOX_CHECK_NO_REPORT;
    extern const enum sandbox_filter_type SANDBOX_CHECK_CANONICAL;
    int sandbox_check(pid_t pid, const char *operation,
                      int type, ...);

    int sandbox_init_with_parameters(const char *profile, uint64_t flags, const char *const parameters[], char **errorbuf);
}

/**
 * Attempts to initialize the sandbox for the caller using the given profile.
 * Returns 0 on success.
 */
int sandbox_initialize(const char *profile)
{
    char *sandbox_error = NULL;

    int success = sandbox_init_with_parameters(profile, 0, NULL, &sandbox_error);
    
    return !(success == 0 && sandbox_error == NULL);
}

/**
 * Returns the filter type required for sandbox_check for
 * the specified operation. Generally and when defining
 * sandbox profiles, there is no such mapping, because
 * multiple types of filters can be specified for each
 * operation. However, logs of sandbox operations contain
 * a single type of resource for each operation only, and
 * that type of resource has to be given to sandbox_check
 * in order for sandbox_check to succeed.
 *
 * For file* operations, which make up the majority of
 * sandbox log output, we only want to check the PATH.
 * For all other operations, the mapping is not clear and
 * a result of SANDBOX_FILTER_UNKNOWN is returned, and the
 * resulting sandbox_check call should be repeated for each
 * and every filter type. It is worth noting that during testing,
 * quite a few operations could not be checked using sandbox_check,
 * because no matter the flags used, the result was not correct.
 * It is unknown if this is a limitation in Apple's API or if some
 * flags require more complex data structures that we do not construct here
 * (so far, everything is a string.)
 *
 * The performance impact of this measure should be acceptable,
 * because the majority of operations are file-* operations,
 * which we have already seen.
 */
int sandbox_filter_type_for_op(const char *operation)
{
    if (!strncmp("file", operation, strlen("file")))
        return SANDBOX_FILTER_PATH;

    // It is possible to register both local and global names.
    // However, we don't know which one was registered, because the log
    // files do not contain that information. Since the default application
    // profile always allows registering local names, we check only for
    // global names, to reduce the number of false matches.
    // Obviously, this increases the number of inconsistent matches (
    // everything that was previously matched to the local version and
    // that is not allowed to be global is now matched inconsistently.)
    if (!strncmp(operation, "mach-register", strlen("mach-register")))
        return SANDBOX_FILTER_GLOBAL_NAME;

    return SANDBOX_FILTER_UNKNOWN;
}

/**
 * Check whether the input rule is allowed in the current sandbox.
 * Similar functionality to the sandbox_check functionality, however
 * this function encapsulates much of the functionality of parameter
 * choice.
 * Returns values from the sandbox_check API.
 */
int sandbox_check_custom(const json &input)
{
    std::string operation = input["operation"];
    int filter_type = sandbox_filter_type_for_op(operation.c_str());

    std::string argument;

    if (input.find("argument") != input.end()) {
        argument = input["argument"];
    }

    pid_t pid = getpid();

    if (argument != "") {
        if (filter_type == SANDBOX_FILTER_UNKNOWN) {
            // Try every filter type, return true if any one returned true.
            // Note: This only works because the sandbox's default decision is deny!
            // If the default decision were allow, this would basically always return true!
            // Because, given the following excerpt of a profile:
            // (allow default)
            // (deny file* (subpath "/usr"))
            // sandbox_check would return 0 for basically any invalid filter type
            for (int current_filter = SANDBOX_FILTER_PATH; 
                 current_filter != SANDBOX_FILTER_UNKNOWN; 
                 ++current_filter) {
                int res = sandbox_check(pid, operation.c_str(), SANDBOX_CHECK_NO_REPORT | current_filter, argument.c_str());
                if (res == 0 /* allowed */) {
                    return 0;
                }
            }

            // sandbox_check never returned 0, so return false
            return 1;
        }

        return sandbox_check(getpid(), operation.c_str(), 
            SANDBOX_CHECK_NO_REPORT | filter_type,
            argument.c_str());

    } else {
        return sandbox_check(getpid(), operation.c_str(), 
            SANDBOX_CHECK_NO_REPORT | SANDBOX_FILTER_NONE);
    }
}

/**
 * The main problem with this approach is the need to generate thousands
 * and thousands of different processed, to use sandbox_check with different
 * profiles. To somewhat combat the immense slowdown, we use batch processing
 */
bool sandbox_check_bulk_for_profile(const char *profile, const json &inputs, int *results)
{
    assert(results);
    assert(inputs != nullptr);
    assert(profile != nullptr);

    // sandbox_check returns 0 or 1, meaning a single bit suffices for this step.
    // However, to ease memory management, we use a single byte to store the result.
    // mmap is used, because the resulting memory can be used by fork()ed processes.
    static const size_t map_size = align_to_pagesize(sizeof(uint8_t) * inputs.size());
    static uint8_t *temp = NULL;
    if (temp == NULL) {
        temp = (uint8_t *)mmap(NULL, map_size, PROT_READ | PROT_WRITE,
                    MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    }

    assert(temp);

    memset(temp, 2, map_size);

    pid_t child = fork();
    if (child == 0) 
    {
        // Inside child. We use the exit status to communicate with our parent
        if (sandbox_initialize(profile) != 0) {
            exit(1);
        }

        for (size_t i = 0; i < inputs.size(); ++i) {
            const json &input = inputs[i];
            int decision = sandbox_check_custom(input);

            assert(decision == 0 || decision == 1);

            temp[i] = (uint8_t ) decision;
        }

        exit(0);
    } 
    else 
    {
        // Inside parent. Wait for child to exit.
        int status;
        waitpid(child, &status, 0);

        if (WIFSIGNALED(status)) {
            std::cerr << "Signal thrown by child. Investigate!" << std::endl;
            std::cerr << "Corresponding profile: " << std::endl 
                      << profile << std::endl;
            return false;
        }

        assert(WIFEXITED(status));
        int exit_status = WEXITSTATUS(status);

        assert(exit_status == 0);

        for (size_t i = 0; i < inputs.size(); ++i) {
            results[i] = temp[i];
        }

        return true;
    }
}

bool sandbox_check_bulk_for_profile(const json &profile, const json &inputs, int *results)
{
    return sandbox_check_bulk_for_profile(ruleset::dump_scheme(profile), inputs, results);
}

enum sandbox_match_status *sandbox_check_bulk_baseline_consistency(const json &profile, const json &inputs)
{
    int *decisions = new int[inputs.size()];
    bool success = sandbox_check_bulk_for_profile(profile, inputs, decisions);
    if (!success)
        return NULL;

    enum sandbox_match_status *result = new enum sandbox_match_status[inputs.size()];

    assert(result && decisions);

    for (size_t i = 0; i < inputs.size(); ++i) {
        const json &input = inputs[i];
        if (input["action"] == "allow" && decisions[i] == 0)
            result[i] = SANDBOX_CONSISTENT;
        else if (input["action"] == "deny" && decisions[i] == 1)
            result[i] = SANDBOX_CONSISTENT;
        else
            result[i] = SANDBOX_INCONSISTENT;
    }

    delete[] decisions;
    return result;
}


#define RULE_UNMATCHED (~0)

/**
 * Finds the matchig rule for all inputs.
 * Returns a list of bool values, each bool signifies whether the corresponding rule could be found (or not).
 * The actual rule numbers are put into the out parameter `matches_out`
 */
enum sandbox_match_status *sandbox_bulk_find_matching_rule(const json &profile, const json &inputs, size_t **matches_out)
{
    enum sandbox_match_status *consistent = sandbox_check_bulk_baseline_consistency(profile, inputs);

    int *baselines = new int[inputs.size()];
    if (!sandbox_check_bulk_for_profile(profile, inputs, baselines))
        return NULL;

    size_t *matching_rules = new size_t[inputs.size()];
    memset(matching_rules, RULE_UNMATCHED, sizeof(size_t) * inputs.size());

    json current_profile = profile;

    int *last_results = new int[inputs.size()];

    // Iteratively remove a rule, until the result either changes (or no rules are there anymore)
    while (true) {
        json removed;
        size_t rule_index;

        current_profile = ruleset::remove_last_rule(current_profile, &rule_index, &removed);

        memset(last_results, 0x2, sizeof(*last_results) * inputs.size());

        if (!sandbox_check_bulk_for_profile(current_profile, inputs, 
                                       last_results))
            return NULL;

        for (size_t i = 0; i < inputs.size(); ++i) {
            // Make sure an actual decision is put into last_results.
            assert((matching_rules[i] != RULE_UNMATCHED) || (last_results[i] != 0x2));

            if (!(consistent[i] == SANDBOX_CONSISTENT))
                continue;

            if ((matching_rules[i] == RULE_UNMATCHED) && (last_results[i] != baselines[i])) {
                matching_rules[i] = rule_index;
            }
        }

        if (current_profile.size() == 0) {
            break;
        }
    }

    // certain deny decisions that are the result of a default deny policy cannot be
    // matched using the code above, because when removing a default deny rule,
    // the remaining ruleset falls back to the default action for the default operation,
    // which is also deny.
    // Handle these cases here!
    for (size_t i = 0; i < inputs.size(); ++i) {
        if (!(consistent[i] == SANDBOX_CONSISTENT))
            continue;

        if (matching_rules[i] == RULE_UNMATCHED) {
            json default_action = ruleset::get_default(profile);
            const json &input = inputs[i];

            if (default_action["action"] == "deny" && 
                input["action"] == "deny") {

                // TODO: To be strictly correct, you'd have to compile a default allow profile
                // and verify that the action is not denied anymore!
                matching_rules[i] = ruleset::index_for_rule(profile, default_action);
            } else {
                // See note below
                consistent[i] = SANDBOX_EXTERNAL;
            }
        }
    }

    /**
     * Note: At this point you expect the following assertion to hold:
     *
     * for (size_t i = 0; i < inputs.size(); ++i) {
     *      assert (((consistent[i] == SANDBOX_CONSISTENT) && (matching_rules[i] != RULE_UNMATCHED))
     *           || ((consistent[i] == SANDBOX_INCONSISTENT) && (matching_rules[i] == RULE_UNMATCHED)));
     * }
     *
     * This assumption however turns out to be wrong. An example is
     *
     * (allow file-map-executable "/usr/lib/libobjc-trampolines.dylib")
     *
     * This case arises because the file-map-executable operation is default allow! A default deny profile
     * with no explicit rule for file-map-executable will therefore default to allowing all file-map-executable
     * actions. Since there is no rule that is responsible for this, we assign SANDBOX_EXTERNAL as the sandbox
     * consistency status. There might be other instances of this phenomenon, also due to the built-in platform
     * sandbox profile.
     */

    *matches_out = matching_rules;

    return consistent;
}

int main(int argc, char *argv[])
{
    const char *program_name = argv[0];

    if (argc != 3) {
        usage(program_name);
        return EXIT_FAILURE;
    }

    json ruleset = ruleset::from_file(argv[1]);
    if (ruleset == nullptr) {
        usage(program_name);
        return EXIT_FAILURE;
    }

    // Technically not a ruleset, but the function does just JSON parsing.
    json inputs = ruleset::from_file(argv[2]);

    size_t *rule_indices = NULL;

    size_t n_unsuccessful = 0;

    json result = json::array();

    // Initialize platform data
    op_data_provider provider = operations_for_platform(platform_get_default());
    operations_install(provider);

    enum sandbox_match_status *statuses = sandbox_bulk_find_matching_rule(ruleset, inputs, &rule_indices);

    for (size_t i = 0; i < inputs.size(); ++i) {
        switch (statuses[i]) {
            case SANDBOX_INCONSISTENT:
                n_unsuccessful++;
                result.push_back({ i, "inconsistent" });
                break;
            case SANDBOX_CONSISTENT:
                result.push_back({ i, rule_indices[i] });
                break;
            case SANDBOX_EXTERNAL:
                result.push_back({ i, "external" });
                break;
        }
    }

    std::cout << result.dump(4) << std::endl;
}
