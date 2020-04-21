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
#include <cstdlib>
#include <cstdint>
#include <string>
#include <set>
#include <algorithm>

#include <ctime>
#include <unistd.h>
#include <sys/mman.h>

#include "ruleset_helpers.h"
#include "sandbox_utils/sandbox_utils.h"

extern "C" {
    #include <simbple/src/platform_data/platforms.h>
    #include <simbple/src/sb/operations/data.h>
    #include <simbple/src/sb/operations/types.h>
}

#include <nlohmann/json.hpp>

using json = nlohmann::json;

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
    << " ruleset.json log_entries.json match_results.json"
    << std::endl;
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
    if (!strncmp("file", operation, strlen("file"))) {
        return SANDBOX_FILTER_PATH;
    }

    return SANDBOX_FILTER_UNKNOWN;
}

/**
 * Check whether the input rule is allowed in the current sandbox.
 * Similar functionality to the sandbox_check functionality, however
 * this function encapsulates much of the functionality of parameter
 * choice.
 * Returns values from the sandbox_check API.
 */
int sandbox_recheck_custom(const json &input)
{
    std::string operation = input["operation"];
    std::string argument = "";

    if (input.find("argument") != input.end()) {
        argument = input["argument"];
    }

    pid_t pid = getpid();

    int status = sandbox_check_perform(pid, operation.c_str(), 0 /* ignored */, argument.c_str());
    if (status != 0)
        return 1;
    return 0;
}

/**
 * The main problem with this approach is the need to generate thousands
 * and thousands of different processed, to use sandbox_check with different
 * profiles. To somewhat combat the immense slowdown, we use batch processing
 */
bool sandbox_recheck_bulk_for_profile(const char *profile, const json &inputs, int *results)
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

    // Contents are set to 2 to distinguish between entries that
    // were set by the code and those that were not.
    memset(temp, 2, map_size);

    pid_t child = fork();
    if (child == 0) 
    {
        // Inside child. We use the exit status to communicate with our parent
        if (sandbox_install_profile(profile) != 0) {
            exit(1);
        }

        for (size_t i = 0; i < inputs.size(); ++i) {
            const json &input = inputs[i];
            int decision = sandbox_recheck_custom(input);

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

bool sandbox_recheck_bulk_for_profile(const json &profile, const json &inputs, int *results)
{
    return sandbox_recheck_bulk_for_profile(ruleset::dump_scheme(profile), inputs, results);
}

bool *sandbox_recheck_bulk_baseline_consistency(const json &profile, const json &inputs)
{
    int *decisions = new int[inputs.size()];
    bool success = sandbox_recheck_bulk_for_profile(profile, inputs, decisions);
    if (!success)
        return NULL;

    bool *result = new bool[inputs.size()];

    assert(result && decisions);

    for (size_t i = 0; i < inputs.size(); ++i) {
        const json &input = inputs[i];
        if (input["action"] == "allow" && decisions[i] == 0)
            result[i] = true;
        else if (input["action"] == "deny" && decisions[i] == 1)
            result[i] = true;
        else
            result[i] = false;
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
bool *sandbox_bulk_find_matching_rule(const json &profile, const json &inputs, size_t **matches_out)
{
    bool *consistent = sandbox_recheck_bulk_baseline_consistency(profile, inputs);

    int *baselines = new int[inputs.size()];
    if (!sandbox_recheck_bulk_for_profile(profile, inputs, baselines))
        return NULL;

    size_t *matching_rules = new size_t[inputs.size()];
    memset(matching_rules, RULE_UNMATCHED, sizeof(size_t) * inputs.size());

    json current_profile = profile;

    int *last_results = new int[inputs.size()];

    // Iteratively remove a rule, until the result either changes (or no rules are there anymore)
    while (true) {
        json removed;
        current_profile = ruleset::remove_last_rule(current_profile, removed);
        const size_t rule_index = ruleset::index_for_rule(profile, removed);

        // Reset last_results variable to contain all 2s, a value which is not
        // a valid returns value from sandbox_check (and therefore can be identified as such)
        memset(last_results, 0x2, sizeof(*last_results) * inputs.size());

        if (!sandbox_recheck_bulk_for_profile(current_profile, inputs, 
                                       last_results))
            return NULL;

        for (size_t i = 0; i < inputs.size(); ++i) {
            // Make sure an actual decision is put into last_results.
            assert((matching_rules[i] != RULE_UNMATCHED) || (last_results[i] != 0x2));

            if (!consistent[i])
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
    const json default_action = ruleset::get_default(profile);
    if (default_action["action"] == "deny") {
        for (size_t i = 0; i < inputs.size(); ++i) {
            if (!consistent[i])
                continue;

            if (matching_rules[i] == RULE_UNMATCHED) {
                const json &input = inputs[i];

                if (input["action"] == "deny") {
                    matching_rules[i] = ruleset::index_for_rule(profile, default_action);
                }
            }
        }
    }

    // Sanity check.
    for (size_t i = 0; i < inputs.size(); ++i) {
        assert (((consistent[i] == true) && (matching_rules[i] != RULE_UNMATCHED))
            || ((consistent[i] == false) && (matching_rules[i] == RULE_UNMATCHED)));
    }

    *matches_out = matching_rules;

    return consistent;
}

int should_rematch(const json &match_entry, const json &log_entry)
{
    // Inconsistent matches should be rematched
    if (!match_entry[1].is_number())
        return true;

    // mach-register rules were matched too leniently
    if (log_entry["operation"] == "mach-register")
        return true;

    return false;
}

int main(int argc, char *argv[])
{
    const char *program_name = argv[0];

    if (argc != 4) {
        usage(program_name);
        return EXIT_FAILURE;
    }

    // Initialize platform data
    op_data_provider provider = operations_for_platform(platform_get_default());
    operations_install(provider);

    json ruleset = ruleset::from_file(argv[1]);
    // Technically not a ruleset, but the function does just JSON parsing.
    json inputs = ruleset::from_file(argv[2]);
    json match_results = ruleset::from_file(argv[3]);

    if (ruleset == nullptr || inputs == nullptr || match_results == nullptr) {
        usage(program_name);
        return EXIT_FAILURE;
    }

    // Carve out only the inputs we want to rematch
    json inputs_to_check = json::array();
    for (std::size_t i = 0; i < inputs.size(); ++i) {
        const json &match_result = match_results[i];
        const json &log_entry = inputs[i];

        // Ignore consistent results
        if (!should_rematch(match_result, log_entry))
            continue;

        inputs_to_check.push_back(inputs[i]);
    }

    std::cerr << "Have " 
              << inputs_to_check.size() << "/" << inputs.size() 
              << " results to recheck." << std::endl;

    size_t *rule_indices = NULL;

    size_t n_unsuccessful = 0;

    json result = json::array();

    bool *successes = sandbox_bulk_find_matching_rule(ruleset, inputs_to_check, &rule_indices);

    for (size_t i = 0; i < inputs_to_check.size(); ++i) {
        // Find corresponding index in real inputs. Highly inefficient, but
        // this part of the program does not dominate runtime, so it does not
        // really matter.
        // Searching for the nth inconsistent rule in inputs
        size_t corresponding_index = 777777;
        int nth_rule = i;

        for (std::size_t j = 0; j < inputs.size(); ++j) {
            const json &match_result = match_results[j];
            const json &log_entry = inputs[j];

            if (should_rematch(match_result, log_entry)) {
                if (nth_rule == 0) {
                    corresponding_index = j;
                    break;
                }
                nth_rule--;
            }
        }

        if (!successes[i]) {
            n_unsuccessful++;
//            std::cerr << inputs[corresponding_index].dump() << " returned inconsistent result" << std::endl;
            result.push_back({ corresponding_index, "inconsistent" });
        } else {
            std::cerr << inputs[corresponding_index].dump() 
                      << " successfully matched with rule "
                      << ruleset[rule_indices[i]].dump()
                      << std::endl;

            result.push_back({ corresponding_index, rule_indices[i] });
        }
    }

    std::cerr << "Failed to rematch " 
              << n_unsuccessful << "/" << inputs_to_check.size() 
              << std::endl;

    std::cout << result.dump(4) << std::endl;
}