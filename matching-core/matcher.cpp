/**
 * This program checks whether input log rules are consistent with a given
 * ruleset.
 *
 * The input of this program is a JSON dictionary passed via standard input
 * containing the sandbox profile (as `sandbox_profile`) and processed logs
 * that should be checked (as `processed_logs`). The output is a JSON list of
 * boolean values, indicating whether a sandbox decision derived from a
 * processed log entry leads to the same decision as the log entry itself.
 *
 * Here, we make use of sandbox interna:
 * We check using sandbox_check API whether the input is allowed or not. If
 * that is unsuccessful we try to perform selected actions and see whether these
 * are permitted.
 */

#include <cassert>
#include <fstream>
#include <iostream>
#include <string>

#include <nlohmann/json.hpp>

#include <sbpldump/convert.h>

#include "sandbox_utils/sandbox_utils.h"

using json = nlohmann::json;

enum sandbox_match_status {
    MATCH_CONSISTENT,
    MATCH_INCONSISTENT,
    MATCH_UNKNOWN
};

typedef decision (*sandbox_check_func)(const json &input);

std::string get_argument(const json &log)
{
    if (log.find("argument") == log.end()) {
        return "";
    }
    return log["argument"];
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
 *
 */
decision sandbox_check_custom(const json &log, const bool is_allow_default)
{
    const std::string &operation = log["operation"];
    const std::string &argument = get_argument(log);
    const pid_t pid = getpid();
    const int filter_type = sandbox_filter_type_for_op(operation.c_str());

    if (argument != "") {
        if (filter_type == SANDBOX_FILTER_UNKNOWN) {
            // Try every filter type, return true if any one returned true.
            // Note: This only works because the sandbox's default decision is deny!
            // If the default decision were allow, this would basically always return true!
            // Because, given the following excerpt of a profile:
            // (allow default)
            // (deny file* (subpath "/usr"))
            // sandbox_check would return 0 for basically any invalid filter type
            if (is_allow_default) {
                return DECISION_UNKNOWN;
            }

            for (int current_filter = SANDBOX_FILTER_PATH;
                 current_filter != SANDBOX_FILTER_UNKNOWN;
                 ++current_filter) {
                int res = sandbox_check(pid, operation.c_str(), SANDBOX_CHECK_NO_REPORT | current_filter, argument.c_str());
                if (res == 0 /* allowed */) {
                    return DECISION_ALLOW;
                }
            }

            // sandbox_check never returned 0, so return false
            return DECISION_DENY;
        }

        const int filter = SANDBOX_CHECK_NO_REPORT | filter_type;
        const int rv = sandbox_check(pid, operation.c_str(), filter, argument.c_str());
        if (!(rv == 0 || rv == 1)) {
            std::cerr << "sandbox_check returned " << rv << ": " << operation << " " << filter << " " << argument << std::endl;
            return DECISION_ERROR;
        }
        return rv == 0 ? DECISION_ALLOW : DECISION_DENY;
    } else {
        const int filter = SANDBOX_CHECK_NO_REPORT | SANDBOX_FILTER_NONE;
        const int rv = sandbox_check(pid, operation.c_str(), filter);
        if (!(rv == 0 || rv == 1)) {
            std::cerr << "sandbox_check returned " << rv << ": " << operation << " " << filter << std::endl;
            return DECISION_ERROR;
        }
        return rv == 0 ? DECISION_ALLOW : DECISION_DENY;
    }
}

decision sandbox_check_perform(const json &log)
{
    const std::string &operation = log["operation"];
    const std::string &argument = get_argument(log);
    const pid_t pid = getpid();
    return sandbox_check_perform(pid, operation.c_str(), 0 /* ignored */, argument.c_str());
}

/**
 * Some operations are checked to leniently if just asking the kernel. Force
 * perfoming a recheck for those.
 */
bool should_recheck(const json &log)
{
    const std::string &operation = log["operation"];
    return operation == "mach_register";
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

    return json();
}

int main(int argc, char *argv[])
{
    // Read JSON input
    std::string input_raw;
    std::string line;
    while (getline(std::cin, line)) {
        input_raw += line;
    }
    const json input = json::parse(input_raw);

    // Validate JSON
    std::vector<std::string> required_keys = {"sandbox_profile", "processed_logs"};
    for (std::vector<std::string>::iterator it = required_keys.begin(); it != required_keys.end(); ++it) {
        if (input.find(*it) == input.end()) {
            std::cerr << "Missing key: " << *it << std::endl;
            return EXIT_FAILURE;
        }
    }

    const json profile = input["sandbox_profile"];
    const json logs = input["processed_logs"];

    const json default_rule = get_default(profile);
    const bool is_allow_default = !default_rule.is_null() && default_rule["action"] == "allow";

    // Setup sandbox
    const char *sbpl = sandbox_rules_dump_scheme(profile.dump().c_str());
    char *error = nullptr;
    const int rv = sandbox_init_with_parameters(sbpl, 0, nullptr, &error);
    if (rv != 0) {
        std::cerr << "Failed to initialise sandbox: " << error << std::endl;
        return EXIT_FAILURE;
    }
    assert(rv == 0);
    assert(error == nullptr);

    // Batch process logs
    std::vector<sandbox_match_status> matches;
    matches.reserve(logs.size());
    for (size_t i = 0; i < logs.size(); ++i) {
        const json &log = logs[i];
        const enum decision decision = sandbox_check_custom(log, is_allow_default);

        if (decision == DECISION_ERROR) {
            std::cerr << "Failed to check log entry #" << i << ":" << std::endl;
            std::cerr << "  Log:       " << log.dump() << std::endl;
            std::cerr << "  Last Rule: " << profile[profile.size() - 1].dump() << std::endl;
            return EXIT_FAILURE;
        }

        auto is_consistent = [](const enum decision decision, const json &log) {
            return (decision == DECISION_ALLOW && log["action"] == "allow")
                || (decision == DECISION_DENY && log["action"] == "deny");
        };

        if (is_consistent(decision, log) && !should_recheck(log)) {
            matches.push_back(MATCH_CONSISTENT);
        } else {
            // Actually try to perform operation with given arguments instead of
            // asking the kernel whether the operation would be allowed.
            const enum decision performed_decision = sandbox_check_perform(log);

            if (performed_decision == DECISION_ERROR) {
                std::cerr << "Failed to re-check log entry #" << i << ":" << std::endl;
                std::cerr << "  Log:       " << log.dump() << std::endl;
                std::cerr << "  Last Rule: " << profile[profile.size() - 1].dump() << std::endl;
                return EXIT_FAILURE;
            }

            if (performed_decision == DECISION_UNKNOWN) {
                if (decision == DECISION_UNKNOWN) {
                    matches.push_back(MATCH_UNKNOWN);
                } else {
                    matches.push_back(is_consistent(decision, log) ? MATCH_CONSISTENT : MATCH_INCONSISTENT);
                }
            } else {
                matches.push_back(is_consistent(performed_decision, log) ? MATCH_CONSISTENT : MATCH_INCONSISTENT);
            }
        }

    }

    // Output results
    std::cout << "[";
    for (std::vector<sandbox_match_status>::iterator it = matches.begin(); it != matches.end(); ++it) {
        if (it != matches.begin()) {
            std::cout << ",";
        }
        switch (*it) {
            case MATCH_CONSISTENT:
                std::cout << "true";
                break;
            case MATCH_INCONSISTENT:
                std::cout << "false";
                break;
            case MATCH_UNKNOWN:
                std::cout << "null";
                break;
        }
    }
    std::cout << "]" << std::endl;

    return EXIT_SUCCESS;
}