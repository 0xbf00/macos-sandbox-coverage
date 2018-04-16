#include "file.h"
#include "apple_sandbox.h"

#include <string.h>
#include <stdlib.h>

/**
 * Extracts the file target from the argument provided.
 * In general, the structure of `argument` is as follows:
 *      "target: /path/to/some/file class: com.apple.app-sandbox.read-write"
 * This function extracts just the target. The caller is responsible for
 * freeing the resulting pointer.
 */
static char *file_issue_extension_parse_target(const char *argument)
{
    const char *start = strstr(argument, "target: ");
    const char *end   = strstr(argument, "class: ");
    // Cannot find the delimiters
    if (!start || !end)
        return NULL;

    const size_t required_len = end - start - strlen("target: ");
    char *result = calloc(1, required_len);

    if (!result)
        return NULL;

    memcpy(result, start + strlen("target: "), required_len);
    result[required_len-1] = '\0';

    return result;
}

/**
 * Extracts the extension class from the supplied argument.
 * For more information, see function above.
 */
static char *file_issue_extension_parse_class(const char *argument)
{
    const char *str_end = argument + strlen(argument);
    const char *start = strstr(argument, "class: ");
    
    if (!start)
        return NULL;
    
    start += strlen("class: ");

    const size_t required_len = str_end - start + 2;

    char *result = calloc(1, required_len);
    if (!result)
        return NULL;

    memcpy(result, start, required_len);
    result[required_len-1] = '\0';

    return result;
}

int sandbox_check_file_issue_extension(const char *argument)
{
    // As a first approximation, we simply call the default sandbox check function with
    // extracted target. This will possible sometimes fail, but we don't care right now.
    // The overwhelming majority of cases are allowed, and these cases will be correctly
    // handled here.
    char *target = file_issue_extension_parse_target(argument);
    char *class = file_issue_extension_parse_class(argument);

    int success = sandbox_check(getpid(),
        "file-issue-extension", 
        SANDBOX_CHECK_NO_REPORT | SANDBOX_FILTER_PATH,
        target);
    
    free(target);

    return success;
}