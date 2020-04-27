#include "file.h"
#include "apple_sandbox.h"

#include <string.h>
#include <stdlib.h>
#include <stdio.h>

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
    char *target = file_issue_extension_parse_target(argument);
    char *class = file_issue_extension_parse_class(argument);

    if (target == NULL || class == NULL) {
        fprintf(stderr, "file-issue-extension parse error:\n    argument: %s\n    target: %s\n    class: %s\n", argument, target, class);
        return -1;
    }

    const char *sandbox_class = NULL;
    if (strcmp(class, "com.apple.app-sandbox.read-write") == 0) {
        sandbox_class = APP_SANDBOX_READ_WRITE;
    } else if (strcmp(class, "com.apple.app-sandbox.read") == 0) {
        sandbox_class = APP_SANDBOX_READ;
    } else {
        return -1;
    }

    char *token = sandbox_extension_issue_file(sandbox_class, target, 0, 0);
    int success = token == NULL;

    free(target);
    free(class);

    return success;
}