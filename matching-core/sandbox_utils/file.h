#ifndef SANDBOX_UTILS_FILE_H
#define SANDBOX_UTILS_FILE_H

#include "decision.h"

/**
 * sandbox_check wrapper that can handle log entry outputs
 * such as
 * target: /path/to/some/file class: com.apple.app-sandbox.read-write
 */
enum decision sandbox_check_file_issue_extension(const char *argument);

#endif