/**
 * sandbox_check wrapper that can handle log entry outputs
 * such as
 * target: /path/to/some/file class: com.apple.app-sandbox.read-write
 */
int sandbox_check_file_issue_extension(const char *argument);