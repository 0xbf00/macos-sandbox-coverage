#ifndef SANDBOX_CHECK_APPLE_SANDBOX_H
#define SANDBOX_CHECK_APPLE_SANDBOX_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <unistd.h>

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
    SANDBOX_FILTER_UNKNOWN,
};
extern const enum sandbox_filter_type SANDBOX_CHECK_NO_REPORT;
extern const enum sandbox_filter_type SANDBOX_CHECK_CANONICAL;
extern const enum sandbox_filter_type SANDBOX_CHECK_NOFOLLOW;

int sandbox_init_with_parameters(const char *profile, uint64_t flags, const char *const parameters[], char **errorbuf);

int sandbox_check(pid_t pid, const char *operation,
                  int type, ...);

extern const char *APP_SANDBOX_READ_WRITE;
extern const char *APP_SANDBOX_READ;

extern char *sandbox_extension_issue_file(const char *ext, const char *path, int reserved, int flags);
extern int sandbox_extension_consume(const char *token);
extern int sandbox_extension_release(const char *token);

#ifdef __cplusplus
}
#endif

#endif