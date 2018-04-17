#ifndef SANDBOX_UTILS_H
#define SANDBOX_UTILS_H

#include "apple_sandbox.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Custom sandbox_check function that attempts to
 * return more sensible results than the default sandbox_check
 * function for some inputs.
 *
 * This function performs its work not by querying the kernel interface
 * as sandbox_check does, but instead actually attempts to perform the
 * actions. Beware that as such, calling this function might actually change the 
 * state of your system. Furthermore, calling this function might trigger
 * other operations than solely the supplied one.
 *
 * Also note that the interface of this function is chosen solely for
 * compatability reasons with sandbox_check. Both the pid argument
 * and the type argument are frequently ignored (but not always!).
 */
__attribute__ ((visibility ("default"))) int sandbox_check_perform(
    pid_t pid, 
    const char *operation, 
    int type, 
    const char *argument
);

/**
 * Custom function that installs a given profile using
 * default flags and parameters. Returns 0 on success.
 */
__attribute__ ((visibility ("default"))) int sandbox_install_profile(
    const char *profile
);

/**
 * Custom function that tries all filter types for the given operation,
 * succeeding if sandbox_check succeeds for at least one such filter type.
 * Note that this approach only works on default-deny profiles, otherwise
 * this function will basically always return success.
 */
__attribute__ ((visibility ("default"))) int sandbox_check_all(
    pid_t pid,
    const char *op,
    const char *argument
);

#ifdef __cplusplus
}
#endif

#endif