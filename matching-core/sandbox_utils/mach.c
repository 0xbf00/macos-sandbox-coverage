#include "mach.h"
#include "file.h"
#include "apple_sandbox.h"

#include <string.h>
#include <stdlib.h>
#include <stdio.h>

enum decision sandbox_check_mach_register(const char *argument)
{
    const int rv = sandbox_check(getpid(), "mach-register", SANDBOX_CHECK_NO_REPORT | SANDBOX_FILTER_GLOBAL_NAME, argument);

    if (!(rv == 0 || rv == 1)) {
        return DECISION_ERROR;
    }

    return (rv == 0) ? DECISION_ALLOW : DECISION_DENY;
}