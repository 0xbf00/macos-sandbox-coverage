#include "mach.h"
#include "file.h"
#include "apple_sandbox.h"

#include <string.h>
#include <stdlib.h>
#include <stdio.h>

int sandbox_check_mach_register(const char *argument)
{
    return sandbox_check(getpid(), "mach-register",SANDBOX_CHECK_NO_REPORT | SANDBOX_FILTER_GLOBAL_NAME, argument);
}