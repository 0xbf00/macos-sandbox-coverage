#include <assert.h>
#include <stdlib.h>

#include "../sandbox_utils.h"

const char *profile = \
    "(version 1)\n"
    "(deny default)\n"
    "(deny process-info*)\n"
    "(allow process-info-dirtycontrol (target self))\n"
    "(allow process-info-setcontrol (target self))\n";

int main(int argc, char *argv[])
{
    assert(0 == sandbox_install_profile(profile));

    // Argument is ignored by our function.
    assert(DECISION_ALLOW == sandbox_check_perform(getpid(), "process-info-dirtycontrol", 0, ""));
    // Multiple calls are OK.
    assert(DECISION_ALLOW == sandbox_check_perform(getpid(), "process-info-dirtycontrol", 0, ""));

    assert(DECISION_ALLOW == sandbox_check_perform(getpid(), "process-info-setcontrol", 0, ""));

    return EXIT_SUCCESS;
}