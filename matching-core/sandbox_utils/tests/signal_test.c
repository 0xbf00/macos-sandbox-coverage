#include <assert.h>
#include <stdlib.h>
#include <sys/mman.h>

#include "../sandbox_utils.h"

const char *profile = \
    "(version 1)\n"
    "(deny default)\n"
    "(allow process-fork)\n"
    "(allow signal (target same-sandbox))\n";


int main(int argc, char *argv[])
{
    assert(0 == sandbox_install_profile(profile));

    // Our signal checker only ever tries to kill its children.
    assert(DECISION_ALLOW == sandbox_check_perform(0, "signal", 0, "does not matter"));
    assert(DECISION_ALLOW == sandbox_check_perform(0, "signal", 0, "does not matter"));

    return EXIT_SUCCESS;
}