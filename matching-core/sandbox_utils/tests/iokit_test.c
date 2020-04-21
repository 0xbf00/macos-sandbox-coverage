#include "sandbox_utils.h"
#include <assert.h>
#include <stdlib.h>

const char *profile = \
    "(version 1)\n"
    "(deny default)\n"
    "(allow iokit-open (iokit-registry-entry-class \"AppleHVClient\"))";

int main(int argc, char *argv[])
{
    assert(0 == sandbox_install_profile(profile));

    assert(0 == sandbox_check_custom(0, "iokit-open", 0, "AppleHVClient"));
    assert(0 != sandbox_check_custom(0, "iokit-open", 0, "AppleLMUClient"));

    return EXIT_SUCCESS;
}