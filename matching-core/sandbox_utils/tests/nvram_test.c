#include <assert.h>
#include <stdlib.h>

#include "../sandbox_utils.h"

const char *profile = \
    "(version 1)\n"
    "(deny default)\n"
    "(deny nvram*)\n"
    "(allow nvram-get (nvram-variable \"ALS_Data\"))\n";

int main(int argc, char *argv[])
{
    assert(0 == sandbox_install_profile(profile));

    assert(DECISION_ALLOW == sandbox_check_perform(0, "nvram-get", 0, "ALS_Data"));
    assert(DECISION_DENY == sandbox_check_perform(0, "nvram-get", 0, "SystemAudioVolume"));

    return EXIT_SUCCESS;
}