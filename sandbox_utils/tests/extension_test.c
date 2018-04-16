#include "sandbox_utils.h"
#include <assert.h>
#include <stdlib.h>

const char *profile = \
    "(version 1)\n"
    "(deny default)\n"
    "(allow file-issue-extension"
    "   (subpath \"/private\"))";

int main(int argc, char *argv[])
{
    assert(0 == sandbox_install_profile(profile));

    // The argument string is rather weird, because that is what is written to the console
    // so that is what we've got.
    assert(0 == sandbox_check_custom(0, "file-issue-extension", 0, "target: /private/etc/hosts class: com.apple.app-sandbox.read"));
    assert(0 != sandbox_check_custom(0, "file-issue-extension", 0, "target: /System/Library/Kernels/kernel class: com.apple.app-sandbox.read-write"));

    return EXIT_SUCCESS;
}