#include <assert.h>
#include <stdlib.h>

#include "../sandbox_utils.h"

const char *profile = \
    "(version 1)\n"
    "(deny default)\n"
    "(allow file-issue-extension\n"
    "   (require-all\n"
    "       (subpath \"/private\")\n"
    "       (extension-class \"com.apple.app-sandbox.read-write\")))\n"
    "\n"
    "(allow file-issue-extension\n"
    "    (require-all\n"
    "       (subpath \"/Users/jakobrieck/Library/Containers/net.shinyfrog.bear/Data/\")\n"
    "       (extension-class \"com.apple.app-sandbox.read-write\")))\n";

int main(int argc, char *argv[])
{
    assert(0 == sandbox_install_profile(profile));

    // The argument string is rather weird, because that is what is written to the console
    // so that is what we've got.
    assert(0 == sandbox_check_perform(0, "file-issue-extension", 0, "target: /private/etc/hosts class: com.apple.app-sandbox.read-write"));
    assert(0 != sandbox_check_perform(0, "file-issue-extension", 0, "target: /System/Library/Kernels/kernel class: com.apple.app-sandbox.read-write"));

    assert(0 == sandbox_check_perform(0, "file-issue-extension", 0, "target: /Users/jakobrieck/Library/Containers/net.shinyfrog.bear/Data/Library/Caches/net.shinyfrog.bear class: com.apple.app-sandbox.read-write"));

    return EXIT_SUCCESS;
}