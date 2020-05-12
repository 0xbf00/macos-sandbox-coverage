#include <assert.h>
#include <stdlib.h>
#include <semaphore.h>

#include "../sandbox_utils.h"

const char *profile = \
    "(version 1)\n"
    "(deny default)\n"
    "(allow ipc-posix-sem-create (ipc-posix-name \"TestName\"))\n"
    "(allow ipc-posix-sem-create\n"
    "       ipc-posix-sem-unlink (ipc-posix-name \"AnotherTest\"))\n"
    "(allow ipc-posix-sem* (ipc-posix-name \"FinalTest\"))";

void cleanup_test()
{
    sem_unlink("TestName");
    sem_unlink("AnotherTest");
    sem_unlink("FinalTest");
}

int main(int argc, char *argv[])
{
    cleanup_test();

    assert(0 == sandbox_install_profile(profile));

    // Check creation
    assert(0 == sandbox_check_perform(0, "ipc-posix-sem-create", 0, "TestName"));
    // We cannot create the same variable twice, and since we are not allowed
    // to delete the first variable, we cannot say whether we'd be allowed to
    // create the variable.
    assert(-1 == sandbox_check_perform(0, "ipc-posix-sem-create", 0, "TestName"));

    // Check deletion
    assert(-1 == sandbox_check_perform(0, "ipc-posix-sem-unlink", 0, "AnotherTest"));
    assert(0 == sandbox_check_perform(0, "ipc-posix-sem-create", 0, "AnotherTest"));
    // Now we are allowed to create the variable and to delete it, but we cannot ordinarily
    // open it...
    assert(-1 == sandbox_check_perform(0, "ipc-posix-sem-create", 0, "AnotherTest"));
    assert(0 == sandbox_check_perform(0, "ipc-posix-sem-unlink", 0, "AnotherTest"));

    // Check everything.
    assert(0 == sandbox_check_perform(0, "ipc-posix-sem-create", 0, "FinalTest"));
    // Now, we finally have permissions to do everything and can do this twice.
    assert(0 == sandbox_check_perform(0, "ipc-posix-sem-create", 0, "FinalTest"));
    assert(0 == sandbox_check_perform(0, "ipc-posix-sem-wait", 0, "FinalTest"));
    // We can post multiple times.
    assert(0 == sandbox_check_perform(0, "ipc-posix-sem-post", 0, "FinalTest"));
    assert(0 == sandbox_check_perform(0, "ipc-posix-sem-post", 0, "FinalTest"));
    assert(0 == sandbox_check_perform(0, "ipc-posix-sem-post", 0, "FinalTest"));
    assert(0 == sandbox_check_perform(0, "ipc-posix-sem-unlink", 0, "FinalTest"));

    cleanup_test();

    return EXIT_SUCCESS;
}