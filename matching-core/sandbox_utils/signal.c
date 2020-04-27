#include "signal.h"
#include <unistd.h>
#include <signal.h>
#include <stdio.h>

#include "apple_sandbox.h"

static int fork_allowed()
{
    int resp = sandbox_check(getpid(), "process-fork", SANDBOX_CHECK_NO_REPORT | SANDBOX_FILTER_NONE);
    return (resp == 0);
}

/**
 * Check whether the sandbox allows
 * signalling children (with the same sandbox)
 * This is the only thing the sandbox allows, and
 * since we only record the PID of the process, we
 * cannot distinguish between children and XPC services,
 * for instance.
 * Argument is ignored!
 */
int sandbox_check_signal(const char *argument /* unused */)
{
    /*
    Practically the only sensible and used
    variation of the signal sandbox operation
    is used to allow parents to signal their children
    that are in the same sandbox.

    Here, we replicate this, by first forking and then
    attempting to kill our child. If this succeeds, we
    can be sure sandbox_check would also succeed.
    */
    // If we fork but are not allowed to, we are killed
    if (!fork_allowed())
        return -1;

    pid_t pid = fork();

    if (pid == 0) {
        // in child
        sleep(5);
    } else {
        // SIGKILL, because it also kills the child process,
        // while we're at it.
        int success = kill(pid, SIGKILL);
        return (success != 0);
    }

    return -1;
}
