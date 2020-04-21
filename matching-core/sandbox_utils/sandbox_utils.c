#include "sandbox_utils.h"

#include "file.h"
#include "posix_sem.h"
#include "posix_shm.h"
#include "nvram.h"
#include "iokit.h"
#include "signal.h"
#include "process_info.h"
#include "mach.h"

#include <stdbool.h>
#include <string.h>
#include <stdio.h>

enum check_function_type {
    ARGUMENT_TYPE_PID,
    ARGUMENT_TYPE_STRING
};

typedef int (*pid_check_func)(const pid_t pid);
typedef int (*str_check_func)(const char *arg);

typedef struct {
    const char *operation;
    enum check_function_type function_type;
    union {
        pid_check_func pid_func;
        str_check_func str_func;
    } function;
} check_function_t;

static const check_function_t check_functions[] = {
    {
        "file-issue-extension",
        ARGUMENT_TYPE_STRING,
        {
            .str_func = sandbox_check_file_issue_extension
        }
    },
    {
        "ipc-posix-shm-write-create",
        ARGUMENT_TYPE_STRING,
        {
            .str_func = sandbox_check_shm_write_create
        }
    },
    {
        "ipc-posix-shm-write-data",
        ARGUMENT_TYPE_STRING,
        {
            .str_func = sandbox_check_shm_write_data
        }
    },
    {
        "ipc-posix-shm-write-unlink",
        ARGUMENT_TYPE_STRING,
        {
            .str_func = sandbox_check_shm_write_unlink
        }
    },
    {
        "ipc-posix-shm-read-data",
        ARGUMENT_TYPE_STRING,
        {
            .str_func = sandbox_check_shm_read_data
        }
    },
    {
        "ipc-posix-shm-read-metadata",
        ARGUMENT_TYPE_STRING,
        {
            .str_func = sandbox_check_shm_read_metadata
        }
    },
    {
        "ipc-posix-sem-create",
        ARGUMENT_TYPE_STRING,
        {
            .str_func = sandbox_check_sem_create
        }
    },
    {
        "ipc-posix-sem-open",
        ARGUMENT_TYPE_STRING,
        {
            .str_func = sandbox_check_sem_open
        }
    },
    {
        "ipc-posix-sem-post",
        ARGUMENT_TYPE_STRING,
        {
            .str_func = sandbox_check_sem_post
        }
    },
    {
        "ipc-posix-sem-wait",
        ARGUMENT_TYPE_STRING,
        {
            .str_func = sandbox_check_sem_wait
        }
    },
    {
        "ipc-posix-sem-unlink",
        ARGUMENT_TYPE_STRING,
        {
            .str_func = sandbox_check_sem_unlink
        }
    },
    {
        "nvram-get",
        ARGUMENT_TYPE_STRING,
        {
            .str_func = sandbox_check_nvram_get
        }
    },
    {
        "process-info-dirtycontrol",
        ARGUMENT_TYPE_PID,
        {
            .pid_func = sandbox_check_dirtycontrol
        }
    },
    {
        "process-info-setcontrol",
        ARGUMENT_TYPE_PID,
        {
            .pid_func = sandbox_check_setcontrol
        }
    },
    {
        "process-info-pidinfo",
        ARGUMENT_TYPE_PID,
        {
            .pid_func = sandbox_check_pidinfo
        }
    },
    {
        "signal",
        ARGUMENT_TYPE_STRING,
        {
            .str_func = sandbox_check_signal
        }
    },
    {
        "iokit-open",
        ARGUMENT_TYPE_STRING,
        {
            .str_func = sandbox_check_iokit_open
        }
    },
    {
        "mach-register",
        ARGUMENT_TYPE_STRING,
        {
            .str_func = sandbox_check_mach_register
        }
    }
};
static const size_t n_check_functions = sizeof(check_functions) / sizeof(*check_functions);

/**
 * Custom sandbox_check function that attempts to
 * return more sensible results than the default sandbox_check
 * function for some inputs.
 *
 * This function performs its work not by querying the kernel interface
 * as sandbox_check does, but instead actually attempts to perform the
 * actions. Beware that as such, calling this function might actually change the 
 * state of your system. Furthermore, calling this function might trigger
 * other operations than solely the supplied one.
 *
 * Also note that the interface of this function is chosen solely for
 * compatability reasons with sandbox_check. Both the pid argument
 * and the type argument are frequently ignored (but not always!).
 */
int sandbox_check_perform(pid_t pid, const char *operation, int type, const char *argument)
{
    for (size_t i = 0; 
         i < n_check_functions; 
         ++i)
    {
        const check_function_t *current = &check_functions[i];
        if (strcmp(current->operation, operation) == 0) {
            // Found match
            if (current->function_type == ARGUMENT_TYPE_PID) {
                return current->function.pid_func(pid);
            }
            else
                return current->function.str_func(argument);
        }
    }

    return -1;
}

int sandbox_install_profile(const char *profile)
{
    char *error = NULL;

    int rv = sandbox_init_with_parameters(profile, 0, NULL, &error);
    if (rv) {
        printf("error occurred: %s\n", error);
    }

    return (error != NULL) || (rv != 0);
}

int sandbox_check_all(pid_t pid, const char *op, const char *argument)
{
    struct sb_check_argument {
        int type;
        bool arg_required;
    };

    static const struct sb_check_argument all_checks[] = {
        { SANDBOX_FILTER_NONE, false },
        { SANDBOX_FILTER_PATH, true },
        { SANDBOX_FILTER_GLOBAL_NAME, true },
        { SANDBOX_FILTER_LOCAL_NAME, true },
        { SANDBOX_FILTER_APPLEEVENT_DESTINATION, true },
        { SANDBOX_FILTER_RIGHT_NAME, true },
        { SANDBOX_FILTER_PREFERENCE_DOMAIN, true },
        { SANDBOX_FILTER_KEXT_BUNDLE_ID, true },
        { SANDBOX_FILTER_INFO_TYPE, true },
        { SANDBOX_FILTER_NOTIFICATION, true }
    };

    const pid_t process_pid = getpid();

    for (size_t i = 0;
         i < sizeof(all_checks) / sizeof(*all_checks);
         ++i) 
    {
        int decision = -1;

        if (all_checks[i].arg_required) {
            decision = sandbox_check(process_pid, op,
                SANDBOX_CHECK_NO_REPORT | all_checks[i].type,
                argument);
        } else {
            decision = sandbox_check(process_pid, op,
                SANDBOX_CHECK_NO_REPORT | all_checks[i].type);
        }

        if (decision == 0) {
            return 0;
        }
    }

    return 1;
}