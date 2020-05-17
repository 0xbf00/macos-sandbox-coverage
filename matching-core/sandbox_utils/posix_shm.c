#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <assert.h>

#include "misc.h"

/**
 * Checks whether the sandbox allows to create a
 * posix shared memory variable with the specified name.
 */
int sandbox_check_shm_write_create(const char *name)
{
    // Check if file descriptor already exists.
    // If it does, we attempt to unlink it, so
    // that the remaining code actually creates
    // it. Otherwise, we simply open an existing
    // descriptor.
    int existing = shm_open(name, O_RDONLY);
    if (existing != -1) {
        close(existing);

        if (shm_unlink(name) != 0) {
            PRINT_ERROR("Cannot unlink existing descriptor");
            if (errno == EACCES || errno == EPERM) {
                return 1;
            } else {
                return -1;
            }
        }
    } else {
        if (errno == EPERM) {
            PRINT_ERROR("No permission to open file descriptor");
            return -1;
        }
    }

    int fd = shm_open(name, O_RDWR | O_CREAT, 0777);
    if (fd == -1) {
        PRINT_ERROR("Cannot create writable shared memory");
        if (errno == EPERM)
            return 1;
        else
            return -1;
    }

    close(fd);
    return 0;
}

int sandbox_check_shm_write_data(const char *name)
{
    int fd = shm_open(name, O_RDWR);
    if (fd == -1) {
        PRINT_ERROR("Cannot lookup named shared memory region");
        if (errno == EPERM)
            return 1;
        else
            return -1;
    }

    close(fd);
    return 0;
}

int sandbox_check_shm_write_unlink(const char *name)
{
    int failed = shm_unlink(name);
    if (failed) {
        PRINT_ERROR("Cannot unlink shared memory");
        if (errno == EPERM)
            return 1;
        else
            return -1;
    }

    return 0;
}

int sandbox_check_shm_read_data(const char *name)
{
    int fd = shm_open(name, O_RDONLY);

    if (fd == -1) {
        PRINT_ERROR("Cannot open shared memory");
        if (errno == EPERM)
            return 1;
        else
            return -1;
    }

    close(fd);
    return 0;
}

int sandbox_check_shm_read_metadata(const char *name)
{
    /**
     * This function unfortunately currently *opens* the shared memory
     * as well, thus starting a read operation on the underlying device.
     * to overcome this limitation, we could use a global structure that
     * allows us to lookup existing descriptors.
     */
    struct stat metadata;
    int fd = shm_open(name, O_RDONLY);

    if (fd == -1) {
        // Cannot open shared memory. Does the variable even exist?
        PRINT_ERROR("Cannot open shared memory");
        return -1;
    }

    int success = fstat(fd, &metadata);
    if (success != 0) {
        PRINT_ERROR("stat failed");
        return 1;
    }

    close(fd);
    return 0;
}
