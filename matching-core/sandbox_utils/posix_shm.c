#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <assert.h>

#include "misc.h"

/**
 * Try to check whether we are allowed to open a shared memory object. Since we
 * do try to check sandbox rules after they have been collected by the original
 * process, the original shared memory objects might have been closed already.
 * Therefore we try to create them instead.
 *
 * If the file descriptor of the shared memory object is needed, you can pass a
 * pointer fd_out and you need to take care of closing the file yourself. If
 * that value is NULL, created files will be closed again automatically.
 */
int shm_open_or_create(const char *name, int oflags, int *fd_out) {
    assert(!(oflags & O_CREAT));

    int fd = shm_open(name, oflags);
    if (fd_out != NULL) {
        *fd_out = fd;
    }
    if (fd == -1) {
        if (errno == EPERM) {
            return 1;
        }
        if (errno == ENOENT) {
            fd = shm_open(name, oflags | O_CREAT, 0777);
            if (fd_out != NULL) {
                *fd_out = fd;
            }
            if (fd == -1) {
                PRINT_ERROR("Failed to create shared memory object");
                return -1;
            }
        }
    }
    if (fd_out == NULL) {
        close(fd);
    }
    return 0;
}


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
    return shm_open_or_create(name, O_RDWR, NULL);
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
    return shm_open_or_create(name, O_RDONLY, NULL);
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
    int fd = -1;
    const int decision = shm_open_or_create(name, O_RDONLY, &fd);

    if (fd == -1) {
        return decision;
    }
    assert(decision == 0);

    int success = fstat(fd, &metadata);
    if (success != 0) {
        PRINT_ERROR("stat failed");
        return 1;
    }

    close(fd);
    return 0;
}
