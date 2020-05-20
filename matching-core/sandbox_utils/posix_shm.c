#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <assert.h>

#include "misc.h"

#include "posix_shm.h"

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
enum decision shm_open_or_create(const char *name, int oflags, int *fd_out) {
    assert(!(oflags & O_CREAT));

    int fd = shm_open(name, oflags);
    if (fd_out != NULL) {
        *fd_out = fd;
    }
    if (fd == -1) {
        if (errno == EPERM) {
            return DECISION_DENY;
        }
        if (errno == ENOENT) {
            fd = shm_open(name, oflags | O_CREAT, 0777);
            if (fd_out != NULL) {
                *fd_out = fd;
            }
            if (fd == -1) {
                /* If we cannot create a shared memory object, the profile might
                 * prohibit creation but still allow opening with the given
                 * `oflags`. We log the error but continue checking other rules,
                 * and return that we are not able to determine the result.
                 */
                PRINT_ERROR("Failed to create shared memory object");
                return DECISION_UNKNOWN;
            }
        }
    }
    if (fd_out == NULL) {
        close(fd);
    }
    return DECISION_ALLOW;
}


/**
 * Checks whether the sandbox allows to create a
 * posix shared memory variable with the specified name.
 */
enum decision sandbox_check_shm_write_create(const char *name)
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
                return DECISION_DENY;
            } else {
                return DECISION_ERROR;
            }
        }
    } else {
        if (errno == EPERM) {
            PRINT_ERROR("No permission to open file descriptor");
            return DECISION_ERROR;
        }
    }

    int fd = shm_open(name, O_RDWR | O_CREAT, 0777);
    if (fd == -1) {
        PRINT_ERROR("Cannot create writable shared memory");
        if (errno == EPERM)
            return DECISION_DENY;
        else
            return DECISION_ERROR;
    }

    close(fd);
    return DECISION_ALLOW;
}

enum decision sandbox_check_shm_write_data(const char *name)
{
    return shm_open_or_create(name, O_RDWR, NULL);
}

enum decision sandbox_check_shm_write_unlink(const char *name)
{
    int failed = shm_unlink(name);
    if (failed) {
        PRINT_ERROR("Cannot unlink shared memory");
        if (errno == EPERM)
            return DECISION_DENY;
        else
            return DECISION_ERROR;
    }

    return DECISION_ALLOW;
}

enum decision sandbox_check_shm_read_data(const char *name)
{
    return shm_open_or_create(name, O_RDONLY, NULL);
}

enum decision sandbox_check_shm_read_metadata(const char *name)
{
    /**
     * This function unfortunately currently *opens* the shared memory
     * as well, thus starting a read operation on the underlying device.
     * to overcome this limitation, we could use a global structure that
     * allows us to lookup existing descriptors.
     */
    struct stat metadata;
    int fd = -1;
    const enum decision decision = shm_open_or_create(name, O_RDONLY, &fd);

    if (fd == -1) {
        return decision;
    }
    assert(decision == DECISION_ALLOW);

    int success = fstat(fd, &metadata);
    if (success != 0) {
        PRINT_ERROR("stat failed");
        return DECISION_DENY;
    }

    close(fd);
    return DECISION_ALLOW;
}
