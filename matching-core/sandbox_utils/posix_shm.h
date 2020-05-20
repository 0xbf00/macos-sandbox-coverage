#ifndef SANDBOX_UTILS_POSIX_SHM_H
#define SANDBOX_UTILS_POSIX_SHM_H

#include "decision.h"

/**
 * Checks whether the sandbox allows to create a
 * posix shared memory variable with the specified name.
 */
enum decision sandbox_check_shm_write_create(const char *name);
enum decision sandbox_check_shm_write_data(const char *name);
enum decision sandbox_check_shm_write_unlink(const char *name);
enum decision sandbox_check_shm_read_data(const char *name);
enum decision sandbox_check_shm_read_metadata(const char *name);

#endif