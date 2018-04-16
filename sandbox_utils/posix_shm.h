/**
 * Checks whether the sandbox allows to create a
 * posix shared memory variable with the specified name.
 */
int sandbox_check_shm_write_create(const char *name);
int sandbox_check_shm_write_data(const char *name);
int sandbox_check_shm_write_unlink(const char *name);
int sandbox_check_shm_read_data(const char *name);
int sandbox_check_shm_read_metadata(const char *name);