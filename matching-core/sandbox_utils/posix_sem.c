#include "posix_sem.h"
#include "misc.h"

#include <stdio.h>
#include <semaphore.h>
#include <errno.h>

/*
 POSIX Semaphore related functions
 */
enum decision sandbox_check_sem_create(const char *name)
{
    sem_t *existing_sem = sem_open(name, 0);
    if (existing_sem != SEM_FAILED) {
        // There already is such a semaphore, we cannot decide whether
        // we are allowed to create a new one. We therefore
        // attempt to unlink the existing one, so we can create a new
        // one. If this fails, we return -1 to indicate we cannot
        // decide what the sandbox'd do.
        if (sem_unlink(name) != 0)
            return DECISION_ERROR;
    } else if (errno == EPERM) {
        return DECISION_ERROR;
    }

    sem_t *semaphore = sem_open(name, O_CREAT, 0777, 1);
    if (semaphore == SEM_FAILED) {
        PRINT_ERROR("Cannot create semaphore");
        if (errno == EPERM)
            return DECISION_DENY;
        else
            return DECISION_ERROR;
    }

    sem_close(semaphore);
    return 0;
}

/* STUB: TODO */
enum decision sandbox_check_sem_open(const char *name)
{
    return DECISION_ERROR;
}

enum decision sandbox_check_sem_post(const char *name)
{
    sem_t *semaphore = sem_open(name, 0);
    if (semaphore == SEM_FAILED) {
        PRINT_ERROR("Cannot open semaphore");
        return DECISION_ERROR;
    }

    int success = sem_post(semaphore);
    return (success != 0) ? DECISION_DENY : DECISION_ALLOW;
}

enum decision sandbox_check_sem_wait(const char *name)
{
    sem_t *semaphore = sem_open(name, 0);
    if (semaphore == SEM_FAILED) {
        PRINT_ERROR("Cannot open semaphore");
        return DECISION_ERROR;
    }

    int success = sem_trywait(semaphore);

    return ((success != 0) && (errno != EAGAIN)) ? DECISION_DENY : DECISION_ALLOW;
}

enum decision sandbox_check_sem_unlink(const char *name)
{
    /*
        Note: this fails if the semaphore does not exist.
        We cannot really work around this here, because
        first opening to check whether the semaphore exists
        triggers another sandbox operation that might be denied.
    */
    int success = sem_unlink(name);
    if (success == -1) {
        if (errno == EPERM)
            return DECISION_DENY;
    }

    return (success == 0) ? DECISION_ALLOW : DECISION_ERROR;
}