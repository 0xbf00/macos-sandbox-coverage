#ifndef SANDBOX_UTILS_POSIX_SEM_H
#define SANDBOX_UTILS_POSIX_SEM_H

#include "decision.h"

enum decision sandbox_check_sem_create(const char *name);
enum decision sandbox_check_sem_open(const char *name);
enum decision sandbox_check_sem_post(const char *name);
enum decision sandbox_check_sem_wait(const char *name);
enum decision sandbox_check_sem_unlink(const char *name);

#endif