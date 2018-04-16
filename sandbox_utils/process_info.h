#ifndef SANDBOX_UTILS_PROCESS_INFO_H
#define SANDBOX_UTILS_PROCESS_INFO_H

#include <unistd.h>

/**
 * Check whether the sandbox allows the
 * process-info-dirtycontrol operation
 */
int sandbox_check_dirtycontrol(pid_t target);

/**
 * Check whether the sandbox allows the
 * process-info-setcontrol operation
 */
int sandbox_check_setcontrol();
int sandbox_check_listpids();
int sandbox_check_pidinfo(pid_t target);
int sandbox_check_pidfdinfo(pid_t target);

#endif