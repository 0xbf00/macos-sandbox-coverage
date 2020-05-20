#ifndef SANDBOX_UTILS_PROCESS_INFO_H
#define SANDBOX_UTILS_PROCESS_INFO_H

#include <unistd.h>

#include "decision.h"

/**
 * Check whether the sandbox allows the
 * process-info-dirtycontrol operation
 */
enum decision sandbox_check_dirtycontrol(pid_t target);

/**
 * Check whether the sandbox allows the
 * process-info-setcontrol operation
 */
enum decision sandbox_check_setcontrol();
enum decision sandbox_check_listpids();
enum decision sandbox_check_pidinfo(pid_t target);
enum decision sandbox_check_pidfdinfo(pid_t target);

#endif