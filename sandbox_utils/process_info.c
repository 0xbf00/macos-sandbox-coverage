#include "process_info.h"

#include <stdint.h>
#include <libproc.h>

/**
 * Check whether the sandbox allows the
 * process-info-dirtycontrol operation
 */
int sandbox_check_dirtycontrol(pid_t target)
{
    pid_t pid = target;
    uint32_t flags = 0;

    int res = proc_get_dirty(pid, &flags);

    return (res != 0);
}

/**
 * Check whether the sandbox allows the
 * process-info-setcontrol operation
 */
int sandbox_check_setcontrol(pid_t target /* unused */)
{
    int res = proc_setpcontrol(PROC_SETPC_NONE);

    return (res != 0);
}

int sandbox_check_listpids(pid_t target /* unused */)
{
    int res = proc_listallpids(NULL, 0);

    // A return value of 0 indicates the operation was denied.
    return (res == 0);
}

int sandbox_check_pidinfo(pid_t target)
{
    pid_t pid = target;
    struct proc_bsdinfo proc;

    int res = proc_pidinfo(pid, PROC_PIDTBSDINFO, 0,
                           &proc, PROC_PIDTBSDINFO_SIZE);
    
    // A return value of PROC_PIDTBSDINFO_SIZE indicates success
    return (res != PROC_PIDTBSDINFO_SIZE);
}

int sandbox_check_pidfdinfo(pid_t target)
{
    pid_t pid = target;
    struct vnode_fdinfowithpath vnode_info;
    
    // Make sure stdout is still valid.
    int res = proc_pidfdinfo(pid, 0, 
        PROC_PIDFDVNODEPATHINFO, 
        &vnode_info, 
        PROC_PIDFDVNODEPATHINFO_SIZE);

    return (res != PROC_PIDFDVNODEPATHINFO_SIZE);
}