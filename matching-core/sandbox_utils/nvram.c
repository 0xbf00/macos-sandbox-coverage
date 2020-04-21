#include "nvram.h"

#include <IOKit/IOKitLib.h>
#include <IOKit/usb/IOUSBLib.h>
#include <assert.h>

static io_registry_entry_t nvram_root()
{
    static io_registry_entry_t nvram = 0;

    if (!nvram) {
        mach_port_t master_port;
        kern_return_t result = IOMasterPort(MACH_PORT_NULL, &master_port);
        if (result != KERN_SUCCESS) {
            return 0;
        }

        nvram = IORegistryEntryFromPath(master_port, "IODeviceTree:/options");
    }

    return nvram;
}

int sandbox_check_nvram_get(const char *variable_name)
{
    io_registry_entry_t root = nvram_root();

    if (!root)
        return 1;

    kern_return_t result;
    CFMutableDictionaryRef dict;
  
    // This call triggers all NVRAM variables to be queried and results
    // in a number of deny statements in the system log ordinarily.
    // However, we can then decide if our particular variable name was
    // allowed or not.
    result = IORegistryEntryCreateCFProperties(root, &dict, 0, 0);
    if (result != KERN_SUCCESS)
        return 1;

    CFStringRef variable = CFStringCreateWithCStringNoCopy(NULL, 
        variable_name, kCFStringEncodingUTF8, kCFAllocatorNull);
    assert(variable);

    const void *value = CFDictionaryGetValue(dict, variable);
    return (value == NULL);
}
