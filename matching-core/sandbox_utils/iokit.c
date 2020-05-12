#include "iokit.h"

#include <IOKit/IOKitLib.h>
#include <IOKit/usb/IOUSBLib.h>
#include <string.h>

/**
 * Convert CFStringRef to C string.
 * The caller is responsible for freeing the return value.
 */
static const char *str_for_cfstr(CFStringRef str)
{
    // Fast path, simply get pointer to internal storage.
    const char *c_str = CFStringGetCStringPtr(str, kCFStringEncodingUTF8);
    if (c_str)
        return strdup(c_str);

    // ... otherwise, copy out characters.
    const size_t buf_size = 1000;
    char local_buf[buf_size] = { 0 };

    bool ret = CFStringGetCString(str, local_buf, buf_size, kCFStringEncodingUTF8);
    if (!ret)
        return NULL;

    return strdup(local_buf);
}

static const char *io_service_for_user_class(const char *user_class)
{
    typedef struct {
        const char *key;
        const char *value;
    } mapping_t;

    // Precomputed list, by way of Siguza's ioscan utility.
    static const mapping_t mappings[] = {
        { "AGPM", "AGPMClient" },
        { "AppleHDAEngineInput", "IOAudioEngineUserClient" },
        { "AppleHSSPIHIDDriver", "IOHIDLibUserClient" },
        { "AppleHV", "AppleHVClient" },
        { "AppleLMUController", "AppleLMUClient" },
        { "AppleUpstreamUserClientDriver", "AppleUpstreamUserClient" },
        { "AudioAUUCDriver", "AudioAUUC"},
        { "IOAudioSelectorControl", "IOAudioControlUserClient" },
        { "IOBluetoothHCIController", "IOBluetoothHCIUserClient" },
        { "IODisplayWrangler", "IOAccelerationUserClient" },
        { "IOGraphicsDevice", "IOFramebufferSharedUserClient" },
        { "IOPMrootDomain", "RootDomainUserClient" },
        { "IORegistryEntry", "AppleUSBHostDeviceUserClient" },
        { "IORegistryEntry", "AppleUSBLegacyDeviceUserClient" },
        { "IORegistryEntry", "IOHIDParamUserClient" },
        { "IOSurfaceRoot", "IOSurfaceRootUserClient" },
        { "IOUSBInterface", "IOUSBInterfaceUserClientV3" },
        { "IOUSBRootHubDevice", "IOUSBDeviceUserClientV2" },
        { "NVKernel", "nvTeslaSurfaceTesla" },
        { "SMCMotionSensor", "SMCMotionSensorClient" }
    };
    const size_t n_mappings = sizeof(mappings) / sizeof(*mappings);

    if (!user_class)
        return NULL;

    // Reverse lookup in table above.
    for (size_t i = 0; i < n_mappings; ++i) {
        if (strcmp(mappings[i].value, user_class) == 0)
            return mappings[i].key;
    }

    return NULL;
}

/**
 * Lookup IOKit service name for (internal) IOKit class
 * Unused right now, because it is flaky for some inputs.
 */
static const char *IOServiceNameForClass(const char *name)
{
    if (!name)
        return NULL;

    CFStringRef class = CFStringCreateWithCStringNoCopy(NULL,
        name, kCFStringEncodingUTF8, kCFAllocatorNull);
    CFStringRef bundle_id = IOObjectCopyBundleIdentifierForClass(class);

    const char *candidate_service = NULL;
    const char *service = NULL;

    if (bundle_id == NULL)
        return NULL;

    io_iterator_t it = MACH_PORT_NULL;
    io_object_t o;

    if(IORegistryCreateIterator(kIOMasterPortDefault, kIOServicePlane, kIORegistryIterateRecursively, &it) == KERN_SUCCESS)
    {
        while((o = IOIteratorNext(it)) != 0)
        {
            CFMutableDictionaryRef p = NULL;
            kern_return_t ret = IORegistryEntryCreateCFProperties(o, &p, NULL, 0);

            if (ret == KERN_SUCCESS) {
                CFStringRef kext_bundle_id = CFDictionaryGetValue(p, CFSTR("CFBundleIdentifier"));

                if (kext_bundle_id && CFEqual(kext_bundle_id, bundle_id)) {
                    // Check to see if the correct IOUserClientClass is specified.
                    CFStringRef user_client = CFDictionaryGetValue(p, CFSTR("IOUserClientClass"));
                    // Grab name of providing class
                    CFStringRef service_name = CFDictionaryGetValue(p, CFSTR("IOClass"));

                    if (user_client && CFEqual(user_client, class)) {
                        service = str_for_cfstr(service_name);
                    } else {
                        candidate_service = str_for_cfstr(service_name);
                    }
                }
            }

            CFRelease(p);
            IOObjectRelease(o);
            if (service)
                break;
        }
        IOObjectRelease(it);
    }

    CFRelease(bundle_id);
    CFRelease(class);

    if (!service)
        service = candidate_service;

    return service;
}

int sandbox_check_iokit_open(const char *name)
{
    kern_return_t     kr;
    io_service_t      serviceObject;
    io_connect_t dataPort = 0;

    const char *service_name = io_service_for_user_class(name);
    if (!service_name)
        return -1;

    serviceObject = IOServiceGetMatchingService(kIOMasterPortDefault,
                        IOServiceNameMatching(service_name));

    if (!serviceObject) {
        return 1;
    }

    kr = IOServiceOpen(serviceObject, mach_task_self(), 0, &dataPort);
    IOObjectRelease(serviceObject);
    if (kr != KERN_SUCCESS) {
        return 1;
    }

    IOServiceClose(dataPort);
    return 0;
}
