#include "iokit.h"

#include <IOKit/IOKitLib.h>
#include <IOKit/usb/IOUSBLib.h>
#include <assert.h>
#include <stdlib.h>
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

/**
 * Get a service for a given user class. We use a pre-computed list based on
 * Siguza's ioscan utility. We cannot directly integrate ioscan here, because
 * we run in a sandbox and cannot arbitrarily open services. We can only
 * identify services we are allowed to open, but we also wnat know whether the
 * sandbox denies us to open a specific service.
 *
 * Trying to find the respective service without opening services will not
 * suffice, as iterated user clients depend heavily on the system's state, such
 * as currently running processes.
 *
 * The mapping can be generated beforehand with the iomap.py script.
 */
static size_t io_services_for_user_class(const char *user_class, const char ***service_names)
{
    typedef struct {
        const char *service;
        const char *client;
    } mapping_t;

    static const mapping_t mappings[] = {
        // Mappings from before 10.14.6? They were in the pre-computed list
        // before but not found for
        // - macOS 10.14.6 (18G4032)
        // - macOS 10.15.4 (19E287)
        { "AppleHV", "AppleHVClient" },
        { "AppleLMUController", "AppleLMUClient" },
        { "IOGraphicsDevice", "IOFramebufferSharedUserClient" },
        { "NVKernel", "nvTeslaSurfaceTesla" },
        { "SMCMotionSensor", "SMCMotionSensorClient" },

        // Common for
        // - macOS 10.14.6 (18G4032)
        // - macOS 10.15.4 (19E287)
        {"AGPM", "AGPMClient"},
        {"AppleAPFSContainer", "AppleAPFSUserClient"},
        {"AppleActuatorDevice", "AppleActuatorDeviceUserClient"},
        {"AppleFDEKeyStore", "AppleFDEKeyStoreUserClient"},
        {"AppleHDAEngineInput", "IOAudioEngineUserClient"},
        {"AppleHDAEngineOutput", "IOAudioEngineUserClient"},
        {"AppleHSSPIController", "AppleHSSPIControllerUserClient"},
        {"AppleHSSPIHIDDriver", "IOHIDLibUserClient"},
        {"AppleIntelFramebuffer", "IOFramebufferSharedUserClient"},
        {"AppleKeyStore", "AppleKeyStoreUserClient"},
        {"AppleMCCSControlModule", "AppleMCCSUserClient"},
        {"AppleMobileFileIntegrity", "AppleMobileFileIntegrityUserClient"},
        {"AppleMultitouchDevice", "AppleMultitouchDeviceUserClient"},
        {"ApplePlatformEnabler", "ApplePlatformEnablerUserClient"},
        {"AppleRTC", "AppleRTCUserClient"},
        {"AppleSMC", "AppleSMCClient"},
        {"AppleUpstreamUserClientDriver", "AppleUpstreamUserClient"},
        {"AudioAUUCDriver", "AudioAUUC"},
        {"IOAVBNub", "IOAVBNubUserClient"},
        {"IOAudioLevelControl", "IOAudioControlUserClient"},
        {"IOAudioSelectorControl", "IOAudioControlUserClient"},
        {"IOAudioToggleControl", "IOAudioControlUserClient"},
        {"IOBluetoothHCIController", "IOBluetoothHCIUserClient"},
        {"IODisplayWrangler", "IOAccelerationUserClient"},
        {"IOFramebufferI2CInterface", "IOI2CInterfaceUserClient"},
        {"IOHIDSystem", "IOHIDParamUserClient"},
        {"IOPMrootDomain", "RootDomainUserClient"},
        {"IOReportHub", "IOReportUserClient"},
        {"IOSurfaceRoot", "IOSurfaceRootUserClient"},
        {"IOThunderboltController", "IOThunderboltFamilyUserClient"},
        {"IOTimeSyncClockManager", "IOTimeSyncClockManagerUserClient"},
        {"IntelAccelerator", "IGAccel2DContext"},
        {"IntelAccelerator", "IGAccelCLContext"},
        {"IntelAccelerator", "IGAccelCommandQueue"},
        {"IntelAccelerator", "IGAccelDevice"},
        {"IntelAccelerator", "IGAccelGLContext"},
        {"IntelAccelerator", "IGAccelSharedUserClient"},
        {"IntelAccelerator", "IGAccelSurface"},
        {"IntelAccelerator", "IGAccelVideoContextMain"},
        {"IntelAccelerator", "IGAccelVideoContextMedia"},
        {"IntelAccelerator", "IGAccelVideoContextVEBox"},
        {"IntelAccelerator", "IOAccelDisplayPipeUserClient2"},
        {"IntelAccelerator", "IOAccelMemoryInfoUserClient"},
        {"IntelFBClientControl", "AppleGraphicsDeviceControlClient"},

        // macOS 10.14.6 (18G4032)
        {"AGDPClientControl", "AppleGraphicsDeviceControlClient"},
        {"AppleBluetoothHIDKeyboard", "IOHIDLibUserClient"},
        {"AppleHDAAudioSelectorControlDP", "IOAudioControlUserClient"},
        {"AppleHDAEngineOutputDP", "IOAudioEngineUserClient"},
        {"AppleIntelMEClientController", "AppleIntelMEUserClient"},
        {"AppleMikeyHIDDriver", "IOHIDLibUserClient"},
        {"IOBluetoothDevice", "IOBluetoothDeviceUserClient"},
        {"IOBluetoothHCIController", "IOBluetoothHCIPacketLogUserClient"},
        {"IONVMeBlockStorageDevice", "AppleNVMeSMARTUserClient"},
        {"IOUSBDevice", "IOUSBDeviceUserClientV2"},
        {"IOUSBInterface", "IOUSBInterfaceUserClientV3"},
        {"IOUSBRootHubDevice", "IOUSBDeviceUserClientV2"},

        // macOS 10.15.4 (19E287)
        {"AGDPClientControl", "AGDPUserClient"},
        {"AppleAHCIDiskDriver", "AHCISMARTUserClient"},
        {"AppleBroadcomBluetoothHostController", "IOBluetoothHostControllerUserClient"},
        {"AppleMEClientController", "AppleSNBFBUserClient"},
        {"IOBluetoothPacketLogger", "IOBluetoothPacketLoggerUserClient"},
        {"IOHIDUserDevice", "IOHIDLibUserClient"},
        {"IOTimeSyncDomain", "IOTimeSyncDomainUserClient"},
        {"IOTimeSyncgPTPManager", "IOTimeSyncgPTPManagerUserClient"},
        {"IOUSBInterface", "AppleUSBHostInterfaceUserClient"},
        {"IOUSBMassStorageResource", "IOUSBMassStorageResourceUserClient"},
        {"IOUSBRootHubDevice", "AppleUSBLegacyDeviceUserClient"},
        {"IntelAccelerator", "IOAccelGLDrawableUserClient"},
        {"IntelAccelerator", "IOAccelSurfaceMTL"}

    };
    const size_t n_mappings = sizeof(mappings) / sizeof(*mappings);

    if (!user_class)
        return 0;

    // Reverse lookup in table above.
    size_t service_count = 0;
    for (size_t i = 0; i < n_mappings; ++i) {
        const mapping_t current = mappings[i];
        if (strcmp(current.client, user_class) == 0) {
            service_count++;
            if (service_count == 1) {
                *service_names = malloc(sizeof(const char*));
            } else {
                *service_names = realloc(*service_names, sizeof(const char*) * service_count);
            }
            if (!*service_names)
                return 0;
            (*service_names)[service_count - 1] = current.service;
        }
    }
    return service_count;
}

/**
 * This function tests, whether the process is allowed to open any service
 * associated with the given client class name.
 *
 * Unfortunately, we do not now the actual service that was opened when the log
 * was generated. We only know the client. Therefore, we have to identify
 * associated services for the given client.
 *
 * Since clients can be used for multiple services and a service stored in our
 * pre-computed service mapping might belong to another macOS version, we simply
 * try top open all associated services and if one succeeds we assume that the
 * operation succeeds.
 *
 * If all services are denied to be opened (return value 1), the result is
 * correct. However, if we find a single service that we are allowed to open
 * (return value 0), the result might not be correct, as a different service
 * could have been used originally, which would result in an inconsistent match.
 */
int sandbox_check_iokit_open(const char *name)
{
    const char **service_names = NULL;
    size_t service_count = io_services_for_user_class(name, &service_names);
    if (0 == service_count)
        return -1;

    assert(service_names);

    // We need to be able to at least open one service in order to decide that
    // the currently checked rule is allowed, since we do not know which
    // service was requested.
    for (size_t i = 0; i < service_count; i++) {
        const char *service_name = service_names[i];

        io_service_t service = IOServiceGetMatchingService(
            kIOMasterPortDefault,
            IOServiceNameMatching(service_name)
        );

        if (!service)
            continue;

        io_connect_t port = MACH_PORT_NULL;
        const kern_return_t kr = IOServiceOpen(service, mach_task_self(), 0, &port);
        IOObjectRelease(service);
        if (kr != KERN_SUCCESS)
            continue;
        assert(MACH_PORT_VALID(port));

        IOServiceClose(port);
        free(service_names);
        return 0;
    }

    free(service_names);
    return 1;
}
