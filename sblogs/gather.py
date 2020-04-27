"""
(c) Jakob Rieck 2018

Tool to collect sandbox logs for a given application. Sandbox logs contain
all allow and deny decisions that sandboxd was nice enough to log to the system log.
"""
import os
import subprocess
import datetime
import json
import plistlib
import tempfile

from maap.misc.logger import create_logger
from maap.misc.app_utils import init_sandbox, container_for_app, run_process
from maap.misc.filesystem import project_path
from maap.misc.plist import parse_resilient
from maap.extern.tools import call_sbpl, tool_named
from maap.bundle.bundle import Bundle

logger = create_logger('sblogs.gather')

def read_sb_profile(metadata_path: str) -> bytes:
    """
    Reads sandbox profile data from the supplied container
    """
    data = parse_resilient(metadata_path)
    return data['SandboxProfileData']

def write_sb_profile(metadata_path: str, profile: bytes):
    """
    Writes (modified) sandbox profile to supplied container
    """
    data = parse_resilient(metadata_path)
    data['SandboxProfileData'] = profile
    with open(metadata_path, "wb") as outfile:
        plistlib.dump(data, outfile)

def compile_sb_profile(profile: str) -> bytes:
    compile_sb = tool_named("compile_sb")
    exit_code, result = compile_sb("/dev/stdin", "/dev/stdout", input=profile)
    if exit_code != 0:
        return
    
    return result


def process_sb_profiles(state: dict) -> (bool, dict):
    """
    This function does three things:
        1. It extracts the original container metadata of the app, allowing
           it to be used later to create the normalised version of this container.
        2. It extracts the original sandbox profile of the app in JSON format,
           allowing it to be used later on for matching purposes
        3. It modifies the sandbox profile to enable comprehensive logging
           output. I refer to this as "patching" a profile.
    """
    bundle = Bundle.make(state['arguments']['app'])

    APP_CONTAINER = container_for_app(bundle)
    APP_METADATA_FILE = os.path.join(APP_CONTAINER, "Container.plist")

    # Original copy of metadata is needed later on to create normalised sandbox profiles
    with open(APP_METADATA_FILE, "rb") as infile:
        state['container_metadata'] = infile.read()

    # Only continue iff simbple is able to correctly recompile the target sandbox profile
    if call_sbpl(APP_CONTAINER, verify=True) is None:
        logger.error(
            f"Unable to verify simbple output for target app's sandbox profile: {APP_CONTAINER}"
        )
        return False, {}
    original_profile = call_sbpl(APP_CONTAINER, result_format='json')

    # We patch the existing profile to enable logging for every allow operation
    patched_profile = call_sbpl(APP_CONTAINER, result_format='scheme', patch=True)

    if 'sandbox_profiles' not in state:
        state['sandbox_profiles'] = dict()

    state['sandbox_profiles'].update({
        'original': original_profile,
        'patched': patched_profile,
    })

    # Compile the profile using stefan esser's tool
    compiled_patched_profile = compile_sb_profile(patched_profile)
    if compiled_patched_profile is None:
        return False, {}
    
    return True, state

def collect_sb_traces(state: dict) -> (bool, dict):
    """
    This function enables comprehensive sandbox logging, runs the supplied app,
    either indefinitely (`timeout` = None) or for the specified number of `timeout`
    seconds. It collects system log entries during this time and stores all of the
    information collected in the `state` structure.
    """
    bundle = Bundle.make(state['arguments']['app'])
    APP_METADATA_FILE = os.path.join(container_for_app(bundle), "Container.plist")
    timeout = state['arguments']['timeout']

    # The easiest way to make sure our patched profile is actually used would be
    # to hook the responsible methods in libsystem_secinit and make them load another
    # profile at runtime. Unfortunately, stock macOS kernels set the CS_RESTRICT flag on
    # applications that have entitlements and dyld will ignore all DYLD_ variables,
    # making this impossible without patching the kernel. (or patching dyld, but dyld is a
    # platform binary which further complicates this task)
    # However, one can simply modify the Container.plist metadata file. Simply modify the
    # SandboxProfileData embedded and the sandbox will happily use this profile.
    write_sb_profile(APP_METADATA_FILE, compile_sb_profile(state['sandbox_profiles']['patched']))

    logger.info("Starting {} to collect sandbox logs.".format(bundle.filepath))

    # Start / stop times necessary to filter log entries
    start = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    with tempfile.TemporaryDirectory() as tempdirname:
        INFO_STDOUT = os.path.join(tempdirname, "stdout")
        INFO_STDERR = os.path.join(tempdirname, "stderr")

        with open(INFO_STDOUT, "w") as stdout_f, open(INFO_STDERR, "w") as stderr_f:
            state['process_infos'] = {
                'pid': run_process(bundle.executable_path(), timeout, stdout_f, stderr_f)
            }

        state['process_infos'].update({
            'stdout': open(INFO_STDOUT).read(),
            'stderr': open(INFO_STDERR).read()
        })

    end = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Restore original container metadata.
    with open(APP_METADATA_FILE, "wb") as outfile:
        outfile.write(state['container_metadata'])

    try:
        state['logs'] = {
            'raw': json.loads(subprocess.check_output(["log", "show",
                         "--start", start,
                         "--end", end,
                         "--style", "json",
                         "--predicate", 'senderImagePath == "/System/Library/Extensions/Sandbox.kext/Contents/MacOS/Sandbox"']))
        }
        return True, state
    except subprocess.CalledProcessError:
        logger.error("Unable to retrieve raw sandbox logs for {}".format(bundle.filepath))
        return False, {}


def gather_logs(state: dict) -> (bool, dict):
    app_path = state['arguments']['app']

    if not (app_path.endswith(".app") or app_path.endswith(".app/")) and Bundle.is_bundle(app_path):
        logger.error("Provided path {} is not a valid app. Skipping.".format(app_path))
        return False, {}

    bundle = Bundle.make(app_path)
    if not bundle.is_sandboxed():
        logger.error("Application at path {} is not sandboxed, therefore no sandbox traces will be collected.".format(app_path))
        return False, {}

    # Make sure to let the sandbox run once, because we need the metadata generated by the sandbox
    init_successful = init_sandbox(bundle, logger, state)
    if not init_successful:
        logger.error("Failed to initialise sandbox for {}. Skipping.".format(app_path))
        return False, {}

    success, state = process_sb_profiles(state)
    if not success:
        logger.error("Could not process sandbox profiles for {}".format(app_path))
        return False, {}

    success, state = collect_sb_traces(state)
    if not success:
        logger.error("Unable to collect sandbox logs for app {}".format(app_path))
        return False, {}

    return True, state