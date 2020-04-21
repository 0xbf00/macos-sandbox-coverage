"""
(c) Jakob Rieck 2018

Tool to collect sandbox logs for a given application. Sandbox logs contain
all allow and deny decisions that sandboxd was nice enough to log to the system log.
"""
import argparse
import os
import subprocess
import datetime
import sys
import json
import plistlib

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
        1. It stores the original container metadata of the app, allowing
           it to be used later to create the normalised version of this container.
        2. It stores the original sandbox profile of the app in JSON format,
           allowing it to be used later on for matching purposes
           The output filename is `outdir/original_profile.json`
        3. It modifies the sandbox profile to enable comprehensive logging
           output. I refer to this as "patching" a profile.
    
    The function returns True on success and Fale otherwise
    """
    bundle = Bundle.make(state['arguments']['app'])

    APP_CONTAINER = container_for_app(bundle)
    APP_METADATA_FILE = os.path.join(APP_CONTAINER, "Container.plist")

    # Original copy of metadata is needed later on to create normalised sandbox profiles
    with open(APP_METADATA_FILE, "rb") as infile:
        state['container_metadata'] = infile.read()

    # Only continue iff simbple is able to correctly recompile the target sandbox profile
    if compile_sb_profile(call_sbpl(APP_CONTAINER)) != read_sb_profile(APP_METADATA_FILE):
        logger.error("Unable to recompile target app's sandbox profile.")
        return False, {}
    original_profile = call_sbpl(APP_CONTAINER, result_format='json')

    # We patch the existing profile to enable logging for every allow operation
    patched_profile = call_sbpl(APP_CONTAINER, result_format='scheme', patch=True)

    state['sandbox_profiles'] = {
        'original': original_profile,
        'patched': patched_profile,
    }

    # Compile the profile using stefan esser's tool
    compiled_patched_profile = compile_sb_profile(patched_profile)
    if compiled_patched_profile is None:
        return False, {}
    
    return True, state

def collect_sb_traces(state: dict) -> (bool, dict):
    """
    This function enables comprehensive sandbox logging, runs the supplied app,
    either indefinitely (`timeout` = None) or for the specified number of `timeout`
    seconds. It collects system log entries during this time and returns them to
    the caller.

    It creates a new folder named "process_infos" in `outdir`. In this directory,
    it stores files "stdout", "stderr" and "pid", which contain the outputs of
    the app and its pid. While the outputs are only relevant in select cases to
    debug issues, the pid file is relevant for filtering log entries
    """
    bundle = Bundle.make(state['arguments']['app'])
    APP_METADATA_FILE = os.path.join(container_for_app(bundle), "Container.plist")
    outdir = state['arguments']['outdir']
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

    # Run app, collect information in "process_infos" subfolder
    INFOS_FOLDER = os.path.join(outdir, "process_infos")
    os.mkdir(INFOS_FOLDER)

    INFO_STDOUT = os.path.join(INFOS_FOLDER, "stdout")
    INFO_STDERR = os.path.join(INFOS_FOLDER, "stderr")

    with open(INFO_STDOUT, "w") as stdout_f, open(INFO_STDERR, "w") as stderr_f:
        state['pid'] = run_process(bundle.executable_path(), timeout, stdout_f, stderr_f)

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
    outdir = state['arguments']['outdir']

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

    # TODO: Extract this bit of functionality
    if os.path.isdir(outdir):
        logger.info("Skipping processing for {}, as output folder already exists.".format(app_path))
        return False, {}

    os.mkdir(outdir)

    success, state = process_sb_profiles(state)
    if not success:
        logger.error("Could not process sandbox profiles for {}".format(app_path))
        return False, {}

    success, state = collect_sb_traces(state)
    if not success:
        logger.error("Unable to collect sandbox logs for app {}".format(app_path))
        return False, {}

    return True, state