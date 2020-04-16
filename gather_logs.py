"""
gather_logs

(c) Jakob Rieck 2018

Tool to collect sandbox logs for a given application. Sandbox logs contain
all allow and deny decisions that sandboxd was nice enough to log to the system log.
"""
import argparse
import os
import subprocess
import datetime
import sys

sys.path.append(os.path.join(os.path.dirname(__file__), "maap"))

from maap.misc.logger import create_logger
from maap.misc.app_utils import init_sandbox, container_for_app, run_process
from maap.misc.filesystem import project_path
from maap.extern.tools import call_sbpl, tool_named
from maap.bundle.bundle import Bundle

from sblogs.process import process_logs

logger = create_logger('rule_matching.gather_logs')

def process_sb_profiles(bundle, outdir):
    """
    This function does three things:
        1. It stores the original sandbox profile of the app in JSON format,
           allowing it to be used later on for matching purposes
           The output filename is `outdir/original_profile.json`
        2. It modifies the sandbox profile to enable comprehensive logging
           output. I refer to this as "patching" a profile.
        3. It injects the compiled modified sandbox profile into the application's
           Container.plist metadata file, forcing the system to use our modified
           sandbox profile for subsequent app launches
    
    The function returns True on success and Fale otherwise
    """
    APP_CONTAINER = container_for_app(bundle)
    ORIGINAL_PROFILE_PATH = os.path.join(outdir, "original_profile.json")
    PATCHED_PROFILE_TEMP_PATH = os.path.join(outdir, "patched_profile.bin")

    # We patch the existing profile to enable logging for every allow operation
    patched_profile = call_sbpl(APP_CONTAINER, result_format='scheme', patch=True)

    # The original profile will be needed later on for matching purposes
    original_profile = call_sbpl(APP_CONTAINER, result_format='json')
    with open(ORIGINAL_PROFILE_PATH, "wb") as outfile:
        outfile.write(original_profile)

    # Compile the profile using stefan esser's tool
    compile_sb = tool_named("compile_sb")
    exit_code, _ = compile_sb("/dev/stdin", PATCHED_PROFILE_TEMP_PATH, input=patched_profile)
    if exit_code != 0:
        return False
    
    # The easiest way to make sure our patched profile is actually used would be
    # to hook the responsible methods in libsystem_secinit and make them load another
    # profile at runtime. Unfortunately, stock macOS kernels set the CS_RESTRICT flag on
    # applications that have entitlements and dyld will ignore all DYLD_ variables,
    # making this impossible without patching the kernel. (or patching dyld, but dyld is a
    # platform binary which further complicates this task)
    # However, one can simply modify the Container.plist metadata file. Simply modify the
    # SandboxProfileData embedded and the sandbox will happily use this profile.

    # Replace the sandbox profile data with our custom compiled profile (see above)
    # PlistBuddy is a useful program to do this.
    container_metadata = os.path.join(APP_CONTAINER, "Container.plist")
    assert os.path.isfile(container_metadata)

    subprocess.call([
        "/usr/libexec/PlistBuddy",
        "-c", "Import SandboxProfileData \"{}\"".format(PATCHED_PROFILE_TEMP_PATH),
        container_metadata
    ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    os.unlink(PATCHED_PROFILE_TEMP_PATH)

    return True

def collect_sb_traces(bundle: Bundle, outdir: str, timeout: int) -> bytes:
    """
    This function runs the supplied app, either indefinitely (`timeout` = None)
    or for the specified number of `timeout` seconds. It collects system log
    entries during this time and returns them to the caller.

    It creates a new folder named "process_infos" in `outdir`. In this directory,
    it stores files "stdout", "stderr" and "pid", which contain the outputs of
    the app and its pid. While the outputs are only relevant in select cases to
    debug issues, the pid file is relevant for filtering log entries
    """
    # Start / stop times necessary to filter log entries
    start = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    logger.info("Starting {} to collect sandbox logs.".format(bundle.filepath))

    # Run app, collect information in "process_infos" subfolder
    INFOS_FOLDER = os.path.join(outdir, "process_infos")
    os.mkdir(INFOS_FOLDER)

    INFO_STDOUT = os.path.join(INFOS_FOLDER, "stdout")
    INFO_STDERR = os.path.join(INFOS_FOLDER, "stderr")
    INFO_PID    = os.path.join(INFOS_FOLDER, "pid")

    with open(INFO_STDOUT, "w") as stdout_f, open(INFO_STDERR, "w") as stderr_f, open(INFO_PID, "w") as pid_f:
        pid = run_process(bundle.executable_path(), timeout, stdout_f, stderr_f)
        print("{}".format(pid), file = pid_f)

    end = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    try:
        return subprocess.check_output(["log", "show",
                         "--start", start,
                         "--end", end,
                         "--style", "json",
                         "--predicate", 'senderImagePath == "/System/Library/Extensions/Sandbox.kext/Contents/MacOS/Sandbox"'])
    except subprocess.CalledProcessError:
        logger.error("Unable to retrieve raw sandbox logs for {}".format(bundle.filepath))
        return


def process_app(app_path, outdir, timeout=60):
    if not (app_path.endswith(".app") or app_path.endswith(".app/")) and Bundle.is_bundle(app_path):
        logger.error("Provided path {} is not a valid app. Skipping.".format(app_path))
        return

    bundle = Bundle.make(app_path)
    if not bundle.is_sandboxed():
        logger.error("Application at path {} is not sandboxed, therefore no sandbox traces will be collected.".format(app_path))
        return

    # Make sure to let the sandbox run once, because we need the metadata generated by the
    # sandbox
    init_successful = init_sandbox(bundle, logger)
    if not init_successful:
        logger.error("Failed to initialise sandbox for {}. Skipping.".format(app_path))
        return

    if os.path.isdir(outdir):
        logger.info("Skipping processing for {}, as output folder already exists.".format(app_path))
        return

    os.mkdir(outdir)

    if not process_sb_profiles(bundle, outdir):
        logger.error("Could not process sandbox profiles for {}".format(app_path))
        return

    traces = collect_sb_traces(bundle, outdir, timeout)
    if not traces:
        logger.error("Unable to collect sandbox logs for app {}".format(app_path))
        return

    TRACES_OUT = os.path.join(outdir, "sandbox_logs.json")
    with open(TRACES_OUT, "wb") as out:
        out.write(traces)


def main():
    parser = argparse.ArgumentParser(description='Collect sandbox logs for an application run')
    parser.add_argument('--app', required=True,
                        help='Path to the app for which to collect sandbox logs.')
    parser.add_argument('--outdir', required=True,
                        help='Base location where to store output files. Note: This directory will be created by the program and must not exist!')
    parser.add_argument('--timeout', required=False, default=None, type=int,
                        help='Number of seconds to wait before killing the program. Leave unspecified to not kill the program at all.')
    args = parser.parse_args()

    process_app(args.app, args.outdir, timeout=args.timeout)


if __name__ == "__main__":
    main()