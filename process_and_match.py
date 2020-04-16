"""Script to post-process all outputs and match the result with our matcher"""
import process_logs

import argparse
import os
import subprocess
import multiprocessing
from misc.logger import create_logger
from misc.filesystem import project_path

logger = create_logger("process_and_match")


def matching_done(for_directory):
    return os.path.exists(os.path.join(for_directory, "match_results.json"))


def perform_matching(for_directory):
    """Invokes the matcher, assuming the directory contains both the profile
    to match against, and processed log entries."""

    matcher_path = project_path("sbpl/matcher/matcher")
    assert os.path.exists(matcher_path)

    ruleset_at = os.path.join(for_directory, "patched_profile.json")
    logs_at = os.path.join(for_directory, "sandbox_logs_processed.json")

    outfile = os.path.join(for_directory, "match_results.json")
    assert not os.path.exists(outfile)

    with open(outfile, "wb") as outf:
        returncode = subprocess.call([matcher_path, ruleset_at, logs_at], stdout=outf)
        if returncode != 0:
            logger.error("Matcher failed matching for {}".format(for_directory))


def process_entry(entry_dir):
    if matching_done(entry_dir):
        logger.info("Skipping matching {} because results are already available.".format(entry_dir))
        return

    pid_file = os.path.join(entry_dir, "process.pid")
    logs_file = os.path.join(entry_dir, "sandbox_logs.json")
    sbpl_profile = os.path.join(entry_dir, "patched_profile.json")

    if not os.path.exists(pid_file):
        logger.error("Skipping processing of {} because PID file missing.".format(entry_dir))
        return
    if not os.path.exists(logs_file):
        logger.error("Skipping processing of {} because sandbox logs file missing.".format(entry_dir))
        return
    if not os.path.exists(sbpl_profile):
        logger.error("Skipping processing of {} because sandbox profile is missing.".format(entry_dir))
        return

    # Process logs first
    try:
        process_logs.process_log_dir(entry_dir)
    except:
        logger.error("Failed converting logs for {}".format(entry_dir))
        return

    # Perform matching
    perform_matching(entry_dir)

    logger.info("Processed {}".format(entry_dir))


def process_entries(basedir):
    dir_entries = [os.path.join(basedir, x) for x in os.listdir(basedir)]

    # Not a swimming pool :-(
    pool = multiprocessing.Pool(2)
    pool.map(process_entry, dir_entries)


def main():
    parser = argparse.ArgumentParser(description='Process and match sandbox logs')
    parser.add_argument('--input', required=True,
                        help='Folder contains results folder. Matching results will be stored in the individual folders.')
    args = parser.parse_args()
    process_entries(args.input)

if __name__ == "__main__":
    main()