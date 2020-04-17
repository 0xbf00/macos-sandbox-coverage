"""Script to re-process inconsistent and wrongly matched outputs"""
import argparse
import os
import subprocess
import multiprocessing
import sys

sys.path.append(os.path.join(os.path.dirname(__file__), "maap"))

from maap.misc.logger import create_logger
from maap.misc.filesystem import project_path

logger = create_logger("reprocess")

stderr_file = open("/tmp/stderr_rematching", "wb")


def rematching_done(for_directory):
    return os.path.exists(os.path.join(for_directory, "rematch_results.json"))


def perform_rematching(for_directory):
    """Invokes the matcher, assuming the directory contains both the profile
    to match against, and processed log entries."""

    matcher_path = project_path("sbpl/matcher/rematcher/rematcher")
    assert os.path.exists(matcher_path)

    ruleset_at = os.path.join(for_directory, "patched_profile.json")
    logs_at = os.path.join(for_directory, "sandbox_logs_processed.json")
    match_resuts_at = os.path.join(for_directory, "match_results.json")

    outfile = os.path.join(for_directory, "rematch_results.json")
    assert not os.path.exists(outfile)

    with open(outfile, "wb") as outf:
        returncode = subprocess.call([matcher_path, ruleset_at, logs_at, match_resuts_at], stdout=outf, stderr=stderr_file)
        if returncode != 0:
            logger.error("Rematching failed matching for {}".format(for_directory))


def process_entry(entry_dir):
    if rematching_done(entry_dir):
        logger.info("Skipping rematching {} because results are already available.".format(entry_dir))
        return

    logs_file = os.path.join(entry_dir, "sandbox_logs.json")
    sbpl_profile = os.path.join(entry_dir, "patched_profile.json")
    match_results = os.path.join(entry_dir, "match_results.json")

    if not os.path.exists(logs_file):
        logger.error("Skipping processing of {} because sandbox logs file missing.".format(entry_dir))
        return
    if not os.path.exists(sbpl_profile):
        logger.error("Skipping processing of {} because sandbox profile is missing.".format(entry_dir))
        return
    if not os.path.exists(match_results):
        logger.error("Skipping processing of {} because match results are missing.".format(entry_dir))

    # Perform matching
    perform_rematching(entry_dir)

    logger.info("Processed {}".format(entry_dir))


def process_entries(basedir):
    dir_entries = [os.path.join(basedir, x) for x in os.listdir(basedir) if not x.startswith(".")]

    # Not a swimming pool :-(
    pool = multiprocessing.Pool(2)
    pool.map(process_entry, dir_entries)


def main():
    parser = argparse.ArgumentParser(description='Reprocess sandbox logs')
    parser.add_argument('--input', required=True,
                        help='Folder contains results folder. Matching results will be stored in the individual folders.')
    args = parser.parse_args()
    process_entries(args.input)

if __name__ == "__main__":
    main()