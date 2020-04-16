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
import json

sys.path.append(os.path.join(os.path.dirname(__file__), "maap"))

from maap.misc.logger import create_logger
from maap.misc.app_utils import init_sandbox, container_for_app, run_process
from maap.misc.filesystem import project_path
from maap.extern.tools import call_sbpl, tool_named
from maap.bundle.bundle import Bundle

from sblogs.gather import gather_logs
from sblogs.process import process_logs

logger = create_logger('rule_matching.gather_logs')

def main():
    parser = argparse.ArgumentParser(description='Collect sandbox logs for an application run')
    parser.add_argument('--app', required=True,
                        help='Path to the app for which to collect sandbox logs.')
    parser.add_argument('--outdir', required=True,
                        help='Base location where to store output files. Note: This directory will be created by the program and must not exist!')
    parser.add_argument('--timeout', required=False, default=None, type=int,
                        help='Number of seconds to wait before killing the program. Leave unspecified to not kill the program at all.')
    args = parser.parse_args()

    res = gather_logs(args.app, args.outdir, timeout=args.timeout)
    if res is None:
        return

    pid, unprocessed_logs = res
    processed_logs = process_logs(unprocessed_logs, pid)

    output_file = os.path.join(args.outdir, "sandbox_logs_processed.json")
    with open(output_file, "w", encoding="utf8") as outfile:
        json.dump(processed_logs, outfile, indent=4, ensure_ascii=False)


if __name__ == "__main__":
    main()