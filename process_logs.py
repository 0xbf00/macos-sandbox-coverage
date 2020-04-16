"""
process_logs

(c) Jakob Rieck 2018

Process logs collected by gather_logs tool.
Raw log files contain lots of information we do not need
At this point, we are only interested in the message text,
which contains the action taken (allow or deny), as well as
the particular operation and resource affected.

This tool further filters the results so that the result
only contains information regarding the process of interest.
"""
import argparse
import os
import json
import re

from misc.logger import create_logger
from misc.filesystem import project_path

logger = create_logger('rule_matching.process_logs')


def get_op_names():
    with open(project_path("mas_tools/scripts/ops.json")) as infile:
        return [x["name"] for x in json.load(infile)]


valid_op_names = get_op_names()


def parse_action_field(action_part):
    """
    Convert a string action part such as "allow", "deny",
    "deny(1)" or similar to the canonical "allow" or "deny"
    decision.

    :param action_part: See description above
    :return: Canonical action, either allow or deny
    """

    if action_part == "allow" or action_part == "deny":
        return action_part

    match = re.search('(allow|deny)\(\d+\)', action_part)
    if match:
        return match.group(1)
    else:
        return None


def convert_log_entry(log_entry):
    """
    Converts log entries from the style returned by `log show` into the style needed
    by the matcher.

    :param log_entry: The entry (dictionary) to transform
    :return: dictionary (later output as JSON) that is input to matcher.
    """
    msg = log_entry["eventMessage"]

    # Make sure our simple heuristics will not be fooled.
    assert (") allow" in msg or ") deny" in msg) and not (") allow" in msg and ") deny" in msg)

    # Simply look for "allow" or "deny", then go from there and ignore the prefix.
    if ") allow" in msg:
        relevant_part = msg[msg.find(") allow") + 2:]
    else:
        relevant_part = msg[msg.find(") deny") + 2:]

    parts = relevant_part.split(" ")

    # At least the decision and the operation should be specified...
    assert len(parts) >= 2

    # ... however, most of the time we'd also like to have an argument
    if len(parts) >= 3:
        # Make sure the operation name is valid, else ignore
        if parts[1] not in valid_op_names:
            logger.error('Skipping processing of log entry, as extracted operation is invalid.')
            return None

        return {
            "action": parse_action_field(parts[0]),
            "operation": parts[1],
            "argument": " ".join(parts[2:])
        }
    else:
        return {
            "action": parse_action_field(parts[0]),
            "operation": parts[1]
        }


def is_relevant_log_entry(log_entry, pid):
    """
    Returns true if the log entry is of interest (Can / should be matched).

    :param log_entry: The entry to look at
    :param pid: The pid of the program that was running at the time of log collection.
    :return: True, if the log entry is of interest, else false
    """
    # We are mainly interested in the eventMessage.
    msg = log_entry["eventMessage"]

    # (Crude) check that the desired processed is responsible for the entry
    # Sandbox messages are of the following form: .... (Processname)(PID) ...
    if not ("({})".format(pid) in msg):
        return False

    if not ("allow" in msg or "deny" in msg):
        return False

    return True


def process_log_dir(basedir):
    assert os.path.exists(os.path.join(basedir, "sandbox_logs.json"))
    assert os.path.exists(os.path.join(basedir, "process.pid"))

    process_pid = int(open(os.path.join(basedir, "process.pid"), "r").read())
    with open(os.path.join(basedir, "sandbox_logs.json"), "r") as json_in:
        log_contents = json_in.read()

    all_entries = json.loads(log_contents)
    output = []

    operations = dict()

    for entry in all_entries:
        if is_relevant_log_entry(entry, process_pid):
            processed = convert_log_entry(entry)
            if processed is None:
                continue

            if processed["operation"] not in operations:
                operations[processed["operation"]] = 1
            else:
                operations[processed["operation"]] += 1

            output.append(convert_log_entry(entry))

    output_file = os.path.join(basedir, "sandbox_logs_processed.json")
    # Make sure we are not overwriting previous output.
    assert not os.path.exists(output_file)

    with open(output_file, "w", encoding="utf8") as outfile:
        json.dump(output, outfile, indent=4, ensure_ascii=False)


def main():
    parser = argparse.ArgumentParser(description='Process sandbox logs')
    parser.add_argument('--input', required=True,
                        help='Location (folder) where logfiles and sandbox profiles are stored at.')
    parser.add_argument('--stats', required=False, default=False, action='store_true', dest='stats')
    args = parser.parse_args()

    basedir = args.input
    process_log_dir(basedir)

if __name__ == "__main__":
    main()
