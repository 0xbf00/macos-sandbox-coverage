"""
(c) Jakob Rieck 2018

Raw log files contain lots of information we do not need. At this point, we are
only interested in the message text, which contains the action taken (allow or deny),
as well as the particular operation and resource affected.
"""
import argparse
import os
import json
import re
import sys

from typing import Optional

from maap.misc.logger import create_logger
from maap.misc.filesystem import project_path

logger = create_logger('sblogs.process')


def parse_action_field(action_part: str):
    """
    Convert a string action part such as "allow", "deny",
    "deny(1)" or similar to the canonical "allow" or "deny"
    decision.

    :param action_part: See description above
    :return: Canonical action, either allow or deny
    """
    if action_part == "allow" or action_part == "deny":
        return action_part

    match = re.search(r'(allow|deny)\(\d+\)', action_part)
    if match:
        return match.group(1)


def convert_log_entry(log_entry: dict) -> dict:
    """
    Converts log entries from the style returned by `log show` into the style needed
    by the matcher.
    """
    msg: str = log_entry["eventMessage"]

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

    operation = parts[1]

    # The log format has changed in Catalina. There is no space between the
    # operation and the argument, eg.: network-outbound*:443
    network_ops = ['network-bind', 'network-inbound', 'network-outbound']
    network_op: Optional[str] = None
    for candidate in network_ops:
        if operation.startswith(candidate):
            network_op = candidate
            break
    if network_op and operation.startswith(network_op) and operation != network_op:
        plen = len(network_op)
        assert len(parts) == 2, str(parts)
        parts.append(operation[plen:])
        operation = operation[:plen]
        assert operation == network_op, operation

    if operation == 'file-issue-extension':
        assert len(parts) >= 4, str(parts)

        # The log format has changed in Catalina, no space after names for
        # arguments. Add the space, so that processed logs are uniform.

        rx = re.compile(r'target: ?(.*) class: ?(.*)')
        m = rx.match(' '.join(parts[2:]))
        assert m, str(parts)
        target = m.group(1)
        cls = m.group(2)

        parts = parts[:2]
        parts.append('target: ' + target)
        parts.append('class: ' + cls)

    result = {
        "action": parse_action_field(parts[0]),
        "operation": operation
    }

    # ... however, most of the time we'd also like to have an argument
    if len(parts) >= 3:
        result.update({
            "argument": " ".join(parts[2:])
        })

    return result

def is_relevant_log_entry(log_entry: dict, pid: int) -> bool:
    """
    Returns true if the log entry is of interest (Can / should be matched).

    :param log_entry: The entry to look at
    :param pid: The pid of the program that was running at the time of log collection.
    :return: Whether the log entry is of interest or not
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


def process_logs(state: dict) -> (bool, dict):
    pid = state['process_infos']['pid']
    logs = state['logs']['raw']

    relevant_entries = filter(lambda entry: is_relevant_log_entry(entry, pid), logs)
    converted_entries = map(convert_log_entry, relevant_entries)

    state['logs']['processed'] = [x for x in converted_entries if x is not None]
    return True, state