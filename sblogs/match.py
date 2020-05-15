import os
import subprocess
import sys
import json

from collections import defaultdict
from typing import Any, Dict, Iterator, List, Optional, Set, Tuple

SandboxProfile = List[Dict[str, Any]]
ProcessedLogs = List[Dict[str, str]]


PROJECT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HELPER_DIR = os.path.join(PROJECT_DIR, 'matching-core', 'build', 'bin')
MATCHER = os.path.join(HELPER_DIR, 'matcher')


def get_matches_for_profile(
    profile: SandboxProfile,
    logs: ProcessedLogs,
) -> List[Optional[bool]]:
    """
    Obtain the match results from the C++ helper.
    """
    sandbox_check = subprocess.run(
        [MATCHER],
        capture_output=True,
        text=True,
        input=json.dumps(dict(
            sandbox_profile=profile,
            processed_logs=logs,
        )),
    )

    if sandbox_check.returncode != 0:
        print(sandbox_check.stderr, file=sys.stderr)
        sandbox_check.check_returncode()

    return json.loads(sandbox_check.stdout)


def reduced_profiles(profile: SandboxProfile) -> Iterator[SandboxProfile]:
    yield profile
    for i in range(1, len(profile) + 1):
        yield profile[:-i]  # Remove last i rules


def invert_last_rule(profile: SandboxProfile) -> SandboxProfile:
    assert 0 < len(profile)
    new_profile = profile.copy()
    action: str = profile[-1]['action']
    if action == 'allow':
        new_profile[-1]['action'] = 'deny'
        if 'modifiers' in new_profile[-1]:
            modifiers = new_profile[-1]['modifiers']
            new_profile[-1]['modifiers'] = [
                modifier
                for modifier in modifiers
                # The report modifier is not allowed for 'deny' rules.
                if modifier['name'] != 'report'
            ]
    elif action == 'deny':
        new_profile[-1]['action'] = 'allow'
        if 'modifiers' in new_profile[-1]:
            modifiers = new_profile[-1]['modifiers']
            new_profile[-1]['modifiers'] = [
                modifier
                for modifier in modifiers
                # The no-report modifier is not allowed for 'allow' rules.
                if modifier['name'] != 'no-report'
            ]
    else:
        assert False, f"Invalid action: {action}"
    return new_profile


def perform_matching(state: dict) -> Tuple[bool, dict]:
    """
    Invokes the matcher, assuming the directory contains both the profile
    to match against, and processed log entries.

    Note that there are implicit default values for some sandbox operations
    that are not overwritten by a default rule. An example is

       (allow file-map-executable "/usr/lib/libobjc-trampolines.dylib")

    The `file-map-executable` operation is allowed by default! A default deny
    profile with no explicit rule for `file-map-executable` will therefore
    default to allowing all `file-map-executable` actions.

    The results in that case will be inconsistent for each profile reduction
    and mutation. We therefore cannot match the log entry to a rule and it will
    be added to the unmatched log entries.
    """

    processed_logs: ProcessedLogs = state['logs']['processed']
    sandbox_profile: SandboxProfile = json.loads(
        state['sandbox_profiles']['original']
    )

    num_rules = len(sandbox_profile)

    decisions_mapping: Dict[int, List[int]] = defaultdict(list)
    redundancy_mapping: Dict[int, List[int]] = defaultdict(list)

    last_matches: Optional[Dict[int, Optional[bool]]] = None
    print(f"  0 % matching rules", file=sys.stderr)
    for profile in reduced_profiles(sandbox_profile):
        rule_idx = len(profile) - 1

        progress = (num_rules - len(profile)) / num_rules * 100.0
        print(f"\r\033[1A{progress: >3.0f} % matching rules", file=sys.stderr)

        if last_matches is None:
            # Test all logs in the beginning
            selected_logs = {
                idx: match for idx, match in enumerate(processed_logs)
            }
        else:
            # Then continue testing only with consistent matches
            selected_logs = {
                idx: processed_logs[idx]
                for idx, match in last_matches.items()
                if match
            }

        selected_idxs = sorted(selected_logs.keys())

        matches = get_matches_for_profile(
            profile,
            [selected_logs[idx] for idx in selected_idxs],
        )
        assert len(matches) == len(selected_idxs)
        new_matches = {
            idx: match for idx, match in zip(selected_idxs, matches)
        }

        if 0 <= rule_idx:
            # Check whether inversion of the current rule leads to a change. If
            # that is the case, the rule might be redundant, if removal of this
            # rule does not result in a change as well. However, this is
            # decided in the next iteration, see below.
            inverted_matches = get_matches_for_profile(
                invert_last_rule(profile),
                [selected_logs[idx] for idx in selected_idxs],
            )
            assert len(inverted_matches) == len(selected_idxs)
            redundancy_mapping[rule_idx] = [
                idx
                for idx, match in zip(selected_idxs, inverted_matches)
                if not match and new_matches[idx]
            ]

        if last_matches is not None:
            removed_rule_idx = rule_idx + 1
            assert removed_rule_idx < num_rules
            changed_idxs = [
                idx for idx, match in new_matches.items() if not match
            ]
            decisions_mapping[removed_rule_idx] = changed_idxs

            # The removed rule is probably also a candidate for redundancy.
            # Since it is now clear, that the rule is responsible, it should
            # not be considered redundant.
            redundancy_mapping[removed_rule_idx] = [
                idx
                for idx in redundancy_mapping[removed_rule_idx]
                if idx not in changed_idxs
            ]

        last_matches = new_matches

    # Remove progress and reset
    print(f"\r\033[1A                    ", file=sys.stderr, end='\r')

    # Get a list of unmatched log entries
    all_log_idxs: Set[int] = set(range(len(processed_logs)))
    matched_log_idxs: Set[int] = set()
    for rule, log_idxs in decisions_mapping.items():
        for idx in log_idxs:
            matched_log_idxs.add(idx)
    for rule, log_idxs in redundancy_mapping.items():
        for idx in log_idxs:
            matched_log_idxs.add(idx)
    unmatched_log_idxs: Set[int] = all_log_idxs.difference(matched_log_idxs)

    state['match_results'] = {
        'rule_deciding_for_log_entries': decisions_mapping,
        'rule_redundant_for_log_entries': redundancy_mapping,
        'unmatched_log_entries': sorted(unmatched_log_idxs),
    }

    return True, state