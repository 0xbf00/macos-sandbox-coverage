#!/usr/bin/env python3

"""
sandbox_coverage

(c) Jakob Rieck 2018

Tool to investigate sandbox profile coverage.
"""
import argparse
import os
import sys
import json
import base64

from typing import Any, Dict, List

sys.path.append(os.path.join(os.path.dirname(__file__), "maap"))

from maap.misc.logger import create_logger

from sblogs.gather import gather_logs
from sblogs.process import process_logs
from sblogs.match import perform_matching
from sbprofiles.normalise import normalise_profile, Platform
from sbprofiles.generalise import generalise_results

logger = create_logger('sandbox_coverage')


def get_generic_profile() -> List[Dict[str, Any]]:
    path = os.path.join(os.path.dirname(__file__), 'data', 'generic_profiles')
    fn = os.path.join(path, '10.14.6-18G4032.json')
    with open(fn, 'r') as fp:
        profile = json.load(fp)
    return profile


def dump_state(state: dict, fp=sys.stdout):
    def serialise(input):
        """
        Serialise byte strings. First try decoding them as JSON, if that does not work out
        encode the byte string as base64.
        This function traverses lists and dicts, modifying their items as required.
        """
        if isinstance(input, dict):
            serialised = [(serialise(k), serialise(v)) for (k, v) in input.items()]
            return dict(serialised)
        elif isinstance(input, list):
            return [serialise(x) for x in input]
        elif isinstance(input, bytes):
            # Try decoding as JSON
            try:
                d = json.loads(input)
                return serialise(d)
            except (json.JSONDecodeError, UnicodeError):
                pass

            # Not valid JSON: Fall back to base64
            return serialise(base64.encodebytes(input).decode())
        else:
            return input

    new_state = serialise(state)
    json.dump(new_state, fp, indent=4, sort_keys=True)


def main():
    parser = argparse.ArgumentParser(description='Collect sandbox coverage information for an application')
    parser.add_argument('--app', required=True,
                        help='Path to the app for which to compute sandbox coverage data.')
    parser.add_argument('--timeout', required=False, default=None, type=int,
                        help='Number of seconds to wait before killing the program. Leave unspecified to not kill the program at all.')
    args = parser.parse_args()

    state = {
        'arguments': {
            'app': args.app,
            'timeout': args.timeout
        },
        'sandbox_profiles': {
            'general': get_generic_profile()
        }
    }

    success, state = gather_logs(state)
    if not success:
        print("Could not gather logs.", file=sys.stderr)
        dump_state(state, fp=sys.stderr)
        return

    success, state = process_logs(state)
    if not success:
        print("Could not process logs.", file=sys.stderr)
        dump_state(state, fp=sys.stderr)
        return

    success, state = perform_matching(state)
    if not success:
        print("Could not perform matching.", file=sys.stderr)
        dump_state(state, fp=sys.stderr)
        return

    success, state = normalise_profile(state)
    if not success:
        print("Could not normalise sandbox profiles.", file=sys.stderr)
        dump_state(state, fp=sys.stderr)
        return

    success, state = generalise_results(state)
    if not success:
        print("Could not generalise results.", file=sys.stderr)
        dump_state(state, fp=sys.stderr)
        return

    dump_state(state)

if __name__ == "__main__":
    main()