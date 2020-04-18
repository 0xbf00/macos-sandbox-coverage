"""
Thin wrapper around matcher component, which is written in C++.
"""
import os
import subprocess
import sys
import tempfile
import json

sys.path.append(os.path.join(os.path.dirname(__file__), "maap"))

from maap.misc.logger import create_logger
from maap.misc.filesystem import project_path

logger = create_logger("sblogs.match")


def perform_matching(state: dict) -> (bool, dict):
    """
    Invokes the matcher, assuming the directory contains both the profile
    to match against, and processed log entries.
    """
    processed_logs = state['logs']['processed']
    sandbox_profile = state['sandbox_profiles']['original']

    matcher_path = "./matcher"
    assert os.path.exists(matcher_path)
    matcher_path = os.path.abspath(matcher_path)

    with tempfile.TemporaryDirectory() as tmpdir:
        # Dump parameters to disk for matching component
        ruleset_at = os.path.join(tmpdir, "patched_profile.json")
        logs_at = os.path.join(tmpdir, "sandbox_logs_processed.json")
        
        with open(ruleset_at, "w") as f:
            json.dump(sandbox_profile, f, ensure_ascii=False, indent=4)
        with open(logs_at, "w") as f:
            json.dump(processed_logs, f, ensure_ascii=False, indent=4)
        
        try:
            state['match_results'] = json.loads(subprocess.check_output([matcher_path, ruleset_at, logs_at]))
            return True, state
        except subprocess.CalledProcessError:
            return False, {}