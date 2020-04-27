#!/usr/bin/env python3

import argparse
import io
import json
import os
import sys

from typing import Optional

sys.path.append(os.path.join(os.path.dirname(__file__), "maap"))

from maap import driver
from maap.bundle.bundle import Bundle
from maap.extern.tools import call_sbpl
from sandbox_coverage import dump_state
from sblogs.gather import gather_logs
from sblogs.process import process_logs
from sblogs.match import perform_matching
from sbprofiles.normalise import normalise_profile
from sbprofiles.generalise import generalise_results


class SandboxCoverageDriver(driver.Driver):

    def __init__(
        self,
        profile: dict,
        timeout: Optional[int] = None,
    ) -> None:
        super().__init__('sandbox_coverage_driver')
        self.profile = profile
        self.timeout = timeout

    def error(self, app: Bundle, msg: str, state: dict) -> None:
        with io.StringIO() as fp:
            dump_state(state, fp)
            s = fp.getvalue()
        self.logger.error(f"{app.filepath}: {msg}: {s}")

    def analyse(self, app: Bundle, out_dir: str) -> driver.Result:
        out_fn = os.path.join(out_dir, 'sandbox_coverage.json')

        # Skip application if we already obtained results
        if os.path.exists(out_fn):
            self.logger.warning(f"{app.filepath}: Already analysed. Skipping.")
            return driver.Result.SKIPPED

        # Run sandbox_coverage for the given application
        state = {
            'arguments': {
                'app': app.filepath,
                'timeout': self.timeout,
            },
            'sandbox_profiles': {
                'general': self.profile,
            },
        }

        success, state = gather_logs(state)
        if not success:
            self.error(app, "Could not gather logs", state)
            return driver.Result.ERROR

        success, state = process_logs(state)
        if not success:
            self.error(app, "Could not process logs", state)
            return driver.Result.ERROR

        success, state = perform_matching(state)
        if not success:
            self.error(app, "Could not perform matching", state)
            return driver.Result.ERROR

        success, state = normalise_profile(state)
        if not success:
            self.error(app, "Could not normalise sandbox profiles", state)
            return driver.Result.ERROR

        success, state = generalise_results(state)
        if not success:
            self.error(app, "Could not generalise results", state)
            return driver.Result.ERROR

        with open(out_fn, 'w') as fp:
            dump_state(state, fp)

        self.logger.info(f"{app.filepath}: Successfully analysed.")
        return driver.Result.OK


def main() -> None:
    parser = argparse.ArgumentParser()

    parser.add_argument(
        'applications',
        help="""
            Path to the directory, where applications are installed. This
            folder will be traversed recursively.
        """,
    )
    parser.add_argument(
        'output',
        help="Path to where the results should be stored",
    )

    args = parser.parse_args()

    apps_dir = os.path.expanduser(args.applications)
    out_dir = os.path.expanduser(args.output)

    container = 'data/com.generic.container'
    profile = json.loads(call_sbpl(container, result_format='json'))

    driver = SandboxCoverageDriver(profile=profile, timeout=60)
    driver.run(apps_dir, out_dir)


if __name__ == '__main__':
    main()
