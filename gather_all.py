"""
gather_all

(c) Jakob Rieck 2018

Tool to collect sandbox logs for all installed MAS applications. Sandbox logs contain
all allow and deny decisions that sandboxd was nice enough to log to the system log.
"""
import argparse
import os

import gather_logs
from misc.logger import create_logger
from bundle.bundle import Bundle
import misc.app_utils as app_utils


logger = create_logger('rule_matching.gather_all_logs')


def mk_output_dir(app_bundle, outdir) -> str:
    # Make a specific output directory for results, inside the outdir directory.
    bundle_id = app_bundle.bundle_identifier()

    outpath = os.path.join(outdir, bundle_id)
    if os.path.exists(outpath):
        return None

    return outpath


def main():
    parser = argparse.ArgumentParser(description='Collect sandbox logs for all MAS applications')
    parser.add_argument('--app-dir', required=True,
                        help='Path to the directory where apps are stored.')
    parser.add_argument('--outdir', required=True,
                        help='Location where to store results at. Each result is stored in a folder of the name of the bundle id.')
    args = parser.parse_args()

    app_dir = args.app_dir

    mas_apps = app_utils.all_apps(app_dir, mas_only=True)

    for app in mas_apps:
        bundle = Bundle.make(app)

        app_outdir = mk_output_dir(bundle, args.outdir)
        if app_outdir is None:
            logger.info("Skipping processing of {} because the output folder already exists.".format(app))
            continue

        try:
            gather_logs.process_app(app, app_outdir)
        except:
            logger.error("Exception occurred during processing of {}".format(app))

if __name__ == "__main__":
    main()
