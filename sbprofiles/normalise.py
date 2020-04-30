import json
import tempfile
import os
import plistlib

from maap.misc.plist import parse_resilient_bytes
from maap.misc.logger import create_logger
from maap.extern.tools import call_sbpl

logger = create_logger('sbprofiles.normalise')


def normalise_container_metadata(metadata: dict) -> dict:
    """Normalises existing container metadata and returns a normalised version
    back to the user.

    :param metadata Dictionary containing the original Container metadata."""

    # Container metadata contains a number of important keys.
    # We only want to change the SandboxProfileDataValidationInfo entries
    relevant_entries = metadata['SandboxProfileDataValidationInfo']

    # SandboxProfileDataValidationParametersKey contains general parameters for
    # sandbox evaluation such as HOME_DIR, USER, app specific information, ...
    sandbox_parameters = relevant_entries['SandboxProfileDataValidationParametersKey']

    # Grab home directory, we need that later.
    home_dir = sandbox_parameters['_HOME']

    # Change values for all keys to placeholders.
    for key in sandbox_parameters.keys():
        # For each key, we simply use the key in uppercase, along delimiters as a placeholder.
        sandbox_parameters[key] = "$" + key.upper() + "$"

        # We prepend a slash to the home path in order to avoid paths not
        # starting with a slash. Otherwise this would conflict with the
        # Scheme definition of the `home-path-ancestors` in `applications.sb`.
        if key == '_HOME':
            sandbox_parameters[key] = "/" + sandbox_parameters[key]

    # SandboxProfileDataValidationRedirectablePathsKey contains redirectable paths that are part
    # of the user's home directory. Patch these paths such that the HOME placeholder is used instead.
    redirectable_paths = [x.replace(home_dir, sandbox_parameters['_HOME'])
                          for x
                          in relevant_entries.get('SandboxProfileDataValidationRedirectablePathsKey', [])]

    # Store the modified values back into the dictionary
    relevant_entries['SandboxProfileDataValidationParametersKey'] = sandbox_parameters
    relevant_entries['SandboxProfileDataValidationRedirectablePathsKey'] = redirectable_paths

    metadata['SandboxProfileDataValidationInfo'] = relevant_entries

    return metadata


def profile_for_metadata(metadata: dict, format='scheme', patch=False) -> bytes:
    with tempfile.TemporaryDirectory() as tempdir:
        container_metadata = os.path.join(tempdir, 'Container.plist')
        with open(container_metadata, 'wb') as outfile:
            plistlib.dump(metadata, outfile)

        return call_sbpl(tempdir, format, patch)


def normalise_profile(state: dict) -> (bool, dict):
    """
    This function normalises the container metadata of the target app, then uses
    this normalised metadata to generate a normalised sandbox profile using simbple.
    """
    app_path = state['arguments']['app']
    metadata = parse_resilient_bytes(state['container_metadata'])

    normalised_metadata = normalise_container_metadata(metadata)

    norm_profile = profile_for_metadata(normalised_metadata, format='json')
    if norm_profile is None:
        logger.error(f"Failed to get normalised profile for metadata for {app_path}")
        return False, {}

    normalised_profile = json.loads(norm_profile)

    state['sandbox_profiles']['normalised'] = normalised_profile
    return True, state