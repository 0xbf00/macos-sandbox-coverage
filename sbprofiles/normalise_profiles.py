import json
import tempfile
import os
import plistlib
import operator

from maap.misc.plist import parse_resilient
from maap.misc.logger import create_logger
from maap.extern.tools import call_sbpl

logger = create_logger('normalise_profiles')


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
    This function looks up the original sandbox profile,
    normalises its container metadata and re-generates a new sandbox profile,
    which is then undergoing basic sanity checking and finally returned
    to the user

    :param match_results Base folder for match results. Is used to read existing results
    and to verify new results.
    :param containers Base folder for Container.plist metadata information.

    :returns New file containing generalised profile
    """
    metadata = state['container_metadata']
    original_profile = state['sandbox_profiles']['original']
 
    profile = profile_for_metadata(metadata, format='json')
    if profile is None:
        logger.error("Failed to get profile for metadata for bundle id {}".format(bundle_id))
        return False, {}

    norm_profile = profile_for_metadata(normalise_container_metadata(metadata), format='json')
    if norm_profile is None:
        logger.error("Failed to get normalised profile for metadata for bundle id {}".format(bundle_id))
        return False, {}

    recreated_profile  = json.loads(profile)
    normalised_profile = json.loads(norm_profile)

    assert isinstance(recreated_profile, list)
    assert isinstance(normalised_profile, list)

    if original_profile != recreated_profile:
        logger.error("Failed to recreate profiles for bundle id {}".format(bundle_id))
        return False, {}

    state['sandbox_profiles']['normalised'] = normalised_profile
    return True, state