import json
import tempfile
import os
import plistlib
import re
import subprocess

from dataclasses import dataclass
from typing import Dict, Tuple

from maap.misc.plist import parse_resilient_bytes
from maap.misc.logger import create_logger
from maap.extern.tools import call_sbpl

logger = create_logger('sbprofiles.normalise')


def version_from_str(version: str) -> int:
    rx = re.compile(r'^(\d+)\.(\d+)\.(\d+)$')
    m = rx.match(version)
    assert m, f"Invalid version: {version}"
    major = int(m.group(1))
    minor = int(m.group(2))
    patch = int(m.group(3))
    assert 0 <= major and major < 255
    assert 0 <= minor and minor < 255
    assert 0 <= patch and patch < 255
    return (major << 16) + (minor << 8) + patch


@dataclass(frozen=True)
class Platform:
    product_name: str
    product_version: str
    build_version: str

    @classmethod
    def determine(cls) -> 'Platform':

        def sw_vers(arg: str) -> str:
            return subprocess.run(
                ['sw_vers', arg],
                check=True,
                text=True,
                capture_output=True
            ).stdout.strip()

        return cls(
            product_name=sw_vers('-productName'),
            product_version=sw_vers('-productVersion'),
            build_version=sw_vers('-buildVersion'),
        )

    def is_newer_or_equal(self, version: str) -> bool:
        other = version_from_str(version)
        this = version_from_str(self.product_version)
        return other <= this


def normalise_container_metadata(metadata: dict) -> Tuple[dict, Dict[str, str]]:
    """Normalises existing container metadata and returns a normalised version
    back to the user.

    :param metadata Dictionary containing the original Container metadata."""

    platform = Platform.determine()

    if platform.is_newer_or_equal("10.15.4"):
        parameters_key = 'Parameters'
        redirectable_paths_key = 'RedirectablePaths'
    else:
        parameters_key = 'SandboxProfileDataValidationParametersKey'
        redirectable_paths_key = 'SandboxProfileDataValidationRedirectablePathsKey'

    # Container metadata contains a number of important keys.
    # We only want to change the SandboxProfileDataValidationInfo entries
    relevant_entries = metadata['SandboxProfileDataValidationInfo']

    # General parameters for sandbox evaluation such as HOME_DIR, USER,
    # app specific information, ...
    sandbox_parameters = relevant_entries[parameters_key]

    # Grab home directory, we need that later.
    home_dir = sandbox_parameters['_HOME']

    replacements: Dict[str, str] = dict()

    # Change values for all keys to placeholders.
    for key in sandbox_parameters.keys():
        # For each key, we simply use the key in uppercase, along delimiters as a placeholder.
        replacement = "$" + key.upper() + "$"

        # We prepend a slash to the home path in order to avoid paths not
        # starting with a slash. Otherwise this would conflict with the
        # Scheme definition of the `home-path-ancestors` in `applications.sb`.
        if key == '_HOME':
            replacement = '/$_HOME$'

        replacements[replacement] = sandbox_parameters[key]
        sandbox_parameters[key] = replacement

    # Redirectable paths that are part of the user's home directory. Patch
    # these paths such that the HOME placeholder is used instead.
    redirectable_paths = [x.replace(home_dir, sandbox_parameters['_HOME'])
                          for x
                          in relevant_entries.get(redirectable_paths_key, [])]

    # Store the modified values back into the dictionary
    relevant_entries[parameters_key] = sandbox_parameters
    relevant_entries[redirectable_paths_key] = redirectable_paths

    metadata['SandboxProfileDataValidationInfo'] = relevant_entries

    return metadata, replacements


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

    normalised_metadata, replacements = normalise_container_metadata(metadata)

    norm_profile = profile_for_metadata(normalised_metadata, format='json')
    if norm_profile is None:
        logger.error(f"Failed to get normalised profile for metadata for {app_path}")
        return False, {}

    normalised_profile = json.loads(norm_profile)

    state['sandbox_profiles']['normalised'] = normalised_profile
    state['normalisation_replacements'] = replacements
    return True, state