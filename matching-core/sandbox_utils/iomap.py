#!/usr/bin/env python3

import argparse
import collections
import json
import re
import subprocess

from typing import Dict, Set

SERVICE_CLASS_RX = re.compile(r'^(\w+) ', re.IGNORECASE)
CLIENT_CLASS_RX = re.compile(r'\x1b\[1;94m(\w+) +\x1b\[0m')


def get_mapping() -> Dict[str, Set[str]]:
    plane = 'IOService'
    start = 0
    stop = 512

    # Theoretically, we would need to scan the full range of possible uint32_t
    # values, but this is not even feasible for a single service, hence we
    # potentially might miss a few mappings. The highest used type found was
    # 258 for the IGAccelVideoContextVEBox client of the IntelAccelerator
    # service. So we are probably fine with scanning 512 types.

    # TODO Limit client scanning to specific services, that utilize multiple
    # client types:
    # - IntelAccelerator
    # - IOBluetoothHCICOntroller

    ioscan = subprocess.run(
        ['ioscan', '-s', '-p', plane, plane, str(start), str(stop)],
        check=True,
        capture_output=True,
        text=True,
    )

    lines = ioscan.stdout.splitlines(keepends=False)
    assert 0 < len(lines)

    mapping: Dict[str, Set[str]] = collections.defaultdict(set)
    for line in lines[1:]:

        service_match = SERVICE_CLASS_RX.match(line)
        assert service_match
        service_class = service_match.group(1)

        client_match = CLIENT_CLASS_RX.search(line)
        if not client_match:
            continue
        client_class = client_match.group(1)

        mapping[service_class].add(client_class)

    return mapping


def reverse_mapping(mapping: Dict[str, Set[str]]) -> Dict[str, Set[str]]:
    reverse: Dict[str, Set[str]] = collections.defaultdict(set)
    for client, services in mapping.items():
        for service in services:
            reverse[service].add(client)
    return reverse


def c_dumps(mapping: Dict[str, Set[str]]) -> str:
    def c_str(value: str) -> str:
        return f'"{value}"'

    result: str = ''
    for service in sorted(mapping.keys()):
        for client in sorted(mapping[service]):
            result += '{%s, %s},\n' % (c_str(service), c_str(client))

    return result[:-2]


def main():
    parser = argparse.ArgumentParser(
        description="""
        This utility will generate a mapping of IOKit services and their
        respective clients.

        You need to have Siguza's `ioscan` utility in your `PATH`.
        See: https://github.com/Siguza/iokit-utils
        """
    )
    parser.add_argument(
        '-r', '--reverse',
        action='store_true',
        help="Map user->service instead of service->user.",
    )
    parser.add_argument(
        '--json',
        action='store_true',
        help="Produce JSON output",
    )
    args = parser.parse_args()

    mapping = get_mapping()
    if args.reverse:
        mapping = reverse_mapping(mapping)

    if args.json:
        result = json.dumps(
            {service: sorted(clients) for service, clients in mapping.items()},
            sort_keys=True,
        )
    else:
        result = c_dumps(mapping)

    print(result)


if __name__ == '__main__':
    main()
