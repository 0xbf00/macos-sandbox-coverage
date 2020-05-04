#!/usr/bin/env python3

import argparse
import json
import os
import subprocess
import sys

from collections import defaultdict
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

import jinja2 as jj
from pygments import highlight
from pygments.lexers import SchemeLexer
from pygments.formatters import HtmlFormatter


PROJECT_DIR = os.path.dirname(os.path.abspath(__file__))
HELPER_DIR = os.path.join(PROJECT_DIR, 'matching-core', 'build', 'bin')
SBPLDUMP = os.path.join(HELPER_DIR, 'sbpldump')


@dataclass(frozen=True)
class AppInfo:
    name: str
    path: str
    bundle_id: str
    version: str

    @property
    def is_empty(self) -> bool:
        return 0 == len(self.bundle_id)

    @classmethod
    def empty(cls, name: str) -> 'AppInfo':
        return cls(
            name=name,
            path='',
            bundle_id='',
            version='',
        )


@dataclass(frozen=True)
class Rule:
    sbpl: str
    hits: int
    redundant_hits: int
    redundancy_sources: List[Optional[int]]

    @property
    def is_covered(self) -> bool:
        return 0 < self.hits

    @property
    def is_redundant(self) -> bool:
        return 0 < self.redundant_hits

    @property
    def is_allow(self) -> bool:
        return (
            self.sbpl.startswith('(allow ') or self.sbpl.startswith('(allow\n')
        )

    @property
    def is_deny(self) -> bool:
        return (
            self.sbpl.startswith('(deny ') or self.sbpl.startswith('(deny\n')
        )

    @property
    def is_other(self) -> bool:
        return not (self.is_allow or self.is_deny)


@dataclass(frozen=True)
class Result:
    info: AppInfo
    rules: List[Rule]

    @classmethod
    def from_profile(
        cls,
        info: AppInfo,
        profile: List[Dict[str, Any]],
        hits: Dict[int, int],
        redundant_hits: Dict[int, int],
        redundancy_sources: Dict[int, List[Optional[int]]],
    ) -> 'Result':
        # Dump SBPL profile
        sbpldump = subprocess.run(
            [SBPLDUMP, '-'],
            check=True,
            capture_output=True,
            input=json.dumps(profile),
            text=True,
        )
        sbpl = sbpldump.stdout

        # Detect rules
        rules: List[Rule] = []
        rule_sbpl: List[str] = []
        for line_idx, line in enumerate(sbpl.splitlines()):
            if line.startswith('('):
                if 0 < line_idx:
                    rule_idx = len(rules)
                    rule = Rule(
                        sbpl='\n'.join(rule_sbpl),
                        hits=hits[rule_idx],
                        redundant_hits=redundant_hits[rule_idx],
                        redundancy_sources=redundancy_sources[rule_idx],
                    )
                    rules.append(rule)
                    rule_sbpl = []
            rule_sbpl.append(line)
        rule_idx = len(rules)
        rule = Rule(
            sbpl='\n'.join(rule_sbpl),
            hits=hits[rule_idx],
            redundant_hits=redundant_hits[rule_idx],
            redundancy_sources=redundancy_sources[rule_idx],
        )
        rules.append(rule)
        return cls(info, rules)

    def with_manual_results(
        self,
        info: AppInfo,
        hits: Dict[int, int],
        redundant_hits: Dict[int, int],
        redundancy_sources: Dict[int, List[Optional[int]]],
    ) -> 'Result':
        rules = [
            Rule(
                self.rules[i].sbpl,
                hits[i],
                redundant_hits[i],
                redundancy_sources[i],
            )
            for i in range(len(self.rules))
        ]
        return self.__class__(info, rules)

    @property
    def rule_count(self) -> int:
        """
        Returns the number of rules. This does not include the version
        statement.
        """
        return len(self.rules) - 1

    @property
    def covered_rules(self) -> List[Rule]:
        return [rule for rule in self.rules if rule.is_covered]

    @property
    def covered_allow_rules(self) -> List[Rule]:
        return [rule for rule in self.covered_rules if rule.is_allow]

    @property
    def covered_deny_rules(self) -> List[Rule]:
        return [rule for rule in self.covered_rules if rule.is_deny]

    @property
    def coverage(self) -> float:
        return len(self.covered_rules) / self.rule_count * 100.0

    @property
    def coverage_allow(self) -> float:
        return len(self.covered_allow_rules) / self.rule_count * 100.0

    @property
    def coverage_deny(self) -> float:
        return len(self.covered_deny_rules) / self.rule_count * 100.0

    @property
    def redundant_rules(self) -> List[Rule]:
        return [rule for rule in self.rules if rule.is_redundant]

    @property
    def only_redundant_rules(self) -> List[Rule]:
        return [rule for rule in self.redundant_rules if not rule.is_covered]

    @property
    def only_redundant_allow_rules(self) -> List[Rule]:
        return [rule for rule in self.only_redundant_rules if rule.is_allow]

    @property
    def only_redundant_deny_rules(self) -> List[Rule]:
        return [rule for rule in self.only_redundant_rules if rule.is_deny]

    @property
    def coverage_only_redundant(self) -> float:
        return len(self.only_redundant_rules) / self.rule_count * 100.0

    @property
    def coverage_only_redundant_allow(self) -> float:
        return len(self.only_redundant_allow_rules) / self.rule_count * 100.0

    @property
    def coverage_only_redundant_deny(self) -> float:
        return len(self.only_redundant_deny_rules) / self.rule_count * 100.0


@dataclass(frozen=True)
class App:
    source_path: str
    sandbox_coverage: Dict[str, Any]

    @property
    def normalisation_replacements(self) -> Dict[str, str]:
        return self.sandbox_coverage['normalisation_replacements']

    @property
    def bundle_id(self) -> str:
        replacements = self.normalisation_replacements
        return replacements['$APPLICATION_BUNDLE_ID$']

    @property
    def version(self) -> str:
        # TODO More reliably way to get app version
        return os.path.basename(os.path.dirname(self.source_path))

    @property
    def name(self) -> str:
        return os.path.splitext(
            os.path.basename(self.sandbox_coverage['arguments']['app'])
        )[0]

    @property
    def path(self) -> str:
        replacements = self.normalisation_replacements
        return replacements['$APPLICATION_BUNDLE$']

    @property
    def info(self) -> AppInfo:
        return AppInfo(
            name=self.name,
            path=self.path,
            bundle_id=self.bundle_id,
            version=self.version,
        )

    def add_offset(self, rule_idx: int) -> int:
        return rule_idx + 1  # +1 for SBPL version statement

    def maybe_add_offset(self, rule_idx: Optional[int]) -> Optional[int]:
        if rule_idx is None:
            return None
        return self.add_offset(rule_idx)

    @property
    def sandbox_profiles(self) -> Dict[str, List[Dict[str, Any]]]:
        return self.sandbox_coverage['sandbox_profiles']

    @property
    def rule_mapping(self) -> Dict[str, Dict[int, int]]:
        d: Dict[str, Dict[str, int]] = self.sandbox_coverage['rule_mapping']
        return {
            key: {int(a): b for a, b in mapping.items()}
            for key, mapping in d.items()
        }

    def normalised_rule_idx(self, original_rule_idx: int) -> Optional[int]:
        mapping = self.rule_mapping['original_to_normalised']
        return mapping.get(original_rule_idx, None)

    def generalised_rule_idx(self, original_rule_idx: int) -> Optional[int]:
        normalised_idx = self.normalised_rule_idx(original_rule_idx)
        if normalised_idx is None:
            return None
        mapping = self.rule_mapping['normalised_to_generalised']
        return mapping.get(normalised_idx, None)

    @property
    def decisions(self) -> Dict[int, List[int]]:
        d: Dict[str, List[int]] = self.sandbox_coverage['match_results'][
            'rule_deciding_for_log_entries'
        ]
        return {int(idx): logs for idx, logs in d.items()}

    @property
    def redundants(self) -> Dict[int, List[int]]:
        d: Dict[str, List[int]] = self.sandbox_coverage['match_results'][
            'rule_redundant_for_log_entries'
        ]
        return {int(idx): logs for idx, logs in d.items()}

    @property
    def original(self) -> Result:
        profile: List[Dict[str, Any]] = self.sandbox_profiles['original']

        hits: Dict[int, int] = defaultdict(int)
        for original_rule_idx, log_idxs in self.decisions.items():
            rule_idx = self.add_offset(original_rule_idx)
            hits[rule_idx] += len(log_idxs)

        redundant_hits: Dict[int, int] = defaultdict(int)
        redundancy_sources: Dict[int, List[Optional[int]]] = defaultdict(list)
        for original_rule_idx, log_idxs in self.redundants.items():
            rule_idx = self.add_offset(original_rule_idx)
            sources = self.redundancy_sources(original_rule_idx)
            redundant_hits[rule_idx] += len(log_idxs)
            redundancy_sources[rule_idx] = [
                self.maybe_add_offset(original_source_idx)
                for original_source_idx in sources
            ]

        return Result.from_profile(
            self.info,
            profile,
            hits,
            redundant_hits,
            redundancy_sources,
        )

    @property
    def normalised(self) -> Result:
        profile: List[Dict[str, Any]] = self.sandbox_profiles['normalised']

        hits: Dict[int, int] = defaultdict(int)
        for original_rule_idx, log_idxs in self.decisions.items():
            rule_idx = self.maybe_add_offset(
                self.normalised_rule_idx(original_rule_idx)
            )
            if rule_idx is None:
                continue
            hits[rule_idx] += len(log_idxs)

        redundant_hits: Dict[int, int] = defaultdict(int)
        redundancy_sources: Dict[int, List[Optional[int]]] = defaultdict(list)
        for original_rule_idx, log_idxs in self.redundants.items():
            rule_idx = self.maybe_add_offset(
                self.normalised_rule_idx(original_rule_idx)
            )
            if rule_idx is None:
                continue
            sources = self.redundancy_sources(original_rule_idx)
            redundant_hits[rule_idx] += len(log_idxs)
            redundancy_sources[rule_idx] = []
            for original_source_idx in sources:
                if original_source_idx is None:
                    redundancy_sources[rule_idx].append(None)
                    continue
                normalised_source_idx = self.maybe_add_offset(
                    self.normalised_rule_idx(original_source_idx)
                )
                if normalised_source_idx is not None:
                    redundancy_sources[rule_idx].append(normalised_source_idx)

        return Result.from_profile(
            self.info,
            profile,
            hits,
            redundant_hits,
            redundancy_sources,
        )

    @property
    def generalised(self) -> Result:
        profile: List[Dict[str, Any]] = self.sandbox_profiles['general']

        hits: Dict[int, int] = defaultdict(int)
        for original_rule_idx, log_idxs in self.decisions.items():
            rule_idx = self.maybe_add_offset(
                self.generalised_rule_idx(original_rule_idx)
            )
            if rule_idx is None:
                continue
            hits[rule_idx] += len(log_idxs)

        redundant_hits: Dict[int, int] = defaultdict(int)
        redundancy_sources: Dict[int, List[Optional[int]]] = defaultdict(list)
        for original_rule_idx, log_idxs in self.redundants.items():
            rule_idx = self.maybe_add_offset(
                self.generalised_rule_idx(original_rule_idx)
            )
            if rule_idx is None:
                continue
            sources = self.redundancy_sources(original_rule_idx)
            redundant_hits[rule_idx] += len(log_idxs)
            redundancy_sources[rule_idx] = []
            for original_source_idx in sources:
                if original_source_idx is None:
                    redundancy_sources[rule_idx].append(None)
                else:
                    source_idx = self.maybe_add_offset(
                        self.generalised_rule_idx(original_source_idx)
                    )
                    if source_idx is not None:
                        redundancy_sources[rule_idx].append(source_idx)

        return Result.from_profile(
            self.info,
            profile,
            hits,
            redundant_hits,
            redundancy_sources,
        )

    def redundancy_sources(self, rule_idx: int) -> List[Optional[int]]:
        """
        Returns indexes of rules actually leading to the decision instead of
        the given redundant rule. If the given rule is not redundant, an empty
        list is returned. If a rule is redundant to an implicit default
        decision (not the default rule added at the beginning!), None is added
        to the result set.
        """

        result: List[Optional[int]] = []
        logs = self.redundants[rule_idx]
        logs_identified = logs.copy()

        for related_rule_idx, decision_logs in self.decisions.items():
            for log in logs:
                if log in decision_logs:
                    if related_rule_idx not in result:
                        result.append(related_rule_idx)
                    logs_identified.remove(log)

        result = sorted(result)

        if 0 < len(logs_identified):
            result.append(None)

        return result


@jj.environmentfilter
def pygmentize(env: jj.Environment, sbpl: str) -> str:
    assert env.autoescape

    lexer = SchemeLexer(stripall=True)
    formatter = HtmlFormatter()
    html = highlight(sbpl, lexer, formatter)
    return jj.Markup(html)


@jj.environmentfilter
def num(env: jj.Environment, value: int) -> str:
    rev = str(value)[::-1]
    parts = [rev[i:i + 3][::-1] for i in range(0, len(rev), 3)]
    if env.autoescape:
        return '&thinsp;'.join(parts[::-1])
    return '\u2009'.join(parts[::-1])


def generate_single_app_report(
    app: App,
    report_type: str,
    title: str,
) -> str:
    if report_type == 'original':
        result = app.original
    elif report_type == 'normalised':
        result = app.normalised
    elif report_type == 'generalised':
        result = app.generalised
    else:
        assert False, f"Unhandled single-app report type: {report_type}"

    env = jj.Environment(
        loader=jj.FileSystemLoader(os.path.join(
            os.path.dirname(os.path.abspath(__file__)), 'data', 'templates',
        )),
        autoescape=jj.select_autoescape(['html', 'xml']),
    )
    env.filters['pygmentize'] = pygmentize
    env.filters['num'] = num
    template = env.get_template('report_profile.htm')
    html = template.render(
        title=title,
        pygments_css=HtmlFormatter().get_style_defs(),
        app=result,
    )
    return html


def generate_aggregated_report(
    apps: List[App],
    title: str,
) -> str:
    assert 0 < len(apps)

    results: List[Result] = [app.generalised for app in apps]

    # TODO Sanity check that all apps use the same generalised profile

    # Calculate total generalised hits
    hits: Dict[int, int] = defaultdict(int)
    redundant_hits: Dict[int, int] = defaultdict(int)
    redundancy_sources: Dict[int, List[Optional[int]]] = defaultdict(list)
    rule_count = results[0].rule_count
    for app, result in zip(apps, results):
        if rule_count != result.rule_count:
            print(
                f"Skipped incompatible report: {app.source_path}",
                file=sys.stderr,
            )
        for rule_idx, rule in enumerate(result.rules):
            hits[rule_idx] += rule.hits
            redundant_hits[rule_idx] += rule.redundant_hits
            for source in rule.redundancy_sources:
                if source not in redundancy_sources[rule_idx]:
                    redundancy_sources[rule_idx].append(source)
            has_implicit = None in redundancy_sources[rule_idx]
            redundancy_sources[rule_idx] = sorted([
                s for s in redundancy_sources[rule_idx] if s is not None
            ])
            if has_implicit:
                redundancy_sources[rule_idx].append(None)
    aggregated = results[0].with_manual_results(
        AppInfo.empty('Generalised Results'),
        hits,
        redundant_hits,
        redundancy_sources,
    )

    # Render HTML
    env = jj.Environment(
        loader=jj.FileSystemLoader(os.path.join(
            os.path.dirname(os.path.abspath(__file__)), 'data', 'templates',
        )),
        autoescape=jj.select_autoescape(['html', 'xml']),
    )
    env.filters['pygmentize'] = pygmentize
    env.filters['num'] = num
    template = env.get_template('report_profile.htm')
    html = template.render(
        title=title,
        pygments_css=HtmlFormatter().get_style_defs(),
        app=aggregated,
    )
    return html


def generate_tabular_report(
    apps: List[App],
    title: str,
) -> Optional[str]:
    assert 0 < len(apps)

    results = [app.original for app in apps]
    average_coverage = sum(app.coverage for app in results) / len(results)

    # Render HTML
    env = jj.Environment(
        loader=jj.FileSystemLoader(os.path.join(
            os.path.dirname(os.path.abspath(__file__)), 'data', 'templates',
        )),
        autoescape=jj.select_autoescape(['html', 'xml']),
    )
    env.filters['pygmentize'] = pygmentize
    env.filters['num'] = num
    template = env.get_template('report_tabular.htm')
    html = template.render(
        title=title,
        apps=results,
        average_coverage=average_coverage,
    )
    return html


def main():
    parser = argparse.ArgumentParser(
        "Create a HTML report for covered sandbox rules."
    )
    parser.add_argument(
        '-t', '--title',
        default="Sandbox Coverage Report",
        help="The title of the report.",
    )
    parser.add_argument(
        '--type',
        dest='report_type',
        choices=[
            'original', 'normalised', 'generalised', 'aggregated', 'tabular',
        ],
        default='normalised',
        help="""
        Type of report generated.

        The choices 'original', 'normalised', and 'generalised' will select the
        type of profile used for creating the report. Default is 'normalised',
        as 'original' might contain sensitive information such as the user's
        name. You need to pass a single JSON file as coverage_result.

        The choices 'aggregated' and 'tabular' will create a report of multiple
        application results. Selecting 'aggregate' will create an aggregated
        generalised profile and 'tabular' will display results for each
        application in a single report, but will not contain any profile. You
        need to pass a directory containing multiple application results such
        as created through the sandbox_coverage_driver script.
        """
    )
    parser.add_argument(
        'coverage_result',
        help="""
        Results generated by the sandbox_coverage script. Can be set to - to
        read from standard input. This will be interpreted as a result for the
        report types 'aggregated' and 'tabular' (see --type).
        """,
    )
    parser.add_argument('report', help="The generated HTML report.")

    args = parser.parse_args()

    if args.report_type in ['aggregated', 'tabular']:
        apps: List[App] = []
        for root, dirs, files in os.walk(args.coverage_result):
            for fn in files:
                if fn == 'sandbox_coverage.json':
                    abs_path = os.path.abspath(os.path.join(root, fn))
                    with open(abs_path, 'r') as fp:
                        sandbox_coverage: Dict[str, Any] = json.load(fp)
                    app = App(abs_path, sandbox_coverage)
                    apps.append(app)
        if args.report_type == 'aggregated':
            html = generate_aggregated_report(apps, args.title)
        elif args.report_type == 'tabular':
            html = generate_tabular_report(apps, args.title)
        else:
            assert False, "Unhandled multi-app report type: {args.report_type}"

    else:
        if args.coverage_result == '-':
            sandbox_coverage: Dict[str, Any] = json.load(sys.stdin)
        else:
            with open(args.coverage_result, 'r') as fp:
                sandbox_coverage: Dict[str, Any] = json.load(fp)
        abs_path = os.path.abspath(args.coverage_result)
        app = App(abs_path, sandbox_coverage)
        html = generate_single_app_report(
            app,
            args.report_type,
            args.title,
        )

    with open(args.report, 'w') as fp:
        fp.write(html)


if __name__ == '__main__':
    main()
