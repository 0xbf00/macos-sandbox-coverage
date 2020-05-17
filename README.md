# `macos-sandbox-coverage`

This project contains code to compute sandbox coverage statistics for macOS applications. Please refer to [this article](https://ubrigens.com/posts/sandbox_coverage.html) for a conceptual overview of the tool's inner workings.

## Installation

This project depends on `cmake` and `nlohmann/json`. The dependencies can be installed using homebrew:

```sh
$ brew tap nlohmann/json
$ brew install cmake nlohmann_json
```

```sh
$ git clone --recursive https://github.com/0xbf00/macos-sandbox-coverage.git
$ cd macos-sandbox-coverage/
# Setup submodules:
# - maap: See instructions at https://github.com/0xbf00/maap
# - simbple: No need to build anything. We are only including some of the project's source code here.
# Build matching-core
$ mkdir matching-core/build
$ cd matching-core/build
$ cmake ..
$ make
```

## Usage

The program only supports two switches:

1. Use `--app` to specify the path to the application you want to collect sandbox coverage data for
2. Use `--timeout` to specify the number of seconds for the app to run. If you do not specify a timeout, the app will run indefinitely or until it is closed by the user.

```sh
$ ./sandbox_coverage.py --app /Applications/Calculator.app > output.json
$ ./report.py output.json output.htm
```

Output files should contain all the information you need to reproduce the results. The JSON output is quite large and makes use of the following keys:

* `arguments`: contains program parameters (path to app and timeout)
* `container_metadata`: base64-encoded `Container.plist` of the target app
* `logs`: under this key you'll find both raw and processed sandbox logs, which are used as input to the matcher.
* `match_results`: contains the original match results.
* `rule_mapping`: contains the mapping of original rules to normalised and generalised rules.
* `process_infos`: contains PID and `stderr` / `stdout` output of the target app
* `sandbox_profiles`: dictionary containing four different sandbox profiles. The original, normalised and generic (_generic_) profile are encoded as JSON, the patched profile compiled and encoded as base64

An example report can be found in [`data/example_report.htm`](data/example_report.htm) (normalised profile of _Calculator_ on macOS Catalina 10.15.3).