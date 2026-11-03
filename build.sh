#!/usr/bin/env bash
# Preserve the original command interface while using the make build.
set -euo pipefail
cd "$(dirname "$0")"
mode=${1:-test}
if (($#)); then shift; fi
case "$mode" in
    test|package|distribution|examples|compile|test-classes|javadoc|clean)
        exec make "$mode" "$@"
        ;;
    stress|probe|capacity|network|compare|key-updates|key-update-trace|lifecycle)
        make test-classes
        exec bash Tools/run.sh "$mode" "$@"
        ;;
    *)
        echo "Unknown build command: $mode; see BUILD.md." >&2
        exit 2
        ;;
esac
