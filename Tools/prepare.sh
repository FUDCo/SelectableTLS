#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
javac_command=$1
compile_flags=$2
jdep_command=$3

command -v "$jdep_command" >/dev/null || {
    echo 'Install jdep from https://github.com/FUDCo/jdep or set JDEP=/path/to/jdep.' >&2
    exit 1
}
mkdir -p build
inputs_file=$(mktemp build/inputs.XXXXXX)
trap 'rm -f "$inputs_file"' EXIT
{
    printf '%s\n' "$javac_command" "$compile_flags" "$jdep_command"
    "$javac_command" -version 2>&1
    cksum Makefile Tools/prepare.sh Tools/compile.sh
    find src/main/java -name '*.java' -print | LC_ALL=C sort
} > "$inputs_file"
if ! cmp -s "$inputs_file" build/main-inputs; then
    rm -rf build/classes build/depend
    rm -f build/main-compiled build/test-compiled build/example-compiled
    rm -f build/selectable-tls.jar build/selectable-tls-sources.jar \
        build/selectable-tls-javadoc.jar build/javadoc-generated
    mv "$inputs_file" build/main-inputs
fi
mkdir -p build/classes build/depend

# Recreate dependencies if a generated file has been removed independently.
while IFS= read -r source; do
    relative=${source#src/main/java/}
    if [[ ! -f build/depend/${relative%.java}.d ]]; then
        rm -f build/main-compiled
        break
    fi
done < <(find src/main/java -name '*.java' ! -name package-info.java -print)

if [[ -f build/main-outputs ]]; then
    while IFS= read -r class_file; do
        if [[ ! -f $class_file ]]; then
            rm -f build/main-compiled
            break
        fi
    done < build/main-outputs
fi

# Invalidate consumers before make reads their timestamps. Older make versions
# can otherwise miss a marker recreated in the same second as its old artifact.
if [[ ! -f build/main-compiled ]]; then
    rm -f build/selectable-tls.jar build/test-compiled build/example-compiled
fi

find src/test/java -name '*.java' -print | LC_ALL=C sort > "$inputs_file"
if ! cmp -s "$inputs_file" build/test-inputs; then
    rm -rf build/test-classes
    rm -f build/test-compiled
    mv "$inputs_file" build/test-inputs
fi
if [[ ! -d build/test-classes ]]; then rm -f build/test-compiled; fi
if [[ ! -d build/example-classes ]]; then rm -f build/example-compiled; fi

printf '%s\n' "$4" "$5" "$6" > "$inputs_file"
if ! cmp -s "$inputs_file" build/package-inputs; then
    rm -f build/selectable-tls.jar build/selectable-tls-sources.jar \
        build/selectable-tls-javadoc.jar build/javadoc-generated
    mv "$inputs_file" build/package-inputs
fi
