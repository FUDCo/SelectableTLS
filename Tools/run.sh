#!/usr/bin/env bash
# Run diagnostics after make has prepared the required classes.
set -euo pipefail
cd "$(dirname "$0")/.."
java_tool_dir=${JAVA_HOME:+${JAVA_HOME}/bin/}
  case ${1:-test} in
    test) "${java_tool_dir}java" -ea -cp build/classes:build/test-classes com.fudco.selectabletls.ConformanceTest ;;
    key-updates) "${java_tool_dir}java" -ea -cp build/classes:build/test-classes com.fudco.selectabletls.ConformanceTest key-updates ;;
    lifecycle) "${java_tool_dir}java" -ea -cp build/classes:build/test-classes com.fudco.selectabletls.ConformanceTest lifecycle "${2:-1000}" ;;
    key-update-trace)
      "${java_tool_dir}java" -Djavax.net.debug=ssl:handshake -ea -cp build/classes:build/test-classes \
        com.fudco.selectabletls.ConformanceTest key-updates > build/key-update-trace.log 2>&1
      awk '/Produced KeyUpdate/ {produced++} /Consuming KeyUpdate/ {consumed++}
        END {printf "JSSE key-update trace: produced=%d consumed=%d\n", produced, consumed;
             if (produced < 1 || consumed < 1) exit 1}' build/key-update-trace.log
      ;;
    probe) shift; "${java_tool_dir}java" -ea -cp build/classes:build/test-classes com.fudco.selectabletls.ResourceProbe "$@" ;;
    capacity)
      shift
      # This changes only the build shell and its child JVM, not system settings.
      capacity_pairs=${1:-10000}
      case $capacity_pairs in ''|*[!0-9]*) echo 'Capacity pairs must be an integer' >&2; exit 2 ;; esac
      if ((capacity_pairs < 1 || capacity_pairs > 100000)); then echo 'Capacity pairs must be 1..100000' >&2; exit 2; fi
      ulimit -n "$((capacity_pairs * 2 + 1024))"
      "${java_tool_dir}java" -Xmx8g -ea -cp build/classes:build/test-classes com.fudco.selectabletls.ResourceProbe "$capacity_pairs" "${2:-10000}" tls 256 reuse-ports
      ;;
    stress) shift; "${java_tool_dir}java" -ea -cp build/classes:build/test-classes com.fudco.selectabletls.StressProbe "$@" ;;
    compare)
      shift
      comparison_jar=${1:?Supply the TLS Channel 1.0.0 JAR}; shift
      mkdir -p build/benchmark-classes
      "${java_tool_dir}javac" --release 17 -Xlint:all -Werror -cp "build/classes:build/test-classes:$comparison_jar" \
        -d build/benchmark-classes FutureWork/Benchmarks/com/fudco/selectabletls/TlsChannelProbe.java
      "${java_tool_dir}java" -ea -cp "build/classes:build/test-classes:build/benchmark-classes:$comparison_jar" \
        com.fudco.selectabletls.TlsChannelProbe "$@"
      ;;
    network) shift; "${java_tool_dir}java" -ea -cp build/classes:build/test-classes com.fudco.selectabletls.NetworkProbe "$@" ;;
    *) echo 'See BUILD.md and FutureWork/Benchmarks/README.md for commands and arguments.' >&2; exit 2 ;;
  esac
