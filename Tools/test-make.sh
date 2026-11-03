#!/usr/bin/env bash
# Exercise the build graph without modifying the working source tree.
set -euo pipefail
cd "$(dirname "$0")/.."
test_dir=$(mktemp -d "${TMPDIR:-/tmp}/SelectableTLS-make.XXXXXX")
cleanup() {
    result=$?
    if ((result == 0)); then
        rm -rf "$test_dir"
    else
        tail -80 "$test_dir/build.log" >&2 || true
        echo "Build-check files retained at $test_dir" >&2
    fi
}
trap cleanup EXIT
cp Makefile Manifest.mf LICENSE "$test_dir"
cp -R Tools "$test_dir"
cd "$test_dir"
mkdir -p src/main/java/com/fudco/selectabletls src/test/java
source_dir=src/main/java/com/fudco/selectabletls
class_dir=build/classes/com/fudco/selectabletls
dep_dir=build/depend/com/fudco/selectabletls
cat > "$source_dir/Dependency.java" <<'JAVA'
package com.fudco.selectabletls;
public final class Dependency {
    public static int value() { return new Obsolete().value(); }
    private static final class Obsolete {
        int value() { return 1; }
    }
}
JAVA
cat > "$source_dir/Consumer.java" <<'JAVA'
package com.fudco.selectabletls;
public final class Consumer {
    public static int value() { return Dependency.value(); }
}
JAVA
cat > "$source_dir/Unrelated.java" <<'JAVA'
package com.fudco.selectabletls;
public final class Unrelated { }
JAVA
cat > "$source_dir/package-info.java" <<'JAVA'
/** Build-graph fixture. */
package com.fudco.selectabletls;
JAVA

build() {
    make --no-print-directory -j4 "$@" >> build.log 2>&1
}
fail() {
    echo "FAIL: $*" >&2
    exit 1
}

build package compile
test -s "$dep_dir/Consumer.d"
test -s "$class_dir/Dependency\$Obsolete.class"
cp -p build/selectable-tls.jar before.jar
cp -p "$class_dir/Consumer.class" before-consumer.class
cp -p "$class_dir/Unrelated.class" before-unrelated.class
sleep 1
build package
cmp -s before.jar build/selectable-tls.jar || fail 'no-op changed JAR contents'
[[ ! build/selectable-tls.jar -nt before.jar ]] || fail 'no-op rebuilt JAR'
[[ ! "$class_dir/Consumer.class" -nt before-consumer.class ]] ||
    fail 'no-op recompiled classes'

touch "$source_dir/Dependency.java"
build package compile
[[ "$class_dir/Consumer.class" -nt before-consumer.class ]] ||
    fail 'jdep did not rebuild the dependent class'
[[ ! "$class_dir/Unrelated.class" -nt before-unrelated.class ]] ||
    fail 'an unrelated class was unnecessarily recompiled'

sleep 1
cat > "$source_dir/Dependency.java" <<'JAVA'
package com.fudco.selectabletls;
public final class Dependency {
    public static int value() { return 2; }
}
JAVA
build package
[[ ! -e "$class_dir/Dependency\$Obsolete.class" ]] ||
    fail 'removed nested class survived compilation'

cp -p "$source_dir/Dependency.java" valid-source.java
sleep 1
printf '\ninvalid source\n' >> "$source_dir/Dependency.java"
if build package; then fail 'invalid source was accepted'; fi
[[ ! -e build/main-compiled ]] || fail 'failed batch kept its success marker'
cp -p valid-source.java "$source_dir/Dependency.java"
build package
test -f build/main-compiled

rm "$source_dir/Unrelated.java"
build package distribution
[[ ! -e "$class_dir/Unrelated.class" ]] || fail 'removed source left a class'
jar_command=${JAVA_HOME:+${JAVA_HOME}/bin/}jar
"$jar_command" tf build/selectable-tls.jar > jar-entries
if grep -q Unrelated jar-entries; then fail 'removed class remained in JAR'; fi

rm "$dep_dir/Consumer.d"
build package
test -s "$dep_dir/Consumer.d"
rm "$class_dir/Consumer.class"
build package
test -s "$class_dir/Consumer.class"

cp -p build/selectable-tls.jar before-options.jar
sleep 1
build package JFLAGS='--release 17 -Xlint:all -Werror -g'
[[ build/selectable-tls.jar -nt before-options.jar ]] ||
    fail 'compiler option change did not rebuild'

# Clean and incremental compilation must package the same bytes on one JDK.
cp build/selectable-tls.jar incremental.jar
build clean
build package JFLAGS='--release 17 -Xlint:all -Werror -g'
cmp -s incremental.jar build/selectable-tls.jar ||
    fail 'clean and incremental artifacts differ'

echo 'MAKE_BUILD_PASS no-op dependency nested-removal failure-retry source-removal missing-output options reproducibility'
