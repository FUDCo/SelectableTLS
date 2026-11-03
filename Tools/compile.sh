#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
javac_command=$1
compile_flags=$2
jdep_command=$3
shift 3

# A failed batch must force a complete retry, even if javac emitted some classes.
rm -f build/main-compiled
sources=()
for class_file in "$@"; do
    relative=${class_file#build/classes/}
    sources+=("src/main/java/${relative%.class}.java")
    # Prune anonymous/nested classes that this source no longer declares.
    rm -f "$class_file" "${class_file%.class}"\$*.class
done
while IFS= read -r source; do
    sources+=("$source")
done < <(find src/main/java -name package-info.java -print)

# Compile flags are a conventional whitespace-separated javac option list.
read -r -a flags <<< "$compile_flags"
"$javac_command" "${flags[@]}" -classpath build/classes \
    -sourcepath src/main/java -d build/classes "${sources[@]}"

# Scan every outer class, including any compiled implicitly by javac.
classes=()
while IFS= read -r source; do
    relative=${source#src/main/java/}
    classes+=("build/classes/${relative%.java}.class")
done < <(find src/main/java -name '*.java' ! -name package-info.java -print)
"$jdep_command" -i com.fudco.selectabletls -c build/classes \
    -j src/main/java -d build/depend "${classes[@]}"
find build/classes -name '*.class' -print | LC_ALL=C sort > build/main-outputs
touch build/main-compiled
