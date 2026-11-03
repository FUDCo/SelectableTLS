# GNU make and jdep build. Maven is an independent alternative.
.DEFAULT_GOAL := all
.DELETE_ON_ERROR:

JDK_BIN = $(if $(JAVA_HOME),$(JAVA_HOME)/bin/)
JAVAC = $(JDK_BIN)javac
JAVA = $(JDK_BIN)java
JAR = $(JDK_BIN)jar
JAVADOC = $(JDK_BIN)javadoc
JFLAGS = --release 17 -Xlint:all -Werror
JDEP = jdep
JAR_DATE = 2026-10-31T00:00:00Z

export JAVA_HOME

BUILD_TARGETS = all package compile test-classes example-classes test examples \
    javadoc distribution stress probe capacity network compare \
    key-updates key-update-trace lifecycle

.PHONY: $(BUILD_TARGETS) clean check-build

clean:
	rm -rf build

check-build:
	bash Tools/test-make.sh

# Prepare inventories before reading dependencies, so removed sources cannot
# leave obsolete prerequisites or class files in an incremental build.
ifneq ($(BUILD_PREPARED),yes)
$(BUILD_TARGETS): prepared-build

.PHONY: prepared-build
prepared-build: prepare
	+$(MAKE) --no-print-directory BUILD_PREPARED=yes \
	    $(if $(filter $(BUILD_TARGETS),$(MAKECMDGOALS)),\
	    $(filter $(BUILD_TARGETS),$(MAKECMDGOALS)),all)

.PHONY: prepare
prepare:
	bash Tools/prepare.sh "$(JAVAC)" "$(JFLAGS)" "$(JDEP)" \
	    "$(JAR)" "$(JAVADOC)" "$(JAR_DATE)"

else
MAIN_DIR = src/main/java
CLASS_DIR = build/classes
DEP_DIR = build/depend
MAIN_SOURCES := $(shell find $(MAIN_DIR) -name '*.java' | LC_ALL=C sort)
CLASS_SOURCES = $(filter-out %/package-info.java,$(MAIN_SOURCES))
MAIN_CLASSES = $(CLASS_SOURCES:$(MAIN_DIR)/%.java=$(CLASS_DIR)/%.class)
MAIN_DEPS = $(CLASS_SOURCES:$(MAIN_DIR)/%.java=$(DEP_DIR)/%.d)
TEST_SOURCES := $(shell find src/test/java -name '*.java' | LC_ALL=C sort)
MAIN_MARKER = build/main-compiled
TEST_MARKER = build/test-compiled
RUNTIME_JAR = build/selectable-tls.jar

all package: $(RUNTIME_JAR)
compile: $(MAIN_MARKER)
test-classes: $(TEST_MARKER)
example-classes: build/example-compiled

# As in jdep's documented scheme, mark all affected classes first, then pass
# their sources to one javac invocation. The marker is committed only after
# compilation and dependency generation succeed.
$(CLASS_DIR)/%.class: $(MAIN_DIR)/%.java
	@mkdir -p "$(@D)"
	@touch "$@"

$(MAIN_MARKER): $(MAIN_CLASSES) $(filter %/package-info.java,$(MAIN_SOURCES)) \
    build/main-inputs
	bash Tools/compile.sh "$(JAVAC)" "$(JFLAGS)" "$(JDEP)" \
	    $(filter %.class,$?)

$(RUNTIME_JAR): $(MAIN_MARKER) Manifest.mf LICENSE build/package-inputs
	"$(JAR)" --create --file $@ --date=$(JAR_DATE) \
	    --manifest Manifest.mf -C $(CLASS_DIR) . -C . LICENSE

$(TEST_MARKER): $(TEST_SOURCES) $(MAIN_MARKER) build/test-inputs
	rm -f $@
	rm -rf build/test-classes
	mkdir -p build/test-classes
	"$(JAVAC)" $(JFLAGS) -cp $(CLASS_DIR) -d build/test-classes $(TEST_SOURCES)
	touch $@

build/example-compiled: Examples/TlsEcho.java $(RUNTIME_JAR)
	rm -f $@
	rm -rf build/example-classes
	mkdir -p build/example-classes
	"$(JAVAC)" $(JFLAGS) -cp $(RUNTIME_JAR) -d build/example-classes $<
	touch $@

test: $(TEST_MARKER)
	"$(JAVA)" -ea -cp $(CLASS_DIR):build/test-classes \
	    com.fudco.selectabletls.ConformanceTest

examples: build/example-compiled
	bash Examples/smoke.sh

javadoc: build/javadoc-generated

build/javadoc-generated: $(MAIN_SOURCES) build/main-inputs build/package-inputs
	rm -f $@
	rm -rf build/javadoc
	"$(JAVADOC)" --release 17 -quiet -notimestamp -Xdoclint:all,-missing \
	    -d build/javadoc $(MAIN_SOURCES)
	touch $@

distribution: $(RUNTIME_JAR) build/selectable-tls-sources.jar \
    build/selectable-tls-javadoc.jar

build/selectable-tls-sources.jar: $(MAIN_SOURCES) build/main-inputs LICENSE \
    build/package-inputs
	"$(JAR)" --create --file $@ --date=$(JAR_DATE) \
	    -C $(MAIN_DIR) . -C . LICENSE

build/selectable-tls-javadoc.jar: build/javadoc-generated LICENSE \
    build/package-inputs
	"$(JAR)" --create --file $@ --date=$(JAR_DATE) \
	    -C build/javadoc . -C . LICENSE

stress probe capacity network compare key-updates key-update-trace \
    lifecycle: \
    $(TEST_MARKER)
	bash Tools/run.sh $@ $(ARGS)

# A deleted source can still appear in an old dependency file when another
# source used to reference it. Let javac diagnose any remaining references.
$(MAIN_DIR)/%.java: ;

-include $(MAIN_DEPS)
endif
