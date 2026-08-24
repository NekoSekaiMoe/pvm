# Macro generating one sh_test target per CI-safe shell suite.
#
# Kept in a .bzl file because BUILD files may not contain function
# definitions (Starlark constraint). See tests/BUILD.bazel for the design
# notes (manual/local/exclusive semantics, prebuilt binaries, runfiles
# data).

# Bazel 8 removed the native shell rules; sh_test comes from rules_shell
# (MODULE.bazel). test_suite remains native.
load("@rules_shell//shell:sh_test.bzl", "sh_test")

# Workspace files CI-safe suites read relative to the workspace root.
# Keep in sync with: grep -l 'uml/\|agentpvm.toml' tests/*.sh
CI_SAFE_DATA = [
    "//cmd/agentpvm",
    "//cmd/umlctl",
    "//uml:agentpvm.toml",
    "//tests:bazel_run.sh",
]

def pvm_suite(name, suite, data = []):
    sh_test(
        name = name,
        # The wrapper absolutizes AGENTPVM_BIN/UMLCTL_BIN against the
        # runfiles tree at execution time (sh_test.env is evaluated at
        # analysis time and cannot know the runfiles path).
        srcs = ["bazel_run.sh"],
        args = [suite],
        data = CI_SAFE_DATA + data + [suite],
        tags = ["manual", "local", "exclusive"],
    )

def pvm_suites(suites):
    """Generate one sh_test per suite and a ci_safe test_suite umbrella."""
    names = []
    for suite in suites:
        name = suite.replace(".sh", "").replace("-", "_")
        pvm_suite(name = name, suite = suite)
        names.append(":" + name)

    native.test_suite(
        name = "ci_safe",
        tests = names,
        # manual so //... skips the umbrella too; member tests keep their
        # own manual/local/exclusive tags.
        tags = ["manual"],
    )
