# Macro generating one sh_test target per CI-safe shell suite.
#
# Kept in a .bzl file because BUILD files may not contain function
# definitions (Starlark constraint). See tests/BUILD.bazel for the design
# notes (manual/local/exclusive semantics, env-injected prebuilt binaries,
# runfiles data).

# Workspace files CI-safe suites read relative to the workspace root.
# Keep in sync with: grep -l 'uml/\|agentpvm.toml' tests/*.sh
CI_SAFE_DATA = [
    "//cmd/agentpvm",
    "//cmd/umlctl",
    "//uml:agentpvm.toml",
]

def pvm_suite(name, suite, data = []):
    native.sh_test(
        name = name,
        srcs = [suite],
        data = CI_SAFE_DATA + data,
        env = {
            # Suites cp these into their sandboxes instead of `go build`ing.
            # Relative to the runfiles root, which is the test's cwd.
            "AGENTPVM_BIN": "cmd/agentpvm/agentpvm",
            "UMLCTL_BIN": "cmd/umlctl/umlctl",
        },
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
