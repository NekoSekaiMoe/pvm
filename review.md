Inline comments:
In `@bpf/egress.c`:
- Around line 26-45: Update the egress filtering logic around the IPv4 protocol
check and UDP fast path so IPv6 and other supported address families are not
implicitly allowed. Apply reserved and local-address blocking before
protocol-specific returns, expanding coverage beyond RFC1918 to include
loopback, link-local, and other sensitive ranges; restrict UDP to approved DNS
resolvers or require the same whitelist validation as other traffic.

In `@cmd/agentpvm/main.go`:
- Around line 55-62: Update the argument-count guard in the snapshot command
branch before accessing os.Args[4]. Require at least five arguments so snapshot
export/import invocations missing the file path show the usage message and
return instead of panicking; keep the existing sub, id, and file parsing
unchanged for valid input.

In `@internal/api/e2b_server.go`:
- Around line 90-96: Validate the container ID before constructing paths in the
log handler around c.Param("id"), restricting it to the safe character set and
confirming the resolved path remains within state.RootDir before reading. Apply
the same validation in internal/api/e2b_server.go lines 100-103 before deletion,
and propagate any os.RemoveAll failure instead of ignoring it.
- Around line 31-36: Update the API setup around the /api group and server
startup to require authentication and authorization for all listed control-plane
routes, including GET /containers, POST /containers/start, DELETE
/containers/:id, POST /images/pull, and POST /exec. Restrict production
listening to a loopback or explicitly trusted interface instead of the wildcard
address, and replace unrestricted CORS with a controlled allowlist of trusted
origins.

In `@internal/snapshot/tar_archive.go`:
- Around line 19-29: Harden Import by validating newContainerID against a safe
allowlist before constructing dir, rejecting traversal characters such as path
separators and "..". Replace the exec.Command tar extraction with archive/tar
and gzip handling that validates every header’s normalized path remains beneath
dir before creating or writing files, while preserving Import’s existing
error-return behavior.

In `@internal/state/manager.go`:
- Around line 13-15: 统一容器目录构造并防止路径穿越：在 internal/state/manager.go 的 ContainerDir
中对 id 增加仅允许字母、数字、下划线和短横线的白名单校验，作为唯一目录构造入口；在 internal/vhost/backend.go
的相关路径逻辑中移除硬编码根目录拼接，改为调用 state.ContainerDir(containerID)。

In `@webui/embed.go`:
- Around line 9-10: Ensure the WebUI generation step runs before any Go
compilation or tests that include the webui package: invoke the existing npm run
generate command in local/CI build workflows before go test ./... or go build
./cmd/umlctl, or otherwise create .output/public according to the Go README
instructions. Keep the webui embedFS declaration unchanged and make the
prerequisite apply to the WebUI startup flow as well.

---

Major comments:
In `@cmd/umlctl/main.go`:
- Around line 176-183: Update the webui startup flow in the “webui” command and
api.StartE2BServer so the service binds to 127.0.0.1 by default instead of all
interfaces, or add authentication to the management API routes. Ensure the
--help text clearly states that WebUI exposes container and image management
APIs.
- Around line 55-61: Update the overlay branch in main to mount the created
overlay filesystem before launching UML, reusing the existing container/image
overlay mount functionality. Set cfg.Rootfs to the container’s merged directory
(<container>/merged) after the mount succeeds, and handle mount errors with the
same startup failure behavior as CreateLayer.
- Around line 145-158: Validate the container ID before using it in the logs
path within the “logs” command, restricting it to the allowed identifier
characters and rejecting values containing path separators or traversal
components. Apply the same validation to the GET /api/containers/:id/logs
handler, reusing the existing container-ID validation mechanism if available,
before resolving or opening console.log.

In `@internal/api/e2b_server.go`:
- Around line 80-85: 启动链路当前未实际运行容器：在 internal/api/e2b_server.go
的容器启动处理处改为调用真实的容器生命周期管理器，并在启动失败或容器未就绪时返回错误；在 cmd/agentpvm/main.go
的启动流程中启动容器进程，并仅在该容器停止后清理 vhost 守护进程，确保不会立即退出并终止相关服务。
- Around line 124-138: Update the /exec handler’s ExecResponse construction so
it does not return ExitCode 0 for the simulated command. Until actual container
execution is implemented, return a clear not-implemented error response instead
of reporting success; preserve the existing request binding validation in the
handler.
- Around line 141-142: Update the catch-all route around the embedded Nuxt UI
handler to serve actual static files when they exist and return index.html for
other non-API paths, preserving API routing and enabling client-side routes such
as /logs/<id> on direct access or refresh. Use the existing webui.GetPublicFS()
filesystem and Echo handler integration.

In `@internal/ebpf/loader.go`:
- Around line 10-22: Update the qdisc setup flow around the existing tc commands
to preserve the interface’s clsact qdisc and unrelated ingress/egress filters:
remove or replace only this project’s owned BPF filter, and capture enough prior
state to restore it if adding or attaching the new program fails. Do not run the
current blanket clsact deletion, and keep unrelated network policies intact.
- Around line 26-30: Update UpdateWhitelist to perform a real eBPF whitelist_map
update instead of only logging and returning nil: open the existing map or its
pinned path, parse the supplied ip into the map’s key format, write the
domain/IP entry, and return any open, parse, or update error. Report the
whitelist update only after the map write succeeds, preserving the caller’s real
update path.

In `@internal/image/manager.go`:
- Around line 35-41: Update Pull to allocate per-invocation unique temporary
mount and tar paths instead of deriving mnt and temp.tar directly from the
shared imgDir. Use the existing safeName context with os.MkdirTemp or
equivalent, and ensure the temporary mount directory and archive are cleaned up
after completion so concurrent image pulls cannot share or overwrite resources.

In `@internal/network/bridge.go`:
- Around line 17-29: Update the bridge setup flow around the iptables command to
derive the NAT source subnet from gatewayIP instead of hardcoding 10.0.0.0/24.
Parse gatewayIP as CIDR, obtain its network address and mask, format the
resulting network CIDR, and use it in the MASQUERADE rule; return a descriptive
error if parsing fails.
- Around line 49-55: Update DeleteBridge to clean up the bridge’s associated
iptables MASQUERADE and forwarding rules before deleting the link, and restore
ip_forward using the previously saved value or reference-counted state rather
than leaving it enabled. Reuse the existing bridge/network configuration symbols
and preserve the current deletion error handling.

In `@internal/network/filter.go`:
- Around line 13-16: Update the BPF setup flow around loadBpfObjects and the
subsequent LinkByName, QdiscAdd, and FilterAdd operations to close objs on every
post-load failure path. After successful attachment, transfer only
objs.WhitelistMap into WhitelistMap and explicitly close or otherwise manage
objs.EgressFilter so its program fd remains tied to the intended lifecycle and
does not accumulate across repeated attaches.
- Around line 32-49: Update the qdisc and filter setup around QdiscAdd and
FilterAdd to ignore only EEXIST; propagate all other qdisc errors. When clsact
already exists, use the appropriate QdiscReplace or QdiscDel flow, and when the
owned egress_filter already exists, replace it or delete it and retry so
repeated application succeeds without returning “failed to attach BPF filter.”

In `@internal/uml/launcher.go`:
- Around line 11-30: The blocking Launch contract prevents callers from
recording a running state and real PID. In internal/uml/launcher.go lines 11-30,
split DefaultLauncher.Launch into start and wait phases (or expose an equivalent
post-start callback/channel) so the PID is available immediately; in
internal/container/manager.go lines 89-114, use the start phase to persist the
PID and set "running", then wait for completion before setting the final
"exited"/"stopped" state.
- Around line 16-24: 在 DefaultLauncher.Launch 的 logFile == nil 分支中同时将 cmd.Stdin
连接到父进程标准输入，并保留现有的标准输出和标准错误配置；logFile 非空时维持当前日志文件重定向行为。

In `@internal/vhost/backend.go`:
- Around line 13-16: 更新 StartStorageDaemon，移除硬编码的容器根目录并改用
state.ContainerDir(containerID) 获取目录路径；复用该函数的 containerID
校验逻辑，并正确处理其返回的错误后再创建目录，确保 socketPath 继续基于校验后的目录构建。
- Around line 36-45: Update the socket-wait loop in the backend startup function
to track whether socketPath was found; after all 10 attempts, return a clear
error instead of nil when the socket is still absent. Preserve the existing
successful return once os.Stat confirms the socket exists.
- Around line 26-30: Validate imagePath before constructing the
qemu-storage-daemon command, rejecting commas and any other characters that can
alter the comma-separated --blockdev property string; ensure invalid cfg.Rootfs
input fails before execution and preserve safe paths unchanged.

In `@scripts/test_io_perf.sh`:
- Around line 5-11: Replace the placeholder sections in scripts/test_io_perf.sh
with two equivalent, repeatable I/O workloads for standard ubd and
vhost-user-blk, measuring each run’s elapsed time or throughput and comparing
the measured results. Remove the hard-coded “3x improvement” output, assert a
defined performance threshold with a nonzero exit on failure, and ensure setup
and command failures also fail the script; if real devices and measurements
cannot be provided, explicitly mark the script as a placeholder rather than
reporting test results.

In `@scripts/test_pkg_install.sh`:
- Around line 7-15: Ensure all listed test scripts propagate failures and
validate actual behavior: in scripts/test_pkg_install.sh lines 7-15, remove the
success-masking fallback and assert the API response or execution result; in
tests/01_test_e2b_api.sh lines 17-29, validate HTTP status, required JSON
fields, and exitCode rather than substring matching; in
tests/02_test_network_qos.sh lines 8-18, separately validate dry-run parsing and
permission-dependent execution without unconditional success output; in
tests/03_test_cgroup_freeze.sh lines 8-21, fail on freeze/thaw errors and verify
state changes by reading the relevant file; in tests/04_test_qcow2_mount.sh
lines 25-32, return nonzero when the socket is absent and remove the invalid
literal “...” path.

In `@tests/01_test_e2b_api.sh`:
- Around line 10-14: Replace the fixed sleep after starting the background
agentpvm service in the test setup with a readiness retry loop that probes port
8081 until the API is accepting connections or a bounded timeout is reached. Add
a cleanup trap immediately after capturing API_PID to kill the process and wait
for it, ensuring cleanup runs when curl or assertions exit early.

In `@tests/04_test_qcow2_mount.sh`:
- Around line 12-21: Update the test flow around the qemu-img availability check
so a missing qemu-img dependency skips or fails explicitly without launching
agentpvm against the nonexistent overlay.qcow2. After starting the background
./agentpvm run command, capture its process ID and wait for or otherwise verify
its startup status so launch failures are detected rather than ignored.

In `@webui/dist`:
- Line 1: Remove the machine-specific absolute symlink at webui/dist and ensure
generated Nuxt output remains portable: either replace it with a relative link
that resolves correctly from the repository or generate .output/public during
the build and keep that temporary output untracked, while preserving
webui/embed.go’s all:.output/public embed path.

---

Minor comments:
In `@bpf/README.md`:
- Around line 7-10: Update the eBPF capability list in the README by removing
the unimplemented container system-call tracing and security-policy claim from
“Security & Observability.” Keep the documentation limited to the implemented
egress traffic whitelist filtering described by bpf/egress.c, adjusting the
entry’s wording or removing it as appropriate.

In `@cmd/umlctl/main.go`:
- Around line 76-82: 在处理 --volume 的代码中更新 volume 解析逻辑：当 strings.SplitN 产生的 parts
长度不是 2 时，明确提示用户参数格式无效，而不是静默跳过挂载设置；保留有效 host:guest 参数通过 container.KeyVolumeHost 和
container.KeyVolumeGuest 设置上下文的行为。

In `@README.md`:
- Line 3: Update the README description to change the compound adjective “UML
based” to “UML-based” while leaving the surrounding wording unchanged.

In `@webui/assets/css/main.css`:
- Line 1: 调整样式表顶部的 `@import` 语法，将 url(...) 改为 Stylelint 要求的字符串形式；同时更新第 23 行
font-family 声明中的字体名称引号，使其符合 font-family-name-quotes 配置，保留字体回退顺序不变。

In `@webui/package.json`:
- Around line 12-15: Replace the vue and vue-router "latest" dependency ranges
in webui/package.json with explicit semver versions matching the versions
already resolved in webui/package-lock.json. Preserve the lockfile and keep the
existing nuxt dependency unchanged.

In `@webui/pages/images.vue`:
- Around line 16-18: 更新 images.vue 中围绕 message
的提示状态：为失败响应单独维护错误状态，拉取失败时设置该状态并使用错误颜色或告警语义，成功消息继续使用 var(--success)。确保模板不会仅因
message 存在就始终按成功样式显示。

In `@webui/pages/index.vue`:
- Around line 63-77: Update startContainer and deleteContainer to check each
fetch response’s res.ok before treating the operation as successful; preserve
newContainer.value.name and avoid refreshing when starting fails, and surface
the API error to the user while retaining the existing successful flows.

---

Nitpick comments:
In `@internal/container/manager.go`:
- Around line 46-57: Simplify the argument-building logic around cfg.UseVirtio
by retaining the special vhost-user handling only when cfg.VhostUserSocket is
non-empty, and merging the identical rootfs/ubd0 and root-device arguments into
a single fallback path for all other cases.

In `@internal/snapshot/tar_archive_test.go`:
- Line 30: Replace the fixed /tmp/test-export.tgz path in the affected test with
a unique per-test temporary archive path, using the test framework’s
temporary-directory facility. Ensure the archive is created and referenced
through that isolated path so parallel runs and repeated executions cannot share
stale state.

In `@internal/snapshot/tar_archive.go`:
- Around line 10-11: 更新 Export，移除硬编码的容器根目录，改用 state.RootDir/state.ContainerDir
或现有共享路径辅助函数构建 dir。将 exec.Command("mkdir", "-p", dir).Run() 替换为 os.MkdirAll(dir,
0755)，并向调用方返回创建目录时的错误。

In `@webui/assets/css/main.css`:
- Line 1: Remove the remote Google Fonts `@import` from main.css and replace the
Inter dependency with a local, offline-safe approach: either bundle font assets
through the WebUI embed flow or use the existing system font stack. Ensure the
resulting typography remains available when umlctl webui runs without network
access.

In @.github/workflows/ci.yml:
- Around line 51-54: 为 CI 工作流中的 “Run Integration Script” 步骤添加合理的
timeout-minutes，限制 scripts/test_integration.sh 在启动或运行挂起时占用 runner 的时间；保持现有 chmod
和脚本执行命令不变。
- Line 13: Restrict the workflow’s repository access to read-only by adding
contents: read permissions, and update the actions/checkout step to set
persist-credentials to false so later install, generation, build, and test
commands cannot reuse Git write credentials
