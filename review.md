Inline comments:
In `@cmd/umlctl/main.go`:
- Around line 54-58: 修复 --overlay 流程，使 image.CreateLayer 创建的层实际用于启动：成功创建 overlay
后，将 cfg.Rootfs 更新为该层的路径，并确保 container.Manager.Start 使用更新后的 cfg.Rootfs；未启用
overlay 时保留用户传入的 rootfs，创建失败则不要继续启动容器。
- Around line 121-141: 在 network 子命令处理逻辑中，为既不是 “create” 也不是 “rm” 的 subcmd
增加明确的未知子命令提示，并输出现有用法说明。保留现有创建、删除及参数不足时的行为不变。
- Around line 89-96: Update the command flow around manager.Start in main so
failures with --rm still return a nonzero process exit code while cleanup runs
before termination. Replace the deferred cleanup registered earlier in main with
explicit cleanup control, ensure cleanup executes before any os.Exit call, and
preserve successful runs’ existing behavior.

In `@internal/container/manager.go`:
- Around line 81-93: 更新启动流程中的三处 state.SaveState 调用：先加载并复用已有
ContainerState，仅修改状态和实际变化字段，保留 StartedAt，并使用 m.Launcher.Launch 提供的进程信息填充 PID。将
Launch 返回错误时的状态设为 exited，成功返回时设为 stopped。检查每次 SaveState 的返回错误并按现有错误处理方式记录或传播。

In `@internal/image/manager.go`:
- Around line 49-58: 在 os.Create 成功后立即为 tarFile 注册 defer os.Remove(tarFile)，确保
crane.Export 失败提前返回时也能清理临时文件；移除当前成功路径中延迟注册的位置，保留现有关闭文件逻辑。
- Around line 37-38: 检查挂载流程中 exec.Command("sudo", "mount", ...)
的返回错误；挂载失败时立即停止后续镜像导出/解压并返回错误，避免继续写入普通目录或报告成功。保留卸载操作的延迟清理，并确保错误能传播到调用方。

In `@internal/network/bridge.go`:
- Around line 9-24: Update SetupBridge to check and propagate errors from every
ip, iptables, and sysctl command instead of discarding them and always returning
nil. Return immediately with contextual errors when a command fails, while
preserving the existing setup order and tapName conditional behavior.

---

Nitpick comments:
In `@cmd/umlctl/main.go`:
- Around line 73-74: Replace the raw "interactive" context key used by the
WithValue calls in the main command flow with the shared typed key or key
constant used by the corresponding ctx.Value consumer in the container manager,
updating both occurrences. Keep the stored value and existing interactive
behavior unchanged.
- Line 64: 将 cmd/umlctl/main.go 中三个 os.RemoveAll
路径引用替换为统一的容器根目录常量，避免重复硬编码；同时复用或提取同一共享常量供
internal/state/manager.go、internal/log/logger.go 和 internal/image/manager.go
使用，确保所有调用保持现有路径行为。

In `@internal/container/manager_test.go`:
- Line 59: Restore the removed TestManager_Start_Virtio coverage in the manager
tests, including assertions for the virtio=... startup argument, root=/dev/vda,
and vec0:transport=tap,ifname=... branches implemented by Manager.Start. Keep
the assertions equivalent to the deleted test and preserve the existing test
structure.
- Around line 48-51: 改造该测试中 cfg 的 state/log
路径配置，使其通过可注入路径或临时目录创建，而不是依赖不可控的系统目录；随后恢复对 manager.Start(context.Background(),
cfg) 错误返回值的校验，并在错误时使用 t.Fatalf，避免吞掉除路径权限外的真实回归。

In `@internal/container/manager.go`:
- Around line 31-36: Replace the bare string keys used by ctx.Value in the
container manager, including “interactive”, “volume_host”, and “volume_guest”,
with a dedicated context-key type and shared key symbols. Update the
corresponding context writes in cmd/umlctl/main.go to use those same symbols,
preserving the existing values and behavior.

In `@internal/log/logger.go`:
- Line 11: 更新 logger.go 中 logDir 的构造，移除硬编码的容器日志根目录并复用 internal/state/manager.go
建议引入的统一路径常量，确保该路径与其他相关文件保持一致。

In `@internal/state/manager.go`:
- Line 19: 提取共享的容器路径辅助函数，集中定义容器根目录并通过类似 ContainerDir(id string) 生成路径；更新
internal/state/manager.go 中 SaveState 和 LoadState 的路径构造，并替换
internal/log/logger.go、internal/image/manager.go、cmd/umlctl/main.go
等位置的重复硬编码，确保所有调用复用同一实现。
