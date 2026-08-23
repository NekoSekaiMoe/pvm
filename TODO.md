# TODO

## [P1] Jail rootless 化：把 UML 监控进程关进 user + PID namespace

**Context / 背景**

当前 jail(mountns + pivot_root + Landlock + seccomp 黑名单 + capability
bounding-set 裁剪)对"被攻破的 UML 监控进程"只是约束而非硬边界。已知
残留逃逸面(截至 2026-08,详见 `internal/jail/seccomp_linux.go` 与
`capability_linux.go` 的注释):

1. `kill`/`tgkill` 可信号**同 uid(root)的宿主进程**——同 uid 发信号不需要
   任何 capability,seccomp 也无法按目标 pid 过滤;只有 PID/user
   namespace 能隔绝。
2. `clone3` 的 `CLONE_NEW*` flags 在结构体指针里,seccomp 无法解引用过滤。
   (爆炸半径可控:子进程仍继承 seccomp 过滤器 + Landlock + no_new_privs。)
3. seccomp 黑名单是 fail-open 模型,未来新增的危险 syscall 默认放行。

**Goal / 目标**

让 UML 监控进程以 **namespaced root**(user namespace)运行,并加 PID
namespace:namespaced root 在 init_user_ns 中零 capability,
ptrace/kill/mount 等全部被 namespace 天然圈住,seccomp/cap 裁剪降级为
纵深防御。这才是对"监控进程被 guest 逃逸攻破"场景的硬边界。

**Blocker / 现有矛盾**

`internal/jail/process_linux.go` 的 `ConfigureProcessIsolation` 注释明确
记录了为什么特权路径**不能**套 userns:namespaced root 在 init_user_ns
没有 capability,会导致:

- `/dev/net/tun` 的 `TUNSETIFF`(需要 host netns 的 `CAP_NET_ADMIN`)
- cgroup v2 写入(文件属主是真 root,0600)
- root 属主的 0600 文件访问

**Design sketch / 方案草图**

把"运行时需要特权"的操作全部前移到宿主侧(manager 是真 root),namespace
内只留 fd 操作:

1. **TAP 预创建 + fd/属主传递**:manager 在宿主侧创建 tap 并 chown 给
   userns 映射的宿主 uid(或将 tap fd 直接传给 workload);jail 内
   `TUNSETIFF` 走"已存在且属主匹配"的 rootless 路径,不再需要
   `CAP_NET_ADMIN`。需要确认 UML vector tap transport 是否支持直接吃 fd,
   不支持则需给 `internal/network` 加"复用已有 tap"模式。
2. **cgroup 委托**:manager 预创建 cgroup 并按 cgroup v2 delegation 惯例
   chown 子树(`cgroup.procs` 等)给映射 uid;jail 内只做文件写入。
3. **文件访问**:jail rootfs / volumes 的属主映射进 userns
   (uid_map 把宿主 uid 映射为 ns 内 0),或预先 chown。
4. **PID namespace 语义**:重评 `ConfigureProcessIsolation` 里"监控进程
   不做 pidns init"的结论——UML 已为自己用到的信号(SIGNALRM/SIGIO/
   SIGSEGV...)安装了 handler,pid1 的"无 handler 信号被忽略"语义不影响
   它;孤儿进程 reparent 到它 + UML `wait4` 回收的行为需要实测验证。
5. seccomp/capability 裁剪保留(纵深防御),但安全结论不再依赖它们。

**Acceptance / 验收**

- [ ] `umlctl start` / `agentpvm run` 默认路径在 NEWUSER+NEWPID 下启动并
      通过 `tests/01–04`(网络、qcow2、cgroup 限制全部生效)
- [ ] 新增对抗测试:jail 内 ptrace/kill 宿主进程(非子进程)→ EPERM
      (放入 `internal/securitytest/`)
- [ ] `security.allow_insecure_degraded` 的降级语义文档同步更新
- [ ] 现有回归不破:`go test ./...`、`tests/*.sh` 全绿

**Risks / 风险**

- UML 对 pidns-init 信号语义的实际兼容性未验证(风险最高的未知项)
- rootless tap 在不同宿主内核/发行版上的行为差异
- cgroup 委托要求宿主 cgroup v2 配置允许子树 chown

**References**

- `internal/jail/process_linux.go` — `ConfigureProcessIsolation` 的
  userns/NEWPID 取舍注释(本次方案就是要翻掉它)
- `internal/jail/capability_linux.go` — 被保留的 `CAP_NET_ADMIN` 注释
- `internal/container/manager.go` — tap/cgroup 的宿主侧创建点
