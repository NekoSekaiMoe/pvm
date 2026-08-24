# TODO

## [P1] Jail rootless 化：把 UML 监控进程关进 user + PID namespace

**Status / 状态 (2026-08-23 实现完成，待 CI 集成验证)**

已按下列决策落地：

- **uid_map**:65536 range / 容器，集中分配表 `internal/uidalloc`（持久化于
  `$PVM_STATE_ROOT/uidmap.json`，启动分配、停止回收、`Prune` 回收崩溃残留）
- **降级**:userns 不可用时回退现有 mountns-only jail,`CheckSecurity`
  新增 `user-namespace` bypassed layer，由 `security.allow_insecure_degraded`
  门控并审计（`security:degraded_warning`)
- **cgroup**：维持 manager 宿主侧写 `cgroup.procs`/`memory.max`/`cpu.max`
  （写的是宿主 pid,jail 内零 cgroup 操作）——本就满足，无需改动
- **tap**:**未改内核**。v6.18 `arch/um/drivers/vector_user.c` 自带
  `transport=fd`(`user_init_fd_fds`);`network.OpenTapFD` 在宿主侧完成
  open+TUNSETIFF+TUNSETOFFLOAD+TUNSETVNETHDRSZ，经 `uml.KeyExtraFiles`
  继承为 workload fd 3,kernel arg 改写为 `vec0:transport=fd,fd=3`;
  rootless 模式下 `/dev/net/tun` 不再 bind 进 jail
- **/proc**:pidns 内挂私有 procfs(helper 在 pivot_root 后挂载）,UML 的
  readlink("/proc/self/exe") re-exec 回退路径恢复可用（personality 预设保留）
- **volumes**：改为属主预检（`volumeAccessNote`)+ audit constrain 警告。
  修正：idmapped mounts 对本拓扑是 no-op(mount idmap 单射，monitor 的
  宿主 creds 固定为 UIDBase+k，无法同时桥接 foreign 属主），契约改为
  「volume 属主落在容器 uid 段内或 world-accessible」
- **vhost-user / egress proxy**：两者本是 manager 进程内 goroutine（非子
  进程），随 manager 保持宿主侧 root；已处理的是 monitor 触达面的属主
  (vhost socket chown 进 uid 段、state 目录 o+x 遍历、overlay chown)
- **两段式 nsexec 启动（runc 模型）**:stage 1 = 真 root 新 mountns（降级腿）
  或 self-map namespaced root（非特权腿），负责 rprivate + 全部 bind
  （workload binary/系统目录/设备/volumes，直接路径）;stage 2 再 clone
  NEWUSER|NEWPID(uid_map 由 stage 1 这个 init_userns 真 root 写入），
  只负责 self-bind rootfs + pivot + 私有 /proc + Landlock/cap/seccomp。
  关键教训：mount 是 namespace 作用域对象，父 ns 打开的 fd 在子 ns 做
  bind 源过不了 check_mnt（曾走 fd 化弯路，CI 三连挂后废弃）;stage1 的
  退出码/pdeathsig/cgroup 继承链已核对（manager 记录的 stage1 pid 经
  cgroup 继承覆盖整棵树，杀 stage1 经 pdeathsig 带走 workload）
- **seccomp**：黑名单保持不动（fail-open 为既有定论，见
  `internal/jail/seccomp_linux.go` 头部历史注释），降级为纵深防御
- **对抗测试**:`internal/securitytest` 新增
  `TestAttack_JailedMonitorCannotTouchHostProcesses`(jail 内 kill/proc
  访问宿主 pid → 拒绝 + pidns-init 断言）

待 CI（需 UML 内核 + root + userns）验证：`tests/01–04` 在
NEWUSER+NEWPID 下全绿；pidns-init 信号语义实测（历史 commit cd20d20 的
hang 疑似与当时未修复的 persona/readlink 问题同源，现已有双保险）。

---

## [P1 原文] Jail rootless 化：把 UML 监控进程关进 user + PID namespace

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
