# PVM Roadmap TODO

> 起源：对标 CubeSandbox（`ref/`）的能力评估。结论：不抄其多节点/多进程
> 目录结构，只吸收四个点——x86_64 UML seccomp 快速模式、审计日志脱敏、
> DNS 学习式域名策略、CubeVS 式 TC/eBPF 数据面（去 bridge）。
>
> 侦察依据：三份 recon（网络数据面 / 审计+egress / 测试+WebUI）与主线内核
> v6.18 源码核实。所有 file:line 引用均基于当前 HEAD。

## 总览与阶段划分

| 阶段 | 内容 | 风险 | 依赖 |
|------|------|------|------|
| P0-A | x86_64 UML seccomp 模式（运行时参数） | 低 | 无 |
| P0-B | 审计日志脱敏（写前 redaction） | 低 | 无 |
| P1-A | 数据面收敛：per-task pinned maps + 启动路径自动挂 eBPF | 中 | 无 |
| P1-B | DNS 学习式域名策略 | 中 | P1-A（per-task map API） |
| P2 | CubeVS 式无 bridge 数据面（固定内网 IP + TC 三挂点 + BPF NAT） | 高 | P1-A |
| 横切 | 测试套件 32–35、WebUI 页面、README/路由清单、套件 10 重号修复 | — | 各对应阶段 |

---

## P0-A · x86_64 UML seccomp 快速模式

**已核实的事实**（主线 v6.18 源码）：

- seccomp userspace 模式 6.16 起在主线 x86_64（`arch/um/os-Linux/start_up.c:425`
  `uml_seccomp_config`），**纯运行时参数** `seccomp=on|auto|off`，默认 off。
- `seccomp=on` 探测失败即 `fatal()`（fail-closed）；`auto` 回退 ptrace。
- **无 CONFIG_UML_SECCOMP 符号**（仅 zalexdev arm64 分支有）；x86_64 不需要
  改 `build_kernel.sh` 的 config，只需修正注释（当前注释把 arm64 分支符号
  误述为主线）。
- 上游安全警告：seccomp 模式下 guest userspace 可读写 guest 物理内存、
  可干扰 stub 的 SIGALRM。→ **guest 内核不再是 TCB**，guest 内
  MEMCG/pids 强制（suite 09）退化为建议性。宿主侧 jail 边界不受影响。

### 任务

- [ ] `internal/spec/spec.go`：`SecuritySpec`（或新增）加
      `uml_seccomp: on|auto|off`，默认 `off`；`Validate` 校验取值；
      未知键拒绝机制（`md.Undecoded()`）无需改动。
- [ ] `internal/container/manager.go` `buildTaskArgs`（约 :1390-1504）：
      按 spec 追加内核参数 `seccomp=<mode>`；aarch64 与 x86_64 统一走同一
      字段（arm64 分支 defconfig 已带 SECCOMP，行为一致）。
- [ ] 决策写入审计：`audit.Record{Action: "security:uml_seccomp", Params:
      {mode, arch}}`；`auto` 回退 ptrace 时追加 `security:degraded_warning`
      （沿用 suite 30 的既有语义）。
- [ ] 文档：在 README/AGENTS 说明安全权衡——seccomp=on 时 guest 内核
      完整性不再保证，资源限制为建议性，仅建议用于"边界在宿主 jail"的
      纯吞吐场景。
- [ ] `scripts/build_kernel.sh`：修正 x86_64 分支关于 UML_SECCOMP 的注释
      （主线无此符号，运行时 `seccomp=` 参数即可）。

### 验收

- spec 设为 `on` 时 UML 启动日志出现 seccomp userspace 标记；
  在装了 seccomp 限制的宿主上 `on` fail-closed、`auto` 优雅回退且有审计行。
- 基准对比（可选）：guest 内 `getpid` 循环 syscall 吞吐 ptrace vs seccomp。

---

## P0-B · 审计日志脱敏（write-time redaction）

**现状**（recon 确认）：

- `internal/audit/ledger.go` `Append`（:226）→ `hashRecord`（:294）对
  **所有字段含 Params/Reason** 做哈希后落盘。脱敏必须发生在哈希之前，
  事后补救不可能（append-only + 哈希链）。
- 唯一已有脱敏：`internal/policy/gateway.go:197-265`
  （`scrubValue`/`isSafeSummaryKey`/`secretRedactionPatterns`：
  gh[pousr]_\*、AKIA\*、xox\*、Bearer）。
- **正在泄露的点**：`internal/approval/manager.go:127-135` 原始 tool
  params 未脱敏直接入链（最高危）；`internal/network/egress/gateway.go:904`
  上游错误文本（可能含 URL query token）入 `Reason`；
  `internal/incident/controller.go` 透传 executor/anomaly 字符串。

### 任务

- [ ] 新建 `internal/audit/redact.go`：把 policy gateway 的
      scrub/pattern 逻辑提升为共享实现（递归 scrub `Params` map/slice；
      对 `Reason`/`Subject`/`Action` 做模式掩码），policy gateway 改为
      调用共享实现（本地副本可删）。
- [ ] `internal/audit/ledger.go`：`Ledger` 增加 `Redactor` 字段，
      在 `Append` 内 `r.Task = l.task`（:248）之后、`hashRecord`（:252）
      之前应用。**唯一收口点**，9 个写入方零改动受益。
- [ ] `audit.Open` 默认挂共享 redactor；提供 `WithRedactor(nil)` 逃生门
      （仅测试用）。
- [ ] 可选纵深：读侧 `/api/audit/:id`（`internal/api/e2b_server.go`）
      对**历史**未脱敏账本再做一次展示层脱敏，响应中标记
      `redacted: true` 字段。
- [ ] `internal/securitytest/`：落盘字节级断言——Append 含 planted
      secret 的记录后，账本文件 grep 不到明文，且 `Verify` 仍通过。

### 验收

- 9 个写入包全量过安全测试；哈希链 verify 不受脱敏影响；
  历史账本读侧脱敏生效。

---

## P1-A · 数据面收敛（CubeVS 前置）

**现状**：bridge + iptables MASQUERADE 手工模型；`agentpvm run` 路径
**不自动**建网（bridge/tap/TC 全是 CLI/库函数）；唯一 eBPF 程序
`bpf/egress.c` 是 TAP **egress** 向、仅目的 IP 白名单 + SSRF 硬编码；
`whitelist_map` 全局单 pin 与 `filter.go` 的 per-tap 注册表设计冲突；
两条加载路径并存（`filter.go` cilium/ebpf vs `internal/ebpf/loader.go`
tc shell-out）。

### 任务

- [ ] 统一到 cilium/ebpf + bpf2go 一条加载路径；废弃
      `internal/ebpf/loader.go`（保留 CLI 兼容壳或直接删）。
- [ ] per-task pinned maps：`/sys/fs/bpf/pvm/<task>/`；调和
      `ebpf.UpdateWhitelist`（全局）与 `network.WhitelistMapFor`（per-tap
      refcount 注册表，filter.go:45）——以 per-tap 为准。
- [ ] `Manager.StartTask`（internal/container/manager.go，prepareTapFD
      附近 :904）自动调用 TC attach（现有 `AttachEgressFilter` 改造为
      per-task map 版本），cleanup 路径对称卸载（仿
      `SetupBridge` 的 rollback 风格 bridge.go:44-75）。
- [ ] `bpf/egress.c` SSRF 楼底层豁免沙箱自身 link-local 地址
      （当前 :41 无差别 drop 169.254.0.0/16，会阻断 P2 的固定内网 IP 模型）。
- [ ] guest IP 契约：内核 cmdline 增加 `pvm_ip=<addr>`（沿用
      `egress_proxy=` 的注入方式 manager.go:1495-1504），结束"guest 自选
      IP、宿主不知情"状态（当前测试脚本全部手写 10.0.0.2/24）。

### 验收

- `agentpvm run` 零手工网络准备即可让 eBPF 白名单生效；
  两个并发 task 的 map 互不污染；task 销毁后 pin 清理无残留。

---

## P1-B · DNS 学习式域名策略

**设计**（对标 CubeVS `dns_allow`/`dns_query_track`，但 P1 先走用户态）：

- 现状：L7 网关只按域名判定（`decideDomain` gateway.go:730），**从不看
  DNS**；eBPF 楼底层只认 IP。域名白名单与实际解析 IP 无关联 → DNS
  rebinding 仅靠 post-dial `isPrivate` 兜底。

### 任务

- [ ] 新建 `internal/network/dnslearn`：DNS snoop/proxy（x/net dnsmessage
      或 miekg/dns），挂在 task 的 TAP/bridge 侧；复用
      `domainMatches`（gateway.go:783）语义判定响应域名是否白名单内。
- [ ] 学习：白名单域名的 A 响应 → 解析出的**公网** IP 写入 per-task
      `whitelist_map`（走 P1-A 的 map API），expiry = min(DNS TTL,
      spec `learn_ttl`)；后台 sweeper 到期删除。非白名单域名只解析不学习
      （默认 DROP 楼底仍然拦截）。
- [ ] `internal/spec/spec.go` `NetworkSpec`（:164-189）新增：
      `dns_learn_enabled bool`、`learn_ttl string`（默认 5m）、
      `dns_upstream string`、`max_learned_entries int`（默认 256）。
      注意 unknown-key 拒绝机制要求必须加结构体字段；Fingerprint 自动覆盖。
- [ ] 审计：`PhaseExec` / `dns:learn`、`dns:expire` 事件入 per-task
      账本（自动享受 P0-B 脱敏）。
- [ ] 可选加固：网关 `dialCheckedTransport`（gateway.go:515）校验拨号
      IP ∈ 该 host 的已学习集合，关闭 rebinding 缺口。
- [ ] IPv6/AAAA 明确列为后续项（egress.c 当前 IPv4-only）。

### 验收

- 白名单域名解析后 guest 直连 IP 可通（不再必须走代理）；
  TTL 到期自动回收；非白名单域名解析的 IP 仍被楼底 DROP；
  学习/过期事件完整入链。

---

## P2 · CubeVS 式无 bridge 数据面

**目标模型**：每沙箱固定内网 IP（如 169.254.68.6，guest 侧不变）+
TC 挂 eBPF 做 L2 转向与 NAT + **去掉 Linux bridge 与 iptables**。
参照 CubeVS 三挂点：TAP ingress（策略+SNAT+会话）、宿主 NIC ingress
（反向 NAT）、宿主侧设备 egress（代理回路）。

### 任务（按序）

- [ ] `bpf/tap_ingress.c`（新）：TAP ingress TC 程序——策略判定、
      SNAT、会话创建（5-tuple LRU_HASH）、`bpf_redirect` 至宿主侧设备。
- [ ] 宿主 NIC ingress 程序：反向 NAT（会话表查找 + 校验和修复）。
- [ ] 会话/NAT maps 设计：pinned、per-sandbox、带 sweeper（仿 CubeVS
      reaper goroutine 模式）。
- [ ] bridgeless 下 L7 代理可达性：per-task listener 从 127.0.0.1 改绑
      宿主侧可达地址，TC 程序负责 guest→proxy 投递。
- [ ] bridge 路径降级为可选/删除：`SetupBridge`（bridge.go:41）的
      iptables MASQUERADE/FORWARD 规则随之移除；`umlctl network create`
      的硬编码 10.0.0.1/24 与 IPAM TODO 一并解决。
- [ ] QoS 对齐：tbf 保留或迁 BPF EDT，接入 StartTask。

### 验收

- 全程无 bridge 无 iptables：guest 出站经 TC-SNAT 直连外网，回包正确
  逆向；`02_test_network_qos.sh` 语义在新数据面下保持；并发 100 task
  无 IP 冲突（固定内网 IP + 宿主侧按 task 区分）。

---

## 横切 · 测试与 WebUI

**现状**：32 个 shell 套件（01–31，**10 号重号**：
`10_test_e2b_sdk.sh` 与 `10_test_volume_api_cli.sh` 撞号）；WebUI 15 页，
其中 identity/incidents/network 三页为纯静态 mock。harness 惯例：mktemp
roots + trap cleanup、per-suite port、Bearer auth、SKIP 优雅降级。

### 新套件

- [ ] `32_test_uml_seccomp_mode.sh`（P0-A）——CI-safe 假内核腿：spec
      字段解析、非法值拒绝、fail-closed/degraded 审计行；内核腿（守卫）：
      控制台标记确认 seccomp userspace 生效。
- [ ] `33_test_audit_redaction.sh`（P0-B）——CI-safe：planted secret
      落盘不可见、脱敏标记、verify 仍过、redactor 热更新、bypass 尝试被拒。
- [ ] `34_test_dns_egress_policy.sh`（P1-B）——CI-safe 假 DNS 事件：
      学习表增长、promote/deny API、TTL 过期、per-task 隔离、审计行。
- [ ] `35_test_tc_ebpf_dataplane.sh`（P1-A/P2）——CI-safe 降级腿（仿
      02）+ root 守卫腿：TC 挂/卸、map pin 生命周期、drop 统计。
- [ ] 修复套件 10 重号（volume 改为 36 或 e2b_sdk 改号，README 矩阵同步）。
- [ ] `25_test_e2b_api_full.sh` 路由清单补 ~12 条新路由。

### 新 API（internal/api）

- [ ] `GET/PUT /api/audit/redaction-policy`（P0-B）
- [ ] `GET /api/egress/:task/learned` · `POST /api/egress/:task/allow` ·
      `DELETE /api/egress/:task/learned/:host`（P1-B）
- [ ] `GET /api/network/dataplane` · `POST/DELETE .../rules` ·
      `GET .../stats`（P1-A/P2）
- [ ] `GET /api/tasks/:id` 响应带 `security.uml_seccomp` 状态（P0-A）

### WebUI（webui/pages/）

- [ ] `network.vue`：从静态 explainer 改为**活页面**——学习域名表 +
      promote/deny 按钮 + egress 模式开关（P1-B）；数据面程序/规则/计数器
      卡片 + `usePoll` 实时刷新（P1-A/P2）。
- [ ] `audit/index.vue` + `audit/[id].vue`：脱敏徽标 + 脱敏策略编辑器
      （P0-B）。
- [ ] `tasks.vue`：seccomp 模式徽标/创建时下拉；degraded 警告浮层
      （沿用 suite 30 语义，P0-A）。

## 非目标（本轮明确不做）

- 多节点化 / 控制面拆分 / 共享 DB（见讨论结论：单机 + fleet 分片即可）。
- TLS MITM 全量代理（CubeEgress OpenResty 路线）。
- 内存态快照恢复（KVM 独占能力，PVM 用 warm pool + 磁盘 CoW 绕开）。
- identity/incidents 两静态页面的 REST 化（不在四个特性范围内）。
