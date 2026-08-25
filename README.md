# PVM (Pico VM)

[![Go Version](https://img.shields.io/badge/Go-1.22+-00ADD8?style=flat&logo=go)](https://golang.org)
[![Nuxt 3](https://img.shields.io/badge/Nuxt-3-00DC82?style=flat&logo=nuxtdotjs)](https://nuxt.com)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

**PVM (Pico VM)** 是一个基于 User-Mode Linux (UML) 的轻量级虚拟化容器管理器与**加固型自主 AI Agent 代码执行沙箱**。

它在进程级别提供真正的独立 Linux 内核级硬件虚拟化隔离，兼备 Docker 级秒级启动速度与虚拟机级强安全边界，专为不可信代码执行、自主 AI 编程代理与多租户环境设计。

---

## 🎯 核心用途 (Use Cases)

1. **AI Agent 安全沙箱**：为 LLM / Agent 代码解释器提供内核级隔离环境，防止容器逃逸、提权与破坏宿主机。
2. **凭证隔离与防泄露**：长效 Secret 永不注入沙箱，仅下发短期 HMAC 凭证，并在宿主机代理层按需附带凭据。
3. **出站网络与 SSRF 防御**：L7 HTTP/HTTPS 域名白名单 + eBPF TC 底层硬阻断（私网 RFC1918、回环 127.0.0.0/8、云元数据 169.254.169.254）。
4. **轻量级容器与快照**：纯 Go 原生 qcow2 驱动实现秒级 CoW 差异盘、原位压缩与快照归档，无外部重型依赖。
5. **人机协同治理与审计**：高危动作（支付/外发/部署）自动拦截进审批流，全程记录基于 SHA-256 默克尔哈希链的防篡改审计日志。

---

## ⚡ 快速上手 (Quick Start)

### 1. 环境准备与构建

确保本地已安装 **Go 1.22+** 和 **pnpm**：

```bash
# 克隆仓库
git clone https://github.com/NekoSekaiMoe/pvm.git
cd pvm

# 构建 WebUI 静态前端资源
cd webui && pnpm install && pnpm run generate && cd ..

# 构建 CLI 与管理控制面二进制
go build -o agentpvm ./cmd/agentpvm
go build -o bin/umlctl ./cmd/umlctl
```

### 2. 启动嵌入式 WebUI 仪表盘

PVM 将 Nuxt 3 前端静态资源直接内嵌至 Go 二进制中，一条命令即可启动带有 E2B 兼容 REST API 与控制台的面板：

```bash
./agentpvm webui --port 3000
```
浏览器访问 `http://localhost:3000` 即可查看沙箱、存储卷、模板中心、审批流及审计日志。

### 3. 运行 Agent 沙箱任务

使用 TaskSpec 配置文件启动完整治理周期的 Agent 沙箱：

```bash
./agentpvm run -config uml/agentpvm.toml
```

> **🔐 安全可选项 — `security.uml_seccomp`**：TaskSpec 的 `[security]` 段支持 `uml_seccomp = "on"|"auto"|"off"`（默认 `off`），通过 UML 内核运行时参数 `seccomp=` 启用 fast userspace 模式（mainline x86_64 ≥ 6.16；aarch64 zalexdev 移植版同样在 defconfig 中开启，两者共用同一内核参数）。**安全权衡（上游原文警告）**：启用后 guest 用户态可读写 guest 物理内存并干扰 stub 的 SIGALRM，guest 内核完整性不再受保证——因此 guest 内的 cgroup 限制（MEMCG/pids）将降级为“建议性”约束；宿主机侧的 jail 隔离边界不受影响。此为逐任务显式开启项，每次 `on`/`auto` 启动都会写入审计记录 `security:uml_seccomp`。

### 4. 或启动独立 UML 容器

使用轻量 CLI `umlctl` 快速启动单个容器实例：

```bash
./bin/umlctl start -name demo-node -rootfs alpine.img -mem 512M
```

---

## 🛠️ CLI 常用速查

| 命令 | 用途 |
|:---|:---|
| `agentpvm run [-config <spec.toml>]` | 启动 TaskSpec 驱动的加固 Agent 沙箱 |
| `agentpvm webui [--port 3000]` | 启动嵌入式 Nuxt 3 Web 仪表盘与 REST API 服务 |
| `agentpvm api [-port 8080]` | 启动 E2B 兼容的 REST API 服务端 |
| `agentpvm cow -compact <overlay.qcow2>` | 原位压缩 qcow2 差异盘并释放零簇 |
| `agentpvm snapshot [export\|import]` | 归档导出或解包还原容器状态 |
| `umlctl start -name <id> -rootfs <img.img>` | 启动独立轻量 UML 容器 |
| `umlctl ps` / `umlctl logs <id>` | 查看容器运行状态与控制台日志 |

---

## 🧭 无 bridge TC/eBPF 数据面（实验性，P2）

除默认的 Linux bridge + iptables 模型外，TaskSpec 可选 `network.dataplane = "tc"`，
采用 CubeVS 风格的无 bridge 数据面（每沙箱固定内网地址，全部转发/NAT 由 TC 挂载的
eBPF 完成，无 iptables 规则）：

```text
 guest 169.254.68.6                host
    │ TAP ingress (tc/eBPF)
    │  ├─ 目的 169.254.68.5 (网关/代理/DNS) → redirect pvm-gw
    │  ├─ SSRF 兜底 + 白名单校验
    │  └─ SNAT(host_ip, 端口段) + 会话表 → host NIC
    ▼
 host NIC ingress (tc/eBPF): 会话表反查 → 反向 DNAT → TAP
 pvm-gw egress   (tc/eBPF): 代理/DNS 应答按监听端口回送 TAP
```

- 每个沙箱内地址固定为 `169.254.68.6`，网关/代理固定为 `169.254.68.5`
  （`pvm_ip=` / `egress_proxy=` 内核参数注入）；宿主侧由 `pvm-gw` dummy 设备承接。
- 会话/NAT 状态在 per-task pinned maps（`/sys/fs/bpf/pvm/<task>/`），空闲超时由
  sweeper 回收；SNAT 端口按任务哈希分段，冲突重试插入。
- 限制（当前）：仅 IPv4 + TCP/UDP（ICMP 丢弃）；需要 root + bpffs；不可用时
  自动降级并写入 `security:degraded_warning` 审计（L7 代理仍是执行点）。
- 状态查询：`GET /api/network/dataplane{,/:task}`（模式、挂载点、会话数、计数器）。

## 🧪 自动化测试

仓库提供完善的单元测试与 18 个 CI-Safe 端到端 Shell 测试套件（套件 `05`–`08` 与 `10`–`22` 为 CI-Safe 无特权测试，`01`–`04` 与 `09` 需 Kernel/Root 支持）：

```bash
# 运行 Go 单元测试与对抗安全测试
go test -v ./...

# 运行所有端到端 Shell 集成测试（遇到错误立即中断）
set -e
for s in tests/*.sh; do ./"$s"; done
```

---

## 📄 许可证 (License)

本项目采用 [Apache License 2.0](http://www.apache.org/licenses/LICENSE-2.0) 开源许可证。
