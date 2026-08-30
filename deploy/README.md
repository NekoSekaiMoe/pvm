# PVM 部署指南

本目录包含 PVM 控制器（`agentpvm`）的全部生产部署物料。控制器有两种服务形态，共用一个二进制：

| 服务 | 命令 | 默认端口 | 说明 |
|---|---|---|---|
| API 服务器 | `agentpvm api` | 8080 | E2B 兼容 REST 控制面（`/api`），WebUI 后端 |
| WebUI 服务器 | `agentpvm webui` | 3000 | 嵌入式 Nuxt 3 仪表盘，与 api 同套路由 |
| envd 兼容面（可选） | 随 api 启动 | 49982 / 49983 | `PVM_ENVD_ENABLED=1` 时拉起，见下文"envd 暴露面" |

三种部署方式任选其一。

## 1. 裸机 + systemd（推荐）

```bash
sudo bash deploy/install.sh
```

安装器是幂等的：构建二进制装入 `/usr/local/bin`（可用 `PREFIX=/opt/pvm` 覆盖），安装
`deploy/systemd/agentpvm-{api,webui}.service`，并把 `deploy/pvm.env.example` 拷贝为
`/etc/pvm/pvm.env`（0600，root:pvm）。

**首次启动前必须编辑 `/etc/pvm/pvm.env`**：

```bash
sudo sed -i "s/__GENERATE_ME__/$(openssl rand -hex 32)/" /etc/pvm/pvm.env
sudo systemctl enable --now agentpvm-api agentpvm-webui
```

`API_SECRET` 未设置时 API 服务器拒绝启动。其余变量见 `pvm.env.example` 内注释。

前置要求：Linux + Go 1.23+（`go.mod` 最低版本）；UML 内核由控制器自行管理。

其他子命令：

| 命令 | 作用 |
|---|---|
| `./deploy/install.sh --uninstall` | 移除二进制与 systemd 单元（保留 `/etc/pvm/pvm.env` 与状态数据） |
| `./deploy/install.sh --docker` | 打印 Docker Compose 用法 |
| `./deploy/install.sh --help` | 帮助 |

## 2. Docker Compose

```bash
# 必须在仓库根执行：compose 文件位于 deploy/，构建上下文指向仓库根
docker compose -f deploy/docker-compose.yml up -d
```

单镜像两个服务：`api`（:8080，带 healthcheck，`webui` 依赖其健康后启动）与
`webui`（:3000）。容器内 UML 内核需要 `NET_ADMIN` 与非限制 seccomp——沙箱隔离由
UML 自身提供，不依赖容器运行时。

CI 已把 WebUI 预生成到 `webui/.output` 时，设 `WEBUI_PREBUILT=1` 构建参数可跳过
Node/pnpm 阶段。

## 3. 手动

```bash
go build -o agentpvm ./cmd/agentpvm
go build -o bin/umlctl ./cmd/umlctl
API_SECRET=$(openssl rand -hex 32) ./agentpvm api -port 8080
```

## 环境变量

| 变量 | 必填 | 说明 |
|---|---|---|
| `API_SECRET` | ✅ | `/api` Bearer 与 E2B 兼容 `X-API-KEY` 的共享密钥；设置后 envd 面同样要求 Bearer |
| `PVM_STATE_ROOT` |  | 状态根（默认 `/var/lib/pvm/state`） |
| `PVM_AUDIT_ROOT` |  | 审计账本根（默认 `/var/lib/pvm/audit`） |
| `PVM_CGROUP_ROOT` |  | cgroup 根（默认 `/var/lib/pvm/cgroup`） |
| `PVM_ENVD_ENABLED` |  | `1` 时随 api 拉起 envd 兼容监听器 |
| `PVM_ENVD_ADDR` |  | envd 绑定地址，**默认 `127.0.0.1`**；仅在有认证的网络环境下改为 `0.0.0.0` |
| `PVM_ENVD_PORT` / `PVM_ENVD_WS_PORT` |  | envd Connect-JSON / WebSocket 端口（默认 49983 / 49982） |
| `PVM_METRICS_NOAUTH` |  | `1` 时 `/metrics` 免认证（仅供无头抓取器） |
| `PVM_PPROF` |  | `1` 时暴露 `/debug/pprof`（始终要求 Bearer） |
| `PVM_REGISTRY_INSECURE` |  | 允许 http 私有 registry 拉取镜像 |
| `PVM_NETWORK_POOL` |  | 子网分配池（默认 `10.64.0.0/12`） |
| `PVM_APPROVAL_WEBHOOK_URL` |  | 审批工单 webhook 通知地址 |

## 健康检查

```bash
curl -s http://127.0.0.1:8080/healthz          # 存活 + uptime
curl -s http://127.0.0.1:8080/version          # 版本
curl -s -H "Authorization: Bearer $API_SECRET" http://127.0.0.1:8080/metrics
```

## envd 暴露面（安全）

envd 兼容面可直接执行 guest 命令、读写任务工作区，因此：

- 默认只绑定 `127.0.0.1`（`PVM_ENVD_ADDR` 控制）；
- 只要设置了 `API_SECRET`，两个端口都要求 `Authorization: Bearer <API_SECRET>`。

远程 SDK 需要访问 envd 时：`PVM_ENVD_ADDR=<内网地址>` + 强 `API_SECRET`，且走 TLS
或受信网络（SDK 对非回环地址强制 https）。

## 目录内容

```
deploy/
├── install.sh              # 幂等裸机安装器（见上）
├── pvm.env.example         # 环境变量模板 → /etc/pvm/pvm.env
├── docker-compose.yml      # api + webui 双服务编排
├── Dockerfile              # 多阶段构建（可选 WebUI 预生成）
└── systemd/
    ├── agentpvm-api.service
    └── agentpvm-webui.service
```
