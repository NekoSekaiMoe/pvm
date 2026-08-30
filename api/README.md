# PVM API 规范（`openapi.yaml`）

本目录存放 PVM 控制面的 **OpenAPI 3.1** 规范。它描述单一 `agentpvm` 二进制对外的
全部 HTTP 面，并驱动 [`sdk/go/`](../sdk/go/) 官方 Go SDK 的接口契约。

## 覆盖范围

| 面 | 说明 |
|---|---|
| `/api/...` | 控制面 REST：沙箱、任务、文件、exec 网关、审计、审批、策略、资源池、门禁、卷、模板、egress、网络、身份、事件（18 个 tag 按平面划分） |
| E2B 兼容根路径 | `/sandboxes/:id` 等 E2B SDK 直连路由（`X-API-KEY` 或 Bearer） |
| 可观测性 | `/healthz`、`/version`（免认证），`/metrics`（Bearer，可 `PVM_METRICS_NOAUTH=1` 豁免） |
| envd Connect-JSON | `:49983` 上的 `/process.Process/*`、`/filesystem.Filesystem/*`、`/files`（`API_SECRET` 设置时要求 Bearer） |

不在规范内：`:49982` 的 envd WebSocket 版本服务。它使用 5 字节帧编解码
（1 字节 flags + 4 字节大端长度 + JSON，end-stream `0x02`），无法表达为 OpenAPI
路径——协议细节见 `internal/api/envd.go` 与 `sdk/go/envd.go` 的注释。

## 认证

```
security:
  - bearerAuth: []     # Authorization: Bearer <API_SECRET>
```

`API_SECRET` 是全局共享密钥（部署见 [`deploy/README.md`](../deploy/README.md)）。
单租户模型：任意持有密钥的调用者可访问全部任务，无任务级隔离——密钥即边界。

## 与实现的关系

- 路由实现：`internal/api/`（Echo）。规范与实现不一致视为 bug，以实现为准修规范
  （或反之），不允许长期漂移。
- SDK：`sdk/go` 按本契约暴露方法；破坏性契约变更需要同步 SDK 与测试。

## 校验

规范带结构自检脚本（依赖 `python3`+PyYAML 与 `jq`）：

```bash
bash scripts/check_openapi.sh api/openapi.yaml
```

它捕获两类历史事故（均在 PR #22 审阅中出现过）：

1. **路径参数不一致** —— `in: path` 参数没有出现在路径模板里，或模板里的 `{param}`
   从未声明（含 `components/parameters` 的 `$ref` 解析）；
2. **误引用** —— 需要 schema 的位置 `$ref` 到了 `components/responses/*`。

外加 YAML 语法检查：

```bash
python3 -c "import yaml; yaml.safe_load(open('api/openapi.yaml')); print('OK')"
```

## 新增 / 修改端点的流程

1. 在 `internal/api/` 实现 Echo 路由与处理器；
2. 在 `openapi.yaml` 补 path + schema（路径参数、响应引用对齐现有风格）；
3. 跑 `bash scripts/check_openapi.sh api/openapi.yaml`；
4. 涉及 SDK 能力时同步 `sdk/go/` 并补测试。
