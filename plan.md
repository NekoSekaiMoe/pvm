基于你提供的 Episode 2 和 Episode 3 的所有架构图，我为你整理了一份完整、详细、可面向工程落地参考的技术文档。

这份文档整合了从"隔离执行"到"生产级运营"的完整知识体系，采用章节式结构展开。

---

# 技术文档：生产级 Agent 沙箱与可信执行体系架构

**文档版本**：v2.0
**对应章节**：Episode 2（参考架构与边界控制） + Episode 3（可恢复运营体系）
**核心命题**：如何构建一个既能安全隔离、又能生产级运营的 Agent 执行环境？

---

## 目录

1. [架构总览与设计哲学](#1-架构总览与设计哲学)
2. [控制平面与执行平面分离](#2-控制平面与执行平面分离)
3. [身份与权限体系](#3-身份与权限体系)
4. [网络出口控制](#4-网络出口控制)
5. [工作区与状态管理](#5-工作区与状态管理)
6. [工具调用与策略网关](#6-工具调用与策略网关)
7. [证据链与独立验证（Artifact Gate）](#7-证据链与独立验证artifact-gate)
8. [生命周期状态机](#8-生命周期状态机)
9. [策略即数据：TaskSpec 规范](#9-策略即数据taskspec-规范)
10. [审批与人工干预设计](#10-审批与人工干预设计)
11. [故障处置与恢复机制](#11-故障处置与恢复机制)
12. [多租户规模化设计](#12-多租户规模化设计)
13. [控制画像：不同角色的权限模板](#13-控制画像不同角色的权限模板)
14. [审计与可重建证据链](#14-审计与可重建证据链)
15. [成熟度模型与建设路线](#15-成熟度模型与建设路线)

---

## 1. 架构总览与设计哲学

### 1.1 一句话核心

> **可信 Agent = 有能力的模型 + 有边界的执行 + 可恢复的运营系统**

### 1.2 三大设计哲学

| 原则 | 说明 |
|------|------|
| **默认拒绝，按需开放** | 网络、工具、权限全部默认 Deny，任务显式声明后才开放 |
| **生成者不能自证清白** | Agent 声称成功，必须经过独立 Artifact Gate 重验才能发布 |
| **控制面与执行面分离** | 执行面只负责"跑"，控制面负责"能不能跑、能跑多久、能碰什么" |

### 1.3 四层架构全景

| 平面 | 职责 | 关键组件 |
|------|------|----------|
| **CONTROL PLANE** | 目标 → TaskSpec → 调度与生命周期 | TaskSpec Compiler、Template/Warm Pool、KILL/REVOKE |
| **EXECUTION PLANE** | Agent + 代码 + 私有工作区 | Container/gVisor/MicroVM/WASM、Resource Budget |
| **POLICY + IDENTITY** | 每次行动前决策 | Credential Broker、Egress Gateway、Tool Gateway、Approval |
| **EVIDENCE + RELEASE** | 产物、重验、审批、发布 | Artifact Bundle、Artifact Gate、Release Service |

---

## 2. 控制平面与执行平面分离

### 2.1 控制平面（Control Plane）

控制平面负责任务的定义、调度和生命周期管理：

| 组件 | 职责 | 细节 |
|------|------|------|
| **User Goal** | 接收用户意图 | 自然语言或结构化任务描述 |
| **TaskSpec Compiler** | 编译目标为可执行规范 | 输出 policy、budget、TTL 等结构化控制合同 |
| **Template / Warm Pool** | 实例预热与复用 | 预置隔离环境，减少冷启动 |
| **KILL / REVOKE** | 强制终止与撤销 | 超时自动 kill；违规时 REVOKE 所有凭证 |

### 2.2 执行平面（Execution Plane）

执行平面负责 Agent 的实际运行：

| 组件 | 职责 | 细节 |
|------|------|------|
| **AGENT** | 推理-行动-观察循环 | ReAct 模式：思考 → 调用工具 → 接收 Observation |
| **Private Workspace** | 隔离的工作目录 | 包含 state、checkpoint，支持暂停/恢复 |
| **Resource Budget** | 硬性资源限制 | CPU/内存/时间三围监控，超限触发 kill |

### 2.3 隔离技术栈

| 技术 | 安全等级 | 性能开销 | 适用场景 |
|------|----------|----------|----------|
| 容器 | 基础 | 低 | 常规任务 |
| gVisor | 中 | 中 | 多租户隔离 |
| MicroVM | 高 | 较高 | 高安全要求 |
| WASM | 中高 | 极低 | 轻量函数式任务 |

---

## 3. 身份与权限体系

### 3.1 核心原则

> **不要把人的权限塞进 Sandbox**

开发者长期密钥 / 共享服务账号 **绝不** 进入镜像、文件、Prompt 或长期环境变量。

### 3.2 Task Identity 设计

```
USER 授权
    ↓
	Task Identity (user × task × tenant)  ← 稳定主体，极小作用域
	    ↓
		Credential Broker → 动态颁发短期凭证
		    ├── repo:read/write
			    ├── TTL: 15 分钟
				    └── 可撤销
					```
					
					### 3.3 凭证生命周期
					
					| 阶段 | 动作 | 说明 |
					|------|------|------|
					| 颁发 | Credential Broker 动态创建 | 不预置任何长期密钥 |
					| 使用 | Agent 通过 Broker 获取 | 凭证不进入环境变量或文件 |
					| 过期 | TTL 到达自动失效 | 默认 15 分钟 |
					| 撤销 | 控制面 REVOKE | 立即切断所有权限 |
					
					### 3.4 审计追踪
					
					记录字段：**谁授权 · 哪个任务 · 什么范围 · 何时过期**
					
					---
					
					## 4. 网络出口控制
					
					### 4.1 核心原则
					
					> **默认拒绝，再按任务开放**
					
					### 4.2 Egress Gateway 架构
					
					```
					SANDBOX
					    ↓
						Agent (DNS/HTTP(S) — no direct socket path)
						    ↓
							EGRESS GATEWAY (domain · port · method · payload size · data class)
							    ↓
								    ├── ALLOW   → Code Repo / Package Proxy / Model API / approved docs
									    ├── BLOCK   → Metadata / Private Network / unknown upload endpoints
										    └── REVIEW  → Large POST / Sensitive Data → approval or DLP inspection
											```
											
											### 4.3 控制维度
											
											| 维度 | 控制粒度 |
											|------|----------|
											| 域名 | 白名单机制 |
											| 端口 | 限制特定端口（如仅 443） |
											| 方法 | GET/POST/PUT 限制 |
											| Payload Size | 限制上传/下载大小 |
											| Data Class | 敏感数据检测 |
											
											### 4.4 技术实现
											
											- **NetworkPolicy（K8s 层）**：控制连接路径（IP/端口）
											- **Egress Proxy（应用层）**：控制数据内容（方法/数据分类）
											
											---
											
											## 5. 工作区与状态管理
											
											### 5.1 核心原则
											
											> **Agent 需要连续状态，但不需要宿主所有状态**
											
											宿主真实目录（如 `~/project`）**不要**直接以读写方式挂载进任务。
											
											### 5.2 工作区架构
											
											```
											Base Image (immutable toolchain + repo snapshot)
											    ↓ COW (Copy-on-Write)
												Private Workspace (task PVC / cache, stable identity)
												    ↓ 运行时
													RUNNING (files · processes · browser · interactive state)
													    ↓ checkpoint
														Checkpoint (pause / resume / snapshot / hibernate)
														    ↓ 输出
															Artifact (diff · build · report — declared output only)
															```
															
															### 5.3 各层说明
															
															| 层 | 特性 | 意图 |
															|----|------|------|
															| **Base Image** | 不可变工具链 + 代码仓库快照 | 确保任务从一致基线开始 |
															| **Private Workspace** | COW 隔离，每任务独立 PVC | 多 Agent 共享 Base，写时复制隔离 |
															| **RUNNING** | 文件、进程、浏览器、交互状态 | 支持多轮对话中的状态保持 |
															| **Checkpoint** | 暂停/恢复/快照/休眠 | 长时间任务可中断恢复 |
															| **Artifact** | 仅声明输出被导出 | 防止 Agent 随意写文件到外部 |
															
															---
															
															## 6. 工具调用与策略网关
															
															### 6.1 网关架构
															
															```
															AGENT
															    ↓ ToolRequest
																TOOL / POLICY GATEWAY
																    (user · task · resource · action · args · risk · budget)
																	    ↓ typed schema + policy decision
																		    ├── ALLOW     → 读操作自动允许
																			    ├── CONSTRAIN → 写操作仅任务分支
																				    ├── APPROVE   → 发送/删除需展示参数+审批
																					    └── DENY      → 支付/生产默认拒绝
																						```
																						
																						### 6.2 分级决策矩阵
																						
																						| 操作类型 | 策略 | 具体行为 |
																						|----------|------|----------|
																						| **READ** | 自动允许 | 读代码/文档/配置 |
																						| **WRITE** | 约束 | 仅允许写入任务分支 |
																						| **SEND / DELETE** | 展示参数 + 审批 | 需完整展示参数 |
																						| **PAY / PROD** | 默认拒绝 | 除非 TaskSpec 显式声明 |
																						
																						### 6.3 关键安全设计
																						
																						> **标准化 Observation 返回模型，原始凭证不返回**
																						
																						网关返回结构化摘要（如"写入成功，路径为 xxx"），API 密钥/支付 token **不返回** Agent，防止模型泄露敏感信息。
																						
																						---
																						
																						## 7. 证据链与独立验证（Artifact Gate）
																						
																						### 7.1 核心原则
																						
																						> **生成者可以提供证据，但不能独自成为最终裁判**
																						
																						### 7.2 三身份模型
																						
																						| 身份 | 职责 | 说明 |
																						|------|------|------|
																						| **task-writer** | Agent 自称成功 | 生产者角色，有动机美化结果 |
																						| **independent-verifier** | Artifact Gate 执行者 | 独立于 Agent，只依据证据重验 |
																						| **release-service** | 执行合并/部署/发送 | 仅接受 Gate 通过的产物 |
																						
																						### 7.3 Artifact Gate 四步验证
																						
																						```
																						SANDBOX
																						    ↓ Agent claims success
																							Artifact Bundle (diff · build · trace · hash)
																							    ↓
																								ARTIFACT GATE
																								    ├── 01 · 只读基线重放   → 验证可复现性
																									    ├── 02 · 重跑测试与扫描 → 功能正确性 + 安全扫描
																										    ├── 03 · 检查敏感差异   → 防止密钥/PII 泄露
																											    └── 04 · 绑定产物哈希   → 固化产物指纹
																												    ↓
																													    ├── PASS → RELEASE (merge/deploy/send)
																														    └── FAIL → structured feedback (哪个测试失败/哪个diff敏感/哈希不匹配)
																															```
																															
																															---
																															
																															## 8. 生命周期状态机
																															
																															### 8.1 核心原则
																															
																															> **能暂停、能恢复，才算能运营**
																															
																															### 8.2 状态转换图
																															
																															```
																															Pending
																															    ↓
																																Provisioning (runtime + policy)
																																    ↓
																																	Ready (health checked)
																																	    ↓
																																		Running (agent loop) ←→ Suspended (checkpointed) → Resuming (restore identity)
																																		    ↓                                ↑
																																			Review (verify / approve)            │
																																			    ↓                                │
																																				Completed (artifact sealed)          │
																																				    ↓                                │
																																					Destroy (revoke / clean)             │
																																					    ↑                                │
																																						Failed (retry / inspect) ────────────┘
																																						    ↓
																																							Quarantined (network revoked) —— 异常隔离
																																							```
																																							
																																							### 8.3 状态转换原则
																																							
																																							| 原则 | 说明 |
																																							|------|------|
																																							| **持久化** | 状态变更必须落盘/记录 |
																																							| **幂等** | 重复操作不产生副作用 |
																																							| **可超时** | 每个状态有最大停留时间 |
																																							| **明确责任方** | 谁驱动这个转换（Agent/Controller/Human） |
																																							
																																							---
																																							
																																							## 9. 策略即数据：TaskSpec 规范
																																							
																																							### 9.1 核心原则
																																							
																																							> **Prompt 描述目标，TaskSpec 规定目标如何被执行**
																																							
																																							### 9.2 TaskSpec 结构（控制合同）
																																							
																																							| 字段 | 内容 | 说明 |
																																							|------|------|------|
																																							| Runtime | image / class | 运行时镜像/规格 |
																																							| Workspace | repo / PVC | 代码仓库/持久卷 |
																																							| Network | egress allowlist | 出口白名单 |
																																							| Identity | scope / TTL | 权限范围/有效期 |
																																							| Tools | schema / policy | 工具 Schema + 策略 |
																																							| Budget | cpu / time / cost | 资源/时间/费用预算 |
																																							| Approval | effect boundary | 什么操作需要审批 |
																																							| Artifacts | declared outputs | 声明哪些是产出物 |
																																							| Lifecycle | pause / TTL / retry | 生命周期控制 |
	
	9.3 设计原则
	versioned：版本化，支持变更追踪
	
	validated：可验证，启动前校验
	
	auditable：可审计，完整记录
	
	policy already resolved：策略在任务启动前已解析完毕，非运行时动态查询
	
	10. 审批与人工干预设计
	10.1 核心原则
	只卡住副作用边界
	
	10.2 审批决策流程
	text
	AGENT proposed action
	    ↓
		POLICY (effect · scope · reversibility · data · budget · production)
		    ↓
			risk decision
			    ├── LOW RISK → 自动执行
				    │   ├── 只读查询
					    │   ├── Sandbox 内修改
						    │   └── 运行测试
							    └── HIGH IMPACT → 需要审批
								        ├── 发邮件
										        ├── 删除数据
												        ├── 修改权限
														        ├── 付款
																        └── 生产部署
																		10.3 审批单设计
																		审批不是一张空白通行证，而是绑定参数的一次性决定
																		
																		字段	示例
																		TARGET	payments-service / production
																		PARAMS	PR #482 → main（参数已绑定）
																		EVIDENCE	18 tests · diff 42 lines · scan passed
																		WHY / COST	修复重复入账 · 预计 3min
																		ROLLBACK	revert commit + feature flag
																		操作选项：Allow once | Edit | Reject
																		
																		10.4 Human Override
																		随时暂停：Human 可随时 PAUSE 运行中任务
																		
																		随时接管：Human 可接管 Agent 的执行权限
																		
																		审计覆盖：所有人工干预行为记录在证据链中
																		
																		11. 故障处置与恢复机制
																		11.1 核心原则
																		先止血，再保留现场
																		
																		Kill 是分支，不是固定步骤
																		
																		11.2 异常处置流程
																		text
																		ANOMALY (上传/越权/循环/危险工具)
																		    ↓
																			INCIDENT CONTROLLER
																			    │
																				    ├── 01 · REVOKE (撤销身份)
																					    ├── 02 · BLOCK (阻断网络 + 新工具)
																						    ├── 03 · PAUSE (暂停/冻结运行时)
																							    └── 04 · PRESERVE (保存现场)
																								    ↓
																									    决策分支
																										    ├── 疑似外传 → 先断网 → TERMINATE
																											    ├── 普通逻辑错误 → PAUSE → 人工接管
																												    └── Kill 是分支，不是固定步骤
																													    ↓
																														RECOVER (基线/检查点/放弃)
																														    ↓
																															CLEAN UP (状态/缓存/身份)
																															    ↓
																																LEARN (策略/回归测试)
																																11.3 处置等级对比
																																动作	目的	可逆性	适用场景
																																PAUSE	冻结现场，保留调查可能	可逆	逻辑错误、可疑行为
																																BLOCK	阻断网络和新工具调用	可逆	数据外传风险
																																REVOKE	撤销所有身份凭证	部分可逆	凭证泄露
																																TERMINATE	彻底终止实例	不可逆	确认攻击/严重违规
																																12. 多租户规模化设计
																																12.1 核心原则
																																共享只读镜像与缓存，不共享任务身份、工作区和可写状态
																																
																																12.2 Warm Pool 架构
																																text
																																SandboxTemplate (runtime + image + policy defaults)
																																    ↓
																																	WARM POOL (pre-created · unattached)
																																	    ├── Sandbox READY
																																		    ├── Sandbox READY
																																			    └── Sandbox READY
																																				    ↓
																																					Task Claim A (tenant-a / exclusive) → 运行
																																					Task Claim B (tenant-b / exclusive) → 运行
																																					Task Claim C → QUOTA EXCEEDED → 排队/拒绝
																																					12.3 Quota 控制维度
																																					维度	说明
																																					concurrency	同时运行任务数
																																					cpu / memory	资源配额
																																					time / tokens	执行时长 / Token 消耗
																																					network / cost	网络流量 / 费用预算
																																					13. 控制画像：不同角色的权限模板
																																					13.1 核心原则
																																					不同 Agent，不共用万能权限
																																					
																																					13.2 四种 Profile
																																					Profile	Workspace	Egress	Identity	High Effect	Release
																																					CODING	repo copy + build, private branch	repo + packages	task repo token	merge / deploy	diff + tests
																																					DATA	read-only snapshot	approved datasets	row-level scope	export / writeback	DLP + review
																																					BROWSE	isolated profile	site allowlist	delegated session	send / submit	preview + approve
																																					COMMERCE	transaction state	merchant + bank	user-bound token	pay / refund	amount-bound gate
																																					14. 审计与可重建证据链
																																					14.1 核心原则
																																					记录不够，还要能重建
																																					
																																					14.2 证据四阶段
																																					阶段	内容	说明
																																					01 · GOAL + AUTH	目标 + 授权	WHO · SCOPE
																																					02 · SPEC + VERSION	TaskSpec + 版本	SPEC · VERSION
																																					03 · EXECUTION	执行证据	TOOL · FILE · NET
																																					04 · RELEASE	审批 + 发布	APPROVAL · HASH
																																					14.3 重建能力
																																					RECONSTRUCT：完整重建"谁 · 做什么 · 依据 · 改什么 · 谁放行"
																																					
																																					14.4 安全审计账本
																																					主体 · 参数 · 决策 · 哈希 —— 全部记录
																																					
																																					证据在 Sandbox 之外 · Agent 不可改写 —— 防止 Agent 篡改审计日志
																																					
																																					14.5 可观测性三支柱
																																					TRACE · METRIC · LOG —— 性能/错误/调用链全覆盖
																																					
																																					15. 成熟度模型与建设路线
																																					15.1 五阶段路线图
																																					等级	名称	核心能力	说明
																																					L0	直接工具调用	developer identity, open network	起点——无防护，最危险
																																					L1	隔离运行	container/runtime, resource limits	只是起点——基础隔离远不够
																																					L2	边界控制	private workspace, egress + task identity, typed tools	网络/身份/工具受控
																																					L3	策略运营	policy engine, approval + lifecycle, external audit	策略引擎驱动，支持审批
																																					L4	可恢复运营	evidence + release gate, pause/resume/takeover, incident response, warm pool + quota	生产级闭环
																																					15.2 优先级排序
																																					不可逆动作 · 长期密钥 · 开放网络 · 直接发布
																																					
																																					这四个是最高优先级风险，必须在 L0→L1 阶段优先封堵。
																																					
																																					附录：Episode 2 + Episode 3 总览对比
																																					维度	Episode 2（架构基础）	Episode 3（运营体系）
																																					核心问题	如何安全隔离执行？	如何生产级运营？
																																					答案	控制面 + 执行面 + 证据面分离	状态机 + 故障恢复 + 审批 + 审计
																																					关键产出	Artifact Gate 独立验证	可恢复的运营闭环
																																					最终目标	防止恶意行为	支持故障、审计、扩容、合规
																																					结束语
																																					运行时回答"在哪里跑"，控制系统回答"什么能成为现实"
																																					
																																					这套架构的本质是：让 Agent 在边界内自由行动，但任何影响真实世界的行为，都必须经过独立验证和策略审批。
																																					
																																					从 L0 到 L4 的演进路径清晰：先隔离，再控制边界，再引入策略，最后实现可恢复运营——每一步都对应可度量的安全提升。
																																					
																																					最终公式：可信 Agent = 有能力的模型 + 有边界的执行 + 可恢复的运营系统
																																					
																																					本回答由 AI 生成，内容仅供参考，请仔细甄别
																																				
