Inline comments:
In `@AGENTS.md`:
- Around line 18-22: Update the build command list in AGENTS.md to include
building the agentpvm binary from cmd/agentpvm, matching the documented
./agentpvm invocation and ensuring it exists in a clean checkout before the
commands at lines 28-30 run.

In `@cmd/agentpvm/main.go`:
- Around line 35-36: 统一校验 CPU 参数：在 cmd/agentpvm/main.go 的 agentpvm
run、cmd/umlctl/main.go 的 umlctl start，以及 internal/api/e2b_server.go 的
/api/containers/start 入口拒绝小于 0 的值；同时在 cgroup.Setup 中校验 CPU 最大上限后再计算
quota，避免溢出或无效值绕过 cpu.max 限制。上述三个入口均需按对应参数解析流程返回明确错误。

In `@internal/config/config.go`:
- Around line 20-38: 将 ParseMemory 改为返回解析值和错误，拒绝空字符串、负数及未支持的单位（如
GiB、T），不要再将未知单位静默当作字节处理；在单位换算前增加溢出校验。更新所有 CLI/API 解析入口及 Setup
的调用方，传播并报告错误，确保无效或溢出规格不会继续配置 memory.max。

In `@internal/container/manager.go`:
- Around line 106-109: Update Launcher.Start so cgroup.NewManager and cg.Setup
complete before cmd.Start, ensuring the child never runs outside the requested
limits. When cgroup creation, PID binding, or CPU/memory controller setup fails,
clean up the cgroup, terminate the process if it was started, and return the
error without recording it as running or reporting successful startup; preserve
normal startup when no setup error occurs.
- Around line 106-107: Validate container IDs before passing them to
cgroup.Manager.Setup, enforcing a strict allowlist that permits only the
expected identifier characters and rejects traversal or absolute-path forms.
Apply the same validation to the /containers/start, agentpvm run --name, and
agentpvm cgroup freeze/thaw flows, using their existing ID-handling symbols so
every cgroup path remains within the configured cgroup root.

In `@plan.md`:
- Around line 150-160: 更新 plan.md 中 UML 说明及相关 vhost 路径描述，明确当前实现使用 vhost-user 与
qemu-storage-daemon 导出 Unix socket，避免将 I/O 归因于 host kernel；若保留 “vhost-like
backend/host kernel”，标注其为未来方向。
- Around line 75-96: 更新“核心收益”示例，移除 virtio 批处理可减少或消除 syscall
的表述，改为强调减少通知、边界穿越及批量处理开销；同时避免将多个 packet 或 io_uring SQE 描述为必然合并成一次 I/O，并明确实际
syscall 数量取决于 guest 驱动和 backend 处理方式。

---

Nitpick comments:
In `@internal/api/e2b_server.go`:
- Around line 89-98: Run gofmt or goimports on the Go file containing the
ContainerConfig literal in the request handler, ensuring the Memory,
MemoryBytes, and CPU fields are consistently tab-aligned with the other fields.
Do not change the configuration values or behavior.

In `@internal/config/config.go`:
- Around line 20-38: Remove the duplicate memory-parsing implementations in
cmd/agentpvm/main.go, cmd/umlctl/main.go, and internal/api/e2b_server.go, and
update their callers to reuse config.ParseMemory. Preserve the existing parsing
behavior while ensuring all memory-unit handling is centralized in ParseMemory.


python error:

+ python3 test_script.py
Traceback (most recent call last):
  File "/usr/lib/python3/dist-packages/urllib3/connection.py", line 203, in _new_conn
      sock = connection.create_connection(
	             ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
				   File "/usr/lib/python3/dist-packages/urllib3/util/connection.py", line 85, in create_connection
				       raise err
					     File "/usr/lib/python3/dist-packages/urllib3/util/connection.py", line 73, in create_connection
						     sock.connect(sa)
							 ConnectionRefusedError: [Errno 111] Connection refused
							 
							 The above exception was the direct cause of the following exception:
							 
							 Traceback (most recent call last):
							   File "/usr/lib/python3/dist-packages/urllib3/connectionpool.py", line 791, in urlopen
							       response = self._make_request(
								                  ^^^^^^^^^^^^^^^^^^^
												    File "/usr/lib/python3/dist-packages/urllib3/connectionpool.py", line 497, in _make_request
													    conn.request(
														  File "/usr/lib/python3/dist-packages/urllib3/connection.py", line 395, in request
														      self.endheaders()
															    File "/usr/lib/python3.12/http/client.py", line 1360, in endheaders
																    self._send_output(message_body, encode_chunked=encode_chunked)
																	  File "/usr/lib/python3.12/http/client.py", line 1120, in _send_output
																	      self.send(msg)
																		    File "/usr/lib/python3.12/http/client.py", line 1064, in send
																			    self.connect()
																				  File "/usr/lib/python3/dist-packages/urllib3/connection.py", line 243, in connect
																				      self.sock = self._new_conn()
																					                  ^^^^^^^^^^^^^^^^
																									    File "/usr/lib/python3/dist-packages/urllib3/connection.py", line 218, in _new_conn
																										    raise NewConnectionError(
																											urllib3.exceptions.NewConnectionError: <urllib3.connection.HTTPConnection object at 0x7f43db0b87d0>: Failed to establish a new connection: [Errno 111] Connection refused
																											
																											The above exception was the direct cause of the following exception:
																											
																											Traceback (most recent call last):
																											  File "/usr/lib/python3/dist-packages/requests/adapters.py", line 486, in send
																											      resp = conn.urlopen(
																												             ^^^^^^^^^^^^^
																															   File "/usr/lib/python3/dist-packages/urllib3/connectionpool.py", line 845, in urlopen
																															       retries = retries.increment(
																																                 ^^^^^^^^^^^^^^^^^^
																																				   File "/usr/lib/python3/dist-packages/urllib3/util/retry.py", line 517, in increment
																																				       raise MaxRetryError(_pool, url, reason) from reason  # type: ignore[arg-type]
																																					       ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
																																						   urllib3.exceptions.MaxRetryError: HTTPConnectionPool(host='127.0.0.1', port=8080): Max retries exceeded with url: /exec (Caused by NewConnectionError('<urllib3.connection.HTTPConnection object at 0x7f43db0b87d0>: Failed to establish a new connection: [Errno 111] Connection refused'))
																																						   
																																						   During handling of the above exception, another exception occurred:
																																						   
																																						   Traceback (most recent call last):
																																						     File "/home/runner/work/pvm/pvm/test_script.py", line 4, in <module>
																																							     res = requests.post("http://127.0.0.1:8080/exec", json={"cmd": "apk update && apk add python3"})
																																								           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
																																										     File "/usr/lib/python3/dist-packages/requests/api.py", line 115, in post
																																											     return request("post", url, data=data, json=json, **kwargs)
																																												            ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
																																															  File "/usr/lib/python3/dist-packages/requests/api.py", line 59, in request
																																															      return session.request(method=method, url=url, **kwargs)
																																																             ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
																																																			   File "/usr/lib/python3/dist-packages/requests/sessions.py", line 589, in request
																																																			       resp = self.send(prep, **send_kwargs)
																																																				              ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
																																																							    File "/usr/lib/python3/dist-packages/requests/sessions.py", line 703, in send
																																																								    r = adapter.send(request, **kwargs)
																																																									        ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
																																																											  File "/usr/lib/python3/dist-packages/requests/adapters.py", line 519, in send
																																																											      raise ConnectionError(e, request=request)
																																																												  requests.exceptions.ConnectionError: HTTPConnectionPool(host='127.0.0.1', port=8080): Max retries exceeded with url: /exec (Caused by NewConnectionError('<urllib3.connection.HTTPConnection object at 0x7f43db0b87d0>: Failed to establish a new connection: [Errno 111] Connection refused'))
																																																												  scripts/test_pkg_install.sh failed but continuing...
																																																												  Running additional test suites serially...))))))
