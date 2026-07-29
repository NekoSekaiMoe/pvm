下面是一份偏工程设计文档风格的实现方案。我会按照你当前确定的方向：

Go 编写 runtime
UML 作为 kernel backend
不依赖 CPU 虚拟化
每个实例独立 Linux kernel
支持完整 userspace（systemd）
第一阶段 ext4 image
后续 overlayfs
host cgroup 管理资源

来设计。

UML Container Runtime 设计文档

版本：v0.1 Draft

1. 项目定位
1.1 目标

实现一个轻量级 Linux 容器运行时：

特点：

不依赖 KVM / VT-x / AMD-V
每个容器拥有独立 Linux kernel
支持完整 Linux userspace
支持 systemd 作为 PID 1
支持持久化 filesystem
使用 Linux cgroup 管理资源
使用 Go 实现管理层

定位：

LXC 的管理体验
+
UML 的独立 kernel
+
microVM 的隔离模型
2. 总体架构
2.1 分层结构
                    CLI
					
					                     |
										                      |
															  
															                Go Runtime Daemon
																			
																			                     |
																								        +-------------+-------------+
																										
																										       |                           |
																											   
																											    Container Manager          Resource Manager
																												
																												       |                           |
																													   
																													          |                         cgroup v2
																															         |
																																	        |
																																			
																																			    UML Manager
																																				
																																				       |
																																					          |
																																							         +----------------+
																																									 
																																									                         |
																																															 
																																															                   UML Kernel
																																																			   
																																																			                           |
																																																									   
																																																									                     rootfs.ext4
																																																														 
																																																														                         |
																																																																				 
																																																																				                    systemd
																																																																									3. 核心组件设计
																																																																									
																																																																									目录：
																																																																									
																																																																									uml-container/
																																																																									
																																																																									├── cmd/
																																																																									│   ├── umlctl/
																																																																									│   └── umld/
																																																																									│
																																																																									├── internal/
																																																																									│
																																																																									│   ├── container/
																																																																									│   │    ├── create.go
																																																																									│   │    ├── start.go
																																																																									│   │    ├── stop.go
																																																																									│   │    └── state.go
																																																																									│   │
																																																																									│   ├── uml/
																																																																									│   │    ├── launcher.go
																																																																									│   │    ├── kernel.go
																																																																									│   │    └── console.go
																																																																									│   │
																																																																									│   ├── filesystem/
																																																																									│   │    ├── ext4.go
																																																																									│   │    └── overlay.go
																																																																									│   │
																																																																									│   ├── cgroup/
																																																																									│   │    └── manager.go
																																																																									│   │
																																																																									│   ├── network/
																																																																									│   │    └── tap.go
																																																																									│   │
																																																																									│   └── config/
																																																																									│        └── config.go
																																																																									│
																																																																									├── images/
																																																																									│
																																																																									└── containers/
																																																																									4. Container 数据结构
																																																																									
																																																																									每个 container：
																																																																									
																																																																									/var/lib/uml-container/
																																																																									
																																																																									container-id/
																																																																									
																																																																									├── config.json
																																																																									
																																																																									├── rootfs.img
																																																																									
																																																																									├── kernel
																																																																									
																																																																									├── state
																																																																									
																																																																									├── console.sock
																																																																									
																																																																									└── logs/
																																																																									
																																																																									config:
																																																																									
																																																																									{
																																																																									    "name":"test",
																																																																										
																																																																										    "kernel":
																																																																											    "/usr/lib/uml/linux",
																																																																												
																																																																												    "rootfs":
																																																																													    "rootfs.img",
																																																																														
																																																																														    "memory":
																																																																															    "512M",
																																																																																
																																																																																    "cpu":
																																																																																	    2,
																																																																																		
																																																																																		    "init":
																																																																																			    "/sbin/init"
																																																																																				}
																																																																																				5. Kernel 方案
																																																																																				5.1 UML 编译
																																																																																				
																																																																																				目标：
																																																																																				
																																																																																				ARCH=um
																																																																																				
																																																																																				配置：
																																																																																				
																																																																																				基础：
																																																																																				
																																																																																				CONFIG_UML=y
																																																																																				
																																																																																				CONFIG_BLK_DEV_UBD=y
																																																																																				
																																																																																				CONFIG_EXT4_FS=y
																																																																																				
																																																																																				CONFIG_TMPFS=y
																																																																																				
																																																																																				CONFIG_PROC_FS=y
																																																																																				
																																																																																				CONFIG_SYSFS=y
																																																																																				systemd 必需
																																																																																				
																																																																																				追加：
																																																																																				
																																																																																				CONFIG_NAMESPACES=y
																																																																																				
																																																																																				CONFIG_PID_NS=y
																																																																																				
																																																																																				CONFIG_NET_NS=y
																																																																																				
																																																																																				
																																																																																				CONFIG_CGROUPS=y
																																																																																				
																																																																																				CONFIG_CGROUP_FREEZER=y
																																																																																				
																																																																																				CONFIG_CGROUP_SCHED=y
																																																																																				
																																																																																				
																																																																																				CONFIG_DEVTMPFS=y
																																																																																				
																																																																																				CONFIG_DEVTMPFS_MOUNT=y
																																																																																				
																																																																																				
																																																																																				CONFIG_UNIX=y
																																																																																				编译
																																																																																				make ARCH=um defconfig
																																																																																				
																																																																																				make ARCH=um menuconfig
																																																																																				
																																																																																				make ARCH=um -j$(nproc)
																																																																																				
																																																																																				输出：
																																																																																				
																																																																																				linux
																																																																																				6. Root filesystem
																																																																																				第一阶段：ext4 image
																																																																																				
																																																																																				结构：
																																																																																				
																																																																																				rootfs.img
																																																																																				
																																																																																				/
																																																																																				
																																																																																				├── bin
																																																																																				
																																																																																				├── etc
																																																																																				
																																																																																				├── usr
																																																																																				
																																																																																				├── var
																																																																																				
																																																																																				├── lib
																																																																																				
																																																																																				└── sbin/init
																																																																																				
																																																																																				创建：
																																																																																				
																																																																																				dd \
																																																																																				 if=/dev/zero \
																																																																																				  of=rootfs.img \
																																																																																				   bs=1M \
																																																																																				    count=2048
																																																																																					
																																																																																					格式化：
																																																																																					
																																																																																					mkfs.ext4 rootfs.img
																																																																																					
																																																																																					挂载：
																																																																																					
																																																																																					mount -o loop rootfs.img /mnt/rootfs
																																																																																					
																																																																																					安装系统：
																																																																																					
																																																																																					例如：
																																																																																					
																																																																																					debootstrap
																																																																																					
																																																																																					或者：
																																																																																					
																																																																																					alpine minirootfs
																																																																																					7. 启动流程
																																																																																					container start
																																																																																					
																																																																																					流程：
																																																																																					
																																																																																					umlctl start test
																																																																																					
																																																																																					        |
																																																																																							
																																																																																							读取 config
																																																																																							
																																																																																							        |
																																																																																									
																																																																																									创建 cgroup
																																																																																									
																																																																																									        |
																																																																																											
																																																																																											启动 UML
																																																																																											
																																																																																											        |
																																																																																													
																																																																																													等待 console
																																																																																													
																																																																																													        |
																																																																																															
																																																																																															systemd 启动完成
																																																																																															
																																																																																															实际命令：
																																																																																															
																																																																																															linux \
																																																																																															 root=/dev/ubda \
																																																																																															  ubd0=rootfs.img \
																																																																																															   init=/sbin/init \
																																																																																															    mem=512M
																																																																																																
																																																																																																Go：
																																																																																																
																																																																																																cmd := exec.Command(
																																																																																																    "./linux",
																																																																																																	
																																																																																																	    "ubd0=rootfs.img",
																																																																																																		
																																																																																																		    "root=/dev/ubda",
																																																																																																			
																																																																																																			    "init=/sbin/init",
																																																																																																				)
																																																																																																				8. 生命周期管理
																																																																																																				状态
																																																																																																				created
																																																																																																				
																																																																																																				  |
																																																																																																				  
																																																																																																				  stopped
																																																																																																				  
																																																																																																				    |
																																																																																																					
																																																																																																					running
																																																																																																					
																																																																																																					  |
																																																																																																					  
																																																																																																					  stopping
																																																																																																					  
																																																																																																					    |
																																																																																																						
																																																																																																						destroyed
																																																																																																						
																																																																																																						state 文件：
																																																																																																						
																																																																																																						{
																																																																																																						 "status":"running",
																																																																																																						 
																																																																																																						  "pid":12345,
																																																																																																						  
																																																																																																						   "started":"2026-07-29"
																																																																																																						   }
																																																																																																						   9. cgroup 设计
																																																																																																						   
																																																																																																						   由于 UML 是一个 host process：
																																																																																																						   
																																																																																																						   结构：
																																																																																																						   
																																																																																																						   /sys/fs/cgroup/
																																																																																																						   
																																																																																																						   uml/
																																																																																																						   
																																																																																																						    └── container-id/
																																																																																																							
																																																																																																							        memory.max
																																																																																																									
																																																																																																									        cpu.max
																																																																																																											
																																																																																																											        io.max
																																																																																																													
																																																																																																													例如：
																																																																																																													
																																																																																																													限制：
																																																																																																													
																																																																																																													512MB：
																																																																																																													
																																																																																																													memory.max=536870912
																																																																																																													
																																																																																																													CPU：
																																																																																																													
																																																																																																													cpu.max="200000 100000"
																																																																																																													
																																																																																																													启动：
																																																																																																													
																																																																																																													create cgroup
																																																																																																													
																																																																																																													↓
																																																																																																													
																																																																																																													fork UML
																																																																																																													
																																																																																																													↓
																																																																																																													
																																																																																																													move pid into cgroup
																																																																																																													10. Console
																																																																																																													
																																																																																																													第一阶段：
																																																																																																													
																																																																																																													使用 UML 自带 console：
																																																																																																													
																																																																																																													参数：
																																																																																																													
																																																																																																													con0=fd:0,fd:1
																																																																																																													
																																																																																																													或者：
																																																																																																													
																																																																																																													con=pts
																																																																																																													
																																																																																																													之后：
																																																																																																													
																																																																																																													实现：
																																																																																																													
																																																																																																													unix socket
																																																																																																													
																																																																																																													↓
																																																																																																													
																																																																																																													console attach
																																																																																																													
																																																																																																													类似：
																																																																																																													
																																																																																																													docker attach
																																																																																																													11. 网络设计
																																																																																																													
																																																																																																													第一阶段：
																																																																																																													
																																																																																																													不实现热插拔。
																																																																																																													
																																																																																																													只提供：
																																																																																																													
																																																																																																													启动时 TAP。
																																																																																																													
																																																																																																													结构：
																																																																																																													
																																																																																																													UML
																																																																																																													
																																																																																																													eth0
																																																																																																													
																																																																																																													 |
																																																																																																													 
																																																																																																													 TAP
																																																																																																													 
																																																																																																													  |
																																																																																																													  
																																																																																																													  bridge
																																																																																																													  
																																																																																																													   |
																																																																																																													   
																																																																																																													   host network
																																																																																																													   
																																																																																																													   参数：
																																																																																																													   
																																																																																																													   eth0=tuntap,tap0
																																																																																																													   
																																																																																																													   Go:
																																																																																																													   
																																																																																																													   创建：
																																																																																																													   
																																																																																																													   /dev/net/tun
																																																																																																													   
																																																																																																													   配置：
																																																																																																													   
																																																																																																													   ip link add
																																																																																																													   bridge
																																																																																																													   12. Overlayfs 设计（第二阶段）
																																																																																																													   
																																																																																																													   目标：
																																																																																																													   
																																																																																																													   类似 Docker image layer。
																																																																																																													   
																																																																																																													   结构：
																																																																																																													   
																																																																																																													   images/
																																																																																																													   
																																																																																																													   ubuntu-base.img
																																																																																																													   
																																																																																																													   
																																																																																																													   containers/
																																																																																																													   
																																																																																																													   test/
																																																																																																													   
																																																																																																													    upper/
																																																																																																														
																																																																																																														 work/
																																																																																																														 
																																																																																																														 
																																																																																																														 启动：
																																																																																																														 
																																																																																																														 overlayfs
																																																																																																														 
																																																																																																														 lowerdir=base
																																																																																																														 
																																																																																																														 upperdir=container
																																																																																																														 
																																																																																																														 merged=rootfs
																																																																																																														 
																																																																																																														 注意：
																																																																																																														 
																																																																																																														 overlay 必须运行在 UML guest kernel 内。
																																																																																																														 
																																																																																																														 13. 镜像管理
																																																																																																														 
																																																																																																														 未来：
																																																																																																														 
																																																																																																														 umlctl image create
																																																																																																														 
																																																																																																														 umlctl image import
																																																																																																														 
																																																																																																														 umlctl image snapshot
																																																																																																														 
																																																																																																														 格式：
																																																																																																														 
																																																																																																														 image/
																																																																																																														 
																																																																																																														 ├── kernel
																																																																																																														 
																																																																																																														 ├── rootfs.img
																																																																																																														 
																																																																																																														 └── metadata.json
																																																																																																														 14. 与 OCI 的兼容
																																																																																																														 
																																																																																																														 可以实现：
																																																																																																														 
																																																																																																														 OCI runtime interface
																																																																																																														 
																																																																																																														 结构：
																																																																																																														 
																																																																																																														 containerd
																																																																																																														 
																																																																																																														     |
																																																																																																															 
																																																																																																															  uml-runtime
																																																																																																															  
																																																																																																															      |
																																																																																																																  
																																																																																																																   UML kernel
																																																																																																																   
																																																																																																																   实现：
																																																																																																																   
																																																																																																																   create
																																																																																																																   
																																																																																																																   start
																																																																																																																   
																																																																																																																   kill
																																																																																																																   
																																																																																																																   delete
																																																																																																																   
																																																																																																																   这样可以接入：
																																																																																																																   
																																																																																																																   Docker
																																																																																																																   Kubernetes（理论）
																																																																																																																   nerdctl
																																																																																																																   15. 第一阶段 MVP
																																																																																																																   
																																																																																																																   目标：
																																																																																																																   
																																																																																																																   一个月版本：
																																																																																																																   
																																																																																																																   支持：
																																																																																																																   
																																																																																																																   ✅ UML kernel 启动
																																																																																																																   
																																																																																																																   ✅ ext4 rootfs
																																																																																																																   
																																																																																																																   ✅ systemd
																																																																																																																   
																																																																																																																   ✅ start/stop
																																																																																																																   
																																																																																																																   ✅ cgroup v2
																																																																																																																   
																																																																																																																   ✅ console attach
																																																																																																																   
																																																																																																																   不做：
																																																																																																																   
																																																																																																																   ❌ overlay
																																																																																																																   
																																																																																																																   ❌ USB
																																																																																																																   
																																																																																																																   ❌ 热插拔
																																																																																																																   
																																																																																																																   ❌ OCI
																																																																																																																   
																																																																																																																   16. 后续路线
																																																																																																																   v0.2
																																																																																																																   
																																																																																																																   加入：
																																																																																																																   
																																																																																																																   overlayfs
																																																																																																																   snapshot
																																																																																																																   image 管理
																																																																																																																   v0.3
																																																																																																																   
																																																																																																																   加入：
																																																																																																																   
																																																																																																																   TAP 网络
																																																																																																																   DNS
																																																																																																																   port forwarding
																																																																																																																   v0.4
																																																																																																																   
																																																																																																																   加入：
																																																																																																																   
																																																																																																																   OCI runtime
																																																																																																																   containerd 集成
																																																																																																																   17. 关键风险
																																																																																																																   1. UML 维护状态
																																																																																																																   
																																																																																																																   风险：
																																																																																																																   
																																																																																																																   新 kernel 兼容性
																																																																																																																   文档较少
																																																																																																																   2. systemd 支持
																																																																																																																   
																																																																																																																   需要：
																																																																																																																   
																																																																																																																   正确 kernel config。
																																																																																																																   
																																																																																																																   否则：
																																																																																																																   
																																																																																																																   Failed to mount cgroup
																																																																																																																   3. 性能
																																																																																																																   
																																																																																																																   主要瓶颈：
																																																																																																																   
																																																																																																																   syscall
																																																																																																																   fork
																																																																																																																   IO flush
																																																																																																																   
																																																																																																																   但是：
																																																																																																																   
																																																																																																																   普通服务：
																																																																																																																   
																																																																																																																   可接受。
																																																																																																																   
																																																																																																																   总结
																																																																																																																   
																																																																																																																   最终架构：
																																																																																																																   
																																																																																																																                   Go Runtime
																																																																																																																				   
																																																																																																																				                        |
																																																																																																																										
																																																																																																																										              cgroup manager
																																																																																																																													  
																																																																																																																													                       |
																																																																																																																																		   
																																																																																																																																		                 UML launcher
																																																																																																																																						 
																																																																																																																																						                      |
																																																																																																																																											  
																																																																																																																																											            +------------------+
																																																																																																																																														
																																																																																																																																														          |  UML Linux       |
																																																																																																																																																  
																																																																																																																																																            |                  |
																																																																																																																																																			
																																																																																																																																																			          |  systemd         |
																																																																																																																																																					  
																																																																																																																																																					            |  services        |
																																																																																																																																																								
																																																																																																																																																								          |                  |
																																																																																																																																																										  
																																																																																																																																																										            |  ext4 rootfs.img |
																																																																																																																																																													
																																																																																																																																																													          +------------------+
																																																																																																																																																															  
																																																																																																																																																															  这个方案本质是：
																																																																																																																																																															  
																																																																																																																																																															  没有硬件虚拟化的 microVM，但保留容器管理方式。
																																																																																																																																																															  
																																																																																																																																																															  第一版不要追求 overlay、OCI、热插拔，先证明：
																																																																																																																																																															  
																																																																																																																																																															  “一个 Go 程序能可靠地创建、启动、停止一个拥有独立 Linux kernel 和 systemd 的实例。”
																																																																																																																																																															  
																																																																																																																																																															  这一步完成，后面的功能都是管理层扩展
																																																																																																																																																															  
