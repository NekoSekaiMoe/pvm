先说结论：

UML 的 syscall 开销可以通过减少 guest↔host 边界切换、使用更高层的 virtio 后端、批量化 I/O 等方式缓解，但无法像 KVM 那样彻底消除，因为 UML 的架构决定了 guest kernel 本身运行在 host userspace 中。

具体有几个方向：

1. 使用 skas0 / skas3 模式优化

UML 历史上有两种运行模式：

TT（tracing thread）

早期模式：

guest process
      |
ptrace
      |
host kernel

性能很差。

SKAS（Separate Kernel Address Space）

现代 UML：

UML kernel process
        |
host mmap / signals
        |
host kernel

减少 ptrace 依赖。

现在基本都用 SKAS。

如果你看到：

CONFIG_MODE_SKAS=y

就是这个方向。

2. 使用 virtio-uml（你提到的）

这是最重要的。

传统 UML：

例如网络：

guest app
 ↓
 guest syscall
  ↓
  UML kernel
   ↓
   UML eth driver
    ↓
	tuntap
	 ↓
	 host kernel
	 
	 virtio-uml：
	 
	 guest app
	  ↓
	  UML kernel
	   ↓
	   virtio-net
	    ↓
		virtqueue
		 ↓
		 backend
		 
		 核心收益：
		 
		 减少频繁的小 syscall。
		 
		 例如：
		 
		 传统：
		 
		 send()
		 send()
		 send()
		 send()
		 
		 可能每次都穿越边界。
		 
		 virtio：
		 
		 多个 packet
		  ↓
		  一次提交 queue
		   ↓
		   backend 批量处理
		   3. io_uring 后端
		   
		   这个其实非常适合 UML。
		   
		   传统 block：
		   
		   guest
		    |
			virtio-blk
			 |
			 host write()
			  |
			  filesystem
			  
			  大量 syscall。
			  
			  如果 backend：
			  
			  UML
			   |
			   virtio-uml
			    |
				io_uring
				 |
				 block device
				 
				 可以：
				 
				 批量提交
				 异步执行
				 减少 syscall 次数
				 
				 类似：
				 
				 1000 次 write()
				 
				 变成：
				 
				 1 次 io_uring submit
				 4. vhost 思路
				 
				 KVM 里：
				 
				 guest
				  |
				  virtio
				   |
				   vhost kernel
				    |
					hardware
					
					性能很好。
					
					UML 可以借鉴：
					
					UML
					 |
					 virtio-uml
					  |
					  vhost-like backend
					   |
					   host kernel
					   
					   把数据处理尽量放到 host kernel。
					   
					   5. 减少 guest syscall 数量
					   
					   这个是软件层面的。
					   
					   例如：
					   
					   不好的：
					   read()
					   read()
					   read()
					   read()
					   好的：
					   readv()
					   splice()
					   mmap()
					   
					   UML 本身无法改变：
					   
					   但是运行在里面的软件可以优化。
					   
					   6. hostfs 少用
					   
					   UML 有个方便功能：
					   
					   hostfs
					   
					   直接访问宿主文件。
					   
					   但是：
					   
					   guest filesystem
					         |
							 hostfs
							       |
								   host filesystem
								   
								   每次文件操作都会经过额外路径。
								   
								   更好的：
								   
								   virtio-blk
								    |
									ext4/xfs
									
									让 UML 自己管理 filesystem。
									
									性能排序大概：
									
									对于 I/O：
									
									virtio-uml + io_uring
									        ↑
											virtio-uml
											        ↑
													UML block/net
													        ↑
															hostfs / slirp
															还有一个容易忽略的问题：UML syscall 本身
															
															用户程序调用：
															
															open()
															
															流程：
															
															application
															    |
																UML syscall handler
																    |
																	UML kernel
																	    |
																		host syscall
																		    |
																			host kernel
																			
																			这个双 kernel syscall 是 UML 固有成本。
																			
																			理论上可以优化：
																			
																			syscall batching
																			vDSO
																			减少 timer tick
																			io_uring
																			
																			但不能完全消除。
																			
																			所以如果设计一个现代 UML 平台，我觉得比较合理的架构应该是：
																			
																			             Go manager
																						                   |
																										           virtio-uml devices
																												                     |
																																	         +---------+---------+
																																			         |                   |
																																					     virtio-blk          virtio-net
																																						         |                   |
																																								     io_uring             tap/vhost
																																									         |
																																											    host storage
																																												
																																												这种情况下：
																																												
																																												CPU 密集：接近原生
																																												网络：接近轻量 VM
																																												磁盘：可以接近 KVM virtio
																																												syscall-heavy：仍有损耗，但比传统 UML 小很多
																																												
																																												实际上这也是为什么 virtio-uml 这个方向比传统 UML 更有价值：它不是试图让 UML 变成 KVM，而是把 UML 最大的问题（I/O 边界）尽量消掉。你之前想做的「无硬件虚拟化轻量 VM」路线，用它作为底层比从零写 syscall 隔离要现实很多。
