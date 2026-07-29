---- Pkg Test Console Output ----
+ sudo cat /var/lib/uml-container/containers/pkg-test/logs/console.log
+ cat pkg_agentpvm.log
flag provided but not defined: -tap
Usage of run:
  -cpu int
      	CPU limit (0 means no limit)
		  -init string
		      	Init script path (default "/init.sh")
				  -kernel string
				      	Kernel path (default "./bin/linux")
						  -memory string
						      	Container memory (default "512M")
								  -name string
								      	Sandbox name (default "agent1")
										  -native-vhost
										      	Use experimental native Go vhost-user backend
												  -native-vhost-net
												      	Use native Go vhost-user-net backend for networking
														  -net-tap string
														      	Network tap device to use
																  -rootfs string
																      	Root filesystem (default "rootfs.img")
																		  -vhost
																		      	Use vhost-user-blk for storage (default true)
																				+ echo '❌ Package installation test failed or timed out.'
																				+ sudo ./bin/umlctl network rm pvm_br0
																				❌ Package installation test failed or timed out.
																				Error deleting network: failed to delete bridge pvm_br0: exit status 1
+ sudo ip link delete tap_pkg
+ exit 1
