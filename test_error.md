+ sudo tee mnt_pkg/init.sh
#!/bin/sh
mount -t proc proc /proc
mount -t sysfs sys /sys
# Assuming eth0 is set up by pvm, we can just bring it up
ip link set eth0 up || true
udhcpc -i eth0 || true

echo "Attempting to install python3..."
apk update && apk add python3 && echo "PKG_INSTALL_SUCCESS"

poweroff -f
+ sudo chmod +x mnt_pkg/init.sh
+ trap - EXIT
+ sudo umount mnt_pkg
+ CONSOLE_LOG=/var/lib/uml-container/containers/pkg-test/logs/console.log
+ sudo rm -f /var/lib/uml-container/containers/pkg-test/logs/console.log
+ sudo ./agentpvm run -name pkg-test -rootfs pkg_rootfs.img -kernel ./bin/linux -init /init.sh -vhost=false
+ echo '---- Pkg Test Console Output ----'
---- Pkg Test Console Output ----
+ sudo cat /var/lib/uml-container/containers/pkg-test/logs/console.log
Core dump limits :
	soft - 0
		hard - 0
		Checking that ptrace can change system call numbers...OK
		Checking syscall emulation patch for ptrace...OK
		Checking advanced syscall emulation patch for ptrace...OK
		Checking environment variables for a tempdir...none found
		Checking if /dev/shm is on tmpfs...OK
		Checking PROT_EXEC mmap in /dev/shm...OK
		Adding 377004032 bytes to physical memory to account for exec-shield gap
		+ sudo grep -q PKG_INSTALL_SUCCESS /var/lib/uml-container/containers/pkg-test/logs/console.log
		+ echo '❌ Package installation test failed.'
		❌ Package installation test failed.
		+ exit 1
		scripts/test_pkg_install.sh failed but continuing...
