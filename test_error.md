Run chmod +x scripts/test_integration.sh
+ echo 'Building binaries...'
+ go build -o bin/umlctl ./cmd/umlctl
Building binaries...
+ go build -o bin/umld ./cmd/umld
+ echo 'Creating rootfs.img...'
+ dd if=/dev/zero of=rootfs.img bs=1M count=100
Creating rootfs.img...
100+0 records in
100+0 records out
104857600 bytes (105 MB, 100 MiB) copied, 0.0193691 s, 5.4 GB/s
+ mkfs.ext4 rootfs.img
mke2fs 1.47.0 (5-Feb-2023)
Discarding device blocks:     0/25600Creating filesystem with 25600 4k blocks and 25600 inodes

Allocating group tables: 0/1Writing inode tables: 0/1Creating journal (1024 blocks): done
Writing superblocks and filesystem accounting information: 0/1
+ echo 'Downloading Alpine Edge minirootfs...'
Downloading Alpine Edge minirootfs...
++ curl -s https://dl-cdn.alpinelinux.org/alpine/edge/releases/x86_64/latest-releases.yaml
++ grep 'file: alpine-minirootfs'
++ head -n 1
++ awk '{print $2}'
+ EDGE_TAR=alpine-minirootfs-3.24.0-x86_64.tar.gz
+ wget -q https://dl-cdn.alpinelinux.org/alpine/edge/releases/x86_64/alpine-minirootfs-3.24.0-x86_64.tar.gz -O alpine.tar.gz
+ echo 'Mounting and extracting...'
Mounting and extracting...
+ mkdir -p mnt
+ sudo mount -o loop rootfs.img mnt
+ sudo tar -xzf alpine.tar.gz -C mnt/
+ echo 'Creating an init script...'
Creating an init script...
+ sudo tee mnt/init.sh
+ cat
#!/bin/sh
echo "=============================="
echo " HELLO_FROM_UML_CONTAINER"
echo "=============================="
# Power off the UML kernel
poweroff -f
+ sudo chmod +x mnt/init.sh
+ sudo umount mnt
+ echo 'Running UML with custom compiled linux kernel...'
Running UML with custom compiled linux kernel...
+ ./bin/umlctl start --name integration-test --kernel ./bin/linux --rootfs rootfs.img --init /init.sh
+ cat uml.log
Starting container integration-test...
Warning: could not setup log file: failed to create log dir: mkdir /var/lib/uml-container: permission denied
Warning: failed to save state: mkdir /var/lib/uml-container: permission denied
Warning: failed to save state: mkdir /var/lib/uml-container: permission denied
Core dump limits :
	soft - 0
		hard - NONE
		Checking that ptrace can change system call numbers...OK
		Checking syscall emulation patch for ptrace...OK
		+ grep -q HELLO_FROM_UML_CONTAINER uml.log
		Checking advanced syscall emulation patch for ptrace...OK
		Checking environment variables for a tempdir...none found
		Checking if /dev/shm is on tmpfs...OK
		Checking PROT_EXEC mmap in /dev/shm...OK
		Adding 776343552 bytes to physical memory to account for exec-shield gap
		Linux version 6.6.9 (runner@runnervmvrwv9) (gcc (Ubuntu 13.3.0-6ubuntu2~24.04.1) 13.3.0, GNU ld (GNU Binutils for Ubuntu) 2.42) #1 Wed Jul 29 13:46:21 UTC 2026
		Zone ranges:
		  Normal   [mem 0x0000000000000000-0x00000000ae460fff]
		  Movable zone start for each node
		  Early memory node ranges
		    node   0: [mem 0x0000000000000000-0x000000004e460fff]
			Initmem setup node 0 [mem 0x0000000000000000-0x000000004e460fff]
			random: crng init done
			Kernel command line: init=/init.sh mem=512M ubd0=rootfs.img root=/dev/ubda console=tty0
			Unknown kernel command line parameters "mem=512M", will be passed to user space.
			Dentry cache hash table entries: 262144 (order: 9, 2097152 bytes, linear)
			Inode-cache hash table entries: 131072 (order: 8, 1048576 bytes, linear)
			Sorting __ex_table...
			Built 1 zonelists, mobility grouping on.  Total pages: 316225
			mem auto-init: stack:all(zero), heap alloc:off, heap free:off
			Memory: 497184K/1282436K available (3728K kernel code, 983K rwdata, 1280K rodata, 155K init, 227K bss, 785252K reserved, 0K cma-reserved)
			+ echo 'FAILED: Did not find expected output from UML.'
			SLUB: HWalign=64, Order=0-3, MinObjects=0, CPUs=1, Nodes=1
			+ exit 1
			NR_IRQS: 64
			clocksource: timer: mask: 0xffffffffffffffff max_cycles: 0x1cd42e205, max_idle_ns: 881590404426 ns
			Calibrating delay loop... 7318.73 BogoMIPS (lpj=36593664)
			Checking that host ptys support output SIGIO...Yes
			pid_max: default: 32768 minimum: 301
			Mount-cache hash table entries: 4096 (order: 3, 32768 bytes, linear)
			Mountpoint-cache hash table entries: 4096 (order: 3, 32768 bytes, linear)
			devtmpfs: initialized
			clocksource: jiffies: mask: 0xffffffff max_cycles: 0xffffffff, max_idle_ns: 19112604462750000 ns
			futex hash table entries: 256 (order: 0, 6144 bytes, linear)
			NET: Registered PF_NETLINK/PF_ROUTE protocol family
			pps_core: LinuxPPS API ver. 1 registered
			pps_core: Software ver. 5.3.6 - Copyright 2005-2007 Rodolfo Giometti <giometti@linux.it>
			PTP clock support registered
			clocksource: Switched to clocksource timer
			VFS: Disk quotas dquot_6.6.0
			VFS: Dquot-cache hash table entries: 512 (order 0, 4096 bytes)
			NET: Registered PF_INET protocol family
			IP idents hash table entries: 32768 (order: 6, 262144 bytes, linear)
			tcp_listen_portaddr_hash hash table entries: 1024 (order: 1, 8192 bytes, linear)
			Table-perturb hash table entries: 65536 (order: 6, 262144 bytes, linear)
			TCP established hash table entries: 16384 (order: 5, 131072 bytes, linear)
			TCP bind hash table entries: 16384 (order: 6, 262144 bytes, linear)
			TCP: Hash tables configured (established 16384 bind 16384)
			UDP hash table entries: 1024 (order: 3, 32768 bytes, linear)
			UDP-Lite hash table entries: 1024 (order: 3, 32768 bytes, linear)
			NET: Registered PF_UNIX/PF_LOCAL protocol family
			printk: console [stderr0] disabled
			mconsole (version 2) initialized on /home/runner/.uml/t7JMM2/mconsole
			Checking host MADV_REMOVE support...OK
			workingset: timestamp_bits=62 max_order=17 bucket_order=0
			io scheduler mq-deadline registered
			io scheduler kyber registered
			NET: Registered PF_PACKET protocol family
			Initialized stdio console driver
			Console initialized on /dev/tty0
			printk: console [tty0] enabled
			Initializing software serial port version 1
			printk: console [mc-1] enabled
			epollctl add err fd 1, Operation not permitted
			
			Warning: failed to save state: mkdir /var/lib/uml-container: permission denied
			FAILED: Did not find expected output from UML.
			Error: Process completed with exit code 1.
