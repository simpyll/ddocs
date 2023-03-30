---
---

The Following has been copied and pasted driectly (03/30/2023):

[Comprehensive Hardening Guide](https://theprivacyguide1.github.io/linux_hardening_guide)

-------------------------------------------

ARCH LINUX SECURITY AND PRIVACY GUIDE
This guide aims to help you harden your system for privacy and security.

This will work for most other Linux distributions. Some settings may be different or some files may be placed elsewhere though.
Contents
1. Kernels

1.1 Sysctl
1.2 Boot Parameters
1.3 hidepid
1.4 Netfilter's connection tracking helper
1.5 Linux-hardened
1.6 Grsecurity
1.7 Compiling your own kernel

2. Mandatory Access Control

3. Sandboxes

3.1 Sandboxing Xorg

4. The Root Account

4.1 /etc/securetty
4.2 Restricting su
4.3 Locking the root account
4.4 Denying Root Login via SSH
4.5 Increase the Number of Hashing Rounds

5. Systemd Sandboxing

6. Restricting Xorg Root Access

7. Firewalls

8. Tor

8.1 Tor browser
8.2 Torsocks
8.3 Stream Isolation
8.4 Transparent Proxy
8.5 Tor over Tor
8.6 Configuring the Tor Browser to prevent Tor over Tor

9. Hostnames and Usernames

10. Wireless Devices

11. MAC Address Spoofing

12. Umask

13. USBs

14. Thunderbolt and Firewire

15. Virtual Machines

15.1 Virtualbox
15.2 KVM/QEMU
15.3 Nested Virtualization

16. Core Dumps

16.1 Sysctl
16.2 Systemd
16.3 Ulimit
16.4 Disabling setuid processes from dumping their memory

17. Microcode Updates

18. ICMP Timestamps

19. NTP

20. IPv6 Privacy Extensions

20.1 NetworkManager
20.2 systemd-networkd

21. Bootloaders

21.1 GRUB
21.2 Syslinux
21.3 systemd-boot

22. PAM

23. Blacklist Uncommon Network Protocols

24. Partitioning and Mount Options

25. Disable Mounting of Uncommon Filesystems

26. Editing Files as Root

27. Entropy

27.1 Haveged
27.2 Jitterentropy

28. Microphones and Webcams

29. Best Practices
1. Kernels
An important part of Linux security is hardening the kernel against exploits. This can be with boot parameters, sysctls, kernel patches etc.

1.1 Sysctl
Sysctl is a tool that can increase the kernel's security by changing certain kernel tunables. To change settings temporarily you can use

sysctl -w (param [value])
To change them permanently you can add files to /etc/sysctl.d.

In /etc/sysctl.d create a file called "kptr_restrict.conf" (the name does not matter as long as it ends in '.conf'). In this file add

kernel.kptr_restrict=2
This setting attempts to prevent any kernel pointer leaks via various methods (such as in /proc/kallsyms or dmesg). Kernel pointers can be very useful for kernel exploits. Alternatively you can add "kernel.kptr_restrict=1" but this only hides kernel symbols for users other than the root user.

Now create "dmesg_restrict.conf" and add

kernel.dmesg_restrict=1
This blocks users other than root from being able to see the kernel logs. The kernel logs can give an attacker useful information such as kernel pointers.

Create "harden_bpf.conf" and add

kernel.unprivileged_bpf_disabled=1
net.core.bpf_jit_harden=2

This makes it so that only root can use the BPF JIT compiler and to harden it. A JIT compiler opens up the possibility for an attacker to exploit many vulnerabilities such as JIT spraying.

Create "ptrace_scope.conf" and add

kernel.yama.ptrace_scope=2
This makes only processes with CAP_SYS_PTRACE able to use ptrace. Ptrace is a system call that allows a program to alter and inspect a running process which allows attackers to easily compromise other running programs.

Create "kexec.conf" and add

kernel.kexec_load_disabled=1
This disables kexec which can be used to replace the running kernel.

Create "tcp_hardening.conf" and add


net.ipv4.tcp_syncookies=1
This helps protect against SYN flood attacks which is a form of denial of service attack where an attacker sends a lot of SYN requests in an attempt to consume enough resources to make the system unresponsive to legitimate traffic.

net.ipv4.tcp_rfc1337=1
This protects against time-wait assassination. It drops RST packets for sockets in the time-wait state.

net.ipv4.conf.default.rp_filter=1
net.ipv4.conf.all.rp_filter=1
These enable source validation of packets received from all interfaces of the machine. This protects against IP spoofing methods in which an attacker can send a packet with a fake IP address.

net.ipv4.conf.all.accept_redirects=0
net.ipv4.conf.default.accept_redirects=0
net.ipv4.conf.all.secure_redirects=0
net.ipv4.conf.default.secure_redirects=0
net.ipv6.conf.all.accept_redirects=0
net.ipv6.conf.default.accept_redirects=0
These disable ICMP redirect acceptance. If these settings are not set then an attacker can redirect an ICMP request to anywhere they want.

net.ipv4.conf.all.send_redirects=0
net.ipv4.conf.default.send_redirects=0
These disable ICMP redirect sending when on a non-router.

net.ipv4.icmp_echo_ignore_all=1
This settings makes your system ignore ICMP requests.

All of these harden the TCP/IP stack and tighten network security options.

Create "mmap_aslr.conf" and add
vm.mmap_rnd_bits=32
vm.mmap_rnd_compat_bits=16

These settings are set to the highest value to improve ASLR effectiveness for mmap. [10]
Create "sysrq.conf" and add

kernel.sysrq=0
This disables the SysRq key which exposes tons of potentially dangerous debugging functionality to unprivileged, local users.

Create "unprivileged_users_clone.conf" and add

kernel.unprivileged_userns_clone=0
This disables unprivileged user namespaces. User namespaces add a lot of attack surface for privilege escalation so it's best to restrict them to root only. This may break some sandboxing programs such as bubblewrap. These can be fixed by making the sandbox binaries setuid.

Create "tcp_sack.conf" and add

net.ipv4.tcp_sack=0
This disables TCP SACK. SACK is commonly exploited and not needed for many circumstances so it should be disabled if you don't need it. To learn if SACK is needed for you or not, see https://serverfault.com/questions/10955/when-to-turn-tcp-sack-off.

1.2 Boot Parameters
Boot parameters pass settings to the kernel at boot using your bootloader. Some settings can be used to increase security. If using GRUB then edit /etc/default/grub and add your parameters at "GRUB_CMDLINE_LINUX_DEFAULT=".

If using Syslinux then edit /boot/syslinux/syslinux.cfg and add them to the 'APPEND' line.

Add "apparmor=1 security=apparmor" to enable AppArmor. If using SELinux or other LSMs then do not use these settings.

Add "slab_nomerge" to disable slab merging. Sometimes a slab can be used in a vulnerable way which an attacker can exploit.

Add "slub_debug=FZ" to enable sanity checks (F) and redzoning (Z). Sanity checks make sure that memory has been overwrited correctly. Redzoning adds extra areas around slabs that detect when a slab is overwritten past its real size, which can help detect overflows.

Add "init_on_alloc=1 init_on_free=1". This zeroes memory during allocation and free time to prevent leaking secrets in memory.

Add "mce=0". This causes the kernel to panic on uncorrectable errors in ECC memory which could be exploited. This is not needed for systems without ECC memory.

Add "pti=on". This enables Kernel Page Table Isolation which mitigates Meltdown and prevents some KASLR bypasses.

Add "mds=full,nosmt" to enable all mitigations for the MDS vulnerability and disable SMT. This may have a significant performance decrease as it disables hyperthreading.

Add "module.sig_enforce=1". This only allows kernel modules signed with a valid key to be loaded which increases security by making it harder to load a malicious kernel module. This prevents all out-of-tree kernel modules from being loaded. This includes modules such as the virtualbox modules, wireguard and nvidia drivers which may not be wanted depending on your setup.

Add "oops=panic". This causes the kernel to panic on oopses. This prevents the kernel from continuing to run a flawed process which can be exploited. Kernel exploits sometimes also cause an oops which this will help against. Sometimes, buggy drivers cause harmless oopses which will result in your system crashing so this boot parameter can only be used on certain hardware.

Optionally add "ipv6.disable=1" to disable the whole IPv6 stack which may have some privacy issues depending on your setup as it uses your MAC address to create an IPv6 address which can be used to track you. This can be solved with IPv6 privacy extensions rather than disabling it entirely. This also reduces attack surface so its best to disable it if not needed.

So now we have

GRUB_CMDLINE_LINUX_DEFAULT="apparmor=1 security=apparmor slab_nomerge slub_debug=FZ init_on_alloc=1 init_on_free=1 mce=0 pti=on mds=full,nosmt module.sig_enforce=1 oops=panic"
You will need to regenerate your GRUB configuration file to apply these by running

grub-mkconfig -o /boot/grub/grub.cfg
1.3 hidepid
/proc contains information about all processes running on the system. [17] By default this is accessible to all users. This can allows an attacker to spy a lot on other processes. To allow users to only see their own processes, edit /etc/fstab and add [18]

proc /proc proc nosuid,nodev,noexec,hidepid=2,gid=proc 0 0
systemd-logind still needs to see other users' processes so, for user sessions to work correctly add this to /etc/systemd/system/systemd-logind.service.d/hidepid.conf

[Service]
SupplementaryGroups=proc
1.4 Netfilter's connection tracking helper
Netfilter's automatic conntrack helper assignment is dangerous as it enables a lot of code in the kernel that parses incoming network packets which is potentially unsafe.

To disable this, create /etc/modprobe.d/no-conntrack-helper.conf and add

options nf_conntrack nf_conntrack_helper=0
1.5 Linux-hardened
In the Arch repositories there is a package with a hardened kernel. This contains many patches for security and more paranoid defaults. [19] You should install this and the linux-hardened-headers package.

1.6 Grsecurity
Grsecurity is a set of kernel patches that can increase kernel security. [20] These patches used to be available for everyone but now it is commercial and you have to pay to get them. These patches offer a great increase in security.
1.7 Compiling your own kernel
You should compile your own kernel and enable as little modules as possible to keep attack surface at a minimum. Distro-compiled kernels also have public kernel symbols which are very useful for exploits. Compiling your own kernel will give you unique kernel symbols which, along with kptr_restrict and dmesg_restrict, will make it a lot harder for attackers to create exploits.

2. Mandatory Access Control (MAC)
MAC systems give fine-grained control over what programs can access. This means your browser won't have access to your entire home directory or something similar.

The most used MAC systems are SELinux and Apparmor. SELinux is a lot more secure than AppArmor but is more difficult to use and isn't supported in Arch so I recommend to use AppArmor.

To enable Apparmor, install the AppArmor package, enable the AppArmor systemd service and set the kernel parameters required for AppArmor described above. Just installing AppArmor won't increase security. You need to develop profiles for certain applications to restrict them.

To create AppArmor profiles run

aa-genprof /usr/bin/(program)
Open the program and start using at as you normally would. AppArmor will detect what files it needs access to and will add them to the profile if you choose. This will not cover everything an application will do but it is a good starting point for creating profiles.

This is only a very basic explanation but I advise you to learn how to use AppArmor as it can help protect your system against lots of attacks.

If you want to take it a step further. You can setup a full system AppArmor policy by using an initramfs hook to confine systemd.

3. Sandboxes
Sandboxes allow you to run a program in an isolated environment that has no, or limited access to the rest of your system. You can use these to secure your applications or run untrusted programs.

I recommend to use bubblewrap to sandbox programs. It is a very powerful sandbox with minimal attack surface.

You should not use Firejail as it has far too large attack surface which has led to Firejail having trivial privilege escalations and sandbox escapes.

3.1 Sandboxing Xorg
Any Xorg window can have access to another window. This allows for keyloggers or screenshot programs that can even record the root password. [21] You can sandbox Xorg with Xpra/Xephyr and bubblewrap. [22] To use Xephyr install xorg-server-xephyr and to use Xpra install 'xpra'. To sandbox a program with bubblewrap and Xephyr run: TO BE WRITTEN

Wayland isolates windows from each other by default and would be better to use than Xorg.

4. The Root Account
Root can do basically anything and has access to your whole system. This means you should lock it down as much as possible so attackers cannot gain root access.

4.1 /etc/securetty
/etc/securetty tells the system where you are allowed to login as root. You should keep this file empty so nobody can login as root from a tty.
4.2 Restricting su
su lets you switch users from a terminal. By default it tries to login as root. To restrict the use of su to users within the 'wheel' group, edit /etc/pam.d/su and /etc/pam.d/su-l (that's the letter l, not the number one) and uncomment

auth required pam_wheel.so use_uid
You should have as little users in the 'wheel' group as possible.

4.3 Locking the root account
To lock the root account to prevent anyone from logging in as root, run

passwd -l root
4.4 Denying Root Login via SSH
To prevent someone from logging in as root via SSH edit /etc/ssh/sshd_config and add [28]

PermitRootLogin no
4.5 Increase the Number of Hashing Rounds
You can increase the number of hashing rounds that shadow can use. This can increase the security of your hashed passwords. It makes an attacker have to compute a lot more hashes to crack your password. By default shadow uses 5000 rounds but you can increase this to as many as you want. The more rounds it does the slower it wil be to login. Edit /etc/pam.d/passwd and add the rounds option. [30]

password required pam_unix.so sha512 shadow nullok rounds=65536
This makes shadow perform 65536 rounds.

Your passwords are not automatically rehashed after applying this setting so you need to reset the password with

passwd username
Replace 'username' with the user whose password you are changing.

This can be applied to your user account or the root account.

5. Systemd Sandboxing
Systemd has the ability to sandbox services so they can only access what they need. Here is an example of a sandboxed systemd service.

[Service]
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
ProtectSystem=strict
ReadWriteDirectories=/var/lib/tor/
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
PrivateTmp=true
PrivateUsers=yes
MemoryDenyWriteExecute=true
NoNewPrivileges=true
RestrictRealtime=true
RestrictAddressFamilies=AF_INET AF_UNIX
SystemCallArchitectures=native
RestrictNamespaces=yes
RuntimeDirectoryMode=0700
SystemCallFilter=~@clock @cpu-emulation @debug @keyring @module @mount @obsolete @raw-io
AppArmorProfile=/etc/apparmor.d/usr.bin.tor
To learn more about the options you can set, read the systemd.exec manpage.
6. Restricting Xorg Root Access
The following section does not apply to Arch Linux as it starts X rootless by default. This may help with other distributions.

Xorg is a massive amount of code and runs as root by default. This makes it more likely to have exploits that can gain root privileges. [31] To stop it from using root create /etc/X11/Xwrapper.config and add [32]

needs_root_rights = no
To make sure that this works run this command as root and check for Xorg.

ps -U root -u root u
7. Firewalls
Firewalls control incoming and outgoing network traffic and can be used to block or allow certain types of traffic. You should always block all incoming traffic unless you have a specific reason not to.

It is recommend to set up a strict iptables or nftables firewall.

8. Tor
Tor is an anonymity network that tries to make you anonymous by routing your internet traffic through multiple nodes across the world.

8.1 Tor browser
The Tor Browser is a browser based on Firefox that is configured for anonymity and security which routes all connections through the Tor network.

It is recommended not to use any other browser for Tor because you can easily misconfigure it and break it. It will also have a completely different browser fingerprint from the Tor Browser which can be used to deanonymize you.

You should use apparmor with the Tor Browser to increase security.

https://github.com/micahflee/torbrowser-launcher/tree/develop/apparmor

8.2 Torsocks
Torsocks can force other programs' network traffic through Tor which allows you to anonymize more than just your browsing.

8.3 Stream Isolation
Stream isolation makes programs use different Tor circuits from each other to prevent identity correlation. [34] To enable this edit /etc/tor/torrc and configure more SocksPorts. 9050 is the default SocksPort. Once you have made more, configure your programs to use those new ports and you will have stream isolation.

Pacman can use stream isolation by editing /etc/pacman.conf. Add this to /etc/pacman.conf

XferCommand = /usr/bin/curl --socks5-hostname localhost:9062 --continue-at - --fail --output %o %u
Replace 9062 with your SocksPort.

8.4 Transparent Proxy
You can configure your whole system to use Tor by default with a transparent proxy to anonymize all internet traffic.

To do this add this to /etc/tor/torrc:

TransPort 9040
DNSPort 5353
SocksPort 9050
Create /etc/iptables/iptables.rules and add:

*nat
:PREROUTING ACCEPT [6:2126]
:INPUT ACCEPT [0:0]
:OUTPUT ACCEPT [17:6239]
:POSTROUTING ACCEPT [6:408]

-A PREROUTING ! -i lo -p udp -m udp --dport 53 -j REDIRECT --to-ports 5353
-A PREROUTING ! -i lo -p tcp -m tcp --tcp-flags FIN,SYN,RST,ACK SYN -j REDIRECT --to-ports 9040
-A OUTPUT -o lo -j RETURN
--ipv4 -A OUTPUT -d 192.168.0.0/16 -j RETURN
-A OUTPUT -m owner --uid-owner "tor" -j RETURN
-A OUTPUT -p udp -m udp --dport 53 -j REDIRECT --to-ports 5353
-A OUTPUT -p tcp -m tcp --tcp-flags FIN,SYN,RST,ACK SYN -j REDIRECT --to-ports 9040
COMMIT

*filter
:INPUT DROP [0:0]
:FORWARD DROP [0:0]
:OUTPUT DROP [0:0]

-A INPUT -i lo -j ACCEPT
-A INPUT -p icmp -j ACCEPT
-A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
--ipv4 -A INPUT -p tcp -j REJECT --reject-with tcp-reset
--ipv4 -A INPUT -p udp -j REJECT --reject-with icmp-port-unreachable
--ipv4 -A INPUT -j REJECT --reject-with icmp-proto-unreachable
--ipv6 -A INPUT -j REJECT
--ipv4 -A OUTPUT -d 127.0.0.0/8 -j ACCEPT
--ipv4 -A OUTPUT -d 192.168.0.0/16 -j ACCEPT
--ipv6 -A OUTPUT -d ::1/8 -j ACCEPT
-A OUTPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
-A OUTPUT -m owner --uid-owner "tor" -j ACCEPT
--ipv4 -A OUTPUT -j REJECT --reject-with icmp-port-unreachable
--ipv6 -A OUTPUT -j REJECT
COMMIT
Symlink this to /etc/iptables/ip6tables.rules if using IPv6.

Edit /etc/resolv.conf and set it to 127.0.0.1. You may need to configure dnsmasq or any other resolver to set your DNS as 127.0.0.1:5353.

Edit /etc/dhcpcd.conf and add "nohook resolv.conf" to stop it from overwriting resolv.conf. Run "chattr +i /etc/resolv.conf" to prevent all services from overwriting it.

To use stream isolation with a transparent proxy then add more SocksPorts in your torrc and configure your programs to use those ports.
8.5 Tor over Tor
If you force Tor traffic to go through Tor again you will get Tor over Tor. For example if you use the default Tor Browser with a transparent proxy. You could get 6 hops from this but it is not guaranteed that these hops will be different. The user could end up with the same hops, possibly in reverse or mixed order.

The Tor Project recommends to not use more than three hops.

We don't want to encourage people to use paths longer than this — it increases load on the network without (as far as we can tell) providing any more security. Remember that the best way to attack Tor is to attack the endpoints and ignore the middle of the path. Also, using paths longer than 3 could harm anonymity, first because it makes "denial of security" attacks easier, and second because it could act as an identifier if only a few people do it ("Oh, there's that person who changed her path length again").
https://2019.www.torproject.org/docs/faq.html.en#ChoosePathLength

8.6 Configuring the Tor Browser to prevent Tor over Tor
If you use a transparent proxy and decide to use the Tor Browser then the Tor Browser's Tor traffic with get forced through Tor which gives you Tor over Tor.

A way around this is to disable Tor in the Tor Browser. In /etc/environment add [36]

## Deactivate tor-launcher
TOR_SKIP_LAUNCH=1

## Environment variable to disable the "TorButton"
## "Open Network Settings" menu item. It is not useful and confusing to have.
TOR_NO_DISPLAY_NETWORK_SETTINGS=1

## Environment variable to skip TorButton control port verification
TOR_SKIP_CONTROLPORTTEST=1
Tor should now be disabled in the Tor Browser. You should also configure the proxy settings of the Tor Browser so you can use stream isolation. Create a user.js file in the default profile of the Tor Browser. Add [36]

user_pref("extensions.torlauncher.start_tor", false);
user_pref("network.proxy.socks", "127.0.0.1");
user_pref("network.proxy.socks_port", "9150");
user_pref("network.proxy.socks_remote_dns", true);
user_pref("network.proxy.type", 1);
user_pref("extensions.torlauncher.control_host", "127.0.0.1");
user_pref("extensions.torlauncher.control_port", "9150");
Change 9150 to your configured SocksPort.

9. Hostnames and Usernames
Do not put anything uniquely indentifying in your hostname or username. It is recommended to keep them as generic names such as "host" and "user" so you can't be identified by them.

10. Wireless Devices
Wireless devices add a lot of potential attack surface so you should disable as much of these as possible to reduce attack surface. To block all wireless devices run

rfkill block all
You can also blacklist certain modules to prevent them from loading. For example, to blacklist the bluetooth module, create /etc/modprobe.d/blacklist-bluetooth.conf and add

install btusb /bin/true
install bluetooth /bin/true
You should always use install (module) /bin/true instead of blacklist (module) as modules blacklisted via blacklist can still be loaded if another module depends on it.

11. MAC Address Spoofing
MAC addresses can be used to identify you. They are unique identifiers exposed when you connect to a network. To spoof them, install macchanger and run

macchanger -e (network interface)
To find out your network interfaces run

ip a


[Unit]
Description=macchanger on eth0
Wants=network-pre.target
Before=network-pre.target
BindsTo=sys-subsystem-net-devices-eth0.device
After=sys-subsystem-net-devices-eth0.device

[Service]
ExecStart=/usr/bin/macchanger -e eth0
Type=oneshot

[Install]
WantedBy=multi-user.target
Here is a systemd service to spoof the MAC address of eth0 at boot. Replace eth0 with your network interface.

You should always use "macchanger -e" rather than "macchanger -r". This is because "macchanger -r" completely randomizes the MAC address which makes it really obvious that you're spoofing your MAC address which makes you stand out. "macchanger -e" doesn't spoof the vendor bytes so it's much more believable.

12. Umask
Umasks set the default file permissions for newly created files. [40] The default is 022 which is not very secure. This gives read access to every user on the system for newly created files. Edit /etc/profile and change the umask to 0077 which makes new files not readable by anyone other than the owner.

13. USBs
USBs are dangerous as they can contain malware. It is best to block all newly connected USBs by default to prevent these attacks. USBGuard is good for this.

You could use "nousb" as a boot parameter to disable all USB support.

If using linux-hardened, set the kernel.deny_new_usb=1 sysctl.

14. DMA Attacks
Thunderbolt and Firewire can be used for Direct Memory Access (DMA) attacks. [42] [43] Disable these modules by creating "/etc/modprobe.d/blacklist-dma.conf". To blacklist these modules from loading add

install firewire-core /bin/true
install thunderbolt /bin/true
You should enable IOMMU in your BIOS and by the "intel_iommu=on" (if using Intel) or the "amd_iommu=on" (if using AMD) boot parameters to enforce isolation between devices.

15. Virtual Machines
Virtual Machines (VMs) isolate processes by virtualizing an entirely new system. I recommend to use KVM/QEMU.

15.1 Virtualbox
You should not use Virtualbox for multiple reasons. [44]

1) They use a non-free toolchain to compile their BIOS which is problematic for some free software projects.

2) They don't fix security bugs. Many bugs are left in because the developers are too lazy to fix them.

3) They rarely tell people about bugs. If they discover a bug they hide it from everyone else which makes it a lot harder for the community to make patches.

4) A lot of important features only come with the extension pack which is proprietary.

15.2 KVM/QEMU
KVM is a kernel module that allows the kernel to function like a hypervisor.

QEMU is an emulator that can use KVM.

Virt-manager and GNOME Boxes are both good and easy to use GUIs to manage KVM/QEMU virtual machines.

16. Core Dumps
Core dumps contain the recorded state of the working memory of a program at a specific time, usually when that program has crashed. These can contain very important information such as passwords and encryption keys. [45] You should disable these to prevent someone from accessing that information.

There are three ways to disable them. With sysctl, systemd and ulimit. The sysctl way may not properly disable core dumps as systemd overrides it. I use all three ways to make sure core dumps are disabled.

16.1 Sysctl
Create /etc/sysctl.d/coredump.conf or edit /etc/sysctl.conf (this does not exist on arch). Add this to possibly disable core dumps. [46] [47]

kernel.core_pattern=|/bin/false
16.2 Systemd
Create /etc/systemd/coredump.conf.d/custom.conf. You may need to create /etc/systemd/coredump.conf.d/ first. Add this to disable core dumps. [46] [47]

[Coredump]
Storage=none
16.3 Ulimit
In /etc/security/limits.conf add [46] [47]

* hard core 0
16.4 Disabling setuid processes from dumping their memory
Process that run with elevated privileges (setuid) may still dump their memory even after these settings. To prevent them from doing this create /etc/sysctl.d/suid_dumpable.conf and add [46]

fs.suid_dumpable=0
Arch sets this setting by default so there is no need to do this on Arch.

17. Microcode Updates
Microcode updates are important. They can fix CPU vulnerabilities such the Meltdown and Spectre bugs.

AMD uses the amd-ucode package and Intel uses the intel-ucode package.

To enable them on GRUB run

grub-mkconfig -o /boot/grub/grub.cfg
More information and ways to enable them on different bootloaders can be found on the Arch Wiki.

18. ICMP Timestamps
ICMP timestamps can expose your clock time which can be used for clock skew fingerprinting attackers. The easiest way is to block these is by blocking all incoming connections with a firewall.

19. NTP
NTP is very insecure as it is unauthenticated and unencrypted. This means someone can do a man in the middle attack on your connection and give you a false time. This allows for fingerprinting as an attacker can give you a unique time and be able to track you with that. It also means you are vulnerable to replay attacks. [52]

NTP leaks your local computer time in NTP timestamp format which can be used for clock skew fingerprinting. This can be used to de-anonymize users and onion services.

There is authentication for NTP called autokey but this is insecure and doesn't solve the problem of clock skew fingerprinting.

You might want to disable this and use your local system and hardware clock although this can make you more vulnerable to clock skew fingerprinting. I have developed a tool called Secure Time Synchronization that securely syncs the time to the current UTC time. You may also want to look into Whonix's sdwdate.

Uninstall any NTP clients and disable it by running

timedatectl set-ntp 0
and

systemctl disable systemd-timesyncd.service
If you're on a server, then it is unrecommended to disable NTP as it is needed for highly accurate time synchronization.

20. IPv6 Privacy Extensions
IPv6 addresses are generated through your computer's MAC address. This makes every IPv6 address completely unique and tied directly to your computer. [53] Since this can be used to track you, you should either use IPv6 privacy extensions or disable IPv6 entirely. As to not lose the benefits of IPv6 you could use privacy extensions rather than disabling it. Privacy extensions generate a random IPv6 address out of your original one to prevent you from being tracked by it. [54]

To enable these create /etc/sysctl/ipv6_privacy.conf and add [55]

net.ipv6.conf.all.use_tempaddr = 2
net.ipv6.conf.default.use_tempaddr = 2
net.ipv6.conf.eth0.use_tempaddr = 2
net.ipv6.conf.wlan0.use_tempaddr = 2
Replace "eth0" and "wlan0" with your network interfaces. You can find these by running

ip a
20.1 NetworkManager
NetworkManager does not use these settings and still uses your original IPv6 address. To enable privacy extensions for NetworkManager, add these lines to /etc/NetworkManager/NetworkManager.conf [56]

[connection]
ipv6.ip6-privacy=2
20.2 systemd-networkd
systemd-networkd also does not use these settings and will still use your original IPv6 address. To enable privacy extensions for systemd-networkd, create /etc/systemd/network/ipv6.conf and add [57]

[Network]
IPv6PrivacyExtensions=kernel
21. Bootloaders
It is very important that you protect your bootloader. A local attacker can get a root shell by using some thing like "init=/bin/bash" as a kernel parameter at boot. This tells the kernel to execute /bin/bash instead of your normal init system. [58] You can prevent this by encrypting /boot or setting a password for your bootloader.

21.1 GRUB
To set a password for GRUB, run [59]

grub-mkpasswd-pbkdf2
Enter your password and a string will be generated from that password. It will be like grub.pbkdf2.sha512.10000.*, where * can be anything. Edit /etc/grub.d/40_custom and add

set superusers="username"
password_pbkdf2 username (password)
Replace "(password)" with the string generated by "grub-mkpasswd-pbkdf2". The username will be for the superusers who are users that are permitted to use the GRUB command line, edit menu entries, and execute any menu entry. For most people you can just keep this as "root".

Regenerate your configuration file with

grub-mkconfig /boot/grub/grub.cfg
GRUB will now be password protected.

To restrict only editing the boot parameters and accessing the GRUB console while still allowing you to boot, edit /boot/grub/grub.cfg and next to "menuentry 'OS Name'" add "--unrestricted" e.g.

menuentry 'Arch Linux' --unrestricted
You will need to regenerate your configuration file again.

GRUB also has support for encrypting /boot.

21.2 Syslinux
Syslinux can either set a master password or a menu password. A master password is required while booting any entry while a menu password is only required while booting a specified entry. [60]

To set a master password for Syslinux, edit /boot/syslinux/syslinux.cfg and add

MENU MASTER PASSWD (password)
Replace "(password)" with the password you want to set.

To set a menu password, edit /boot/syslinux/syslinux.cfg and within a label that has the item you want to password protect, add

MENU PASSWD (password)
Replace "(password)" with the password you want to set.

These passwords can either be plaintext or hashed with MD5, SHA-1, SHA-2-256 or SHA-2-512.

Syslinux does not have support for encrypting /boot.

21.3 systemd-boot
systemd-boot has the option to prevent editing the kernel parameters at boot. In the loader.conf file add [61]

editor no
This will disabling editing the boot parameters.

systemd-boot does not officially support password protecting the kernel parameters editor but you can do it with systemd-boot-password from the AUR. To install this run

sbpctl install (esp)
Replace "(esp)" with your esp directory. The editor needs to be enabled in loader.conf to be prompted for a password.

22. PAM
PAM is a framework for system-wide user authentication. [62] It is what you use when you login. You can make it more secure by requiring strong passwords, locking out users etc.

To enforce strong passwords you can use pam_cracklib. It enforces a configurable policy for passwords throughout the system. [63] If you want passwords to require 10 characters minimum (minlen), at least 6 different characters from the old password (difok), at least 1 digit (dcredit), at least 1 uppercase (ucredit), at least 1 other character (ocredit) and at least 1 lowercase (lcredit) then edit /etc/pam.d/passwd and add

password required pam_cracklib.so retry=2 minlen=10 difok=6 dcredit=-1 ucredit=-1 ocredit=-1 lcredit=-1
password required pam_unix.so use_authtok sha512 shadow
This can be changed to whatever you want.

To add a delay of at least 4 seconds between failed login attempts edit /etc/pam.d/system-login and add [64]

auth optional pam_faildelay.so delay=4000000
4000000 is 4 seconds in microseconds.

To lockout user after three failed login attempts edit /etc/pam.d/system-login and add [65]

auth required pam_tally2.so deny=3 unlock_time=600 onerr=succeed file=/var/log/tallylog
23. Blacklist Uncommon Network Protocols
The kernel allows unprivileged users to cause certain modules to be loaded via module auto-loading which adds a ton of attack surface as users can auto-load vulnerable modules which is then exploited. Obscure networking protocols in particular add a lot of attack surface and unused protocols should be blacklisted. [66] [67] Create /etc/modprobe.d/uncommon-network-protocols.conf and add

install dccp /bin/true
install sctp /bin/true
install rds /bin/true
install tipc /bin/true
install n-hdlc /bin/true
install ax25 /bin/true
install netrom /bin/true
install x25 /bin/true
install rose /bin/true
install decnet /bin/true
install econet /bin/true
install af_802154 /bin/true
install ipx /bin/true
install appletalk /bin/true
install psnap /bin/true
install p8023 /bin/true
install llc /bin/true
install p8022 /bin/true
"install" tells modprobe to run a command instead of loading the module as normal. /bin/true is a command that returns 0 which will do nothing. Both of these together tells the kernel to run /bin/true instead of loading the module which will prevent the module from being loaded.

24. Partitioning and Mount Options
You should separate file systems into various partitions so you will have more fine grained control over their permissions and will add an extra layer of security. You can add different mount options to restrict what can happen on a file system. The main ones are:

nodev - Do not interpret devices on the file system.
nosuid - Do not allow setuid or setgid bits.
noexec - Do not allow execution of any binaries on the filesystem.

You should put these mount options wherever possible. Nodev can be put everywhere except / and chroot partitions. Noexec can be put anywhere that doesn't execute binaries inside it.

You can do this in /etc/fstab.

An example of a /etc/fstab file:

/        /          ext4    defaults                      1 1
/tmp     /tmp       ext4    defaults,nosuid,noexec,nodev  1 2
/home    /home      ext4    defaults,nosuid,nodev         1 2
/var     /var       ext4    defaults,nosuid               1 2
/boot    /boot      ext4    defaults,nosuid,noexec,nodev  1 2
/tmp     /var/tmp   ext4    defaults,bind,nosuid,noexec,nodev 1 2
      
25. Disable Mounting of Uncommon Filesystems
There are a few uncommon filesystems that are very rarely used. These don't serve any purpose for most people and it would be best to disable mounting these to reduce attack surface. Create /etc/modprobe.d/uncommon-filesystems.conf and add

install cramfs /bin/true
install freevxfs /bin/true
install jffs2 /bin/true
install hfs /bin/true
install hfsplus /bin/true
install squashfs /bin/true
install udf /bin/true
You should make sure that these filesystems aren't being used anywhere before doing this.

26. Editing Files as Root
It is unrecommended to run ordinary text editors as root because many text editors can do more than edit text files and this can be exploited. For example, open vi as root by running

sudo vi
Now enter ":sh". You now have a root shell with access to your entire system which an attacker can easily exploit this.

A solution to this, is using sudoedit. This copies the file to a temporary location, opens the text editor as an ordinary user, edits the temporary file and overwrites the original file as root. This way, the actual editor doesn't run as root. To use sudoedit, run

sudoedit /path/to/file
By default, it uses vi but the default editor can be changed using the EDITOR or SUDO_EDITOR environment variable. For example, to use sudoedit with nano, run

EDITOR=nano sudoedit /path/to/file
This environment variable can be set globally in /etc/environment.

27. Entropy
Entropy is the randomness collected by an operating system. Entropy is crucial for things such as encryption so it is best to gather as much entropy as possible.

27.1 Haveged
Haveged is a random number generator that gathers more entropy. To install it, run

sudo pacman -S haveged
Enable it by running

sudo systemctl enable --now haveged.service
27.2 Jitterentropy
Jitterentropy is another random number generator. To install it, run

sudo pacman -S jitterentropy
28. Microphones and Webcams
Malware can take over microphones and webcams[71] which can then be used to spy on you by recording a video of you or recording what you say. Because of this, it is recommended to remove any microphones or webcams. It is best to physically remove them but you can also blacklist the kernel modules for them. Speakers can also be turned into a microphone to spy on you. [72]

To blacklist the webcam kernel module, create /etc/modprobe.d/blacklist-webcam.conf and add

install uvcvideo /bin/true
The kernel module for the microphone is the same as the one for the speaker. This means disabling the microphone in this method will also disable any speakers. To find the name of the module, look in /proc/asound/modules. Create /etc/modprobe.d/blacklist-mic.conf and add

install (module) /bin/true
Replace "(module)" with whatever you found in /proc/asound/modules. For example, if you found "snd_hda_intel", you would add

install snd_hda_intel /bin/true
You should also disable the webcam and microphone in your BIOS if possible.

29. Best Practices
Now you will have a secure system and there isn't really much more you can do. You should follow good privacy/security practices:

1. Disable/remove things you don't need.
2. Use strong passwords.
3. Stay updated. Configure a cron job to update your system daily.
4. Don't leak any information about you or your system.

Other Guides
Arch Linux Hardening Guide

Debian Hardening Guide

Gentoo Hardening Guide

CentOS Hardening Guide

Whonix Documentation

NSA RHEL5 Hardening Guide (a bit outdated)

Discover here lots of privacy blockchain projects
References
1. kptr_restrict for hiding kernel pointers https://lwn.net

2. Kernel Sysctl Docs https://www.kernel.org

3. Kernel Sysctl Docs https://www.kernel.org

4. Protect against the usage of Ptrace https://linux-audit.com

5. ptrace https://en.wikipedia.org

6. Kernel Sysctl Docs https://www.kernel.org

7. kexec https://en.wikipedia.org

8. sysctl https://wiki.archlinux.org

9. SYN flood https://en.wikipedia.org

10. Allow customizable random offset to mmap_base address. https://www.mail-archive.com/linux-kernel

11. Disable TCP Timestamps https://www.whonix.org

12. AppArmor https://wiki.archlinux.org

13. The kernel’s command-line parameters https://www.kernel.org

14. kernel hardening https://tails.boum.org

15. Kernel IPv6 Docs https://www.kernel.org

16. Audit framework https://wiki.archlinux.org

17. procfs https://en.wikipedia.org

18. procfs: add hidepid= and gid= mount options https://git.kernel.org

19. linux-hardened https://github.com

20. Grsecurity https://grsecurity.net

21. The Linux Security Circus: On GUI isolation https://blog.invisiblethings.org

22. X11 Guide https://firejail.wordpress.com

23. SECURETTY(5) http://man7.org

24. SU(1) http://man7.org

25. Restrict the use of su command https://www.cyberciti.biz

26. The root password is ... irrelevant https://cromwell-intl.com

27. PASSWD(1) http://man7.org

28. OpenSSH https://wiki.archlinux.org

29. OpenSSH https://wiki.archlinux.org

30. SHA password hashes https://wiki.archlinux.org

31. Why are people saying that the X Window System is not secure? https://security.stackexchange.com

32. Xorg https://wiki.archlinux.org

33. Torsocks https://trac.torproject.org

34. Stream Isolation https://whonix.org

35. TransparentProxy https://trac.torproject.org

36. Other Operating Systems https://www.whonix.org

37. rfkill(1) - Linux man page https://linux.die.net

38. MAC address https://en.wikipedia.org

39. MAC Address Spoofing in NetworkManager 1.4.0 https://blogs.gnome.org

40. umask https://en.wikipedia.org

41. USBGuard https://usbguard.github.io

42. Thunderbolt https://en.wikipedia.org

43. IEEE 1394 https://en.wikipedia.org

44. Why Use KVM Over VirtualBox? https://www.whonix.org

45. Core dump https://en.wikipedia.org

46. Understand and configure core dumps on Linux https://linux-audit.com

47. Core dump https://wiki.archlinux.org

48. Is the Intel Management Engine a backdoor? https://www.techrepublic.com

49. AMD Secure Technology https://www.amd.com

50. AMD is NOT Opensourcing their PSP code ANYTIME SOON https://www.reddit.com

51. Disable ICMP Timestamps https://www.whonix.org

52. Time Attacks https://www.whonix.org

53. Facing the privacy implications of IPv6 https://iapp.org

54. RFC 4941 - Privacy Extensions for Stateless Address Autoconfiguration in IPv6 https://tools.ietf.org

55. Kernel IPv6 Sysctl Docs https://www.kernel.org

56. NetworkManager and privacy in the IPv6 internet https://blogs.gnome.org

57. systemd.network https://www.freedesktop.org

58. Re: kernel boot parameter : init=/bin/bash https://www.redhat.com

59. GNU GRUB Manual 2.02 https://www.gnu.org

60. Comboot/menu.c32 https://wiki.syslinux.org

61. loader.conf https://www.freedesktop.org

62. What is Linux-PAM? www.linux-pam.org

63. 6.2. pam_cracklib http://www.linux-pam.org

64. 6.8. pam_faildelay http://www.linux-pam.org

65. 6.33. pam_tally2 http://www.linux-pam.org

66. Linux kernel: CVE-2017-6074: DCCP double-free vulnerability (local root) https://seclists.org

67. CVE-2017-8824 https://security.archlinux.org

68. modprobe.d(5) - Linux man page https://linux.die.net

69. What is /bin/true https://stackoverflow.com

70. mount(8) - Linux man page https://linux.die.net

71. How the NSA Plans to Infect ‘Millions’ of Computers with Malware https://theintercept.com

72. SPEAKE(a)R: Turn Speakers to Microphones for Fun and Profit https://arxiv.org
