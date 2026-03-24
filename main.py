import random
from command_runner import CommandRunner

# 300 SAFE LINUX COMMANDS FOR RESEARCH
# Focused on System Discovery, Networking, and File Enumeration
COMMAND_LIST = [
    # --- GROUP 1: SYSTEM IDENTIFICATION (50 commands) ---
    "uname -a", "uname -s", "uname -n", "uname -m", "uname -p", "uname -i", "uname -o",
    "hostname", "hostname -f", "hostname -i", "hostname -I", "uptime", "uptime -p", "uptime -s",
    "lscpu", "lsblk", "lsblk -a", "lsusb", "lspci", "lsscsi", "lsmod", "arch",
    "cat /etc/os-release", "cat /etc/issue", "cat /etc/hostname", "cat /proc/version",
    "cat /proc/cpuinfo", "cat /proc/meminfo", "cat /proc/partitions", "cat /proc/modules",
    "free -h", "free -m", "df -h", "df -T", "du -sh /tmp", "getconf LONG_BIT",
    "timedatectl", "date", "cal", "last reboot", "runlevel", "systemd-analyze",
    "cat /etc/timezone", "ls /boot", "ls /lib/modules", "sysctl kernel.hostname",
    "cat /proc/cmdline", "cat /proc/uptime", "cat /proc/loadavg", "cat /proc/swaps",

    # --- GROUP 2: NETWORK ENUMERATION (70 commands) ---
    "ip addr", "ip -4 addr", "ip -6 addr", "ip link", "ip route", "ip neigh", "ip rule",
    "netstat -i", "netstat -s", "netstat -rn", "netstat -ant", "netstat -unp", "ss -t -a",
    "ss -u -a", "ss -ntulp", "arp -a", "arp -v", "cat /etc/resolv.conf", "cat /etc/hosts",
    "cat /etc/networks", "cat /etc/protocols", "cat /etc/services", "nmcli device",
    "nmcli connection show", "route -n", "ping -c 1 127.0.0.1", "ping -c 1 google.com",
    "host localhost", "nslookup localhost", "dig -v", "iptables -L -n", "iptables -S",
    "ip route show default", "cat /proc/net/dev", "cat /proc/net/arp", "cat /proc/net/route",
    "cat /proc/net/tcp", "cat /proc/net/udp", "cat /proc/net/snmp", "ifconfig -a",
    "iwconfig", "ether-wake -V", "nmap --version", "wget --version", "curl --version",
    "ssh -V", "ip maddr", "ip tunnel show", "bridge link", "routel", "ip addr show eth0",
    "ip addr show lo", "cat /proc/net/fib_trie", "cat /proc/net/netstat", "ss -s",
    "netstat -g", "cat /etc/nsswitch.conf", "cat /etc/host.conf", "hostname --all-ip-addresses",
    "ip token list", "ip -6 route show", "ip -6 neigh show", "cat /proc/net/if_inet6",
    "ls /sys/class/net", "cat /sys/class/net/lo/mtu", "cat /sys/class/net/eth0/address",

    # --- GROUP 3: USER & PROCESS DISCOVERY (60 commands) ---
    "whoami", "id", "id -u", "id -g", "groups", "users", "who", "w", "last -n 10",
    "lastlog", "cat /etc/passwd", "cat /etc/group", "getent passwd", "getent group",
    "ps aux", "ps -ef", "ps -e --forest", "ps -eo pid,ppid,cmd,%mem,%cpu", "top -n 1 -b",
    "htop --version", "pstree", "pstree -p", "pgrep -l ssh", "cat /proc/self/status",
    "ls /home", "ls -la /home", "ls -la /root 2>/dev/null", "sudo -l", "env", "printenv",
    "alias", "cat ~/.bashrc | head -n 20", "cat ~/.profile", "cat /etc/profile",
    "ls -la /etc/sudoers.d", "cat /etc/shells", "cat /etc/login.defs", "finger",
    "pinky", "users | wc -w", "ps -u $(whoami)", "cat /proc/self/cmdline", "ls /var/run",
    "ls /var/spool/cron", "crontab -l", "ls /etc/cron.daily", "ls /etc/init.d",
    "systemctl list-unit-files --type=service", "systemctl is-active ssh",
    "logname", "cat /proc/sys/kernel/osrelease", "cat /proc/sys/kernel/hostname",
    "ls -d /home/*", "cut -d: -f1 /etc/passwd", "awk -F: '{ print $1 }' /etc/passwd",

    # --- GROUP 4: FILE SYSTEM & CONFIGS (120 commands) ---
    "ls -R /etc | head -n 20", "ls -la /tmp", "ls -la /var/tmp", "ls -la /dev/shm",
    "ls -F /", "ls -l /bin", "ls -l /sbin", "ls -l /usr/bin", "ls -l /usr/sbin",
    "find /tmp -maxdepth 1", "find /var/log -name '*.log' 2>/dev/null | head -n 10",
    "ls -la /etc/apt/sources.list", "ls /etc/apt/sources.list.d", "dpkg -l | head -n 20",
    "apt list --installed | head -n 20", "ls /usr/share/doc", "ls /usr/share/man",
    "cat /etc/fstab", "cat /etc/mtab", "mount -l", "lsblk -f", "ls /proc",
    "ls -la /sys", "ls /snap 2>/dev/null", "ls /opt", "ls /mnt", "ls /media",
    "ls -la /var/log", "tail -n 10 /var/log/syslog 2>/dev/null", "dmesg | head -n 10",
    "cat /proc/filesystems", "cat /proc/mounts", "cat /proc/diskstats",
    "ls -i /", "ls -sh /", "ls -t /tmp", "ls -S /etc", "ls -c /etc",
    "file /bin/ls", "file /etc/passwd", "stat /etc/passwd", "which ls", "which python3",
    "whereis bash", "type cd", "readlink -f /bin/sh", "lsattr /etc/passwd 2>/dev/null",
    "findmnt", "lsof -v", "cat /etc/updatedb.conf", "ls /etc/xdg", "ls /etc/X11",
    "ls /etc/skel", "cat /etc/bash.bashrc", "ls /etc/perl", "ls /etc/python3",
    "ls /var/mail", "ls /var/backups", "ls /var/cache", "ls /var/lib",
    "ls -la /etc/security", "cat /etc/pam.conf 2>/dev/null", "ls /etc/pam.d",
    "ls /etc/ssh", "cat /etc/ssh/ssh_config", "ls /etc/ssl", "ls /etc/ca-certificates",
    "ls /usr/local/bin", "ls /usr/local/sbin", "ls /usr/games", "ls /usr/include",
    "ls /usr/lib64 2>/dev/null", "ls /usr/libexec", "ls /usr/src", "ls /srv",
    "cat /etc/crontab", "cat /etc/anacrontab", "ls /etc/cron.d", "ls /etc/cron.hourly",
    "ls /etc/cron.weekly", "ls /etc/cron.monthly", "cat /etc/group-", "cat /etc/passwd-",
    "ls /etc/modprobe.d", "cat /etc/modules-load.d/*.conf 2>/dev/null",
    "ls /etc/sysctl.d", "cat /etc/sysctl.conf", "ls /etc/udev/rules.d",
    "ls /etc/systemd", "ls /etc/logrotate.d", "ls /etc/alternatives",
    "ls /etc/apparmor.d 2>/dev/null", "ls /etc/grub.d 2>/dev/null",
    "cat /etc/default/grub 2>/dev/null", "ls /etc/kernel", "ls /etc/terminfo",
    "ls /etc/vim", "cat /etc/vim/vimrc 2>/dev/null", "ls /etc/fonts",
    "ls /etc/xml", "ls /etc/sgml", "ls /etc/dbus-1", "ls /etc/dconf",
    "ls /etc/depmod.d", "ls /etc/ghostscript", "ls /etc/groff",
    "ls /etc/inputrc", "ls /etc/magic", "ls /etc/mime.types", "ls /etc/mke2fs.conf",
    "ls /etc/nanorc", "ls /etc/networks", "ls /etc/pnm2ppa.conf 2>/dev/null"
]

if __name__ == "__main__":
    # Ensure command_runner.py and sender.py are in the same directory
    runner = CommandRunner(COMMAND_LIST)
    
    print(f"[*] Loaded {len(COMMAND_LIST)} safe Linux commands.")
    print("[*] Starting realistic C2 simulation...")
    
    # Run 5 rounds to generate ~1500 packets (adds to your 'Gigabytes' goal)
    runner.start_session(rounds=5)