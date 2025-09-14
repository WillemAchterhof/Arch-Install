# Arch-Install
Tailored for my laptop, based on "Ataraxxia secure-arch"


# ==============================================================================
#  0. Cleanup Disk (Partition Table & Filesystem Signatures)
# ==============================================================================
wipefs --all --force /dev/nvme0n1
wipefs -n /dev/nvme0n1
sgdisk --zap-all /dev/nvme0n1

# ==============================================================================
#  1. Partitioning
# ==============================================================================
sgdisk --new=1:0:+512MiB --typecode=1:EF00 --change-name=1:"EFI System Partition" /dev/nvme0n1
sgdisk --new=2:0:0 --typecode=2:8309 --change-name=2:"Encrypted Root" /dev/nvme0n1
partprobe /dev/nvme0n1  # Reload partition table

# ==============================================================================
#  2. Encryption (LUKS2) and Open
# ==============================================================================
cryptsetup luksFormat --type luks2 --label cryptroot /dev/nvme0n1p2
cryptsetup open --persistent /dev/nvme0n1p2 cryptroot

# ==============================================================================
#  3. LVM Setup
# ==============================================================================
pvcreate /dev/mapper/cryptroot
vgcreate vg /dev/mapper/cryptroot
lvcreate -l 100%FREE vg -n root

# ==============================================================================
#  4. Filesystem Creation
# ==============================================================================
mkfs.fat -F32 -n ESP /dev/nvme0n1p1
mkfs.btrfs -f -L archroot /dev/vg/root

# ==============================================================================
#  5. Mounting & Btrfs Subvolumes
# ==============================================================================
mount /dev/vg/root /mnt
btrfs subvolume create /mnt/@
btrfs subvolume create /mnt/@home
btrfs subvolume create /mnt/@var
btrfs subvolume create /mnt/@snapshots
umount /mnt

mount -o noatime,compress=zstd,subvol=@ /dev/vg/root /mnt
mkdir -p /mnt/{home,var,.snapshots,boot/efi}
mount -o noatime,compress=zstd,subvol=@home      /dev/vg/root /mnt/home
mount -o noatime,compress=zstd,subvol=@var       /dev/vg/root /mnt/var
mount -o noatime,compress=zstd,subvol=@snapshots /dev/vg/root /mnt/.snapshots
mount /dev/nvme0n1p1 /mnt/boot/efi  # EFI Partition

# ==============================================================================
#  6. Time & NTP
# ==============================================================================
if ! timedatectl show --property=NTPSynchronized | grep -q "NTPSynchronized=yes"; then
  timedatectl set-ntp true
fi
timedatectl set-timezone Europe/Amsterdam
ln -sf /usr/share/zoneinfo/Europe/Amsterdam /etc/localtime
hwclock --systohc

# ==============================================================================
#  7. Base System Installation
# ==============================================================================
vim /etc/pacman.conf  # change ParallelDownloads to 12
pacstrap -K /mnt \
  base base-devel linux linux-firmware \
  btrfs-progs cryptsetup \
  dracut \
  sbctl sbsigntools \
  tpm2-tss tpm2-tools \
  efibootmgr \
  lvm2 \
  amd-ucode \
  apparmor \
  bluez bluez-utils \
  networkmanager iwd \
  git neovim sudo man-db reflector openssh timeshift binutils inotify-tools \
  zsh zsh-completions zsh-autosuggestions kitty pacman

genfstab -U /mnt >> /mnt/etc/fstab
clear
cat /mnt/etc/fstab

arch-chroot /mnt
clear

# ==============================================================================
#  8. Environment Variables
# ==============================================================================
cat <<EOF > /etc/environment
GTK_IM_MODULE=fcitx
QT_IM_MODULE=fcitx
XMODIFIERS=@im=fcitx
TERMINAL=kitty
EDITOR=nvim
VISUAL=nvim
SHELL=/usr/bin/zsh
EOF
clear
cat /etc/environment

# ==============================================================================
#  9. Pacman Configuration & Mirror Setup
# ==============================================================================
sed -i \
  -e 's/^ParallelDownloads =.*/ParallelDownloads = 100/' \
  -e 's/^#Color/Color/' \
  -e '/^#\[multilib\]/,/^#Include = \/etc\/pacman.d\/mirrorlist/ s/^#//' \
  /etc/pacman.conf
clear
cat /etc/pacman.conf

reflector --country Netherlands,Germany --age 10 --protocol https --sort rate \
  --save /etc/pacman.d/mirrorlist
clear
cat /etc/pacman.d/mirrorlist
pacman -Sy

# ==============================================================================
#  10. Essential Services
# ==============================================================================
systemctl enable systemd-timesyncd
systemctl enable reflector.timer
systemctl enable fstrim.timer
systemctl enable apparmor
systemctl enable bluetooth
systemctl enable NetworkManager

# Configure NetworkManager to use iwd
cat <<EOF > /etc/NetworkManager/NetworkManager.conf
[device]
wifi.backend=iwd
EOF
clear
cat /etc/NetworkManager/NetworkManager.conf

# ==============================================================================
#  11. Localization & Keyboard
# ==============================================================================
sed -i '/^#en_US.UTF-8 UTF-8/s/^#//' /etc/locale.gen
sed -i '/^#ja_JP.UTF-8 UTF-8/s/^#//' /etc/locale.gen
clear
cat /etc/locale.gen

cat <<EOF > /etc/locale.conf
LANG=en_US.UTF-8
LC_CTYPE=ja_JP.UTF-8
EOF
clear
cat /etc/locale.conf

echo KEYMAP=us-intl > /etc/vconsole.conf
clear
cat /etc/vconsole.conf

pacman -S --noconfirm \
  noto-fonts-cjk \
  fcitx5 fcitx5-mozc fcitx5-configtool

cp /usr/share/applications/org.fcitx.Fcitx5.desktop /etc/xdg/autostart/
locale-gen

# ==============================================================================
#  12. Hostname & Hosts
# ==============================================================================
echo Arch-WA > /etc/hostname
echo "127.0.1.1   Arch-WA.localdomain Arch-WA" >> /etc/hosts
clear
cat /etc/hosts

# ==============================================================================
#  13. User & Root Setup
# ==============================================================================
passwd
sed -i '/^# %wheel ALL=(ALL:ALL) ALL/s/^# //' /etc/sudoers
cat /etc/sudoers

useradd -mG wheel,users -s /bin/zsh willem
passwd willem
sudo passwd root -l

# ==============================================================================
#  14. Dracut Setup & Pacman Hooks
# ==============================================================================
mkdir -p /usr/local/bin
cat <<EOF > /usr/local/bin/dracut-install.sh
#!/usr/bin/env bash
mkdir -p /boot/efi/EFI/Linux
while read -r line; do
	if [[ "$line" == 'usr/lib/modules/'+([^/])'/pkgbase' ]]; then
		kver="\${line#'usr/lib/modules/'}"
		kver="\${kver%'/pkgbase'}"
		dracut --force --uefi --kver "\$kver" /boot/efi/EFI/Linux/bootx64.efi
	fi
done
EOF
vim /usr/local/bin/dracut-install.sh

cat <<EOF > /usr/local/bin/dracut-remove.sh
#!/usr/bin/env bash
rm -f /boot/efi/EFI/Linux/bootx64.efi
EOF

chmod +x /usr/local/bin/dracut-*

mkdir -p /etc/pacman.d/hooks
cat <<EOF > /etc/pacman.d/hooks/90-dracut-install.hook
[Trigger]
Type = Path
Operation = Install
Operation = Upgrade
Target = usr/lib/modules/*/pkgbase
[Action]
Description = Updating linux EFI image
When = PostTransaction
Exec = /usr/local/bin/dracut-install.sh
Depends = dracut
NeedsTargets
EOF

cat <<EOF > /etc/pacman.d/hooks/60-dracut-remove.hook
[Trigger]
Type = Path
Operation = Remove
Target = usr/lib/modules/*/pkgbase
[Action]
Description = Removing linux EFI image
When = PreTransaction
Exec = /usr/local/bin/dracut-remove.sh
NeedsTargets
EOF

# ==============================================================================
#  15. Kernel Flags for Dracut
# ==============================================================================
UUID=$(blkid -s UUID -o value /dev/nvme0n1p2)
cat << EOF > /etc/dracut.conf.d/cmdline.conf
kernel_cmdline="rd.luks.uuid=$UUID rd.luks.options=tpm2-device=auto rd.lvm.lv=vg/root root=/dev/mapper/vg-root rootfstype=btrfs rootflags=subvol=/@,rw,relatime"
EOF

cat <<EOF > /etc/dracut.conf.d/flags.conf
compress="zstd"
hostonly="no"
EOF

pacman -S linux
ls -alh /boot/efi/EFI/Linux/

# ==============================================================================
#  16. Bootloader & Secure Boot
# ==============================================================================
efibootmgr -b * -B  # remove all existing entries
efibootmgr --create --disk /dev/nvme0n1 --part 1 --label "Arch Linux" --loader 'EFI\Linux\bootx64.efi' --unicode
efibootmgr -o 0000

sbctl status
sbctl create-keys
sbctl sign -s /boot/efi/EFI/Linux/bootx64.efi

cat <<EOF > /etc/dracut.conf.d/secureboot.conf
uefi_secureboot_cert="/var/lib/sbctl/keys/db/db.pem"
uefi_secureboot_key="/var/lib/sbctl/keys/db/db.key"
EOF

cat <<EOF > /etc/pacman.d/hooks/zz-sbctl.hook
[Trigger]
Type = Path
Operation = Install
Operation = Upgrade
Operation = Remove
Target = boot/*
Target = efi/*
Target = usr/lib/modules/*/vmlinuz
Target = usr/lib/initcpio/*
Target = usr/lib/**/efi/*.efi*
[Action]
Description = Signing EFI binaries...
When = PostTransaction
Exec = /usr/bin/sbctl sign /boot/efi/EFI/Linux/bootx64.efi
EOF

sbctl enroll-keys -m
systemd-cryptenroll /dev/nvme0n1p2 --wipe-slot=empty --tpm2-device=auto

# ==============================================================================
# 17. Prepare Timeshift Configuration (Btrfs, manual snapshots)
# ==============================================================================
mkdir -p /etc/timeshift
sudo rm -f /etc/timeshift/default.json
blkid -s UUID -o value /dev/dm-1

cat <<EOF > /etc/timeshift/default.json
{
    "backup_device_uuid": "$UUID",
    "snapshot_device": "/dev/dm-1",
    "do_first_run": false,
    "btrfs_mode": true,
    "snapshot_name": "manual",
    "include_btrfs_home": false,
    "snapshot_limit": 1,
    "snapshot_dirs": ["@", "@var"],
    "exclude": ["@home"],
    "boot_dirs": ["/boot"]
}
EOF
clear
cat /etc/timeshift/default.json

# ==============================================================================
#  18. Hardening: Firewall (nftables) & Kernel
# ==============================================================================
# This section sets up nftables for packet filtering and applies kernel hardening
# settings for networking security and system resilience.

# --------------------------
# 18.1. Configure nftables
# --------------------------
cat <<EOF > /etc/nftables.conf
#!/usr/bin/nft -f

# Clean up any existing table to ensure a fresh start

table inet filter {
  chain input {
    type filter hook input priority filter;
    policy drop;

    # Drop invalid packets early
    ct state invalid drop comment "Drop invalid connections"

    # Accept established and related connections
    ct state { established, related } accept comment "Allow tracked connections"

    # Allow loopback interface
    iifname "lo" accept comment "Allow loopback traffic"

    # Allow ICMP (IPv4 and IPv6)
    ip protocol icmp accept comment "Allow ICMP (IPv4)"
    meta l4proto ipv6-icmp accept comment "Allow ICMPv6"

    # Rate limit incoming packets to prevent abuse
    pkttype host limit rate 5/second counter reject with icmpx type admin-prohibited comment "Rate limit and reject excess traffic"

    # Count all other dropped packets for logging/statistics
    counter comment "Count dropped packets"
  }

  chain forward {
    type filter hook forward priority filter;
    policy drop;
  }

  chain output {
    type filter hook output priority filter;
    policy accept;
  }
}
EOF

# Enable nftables on boot
systemctl enable nftables

# --------------------------
# 18.2. Kernel Hardening Settings
# --------------------------
cat <<EOF > /etc/sysctl.d/99-hardening.conf
# Disable IP forwarding (prevent routing)
net.ipv4.ip_forward = 0
net.ipv6.conf.all.forwarding = 0

# Disable ICMP redirects (prevent MITM attacks)
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0

# Do not send ICMP redirects
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0

# Disable source routing
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0

# Enable reverse path filtering (anti-spoofing)
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# Protect against SYN flood attacks
net.ipv4.tcp_syncookies = 1

# Ignore broadcast pings (Smurf attack protection)
net.ipv4.icmp_echo_ignore_broadcasts = 1

# Ignore bogus ICMP error responses
net.ipv4.icmp_ignore_bogus_error_responses = 1

# Harden kernel pointers (hide from /proc and logs)
kernel.kptr_restrict = 2

# Restrict access to dmesg (only root)
kernel.dmesg_restrict = 1

# Disable core dumps from setuid binaries
fs.suid_dumpable = 0
EOF

# Apply kernel parameters immediately
sysctl --system

# ==============================================================================
# 19. Utilities Installation & USB Security
# ==============================================================================
# Install password manager and enforce USB security.

# Install KeepassXC (password manager) and USBGuard (USB device control)
pacman -S --noconfirm keepassxc usbguard timeshift

# Enable USBGuard service to enforce USB device policies at boot
systemctl enable usbguard

# ==============================================================================
# 20. System Cleanup & Journal Maintenance &  base snapshot
# ==============================================================================
# Rotate system logs, clean old journal entries, and clear temporary files.

# Rotate journal logs
journalctl --rotate

# Remove old journal files to free space
journalctl --vacuum-time=1s

# Clear temporary files
rm -rf /var/tmp/*

# Clean cached package files from Pacman
pacman -Sc --noconfirm

sudo timeshift --create --comments "Base system snapshot, clean setup" --tags D

# ==============================================================================
# 21. User & Root Hardening
# ==============================================================================
# Lock root account to prevent direct login and ensure sudo access via user account.

# Switch to the standard user 'willem'
su willem

# Lock root account
sudo passwd root -l

exit
reboot
