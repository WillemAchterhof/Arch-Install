
# ==============================================================================
#  Arch Linux Full Install (Willem Edition) Part One
#  Secure + Btrfs + LUKS2 + TPM2 + Secure Boot + Plymouth
# ==============================================================================

# ---------------------------
# 0. Cleanup Disk
# ---------------------------
wipefs --all --force /dev/nvme0n1
wipefs -n /dev/nvme0n1
sgdisk --zap-all /dev/nvme0n1

# ---------------------------
# 1. Partitioning
# ---------------------------
sgdisk --new=1:0:+512MiB --typecode=1:EF00 --change-name=1:"EFI System Partition" /dev/nvme0n1
sgdisk --new=2:0:0 --typecode=2:8309 --change-name=2:"Encrypted Root" /dev/nvme0n1
partprobe /dev/nvme0n1

# ---------------------------
# 2. Encryption (LUKS2)
# ---------------------------
cryptsetup luksFormat --type luks2 --label cryptroot /dev/nvme0n1p2
cryptsetup open /dev/nvme0n1p2 root

# ---------------------------
# 3. Filesystem Creation
# ---------------------------
mkfs.fat -F32 -n ESP /dev/nvme0n1p1
mkfs.btrfs -L archroot /dev/mapper/root

# ---------------------------
# 4. Mounting & Btrfs Subvolumes
# ---------------------------
mount /dev/mapper/root /mnt
btrfs subvolume create /mnt/@
btrfs subvolume create /mnt/@home
btrfs subvolume create /mnt/@snapshots
umount /mnt

mount -o noatime,compress=zstd,ssd,subvol=@ /dev/mapper/root /mnt
mkdir -p /mnt/{home,.snapshots,boot}
mount -o noatime,compress=zstd,ssd,subvol=@home /dev/mapper/root /mnt/home
mount -o noatime,compress=zstd,ssd,subvol=@snapshots /dev/mapper/root /mnt/.snapshots
mount /dev/nvme0n1p1 /mnt/boot  # ESP mounted at /boot for systemd-boot

# ---------------------------
# 5. Time & NTP
# ---------------------------
timedatectl set-ntp true
timedatectl set-timezone Europe/Amsterdam

# ---------------------------
# 6. Base System Installation
# ---------------------------
sed -i \
  -e 's/^ParallelDownloads =.*/ParallelDownloads = 20/' \
  -e 's/^#Color/Color/' \
  -e '/^#\[multilib\]/,/^#Include = \/etc\/pacman.d\/mirrorlist/ s/^#//' \
  /etc/pacman.conf

reflector --country Netherlands,Germany --age 10 --protocol https --sort rate \
  --save /etc/pacman.d/mirrorlist

pacstrap -K /mnt \
  base base-devel linux linux-firmware \
  btrfs-progs cryptsetup \
  mkinitcpio \
  sbctl sbsigntools efibootmgr \
  tpm2-tss tpm2-tools \
  amd-ucode \
  apparmor nftables usbguard \
  networkmanager iwd \
  sudo git neovim man-db reflector \
  zsh zsh-completions zsh-autosuggestions \
  alacritty \
  binutils inotify-tools \
  plymouth \
  timeshift \
  bluez bluez-utils pipewire pipewire-alsa pipewire-pulse pipewire-jack wireplumber \
  mesa vulkan-radeon libva-mesa-driver lib32-mesa lib32-vulkan-radeon lib32-libva-mesa-driver 

genfstab -U /mnt >> /mnt/etc/fstab
arch-chroot /mnt

# ---------------------------
# 8. Environment Variables
# ---------------------------
cat <<EOF > /etc/environment
TERMINAL=alacritty
EDITOR=nvim
VISUAL=nvim
SHELL=/usr/bin/zsh
EOF

# ---------------------------
# 9. Pacman & Mirrors (inside chroot)
# ---------------------------
timedatectl set-ntp true
ln -sf /usr/share/zoneinfo/Europe/Amsterdam /etc/localtime
hwclock --systohc

sed -i \
  -e 's/^ParallelDownloads =.*/ParallelDownloads = 20/' \
  -e 's/^#Color/Color/' \
  -e '/^#\[multilib\]/,/^#Include = \/etc\/pacman.d\/mirrorlist/ s/^#//' \
  /etc/pacman.conf
clear
cat /etc/pacman.conf

reflector --country Netherlands,Germany --age 10 --protocol https --sort rate \
  --save /etc/pacman.d/mirrorlist
clear
cat /etc/pacman.d/mirrorlist

pacman -Syu --noconfirm

# ---------------------------
# 10. Essential Services
# ---------------------------
systemctl enable systemd-timesyncd
systemctl enable reflector.timer
systemctl enable fstrim.timer
systemctl enable apparmor
systemctl enable NetworkManager
systemctl enable usbguard
systemctl enable nftables
systemctl enable bluetooth

cat <<EOF > /etc/NetworkManager/NetworkManager.conf
[device]
wifi.backend=iwd
EOF

# ---------------------------
# 11. Localization & Keyboard
# ---------------------------
sed -i '/^#en_US.UTF-8 UTF-8/s/^#//' /etc/locale.gen
locale-gen

cat <<EOF > /etc/locale.conf
LANG=en_US.UTF-8
EOF

echo KEYMAP=us > /etc/vconsole.conf

# ---------------------------
# 12. Hostname & Hosts
# ---------------------------
echo Arch-WA > /etc/hostname
cat <<'EOF' > /etc/hosts
127.0.0.1   localhost
::1         localhost
127.0.1.1   Arch-WA.localdomain Arch-WA
EOF
clear
cat /etc/hosts

# ---------------------------
# 13. User & Root Setup
# ---------------------------
passwd
sed -i '/^# %wheel ALL=(ALL:ALL) ALL/s/^# //' /etc/sudoers

useradd -mG wheel,users -s /bin/zsh willem
passwd willem

# ---------------------------
# 14. mkinitcpio Basics & Plymouth
# ---------------------------
sed -i 's/^MODULES=.*/MODULES=()/' /etc/mkinitcpio.conf
sed -i 's/^BINARIES=.*/BINARIES=()/' /etc/mkinitcpio.conf
sed -i 's|^HOOKS=.*|HOOKS=(base systemd autodetect microcode modconf kms keyboard sd-vconsole plymouth block sd-encrypt filesystems fsck)|' /etc/mkinitcpio.conf
sed -i 's|^#*COMPRESSION=.*|COMPRESSION="zstd"|' /etc/mkinitcpio.conf
sed -i 's|^#*COMPRESSION_OPTIONS=.*|COMPRESSION_OPTIONS="-3"|' /etc/mkinitcpio.conf

UUID=$(blkid -s UUID -o value /dev/nvme0n1p2)
cat <<EOF > /etc/kernel/cmdline
quiet splash rd.luks.name=$UUID=root rd.luks.options=tpm2-device=auto \
root=/dev/mapper/root rootfstype=btrfs rootflags=subvol=/@,rw,noatime \
lsm=landlock,lockdown,yama,apparmor,bpf apparmor=1
EOF
clear
cat /etc/kernel/cmdline

mkinitcpio -P

# ---------------------------
# 15. mkinitcpio Presets & Bootloader
# ---------------------------
cat <<EOF > /etc/mkinitcpio.d/linux.preset
PRESETS=('default' 'fallback')
ALL_kver="/boot/vmlinuz-linux"
default_uki="/boot/EFI/Linux/arch-linux.efi"
fallback_uki="/boot/EFI/Linux/arch-linux-fallback.efi"
fallback_options="-S autodetect"
EOF
clear
cat /etc/mkinitcpio.d/linux.preset

bootctl install

# ---------------------------
# 16. Pacman Hooks for sbctl Signing (UKIs)
# ---------------------------
mkdir -p /etc/pacman.d/hooks
cat <<'EOF' > /etc/pacman.d/hooks/zz-sbctl-uki.hook
[Trigger]
Type = Path
Operation = Install
Operation = Upgrade
Operation = Replace
Target = /boot/EFI/Linux/*.efi

[Action]
Description = Signing UKIs with sbctl...
When = PostTransaction
Exec = /usr/bin/sbctl sign --path /boot/EFI/Linux
NeedsTargets
EOF
clear
cat /etc/pacman.d/hooks/zz-sbctl-uki.hook

# ---------------------------
# 17. Secure Boot & TPM2 Enrollment
# ---------------------------
sbctl create-keys
sbctl enroll-keys --yes-this-might-brick-my-machine
mkinitcpio -P
sbctl sign --all
sbctl verify

systemd-cryptenroll /dev/nvme0n1p2 --recovery-key
systemd-cryptenroll /dev/nvme0n1p2 --tpm2-device=auto --tpm2-with-pin=true

# ---------------------------
# 18. Firewall & Kernel Hardening
# ---------------------------
cat <<'EOF' > /etc/nftables.conf
table inet filter {
  chain input {
    type filter hook input priority filter;
    policy drop;

    ct state invalid drop
    ct state { established, related } accept
    iifname "lo" accept

    # ICMPv4 / ICMPv6
    ip protocol icmp accept
    meta l4proto ipv6-icmp accept

    # DHCPv4/v6
    udp dport { 67, 68 } accept
    udp dport { 546, 547 } accept

    # mDNS
    ip daddr 224.0.0.251 udp dport 5353 accept
    ip6 daddr ff02::fb   udp dport 5353 accept
  }
  chain forward { type filter hook forward priority filter; policy drop; }
  chain output { type filter hook output priority filter; policy accept; }
}
EOF

cat <<'EOF' > /etc/sysctl.d/99-hardening.conf
net.ipv4.ip_forward = 0
net.ipv6.conf.all.forwarding = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
fs.suid_dumpable = 0
EOF

# ---------------------------
# 19. USBGuard & MAC Randomization
# ---------------------------
usbguard generate-policy | tee /etc/usbguard/rules.conf

# Persistently block new devices and apply policy to present devices
cat <<'EOF' > /etc/usbguard/usbguard-daemon.conf
ImplicitPolicyTarget=block
PresentDevicePolicy=apply-policy
EOF
systemctl restart usbguard

cat <<EOF > /etc/NetworkManager/conf.d/20-mac-randomize.conf
[connection]
wifi.cloned-mac-address=random
ethernet.cloned-mac-address=random
EOF

# ---------------------------
# 20. Disable unnecessary services
# ---------------------------
systemctl disable \
  NetworkManager-dispatcher.service \
  NetworkManager-wait-online.service \
  systemd-homed-activate.service \
  systemd-homed.service \
  systemd-network-generator.service \
  systemd-networkd-wait-online.service \
  systemd-networkd.service \
  systemd-pstore.service \
  systemd-resolved.service \
  systemd-journald-audit.socket \
  systemd-mountfsd.socket \
  systemd-nsresourced.socket \
  machines.target \
  remote-integritysetup.target \
  remote-veritysetup.target

# ---------------------------
# 21. Timeshift Setup
# ---------------------------
mkdir -p /etc/timeshift
UUID=$(blkid -s UUID -o value /dev/mapper/root)
cat <<EOF > /etc/timeshift/default.json
{
    "backup_device_uuid": "$UUID",
    "snapshot_device": "$UUID",
    "do_first_run": false,
    "btrfs_mode": true,
    "snapshot_name": "manual",
    "include_btrfs_home": false,
    "snapshot_limit": 1,
    "snapshot_dirs": ["/@"],
    "exclude": ["/@home"],
    "boot_dirs": ["/boot"]
}
EOF

# ---------------------------
# 22. Post-Reboot User & Checks
# ---------------------------
Switch to standard user:
su - willem
sudo passwd root -l
sudo nft list ruleset
sudo sysctl --system
sudo aa-status
sudo sbctl verify
sudo usbguard list-devices
chmod 700 /home/willem

# ---------------------------
# 23. System Cleanup & Base Snapshot
# ---------------------------
sudo journalctl --rotate
sudo journalctl --vacuum-time=1s
sudo rm -rf /var/tmp/*
sudo pacman -Sc --noconfirm
sudo timeshift --create --comments "Base system, clean setup" --tags D
