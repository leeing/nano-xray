#!/usr/bin/env bash
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  nano-xray 服务器初始化脚本（幂等，可重复运行）
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
set -euo pipefail

info()  { echo -e "\033[0;32m[INFO]\033[0m  $*"; }
warn()  { echo -e "\033[1;33m[WARN]\033[0m  $*"; }

# ── 1. 基础工具 ──────────────────────────────────────────
info "安装基础工具..."
apt update -y
apt install -y wget git curl tmux htop sysstat vnstat

# ── 2. SSH 公钥 ──────────────────────────────────────────
info "配置 SSH 公钥..."
mkdir -p /root/.ssh && chmod 700 /root/.ssh

if [ ! -f /root/.ssh/id_rsa ]; then
  ssh-keygen -t rsa -N "" -f /root/.ssh/id_rsa
  info "  生成服务器密钥对 ✓"
fi

KEYS=(
  "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDnKS1aDPp1ObH5gd0GgQVjbZtK+8kvV4kmsRRM2z88n7+P0jZNjhFGlQe/LLgzor8vB4D3ylxjlOrtmhHvzidq42KQomj8L6wjUfOjfFRK2jMJNhyNjOJbG0llZJW8eZxW8S/j96wJxqQHgNbxs793S9s1Cncq0GQ6evQMPA+8A2Z/+xBsDi344UFrrn3d0pzNsbxARy4fjGR8MEzdTK/3eVOqYRpLYuXyfh6cJaS+glwNh2azAwXpmjLdlF2EFeqWy2igdZYU2n0X6q0ogxq66LFJOXOKOR6HmU7lCWq1NEhxKIkOk2Y5ZLEcXG91l5+ZC4Zc4cahzQcsMRV8MF91iY+4nkWkrZY0a52Qalul4zByLDWz6W3HiqPn77md+N2rr/DFdwqof10uTbVm0fJvsuVabWd7qTP7BF1PZp71Wab/U3QsGVoOvgFEPtIB9Z+NO4ecs4d7RIT5Vffxsy6HjKMEaXiAnY3K/p8z2SXHRdlmNTFOvx6SRSg6vmmr2V8= qadmlee@airlee.local"
  "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC6+7d79iZ0FiK5dHoVEdPyOxMAjNzHpnMUOynJAie9iRTMy+YpOddyRPdGX1U/ROj95feSUJw/AmUNtvjuKV9eyXjP5Uet7mpLFDPYD89SQ8+WdRVnQ/kzc0p2nI+1TBKsHBX6a+ODQBnw07pHLIjgONlqUjZffe6ndotmkTVUxOdQ0B9vI5RkIz1UE4+qlqu0x6Kerg2G2xJyy00BRGAfOmsGAcl1oIsmoACbUJP4Vj7PAGORkImhFczijiFiqFQ/7CjkKPFVy6B1If/MWtsQomqQP7tREFr2mVPO6VzGBU59/qs1los2LjlrE5iHm3UuEP7aJW43bfAC5tqyjt/Zim0VckhxKj/O91HxKqRym5ehm5FkZL+Mffq1uYbprCgfFqhMsGTtiWw63yZZfc2k79IN2CMdZKlTCImMn7QICwElkQuva4/jfhGX8SUwzY8QzYI9hs1FWehEexF5rdgSBlEFeo1Tsp28IWXnAj6bboMhhyGINDL1dvJvYF8awwE= qadmlee@minilee.local"
)

for key in "${KEYS[@]}"; do
  if ! grep -qF "$key" /root/.ssh/authorized_keys 2>/dev/null; then
    echo "$key" >> /root/.ssh/authorized_keys
    info "  添加公钥: ${key##* }"
  fi
done
chmod 600 /root/.ssh/authorized_keys

# ── 3. 时区 ──────────────────────────────────────────────
info "设置时区 Asia/Shanghai..."
timedatectl set-timezone Asia/Shanghai

# ── 4. SSH 加固 ──────────────────────────────────────────
info "部署 sshd_config..."
cp scripts/sshd_config /etc/ssh/sshd_config
systemctl restart sshd

# ── 5. Docker ────────────────────────────────────────────
if command -v docker &>/dev/null; then
  info "Docker 已安装，跳过"
else
  info "安装 Docker..."
  # 清理旧包（忽略不存在的包）
  for pkg in docker.io docker-compose docker-doc podman-docker containerd runc; do
    dpkg -l "$pkg" &>/dev/null && apt remove -y "$pkg" || true
  done

  apt install -y ca-certificates curl
  install -m 0755 -d /etc/apt/keyrings
  curl -fsSL https://download.docker.com/linux/debian/gpg -o /etc/apt/keyrings/docker.asc
  chmod a+r /etc/apt/keyrings/docker.asc

  tee /etc/apt/sources.list.d/docker.sources <<EOF
Types: deb
URIs: https://download.docker.com/linux/debian
Suites: $(. /etc/os-release && echo "$VERSION_CODENAME")
Components: stable
Signed-By: /etc/apt/keyrings/docker.asc
EOF

  apt update
  apt install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
  info "Docker 安装完成 ✓"
fi

# ── 6. 网络调优（BBR + 代理优化） ────────────────────────
info "配置网络参数..."
SYSCTL_PARAMS=(
  # BBR 拥塞控制
  "net.core.default_qdisc=fq"
  "net.ipv4.tcp_congestion_control=bbr"
  # TCP Fast Open（加速 TLS 握手）
  "net.ipv4.tcp_fastopen=3"
  # 空闲后不重置拥塞窗口
  "net.ipv4.tcp_slow_start_after_idle=0"
  # 自动探测 MTU，避免分片
  "net.ipv4.tcp_mtu_probing=1"
  # 连接队列上限
  "net.ipv4.tcp_max_syn_backlog=8192"
  "net.core.somaxconn=8192"
  # TCP 缓冲区（最大 64MB，适合高带宽代理）
  "net.ipv4.tcp_rmem=4096 87380 67108864"
  "net.ipv4.tcp_wmem=4096 65536 67108864"
  "net.core.rmem_max=67108864"
  "net.core.wmem_max=67108864"
)

for param in "${SYSCTL_PARAMS[@]}"; do
  grep -qF "$param" /etc/sysctl.conf || echo "$param" >> /etc/sysctl.conf
done
sysctl -p

# ── 7. UFW 防火墙 ────────────────────────────────────────
info "配置 UFW..."
apt install -y ufw
ufw default deny incoming
ufw default allow outgoing
ufw allow 22/tcp
ufw allow 80/tcp
ufw allow 443/tcp
ufw allow 443/udp
if ! ufw status | grep -q "Status: active"; then
  yes | ufw enable
  info "  UFW 已启用 ✓"
else
  info "  UFW 已处于活跃状态，跳过启用"
fi

# ── 8. fail2ban ──────────────────────────────────────────
info "配置 fail2ban..."
apt install -y fail2ban
cp scripts/defaults-debian.conf /etc/fail2ban/jail.d/
systemctl restart fail2ban

# ── 完成 ─────────────────────────────────────────────────
echo ""
info "========================================="
info "  服务器初始化完成 ✓"
info "========================================="
info "  时区: $(timedatectl show -p Timezone --value)"
info "  Docker: $(docker --version 2>/dev/null || echo '未安装')"
info "  BBR: $(sysctl net.ipv4.tcp_congestion_control 2>/dev/null)"
info "  fail2ban: $(systemctl is-active fail2ban)"
echo ""
