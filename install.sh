#!/usr/bin/env bash
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

apt-get update
apt-get install -y wireguard wireguard-tools ufw python3 python3-venv python3-pip git acl build-essential jq curl

WG_IFACE=${WG_IFACE:-wg0}
WG_DIR=${WG_DIR:-/etc/wireguard}
WG_CONF=${WG_CONF:-${WG_DIR}/${WG_IFACE}.conf}
WG_PORT=${WG_PORT:-51820}
SERVER_ADDR=${SERVER_ADDR:-10.8.0.1/24}
DASH_DIR=${DASH_DIR:-/opt/WireGuard-Dashboard}
DASH_ENV=${DASH_DIR}/.venv
DASH_PORT=${DASH_PORT:-8088}
APP_MODULE=${APP_MODULE:-app:app}
REPO_URL=${REPO_URL:-https://github.com/Migrim/Wireguard-Dashboard.git}
BRANCH=${BRANCH:-main}

# figure out outgoing iface
NET_IF=$(ip route get 1.1.1.1 | awk '{for(i=1;i<=NF;i++){if($i=="dev"){print $(i+1); exit}}}')

# make wg dir readable for www-data group
install -d -m 750 -g www-data "${WG_DIR}"

# 1) keys
if [ ! -f "${WG_DIR}/server_privatekey" ]; then
  umask 077
  wg genkey | tee "${WG_DIR}/server_privatekey" | wg pubkey > "${WG_DIR}/server_publickey"
  chgrp www-data "${WG_DIR}/server_privatekey" "${WG_DIR}/server_publickey" || true
  chmod 640 "${WG_DIR}/server_privatekey" "${WG_DIR}/server_publickey" || true
fi

# 2) wg0.conf
if [ ! -f "${WG_CONF}" ]; then
  umask 077
  cat > "${WG_CONF}" <<CFG
[Interface]
Address = ${SERVER_ADDR}
ListenPort = ${WG_PORT}
PrivateKey = $(cat "${WG_DIR}/server_privatekey")
CFG
else
  umask 077
  grep -qE '^[[:space:]]*Address[[:space:]]*=' "${WG_CONF}" || printf '\nAddress = %s\n' "${SERVER_ADDR}" >> "${WG_CONF}"
  grep -qE '^[[:space:]]*ListenPort[[:space:]]*=' "${WG_CONF}" || printf 'ListenPort = %s\n' "${WG_PORT}" >> "${WG_CONF}"
  grep -qE '^[[:space:]]*PrivateKey[[:space:]]*=' "${WG_CONF}" || printf 'PrivateKey = %s\n' "$(cat "${WG_DIR}/server_privatekey")" >> "${WG_CONF}"
fi
chgrp www-data "${WG_CONF}"
chmod 640 "${WG_CONF}"

# 3) peers db
if [ ! -f "${WG_DIR}/peers.json" ]; then
  echo '{}' > "${WG_DIR}/peers.json"
fi
chgrp www-data "${WG_DIR}/peers.json"
chmod 640 "${WG_DIR}/peers.json"

# 4) sysctl + ufw
sysctl -w net.ipv4.ip_forward=1 >/dev/null
grep -q '^net.ipv4.ip_forward=1$' /etc/sysctl.conf || echo net.ipv4.ip_forward=1 >> /etc/sysctl.conf

ufw allow OpenSSH || true
ufw allow ${WG_PORT}/udp || true
ufw allow ${DASH_PORT}/tcp || true
ufw --force enable

# 5) NAT rule (FIXED: embed SERVER_ADDR instead of reading env in python)
WG_NET=$(python3 - <<PY
import ipaddress
print(ipaddress.ip_interface("${SERVER_ADDR}").network)
PY
)
if ! grep -q "START WIREGUARD NAT" /etc/ufw/before.rules 2>/dev/null; then
  tmpf=$(mktemp)
  awk '1; END{print "# START WIREGUARD NAT\n*nat\n:POSTROUTING ACCEPT [0:0]\n-A POSTROUTING -s '"${WG_NET}"' -o '"${NET_IF}"' -j MASQUERADE\nCOMMIT\n# END WIREGUARD NAT"}' /etc/ufw/before.rules > "$tmpf"
  install -m 644 "$tmpf" /etc/ufw/before.rules
  rm -f "$tmpf"
fi
sed -i 's/^#\?DEFAULT_FORWARD_POLICY=.*/DEFAULT_FORWARD_POLICY="ACCEPT"/' /etc/default/ufw || true
ufw reload || true

# 6) ensure wg-quick service
UNIT="wg-quick@${WG_IFACE}"
systemctl daemon-reload
systemctl enable "${UNIT}" || true
# restart may fail if config is bad – that's fine, we'll fix wg0.conf later
systemctl restart "${UNIT}" || true

# 7) clone app SAFELY
tmpdir=$(mktemp -d /tmp/wgdash.XXXXXX)
git clone -b "${BRANCH}" "${REPO_URL}" "${tmpdir}"
# move into place
rm -rf "${DASH_DIR}"
mv "${tmpdir}" "${DASH_DIR}"
chown -R root:root "${DASH_DIR}"

# 8) venv + deps
python3 -m venv "${DASH_ENV}"
"${DASH_ENV}/bin/pip" install --upgrade pip wheel
"${DASH_ENV}/bin/pip" install flask gunicorn

# 9) www-data
id -u www-data >/dev/null 2>&1 || useradd -r -s /usr/sbin/nologin www-data
chown -R www-data:www-data "${DASH_DIR}"

# 10) env for service
cat > /etc/wg-dashboard.env <<ENV
APP_PORT=${DASH_PORT}
WG_IFACE=${WG_IFACE}
WG_DIR=${WG_DIR}
WG_CONF=${WG_CONF}
WG_PORT=${WG_PORT}
SERVER_ADDR=${SERVER_ADDR}
FLASK_ENV=production
ENV
chmod 640 /etc/wg-dashboard.env

# 11) sudoers
cat >/etc/sudoers.d/wg-dashboard <<'SUD'
www-data ALL=(root) NOPASSWD: /usr/bin/wg, /usr/bin/wg-quick, /usr/bin/systemctl, /usr/bin/install, /usr/sbin/ufw, /bin/cat, /usr/bin/journalctl
SUD
chmod 440 /etc/sudoers.d/wg-dashboard
visudo -c

# 12) systemd unit
cat >/etc/systemd/system/wg-dashboard.service <<UNIT
[Unit]
Description=WireGuard Dashboard
After=network.target

[Service]
User=www-data
Group=www-data
EnvironmentFile=/etc/wg-dashboard.env
WorkingDirectory=${DASH_DIR}
ExecStart=${DASH_ENV}/bin/gunicorn -w 2 -b 0.0.0.0:\${APP_PORT} ${APP_MODULE}
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable wg-dashboard
systemctl restart wg-dashboard

echo "UNIT=${UNIT}"
echo "WireGuard UDP: ${WG_PORT}"
echo "Dashboard: http://$(hostname -I | awk '{print $1}'):${DASH_PORT}"