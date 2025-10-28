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
REPO_URL=${REPO_URL:-https://github.com/Migrim/OpenVPN-Dashboard.git}
BRANCH=${BRANCH:-main}

NET_IF=$(ip route get 1.1.1.1 | awk '{for(i=1;i<=NF;i++){if($i=="dev"){print $(i+1); exit}}}')

install -d -m 700 "${WG_DIR}"

if [ ! -f "${WG_DIR}/server_privatekey" ]; then
  umask 077
  wg genkey | tee "${WG_DIR}/server_privatekey" | wg pubkey > "${WG_DIR}/server_publickey"
fi

if [ ! -f "${WG_CONF}" ]; then
  umask 077
  cat > "${WG_CONF}" <<EOF
[Interface]
Address = ${SERVER_ADDR}
ListenPort = ${WG_PORT}
PrivateKey = $(cat "${WG_DIR}/server_privatekey")
EOF
  chmod 600 "${WG_CONF}"
fi

sysctl -w net.ipv4.ip_forward=1 >/dev/null
grep -q '^net.ipv4.ip_forward=1$' /etc/sysctl.conf || echo net.ipv4.ip_forward=1 >> /etc/sysctl.conf

ufw allow OpenSSH || true
ufw allow ${WG_PORT}/udp || true
ufw --force enable

SUBNET=$(echo "${SERVER_ADDR}" | awk -F/ '{print $1"/"$2}')
if ! grep -q "START WIREGUARD NAT" /etc/ufw/before.rules 2>/dev/null; then
  tmpf=$(mktemp)
  awk '1; END{print "# START WIREGUARD NAT\n*nat\n:POSTROUTING ACCEPT [0:0]\n-A POSTROUTING -s '"${SUBNET}"' -o '"${NET_IF}"' -j MASQUERADE\nCOMMIT\n# END WIREGUARD NAT"}' /etc/ufw/before.rules > "$tmpf"
  install -m 644 "$tmpf" /etc/ufw/before.rules
  rm -f "$tmpf"
fi
sed -i 's/^#\?DEFAULT_FORWARD_POLICY=.*/DEFAULT_FORWARD_POLICY="ACCEPT"/' /etc/default/ufw || true
ufw reload || true

UNIT="wg-quick@${WG_IFACE}"
systemctl daemon-reload
systemctl enable "${UNIT}" || true
systemctl restart "${UNIT}" || true

if [ -d "${DASH_DIR}/.git" ]; then
  systemctl stop wg-dashboard || true
  git -C "${DASH_DIR}" fetch --all
  git -C "${DASH_DIR}" reset --hard "origin/${BRANCH}"
else
  rm -rf "${DASH_DIR}"
  git clone -b "${BRANCH}" "${REPO_URL}" "${DASH_DIR}"
fi

git config --global --add safe.directory "${DASH_DIR}"

python3 -m venv "${DASH_ENV}"
"${DASH_ENV}/bin/pip" install --upgrade pip wheel
if [ -f "${DASH_DIR}/requirements.txt" ]; then
  "${DASH_ENV}/bin/pip" install -r "${DASH_DIR}/requirements.txt"
else
  "${DASH_ENV}/bin/pip" install flask gunicorn
fi

id -u www-data >/dev/null 2>&1 || useradd -r -s /usr/sbin/nologin www-data
chown -R www-data:www-data "${DASH_DIR}"

cat > /etc/wg-dashboard.env <<EOF
APP_PORT=${DASH_PORT}
WG_IFACE=${WG_IFACE}
WG_DIR=${WG_DIR}
WG_CONF=${WG_CONF}
WG_PORT=${WG_PORT}
FLASK_ENV=production
EOF
chmod 640 /etc/wg-dashboard.env

cat >/etc/sudoers.d/wg-dashboard <<EOF
www-data ALL=(ALL) NOPASSWD:/usr/bin/systemctl *,/bin/bash -lc *
EOF
chmod 440 /etc/sudoers.d/wg-dashboard

cat >/etc/systemd/system/wg-dashboard.service <<EOF
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
EOF

systemctl daemon-reload
systemctl enable wg-dashboard
systemctl restart wg-dashboard

echo "UNIT=${UNIT}"
echo "WireGuard UDP: ${WG_PORT}"
echo "Dashboard: http://$(hostname -I | awk '{print $1}'):${DASH_PORT}"