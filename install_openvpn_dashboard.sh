#!/usr/bin/env bash
set -euo pipefail

export DEBIAN_FRONTEND=noninteractive

apt-get update
apt-get install -y openvpn easy-rsa ufw python3 python3-venv python3-pip git iptables-persistent build-essential

OVPN_DIR=/etc/openvpn
EASYRSA_DIR=/etc/openvpn/easy-rsa
PKI_DIR=/etc/openvpn/pki
SRV_NAME=server
UDP_PORT=${OVPN_PORT:-1194}
NET_IF=$(ip route get 1.1.1.1 | awk '{for(i=1;i<=NF;i++){if($i=="dev"){print $(i+1); exit}}}')

REPO_URL=${REPO_URL:-https://github.com/Migrim/OpenVPN-Dashboard.git}
BRANCH=${BRANCH:-main}
DASH_DIR=/opt/OpenVPN-Dashboard
DASH_ENV=${DASH_DIR}/.venv
DASH_PORT=${DASH_PORT:-8088}
APP_MODULE=${APP_MODULE:-app:app}

export EASYRSA_PKI=${PKI_DIR}
export EASYRSA_BATCH=1
mkdir -p "${EASYRSA_DIR}" "${PKI_DIR}"
if [ ! -x "${EASYRSA_DIR}/easyrsa" ]; then
  if [ -f /usr/share/easy-rsa/easyrsa ]; then
    cp -r /usr/share/easy-rsa/* "${EASYRSA_DIR}/"
    chmod +x "${EASYRSA_DIR}/easyrsa"
  elif command -v make-cadir >/dev/null 2>&1; then
    make-cadir "${EASYRSA_DIR}"
  else
    echo "easy-rsa missing" >&2
    exit 1
  fi
fi

cd "${EASYRSA_DIR}"
./easyrsa init-pki
echo | ./easyrsa build-ca nopass
./easyrsa gen-dh
EASYRSA_CERT_EXPIRE=3650 ./easyrsa build-server-full "${SRV_NAME}" nopass
openvpn --genkey secret "${PKI_DIR}/ta.key"
./easyrsa gen-crl
install -d -m 755 "${OVPN_DIR}"
install -m 644 "${PKI_DIR}/ca.crt" "${OVPN_DIR}/"
install -m 600 "${PKI_DIR}/issued/${SRV_NAME}.crt" "${OVPN_DIR}/"
install -m 600 "${PKI_DIR}/private/${SRV_NAME}.key" "${OVPN_DIR}/"
install -m 600 "${PKI_DIR}/ta.key" "${OVPN_DIR}/"
install -m 600 "${PKI_DIR}/dh.pem" "${OVPN_DIR}/"
install -m 644 "${PKI_DIR}/crl.pem" "${OVPN_DIR}/crl.pem"

cat >"/etc/openvpn/${SRV_NAME}.conf" <<EOF
port ${UDP_PORT}
proto udp
dev tun
ca ${OVPN_DIR}/ca.crt
cert ${OVPN_DIR}/${SRV_NAME}.crt
key ${OVPN_DIR}/${SRV_NAME}.key
dh ${OVPN_DIR}/dh.pem
tls-auth ${OVPN_DIR}/ta.key 0
crl-verify ${OVPN_DIR}/crl.pem
topology subnet
server 10.8.0.0 255.255.255.0
push "redirect-gateway def1 bypass-dhcp"
push "dhcp-option DNS 1.1.1.1"
keepalive 10 120
data-ciphers AES-256-GCM:AES-128-GCM
cipher AES-256-GCM
user nobody
group nogroup
persist-key
persist-tun
verb 3
explicit-exit-notify 1
EOF

sysctl -w net.ipv4.ip_forward=1
grep -q '^net.ipv4.ip_forward=1$' /etc/sysctl.conf || echo net.ipv4.ip_forward=1 >> /etc/sysctl.conf

ufw allow OpenSSH
ufw allow ${UDP_PORT}/udp
ufw --force enable

iptables -t nat -C POSTROUTING -s 10.8.0.0/24 -o "${NET_IF}" -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o "${NET_IF}" -j MASQUERADE
netfilter-persistent save

systemctl enable "openvpn@${SRV_NAME}"
systemctl restart "openvpn@${SRV_NAME}"

if [ -d "${DASH_DIR}/.git" ]; then
  git -C "${DASH_DIR}" fetch --all
  git -C "${DASH_DIR}" reset --hard "origin/${BRANCH}"
else
  git clone -b "${BRANCH}" "${REPO_URL}" "${DASH_DIR}"
fi

python3 -m venv "${DASH_ENV}"
"${DASH_ENV}/bin/pip" install --upgrade pip wheel
if [ -f "${DASH_DIR}/requirements.txt" ]; then
  "${DASH_ENV}/bin/pip" install -r "${DASH_DIR}/requirements.txt"
else
  "${DASH_ENV}/bin/pip" install flask gunicorn
fi

id -u www-data >/dev/null 2>&1 || useradd -r -s /usr/sbin/nologin www-data
chown -R www-data:www-data "${DASH_DIR}"

cat > /etc/ovpn-dashboard.env <<EOF
APP_PORT=${DASH_PORT}
OVPN_PORT=${UDP_PORT}
FLASK_ENV=production
EOF
chmod 640 /etc/ovpn-dashboard.env

cat >/etc/sudoers.d/ovpn-dashboard <<EOF
www-data ALL=(ALL) NOPASSWD:/usr/bin/systemctl restart openvpn@${SRV_NAME},/usr/bin/systemctl stop openvpn@${SRV_NAME},/usr/bin/systemctl start openvpn@${SRV_NAME},/bin/bash -lc *
root ALL=(ALL) NOPASSWD:ALL
EOF
chmod 440 /etc/sudoers.d/ovpn-dashboard

cat >/etc/systemd/system/ovpn-dashboard.service <<EOF
[Unit]
Description=OpenVPN Dashboard
After=network.target

[Service]
User=www-data
Group=www-data
EnvironmentFile=/etc/ovpn-dashboard.env
WorkingDirectory=${DASH_DIR}
ExecStart=${DASH_ENV}/bin/gunicorn -w 2 -b 0.0.0.0:\${APP_PORT} ${APP_MODULE}
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable ovpn-dashboard
systemctl restart ovpn-dashboard

echo "OpenVPN UDP: ${UDP_PORT}"
echo "Dashboard: http://$(hostname -I | awk '{print $1}'):${DASH_PORT}"