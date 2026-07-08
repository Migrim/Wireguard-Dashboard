#!/bin/bash
set -e

WG_IFACE=${WG_IFACE:-wg0}
WG_DIR=${WG_DIR:-/etc/wireguard}
WG_CONF=${WG_CONF:-${WG_DIR}/${WG_IFACE}.conf}
WG_PORT=${WG_PORT:-51820}
SERVER_ADDR=${SERVER_ADDR:-10.8.0.1/24}
APP_PORT=${APP_PORT:-8088}
export WG_IFACE WG_DIR WG_CONF WG_PORT SERVER_ADDR APP_PORT

# WireGuard needs CAP_NET_ADMIN (bit 12 of the effective capability mask).
# Plain "docker run IMAGE" and GUI run buttons don't grant it, so fail fast
# with the fix instead of booting a dashboard that can never work.
CAP_EFF=$(awk '/^CapEff:/{print $2}' /proc/self/status)
if (( (16#${CAP_EFF} >> 12 & 1) == 0 )); then
  cat >&2 <<'MSG'
==================================================================
 ERROR: container is missing the NET_ADMIN capability.
 WireGuard cannot create interfaces without it.

 Start the dashboard with docker compose (recommended):

   docker compose up -d

 or with docker run:

   docker run -d --name wg-dashboard \
     --cap-add NET_ADMIN \
     --sysctl net.ipv4.ip_forward=1 \
     --sysctl net.ipv4.conf.all.src_valid_mark=1 \
     -p 8088:8088 -p 51820:51820/udp \
     -v wg_data:/etc/wireguard \
     --restart unless-stopped \
     IMAGE_NAME

 (GUI "Run" buttons cannot add capabilities - use the CLI/compose.)
==================================================================
MSG
  exit 1
fi

mkdir -p "$WG_DIR"

# app.py stages atomic writes in /tmp and os.replace()s them into WG_DIR.
# WG_DIR is a volume (a different filesystem), so those renames would fail
# with EXDEV and fall back to a racy sudo-install. Point /tmp at a scratch
# dir inside the volume so renames stay on one filesystem.
TMP_SCRATCH="${WG_DIR}/.tmp"
mkdir -p "$TMP_SCRATCH"
chmod 1777 "$TMP_SCRATCH"
if [ ! -L /tmp ]; then
  rm -rf /tmp
  ln -s "$TMP_SCRATCH" /tmp
fi
find "$TMP_SCRATCH" -mindepth 1 -delete 2>/dev/null || true

umask 077

if [ ! -f "${WG_DIR}/server_privatekey" ]; then
  wg genkey | tee "${WG_DIR}/server_privatekey" | wg pubkey > "${WG_DIR}/server_publickey"
fi

NET_IF=$(ip route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++){if($i=="dev"){print $(i+1); exit}}}')
NET_IF=${NET_IF:-eth0}

if [ ! -f "$WG_CONF" ]; then
  cat > "$WG_CONF" <<CFG
[Interface]
Address = ${SERVER_ADDR}
ListenPort = ${WG_PORT}
PrivateKey = $(cat "${WG_DIR}/server_privatekey")
PostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -A FORWARD -o %i -j ACCEPT; iptables -t nat -A POSTROUTING -o ${NET_IF} -j MASQUERADE
PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -D FORWARD -o %i -j ACCEPT; iptables -t nat -D POSTROUTING -o ${NET_IF} -j MASQUERADE
CFG
fi

[ -f "${WG_DIR}/peers.json" ] || echo '{}' > "${WG_DIR}/peers.json"

sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1 || true

mkdir -p /run/wg-dashboard
touch /var/log/wg-quick.log

[ -f "${WG_DIR}/.wg-autostart" ] || echo enabled > "${WG_DIR}/.wg-autostart"
if grep -q enabled "${WG_DIR}/.wg-autostart" 2>/dev/null; then
  if ! systemctl start "wg-quick@${WG_IFACE}"; then
    echo "ERROR: wg-quick up ${WG_IFACE} failed:" >&2
    tail -n 20 /var/log/wg-quick.log >&2
    echo "(container keeps running; fix the cause, then start WireGuard from the dashboard)" >&2
  fi
fi

# Single worker: the app keeps caches and background samplers in memory,
# which multiple workers would duplicate. Threads provide request concurrency.
exec gunicorn -w 1 --threads 16 --worker-tmp-dir /dev/shm \
  -b "0.0.0.0:${APP_PORT}" app:app
