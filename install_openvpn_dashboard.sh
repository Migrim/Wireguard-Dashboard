#!/usr/bin/env bash
set -euo pipefail

export DEBIAN_FRONTEND=noninteractive

apt-get update
apt-get install -y openvpn easy-rsa ufw python3 python3-venv python3-pip git

OVPN_DIR=/etc/openvpn
EASYRSA_DIR=/etc/openvpn/easy-rsa
PKI_DIR=/etc/openvpn/pki
DASH_DIR=/opt/ovpn-dashboard
DASH_ENV=${DASH_DIR}/.venv
SRV_NAME=server
UDP_PORT=1194
DASH_PORT=8088
NET_IF=$(ip route get 1.1.1.1 | awk '{for(i=1;i<=NF;i++){if($i=="dev"){print $(i+1); exit}}}')

mkdir -p ${EASYRSA_DIR}
make-cadir ${EASYRSA_DIR} >/dev/null 2>&1 || true

cd ${EASYRSA_DIR}
./easyrsa init-pki
echo | ./easyrsa build-ca nopass
./easyrsa gen-dh
EASYRSA_CERT_EXPIRE=3650 ./easyrsa build-server-full ${SRV_NAME} nopass
openvpn --genkey secret ${PKI_DIR}/ta.key

install -d -m 755 ${OVPN_DIR}
install -m 644 ${PKI_DIR}/ca.crt ${OVPN_DIR}/
install -m 600 ${PKI_DIR}/issued/${SRV_NAME}.crt ${OVPN_DIR}/
install -m 600 ${PKI_DIR}/private/${SRV_NAME}.key ${OVPN_DIR}/
install -m 600 ${PKI_DIR}/ta.key ${OVPN_DIR}/
install -m 600 ${PKI_DIR}/dh.pem ${OVPN_DIR}/

cat >/etc/openvpn/${SRV_NAME}.conf <<EOF
port ${UDP_PORT}
proto udp
dev tun
ca ${OVPN_DIR}/ca.crt
cert ${OVPN_DIR}/${SRV_NAME}.crt
key ${OVPN_DIR}/${SRV_NAME}.key
dh ${OVPN_DIR}/dh.pem
tls-auth ${OVPN_DIR}/ta.key 0
topology subnet
server 10.8.0.0 255.255.255.0
push "redirect-gateway def1 bypass-dhcp"
push "dhcp-option DNS 1.1.1.1"
keepalive 10 120
cipher AES-256-GCM
user nobody
group nogroup
persist-key
persist-tun
verb 3
explicit-exit-notify 1
EOF

sysctl -w net.ipv4.ip_forward=1
if ! grep -q net.ipv4.ip_forward /etc/sysctl.conf; then echo net.ipv4.ip_forward=1 >> /etc/sysctl.conf; fi

ufw allow OpenSSH
ufw allow ${UDP_PORT}/udp
ufw --force enable

iptables -t nat -C POSTROUTING -s 10.8.0.0/24 -o ${NET_IF} -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o ${NET_IF} -j MASQUERADE
apt-get install -y iptables-persistent
netfilter-persistent save

systemctl enable openvpn@${SRV_NAME}
systemctl restart openvpn@${SRV_NAME}

mkdir -p ${DASH_DIR}
cat > ${DASH_DIR}/app.py <<'PY'
import os, subprocess, json, socket, datetime, re
from flask import Flask, render_template_string, request, send_file, redirect, url_for, jsonify

APP_PORT=int(os.environ.get("APP_PORT","8088"))
EASYRSA_DIR="/etc/openvpn/easy-rsa"
PKI="/etc/openvpn/pki"
OVPN_DIR="/etc/openvpn"
SRV_NAME="server"
UDP_PORT=int(os.environ.get("OVPN_PORT","1194"))
HOST_IP=subprocess.check_output(["bash","-lc","hostname -I | awk '{print $1}'"]).decode().strip()

app=Flask(__name__)

TPL="""
<!doctype html><html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<link href="https://fonts.googleapis.com/css2?family=Roboto:wght@400;500;700&display=swap" rel="stylesheet">
<link href="https://fonts.googleapis.com/icon?family=Material+Icons" rel="stylesheet">
<title>OpenVPN Dashboard</title>
<style>
:root{--bg:#0a0a0b;--card:#101114;--text:#e5e7eb;--muted:#94a3b8;--border:#1f2430;--accent:#4f46e5;--ok:#16a34a;--bad:#ef4444}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font-family:Roboto,system-ui}
.wrap{max-width:1100px;margin:24px auto;padding:0 16px;display:grid;gap:16px}
.row{display:grid;grid-template-columns:1fr 1fr 1fr;gap:16px}
.card{background:var(--card);border:1px solid var(--border);border-radius:16px;padding:16px;box-shadow:0 8px 30px rgba(0,0,0,.2)}
.h{display:flex;justify-content:space-between;align-items:center;margin-bottom:12px}
.h b{font-size:16px}
.kv{display:grid;grid-template-columns:auto 1fr;gap:8px 12px;align-items:center}
.badge{display:inline-flex;align-items:center;gap:6px;padding:4px 8px;border-radius:999px;border:1px solid var(--border);font-size:12px}
.ok{color:#22c55e;border-color:#1e3a2f}
.err{color:#f87171;border-color:#3a1e1e}
.btn{display:inline-flex;gap:8px;align-items:center;background:#15161a;border:1px solid var(--border);border-radius:10px;padding:8px 12px;color:#fff;text-decoration:none}
.btn[disabled]{opacity:.5;pointer-events:none}
.table{width:100%;border-collapse:collapse;font-size:14px}
.table th,.table td{padding:10px;border-bottom:1px solid var(--border)}
.flex{display:flex;gap:8px;flex-wrap:wrap}
.input{background:#0f1116;border:1px solid var(--border);color:#fff;border-radius:10px;padding:10px;width:260px}
.log{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12px;white-space:pre-wrap;height:220px;overflow:auto;background:#0b0c10;border:1px solid var(--border);border-radius:10px;padding:12px}
.grid2{display:grid;grid-template-columns:2fr 1fr;gap:16px}
@media(max-width:900px){.row{grid-template-columns:1fr}.grid2{grid-template-columns:1fr}}
</style>
</head><body><div class="wrap">
<div class="row">
  <div class="card">
    <div class="h"><b>Status</b><span class="badge {{ 'ok' if data['service_active'] else 'err' }}"><span class="material-icons" style="font-size:16px">{{ 'check_circle' if data['service_active'] else 'error' }}</span>{{ 'running' if data['service_active'] else 'stopped' }}</span></div>
    <div class="kv">
      <div>Server IP</div><div>{{data['host_ip']}}</div>
      <div>Listen</div><div>udp/{{data['udp_port']}}</div>
      <div>Process</div><div>{{data['unit']}}</div>
      <div>Clients</div><div>{{data['clients']}}</div>
    </div>
    <div class="flex" style="margin-top:12px">
      <a class="btn" href="/action/restart"><span class="material-icons">restart_alt</span>Restart</a>
      <a class="btn" href="/action/stop"><span class="material-icons">stop_circle</span>Stop</a>
      <a class="btn" href="/action/start"><span class="material-icons">play_circle</span>Start</a>
    </div>
  </div>
  <div class="card">
    <div class="h"><b>Port Check</b></div>
    <div class="kv">
      <div>Local Socket</div><div><span class="badge {{ 'ok' if data['local_listen'] else 'err' }}">{{ 'listening' if data['local_listen'] else 'not listening' }}</span></div>
      <div>UFW</div><div><span class="badge {{ 'ok' if data['ufw_open'] else 'err' }}">{{ 'allowed' if data['ufw_open'] else 'blocked' }}</span></div>
      <div>Ping</div><div><span class="badge {{ 'ok' if data['ping_ok'] else 'err' }}">{{ 'ok' if data['ping_ok'] else 'fail' }}</span></div>
    </div>
    <div class="flex" style="margin-top:12px">
      <a class="btn" href="/check/refresh"><span class="material-icons">refresh</span>Refresh</a>
    </div>
  </div>
  <div class="card">
    <div class="h"><b>Create User</b></div>
    <form method="post" action="/users">
      <input class="input" name="name" placeholder="username">
      <button class="btn" type="submit"><span class="material-icons">person_add</span>Create</button>
    </form>
  </div>
</div>

<div class="grid2">
  <div class="card">
    <div class="h"><b>Users</b></div>
    <table class="table">
      <thead><tr><th>User</th><th>Status</th><th>Created</th><th class="flex" style="justify-content:flex-end">Actions</th></tr></thead>
      <tbody>
        {% for u in users %}
        <tr>
          <td>{{u['name']}}</td>
          <td>{{u['status']}}</td>
          <td>{{u['created']}}</td>
          <td style="text-align:right" class="flex" >
            {% if u['status']=='active' %}
            <a class="btn" href="/users/{{u['name']}}/ovpn"><span class="material-icons">download</span>Profile</a>
            <form method="post" action="/users/{{u['name']}}/revoke" style="display:inline"><button class="btn" type="submit"><span class="material-icons">block</span>Revoke</button></form>
            {% else %}
            <form method="post" action="/users/{{u['name']}}/restore" style="display:inline"><button class="btn" type="submit"><span class="material-icons">undo</span>Restore</button></form>
            {% endif %}
          </td>
        </tr>
        {% endfor %}
      </tbody>
    </table>
  </div>
  <div class="card">
    <div class="h"><b>Logs</b></div>
    <div class="log">{{data['logs']}}</div>
  </div>
</div>
</div></body></html>
"""

def _run(cmd):
    r=subprocess.run(cmd,shell=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True)
    return r.stdout.strip()

def service_active():
    o=_run("systemctl is-active openvpn@{}".format(SRV_NAME))
    return o.strip()=="active"

def ufw_allowed(port):
    o=_run("ufw status verbose | grep -E '\\b{}/udp\\b' || true".format(port))
    return bool(o)

def local_listening(port):
    try:
        o=_run("ss -lunp | grep ':{} ' || true".format(port))
        return bool(o)
    except:
        return False

def ping_ok():
    o=_run("ping -c1 -W1 1.1.1.1 >/dev/null 2>&1; echo $?")
    return o.strip()=="0"

def logs_tail():
    return _run("journalctl -u openvpn@{} -n 60 --no-pager".format(SRV_NAME))

def list_clients():
    out=[]
    issued_dir=os.path.join(PKI,"issued")
    revoked_idx=os.path.join(PKI,"index.txt")
    revoked=set()
    if os.path.exists(revoked_idx):
        for line in open(revoked_idx):
            if line.startswith("R"):
                m=re.search(r"/CN=([^/]+)",line)
                if m: revoked.add(m.group(1))
    for fn in sorted(os.listdir(issued_dir)):
        if not fn.endswith(".crt"): continue
        name=fn[:-4]
        if name==SRV_NAME: continue
        status="revoked" if name in revoked else "active"
        crt_path=os.path.join(issued_dir,fn)
        st=os.stat(crt_path)
        created=datetime.datetime.fromtimestamp(st.st_mtime).strftime("%Y-%m-%d")
        out.append({"name":name,"status":status,"created":created})
    return out

def gen_ovpn_inline(name):
    ca=open(os.path.join(PKI,"ca.crt")).read()
    crt=open(os.path.join(PKI,"issued","{}.crt".format(name))).read()
    key=open(os.path.join(PKI,"private","{}.key".format(name))).read()
    ta=open(os.path.join(PKI,"ta.key")).read() if os.path.exists(os.path.join(PKI,"ta.key")) else open(os.path.join(OVPN_DIR,"ta.key")).read()
    return f"""client
dev tun
proto udp
remote {HOST_IP} {UDP_PORT}
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
cipher AES-256-GCM
verb 3
key-direction 1
<ca>
{ca}
</ca>
<cert>
{crt}
</cert>
<key>
{key}
</key>
<tls-auth>
{ta}
</tls-auth>
"""

@app.route("/")
def home():
    data={
        "service_active":service_active(),
        "host_ip":HOST_IP,
        "udp_port":UDP_PORT,
        "unit":"openvpn@{}".format(SRV_NAME),
        "local_listen":local_listening(UDP_PORT),
        "ufw_open":ufw_allowed(UDP_PORT),
        "ping_ok":ping_ok(),
        "clients":len([u for u in list_clients() if u["status"]=="active"]),
        "logs":logs_tail()
    }
    users=list_clients()
    return render_template_string(TPL,data=data,users=users)

@app.route("/action/<what>")
def action(what):
    if what=="restart": _run("sudo systemctl restart openvpn@{}".format(SRV_NAME))
    elif what=="stop": _run("sudo systemctl stop openvpn@{}".format(SRV_NAME))
    elif what=="start": _run("sudo systemctl start openvpn@{}".format(SRV_NAME))
    return redirect(url_for("home"))

@app.route("/check/refresh")
def refresh():
    return redirect(url_for("home"))

@app.route("/users",methods=["POST"])
def create_user():
    name=request.form.get("name","").strip()
    if not name: return redirect(url_for("home"))
    cmd=f"cd {EASYRSA_DIR} && ./easyrsa build-client-full {name} nopass"
    _run("sudo bash -lc '{}'".format(cmd))
    return redirect(url_for("home"))

@app.route("/users/<name>/revoke",methods=["POST"])
def revoke_user(name):
    cmd=f"cd {EASYRSA_DIR} && echo yes | ./easyrsa revoke {name} && ./easyrsa gen-crl && install -m 644 {PKI}/crl.pem {OVPN_DIR}/crl.pem"
    _run("sudo bash -lc '{}'".format(cmd))
    _run("sudo systemctl restart openvpn@{}".format(SRV_NAME))
    return redirect(url_for("home"))

@app.route("/users/<name>/restore",methods=["POST"])
def restore_user(name):
    _run("sudo rm -f {}/revoked/certs_by_serial/* || true".format(PKI))
    _run("sudo bash -lc 'cd {} && ./easyrsa build-client-full {} nopass'".format(EASYRSA_DIR,name))
    return redirect(url_for("home"))

@app.route("/users/<name>/ovpn")
def download_ovpn(name):
    profile=gen_ovpn_inline(name)
    p=f"/tmp/{name}.ovpn"
    open(p,"w").write(profile)
    return send_file(p,as_attachment=True,download_name=f"{name}.ovpn")

if __name__=="__main__":
    app.run(host="0.0.0.0",port=APP_PORT)
PY

python3 -m venv ${DASH_ENV}
${DASH_ENV}/bin/pip install flask

cat >/etc/sudoers.d/ovpn-dashboard <<EOF
www-data ALL=(ALL) NOPASSWD:/usr/bin/systemctl restart openvpn@server,/usr/bin/systemctl stop openvpn@server,/usr/bin/systemctl start openvpn@server,/bin/bash -lc *
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
Environment=APP_PORT=${DASH_PORT}
Environment=OVPN_PORT=${UDP_PORT}
WorkingDirectory=${DASH_DIR}
ExecStart=${DASH_ENV}/bin/python ${DASH_DIR}/app.py
Restart=always

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable ovpn-dashboard
systemctl restart ovpn-dashboard

echo "Done. Dashboard on http://$(hostname -I | awk '{print $1}'):${DASH_PORT}"