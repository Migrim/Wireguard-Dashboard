import os, subprocess, datetime, re, time, shlex
from typing import Tuple, Dict, Any, List
import logging
from flask import Flask, render_template, request, send_file, redirect, url_for, jsonify, abort

APP_PORT=int(os.environ.get("APP_PORT","8088"))
EASYRSA_DIR=os.environ.get("EASYRSA_DIR","/etc/openvpn/easy-rsa")
PKI=os.environ.get("PKI_DIR","/etc/openvpn/pki")
OVPN_DIR=os.environ.get("OVPN_DIR","/etc/openvpn")
SRV_NAME=os.environ.get("SRV_NAME","server")
UDP_PORT=int(os.environ.get("OVPN_PORT","1194"))
HOST_IP=subprocess.check_output(["bash","-lc","hostname -I | awk '{print $1}'"]).decode().strip()
SERVER_CONF_CANDIDATES=["/etc/openvpn/server.conf","/etc/openvpn/server/server.conf"]
STATUS_CANDIDATES=[f"/run/openvpn/{SRV_NAME}.status","/var/log/openvpn/status.log","/var/log/openvpn/openvpn-status.log"]

app=Flask(__name__)

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
app.logger.setLevel(logging.INFO)

@app.before_request
def _log_request():
    app.logger.info("%s %s", request.method, request.path)

@app.after_request
def _log_response(res):
    app.logger.info("status=%s path=%s", res.status_code, request.path)
    return res

@app.context_processor
def inject_year():
    return {"current_year": datetime.datetime.utcnow().year}

def _run(cmd: str) -> Tuple[str,int]:
    r=subprocess.run(cmd,shell=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True)
    return r.stdout.strip(), r.returncode

def _sudorun(cmd: str) -> Tuple[str,int]:
    app.logger.info("run: %s", cmd)
    o,c=_run("sudo bash -lc {}".format(shlex.quote(cmd)))
    app.logger.info("rc=%s", c)
    return o,c

def service_active() -> bool:
    o,c=_run("systemctl is-active openvpn@{}".format(SRV_NAME))
    return o.strip()=="active"

def service_enabled() -> bool:
    o,c=_run("systemctl is-enabled openvpn@{} || true".format(SRV_NAME))
    return o.strip()=="enabled"

def ufw_allowed(port: int, proto: str="udp") -> bool:
    o,c=_run("ufw status numbered | grep -E '\\b{}/{}\\b' || true".format(port,proto))
    return bool(o)

def local_listening(port: int, proto: str="udp") -> bool:
    if proto=="udp":
        o,c=_run("ss -lunp | grep ':{} ' || true".format(port))
    else:
        o,c=_run("ss -ltnp | grep ':{} ' || true".format(port))
    return bool(o)

def ping_ok() -> bool:
    o,c=_run("ping -c1 -W1 1.1.1.1 >/dev/null 2>&1")
    return c==0

def timedate_ntp() -> str:
    o,c=_run("timedatectl 2>/dev/null | awk -F': ' '/NTP service:|System clock synchronized:/{print $2}' | xargs | sed 's/ /, /g'")
    return o.strip()

def logs_tail(n: int=200) -> str:
    o,c=_run("journalctl -u openvpn@{} -n {} --no-pager".format(SRV_NAME,int(n)))
    return o

def list_clients() -> List[Dict[str,Any]]:
    out=[]
    issued_dir=os.path.join(PKI,"issued")
    revoked_idx=os.path.join(PKI,"index.txt")
    revoked=set()
    if os.path.exists(revoked_idx):
        with open(revoked_idx,encoding="utf-8",errors="ignore") as f:
            for line in f:
                if line.startswith("R"):
                    m=re.search(r"/CN=([^/]+)",line)
                    if m:
                        revoked.add(m.group(1))
    if os.path.isdir(issued_dir):
        for fn in sorted(os.listdir(issued_dir)):
            if not fn.endswith(".crt"):
                continue
            name=fn[:-4]
            if name==SRV_NAME:
                continue
            status="revoked" if name in revoked else "active"
            crt_path=os.path.join(issued_dir,fn)
            st=os.stat(crt_path)
            created=datetime.datetime.fromtimestamp(st.st_mtime).strftime("%Y-%m-%d")
            out.append({"name":name,"status":status,"created":created})
    return out

def gen_ovpn_inline(name: str) -> str:
    ca_path=os.path.join(PKI,"ca.crt")
    crt_path=os.path.join(PKI,"issued",f"{name}.crt")
    key_path=os.path.join(PKI,"private",f"{name}.key")
    if not os.path.exists(ca_path):
        raise FileNotFoundError(f"missing {ca_path}")
    if not os.path.exists(crt_path):
        raise FileNotFoundError(f"missing {crt_path}")
    if not os.path.exists(key_path):
        raise FileNotFoundError(f"missing {key_path}")
    with open(ca_path) as f:
        ca=f.read()
    with open(crt_path) as f:
        crt=f.read()
    with open(key_path) as f:
        key=f.read()
    conf_path, conf = read_server_conf()
    proto = (conf.get("proto", ["udp"]) or ["udp"])[0] if conf else "udp"
    port = (conf.get("port", [str(UDP_PORT)]) or [str(UDP_PORT)])[0] if conf else str(UDP_PORT)
    tls_mode = None
    tls_arg = None
    if conf:
        if "tls-crypt" in conf:
            tls_mode = "tls-crypt"
            tls_arg = (conf["tls-crypt"][0] if conf["tls-crypt"] else "").strip()
        elif "tls-auth" in conf:
            tls_mode = "tls-auth"
            tls_arg = (conf["tls-auth"][0] if conf["tls-auth"] else "").strip()
    exit_notify = "\nexplicit-exit-notify 3" if str(proto).lower().startswith("udp") else ""
    ta = ""
    if tls_mode:
        key_path = None
        if tls_arg:
            parts = tls_arg.split()
            if parts:
                cand = parts[0]
                if os.path.isabs(cand) and os.path.exists(cand):
                    key_path = cand
                else:
                    # try relative to server.conf directory
                    if conf_path:
                        base_dir = os.path.dirname(conf_path)
                        rel = os.path.join(base_dir, cand)
                        if os.path.exists(rel):
                            key_path = rel
        if not key_path:
            for cand in [
                os.path.join(PKI, "ta.key"),
                os.path.join(OVPN_DIR, "ta.key"),
                "/etc/openvpn/server/ta.key",
            ]:
                if os.path.exists(cand):
                    key_path = cand
                    break
        if not key_path:
            raise FileNotFoundError("missing ta.key for " + tls_mode)
        with open(key_path) as f:
            ta = f.read()
    key_dir_line = "\nkey-direction 1" if tls_mode == "tls-auth" else ""
    tls_block = ""
    if tls_mode:
        tls_block = f"<{tls_mode}>\n{ta}\n</{tls_mode}>\n"
    return f"""client
dev tun
proto {proto}
remote {HOST_IP} {port}
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
cipher AES-256-GCM
auth SHA256
verb 3{key_dir_line}{exit_notify}
<ca>
{ca}
</ca>
<cert>
{crt}
</cert>
<key>
{key}
</key>
{tls_block}
"""

def detect_iface() -> str:
    o,c=_run("ip -o link show | awk -F': ' '/^(\\d+): (tun|tap)/{print $2; exit}'")
    return o.strip() if o.strip() else "tun0"

def read_bytes() -> Tuple[str,int,int]:
    iface=detect_iface()
    rx=f"/sys/class/net/{iface}/statistics/rx_bytes"
    tx=f"/sys/class/net/{iface}/statistics/tx_bytes"
    try:
        with open(rx) as fr: r=int(fr.read().strip())
        with open(tx) as ft: t=int(ft.read().strip())
        return iface,r,t
    except:
        return iface,0,0

def read_server_conf() -> Tuple[str,Dict[str,List[str]]]:
    p=None
    for c in SERVER_CONF_CANDIDATES:
        if os.path.exists(c):
            p=c
            break
    data={}
    if p:
        with open(p,encoding="utf-8",errors="ignore") as f:
            for line in f:
                line=line.strip()
                if not line or line.startswith("#"):
                    continue
                parts=line.split()
                k=parts[0]
                v=" ".join(parts[1:]) if len(parts)>1 else ""
                data.setdefault(k,[]).append(v)
    return p,data

def write_server_conf(updates: Dict[str,Any]) -> Tuple[bool,str]:
    p,cur=read_server_conf()
    if not p:
        return False,"missing server.conf"
    lines=open(p,encoding="utf-8",errors="ignore").read().splitlines()
    allow={"port","proto","push","cipher","auth","dhcp-option"}
    updates={k:v for k,v in updates.items() if k in allow}
    new=[]
    seen=set()
    for ln in lines:
        s=ln.strip()
        if not s or s.startswith("#"):
            new.append(ln)
            continue
        key=s.split()[0]
        if key in updates and key not in seen:
            val=updates[key]
            if isinstance(val,list):
                for x in val:
                    new.append(f"{key} {x}")
            else:
                new.append(f"{key} {val}")
            seen.add(key)
        elif key in updates and key in seen:
            continue
        else:
            new.append(ln)
    for key,val in updates.items():
        if key not in seen:
            if isinstance(val,list):
                for x in val:
                    new.append(f"{key} {x}")
            else:
                new.append(f"{key} {val}")
    tmp=p+".tmp"
    with open(tmp,"w",encoding="utf-8") as f:
        f.write("\n".join(new)+"\n")
    o,c=_sudorun(f"install -m 644 {shlex.quote(tmp)} {shlex.quote(p)} && rm -f {shlex.quote(tmp)}")
    return c==0,o if c!=0 else "ok"

def parse_status_file() -> Dict[str,Any]:
    path=None
    for c in STATUS_CANDIDATES:
        if os.path.exists(c):
            path=c
            break
    res={"clients":[],"updated":None}
    if not path:
        return res
    lines=open(path,encoding="utf-8",errors="ignore").read().splitlines()
    mode=None
    for ln in lines:
        if ln.startswith("Updated,"):
            res["updated"]=ln.split(",",1)[1].strip()
        if ln.strip()=="CLIENT_LIST":
            mode="clients"
            continue
        if ln.strip()=="ROUTING_TABLE":
            mode="routes"
            continue
        if ln.strip()=="GLOBAL_STATS":
            mode="stats"
            continue
        if ln.strip()=="END":
            mode=None
        if mode=="clients" and ln.startswith("CLIENT_LIST,"):
            p=ln.split(",")
            res["clients"].append({"cn":p[1],"remote":p[2],"bytes_recv":int(p[5]),"bytes_sent":int(p[6]),"since":p[7]})
    return res

_last_snapshot={"ts":0,"rx":0,"tx":0}

@app.route("/")
def home():
    users=list_clients()
    data={
        "service_active":service_active(),
        "service_enabled":service_enabled(),
        "host_ip":HOST_IP,
        "udp_port":UDP_PORT,
        "unit":"openvpn@{}".format(SRV_NAME),
        "local_listen":local_listening(UDP_PORT),
        "ufw_open":ufw_allowed(UDP_PORT),
        "ping_ok":ping_ok(),
        "ntp":timedate_ntp(),
        "clients":len([u for u in users if u["status"]=="active"]),
        "logs":logs_tail(60)
    }
    iface,_,_=read_bytes()
    return render_template("index.html",data=data,users=users,iface=iface)

@app.route("/action/<what>")
def action(what: str):
    if what=="restart":
        _sudorun("systemctl restart openvpn@{}".format(SRV_NAME))
    elif what=="stop":
        _sudorun("systemctl stop openvpn@{}".format(SRV_NAME))
    elif what=="start":
        _sudorun("systemctl start openvpn@{}".format(SRV_NAME))
    return redirect(url_for("home"))

@app.route("/users",methods=["POST"])
def create_user():
    name=request.form.get("name","\n").strip()
    if not re.match(r"^[A-Za-z0-9._-]{1,64}$",name):
        return redirect(url_for("home"))
    o,c=_sudorun(f"cd {shlex.quote(EASYRSA_DIR)} && ./easyrsa build-client-full {shlex.quote(name)} nopass")
    dl=request.form.get("download","0")
    if dl=="1":
        return redirect(url_for("download_ovpn",name=name))
    return redirect(url_for("home"))

def _valid_name(x: Any) -> bool:
    return bool(re.match(r"^[A-Za-z0-9._-]{1,64}$", str(x or "").strip()))

def _valid_cn(x: Any) -> bool:
    return bool(re.match(r"^[A-Za-z0-9._\- ]{1,64}$", str(x or "").strip()))

def _valid_ip(x: Any) -> bool:
    return bool(re.match(r"^(?:\d{1,3}\.){3}\d{1,3}$", str(x or "").strip()))

def ensure_ccd():
    ccd_dir=os.path.join(OVPN_DIR,"ccd")
    if not os.path.isdir(ccd_dir):
        _sudorun(f"install -d -m 755 {shlex.quote(ccd_dir)}")
    conf_path,_=read_server_conf()
    if conf_path and "client-config-dir" not in open(conf_path,encoding="utf-8",errors="ignore").read():
        _sudorun(f"bash -lc \"printf '\\nclient-config-dir {shlex.quote(ccd_dir)}\\n' | sudo tee -a {shlex.quote(conf_path)} >/dev/null\"")

@app.route("/users/<name>/revoke",methods=["POST"])
def revoke_user(name: str):
    if not re.match(r"^[A-Za-z0-9._-]{1,64}$",name):
        return redirect(url_for("home"))
    _sudorun(f"cd {shlex.quote(EASYRSA_DIR)} && echo yes | ./easyrsa revoke {shlex.quote(name)} && ./easyrsa gen-crl && install -m 644 {shlex.quote(os.path.join(PKI,'crl.pem'))} {shlex.quote(os.path.join(OVPN_DIR,'crl.pem'))}")
    _sudorun("systemctl restart openvpn@{}".format(SRV_NAME))
    return redirect(url_for("home"))

@app.route("/users/<name>/restore",methods=["POST"])
def restore_user(name: str):
    if not re.match(r"^[A-Za-z0-9._-]{1,64}$",name):
        return redirect(url_for("home"))
    _sudorun(f"cd {shlex.quote(EASYRSA_DIR)} && ./easyrsa build-client-full {shlex.quote(name)} nopass")
    return redirect(url_for("home"))

@app.route("/users/<name>/ovpn")
def download_ovpn(name: str):
    if not re.match(r"^[A-Za-z0-9._-]{1,64}$",name):
        abort(400)
    profile=gen_ovpn_inline(name)
    p=f"/tmp/{name}.ovpn"
    with open(p,"w") as f:
        f.write(profile)
    return send_file(p,as_attachment=True,download_name=f"{name}.ovpn")

@app.route("/api/status")
def api_status():
    iface,rx,tx=read_bytes()
    conf_path,conf=read_server_conf()
    st=parse_status_file()
    issued=list_clients()
    return jsonify({
        "service":{"active":service_active(),"enabled":service_enabled(),"unit":f"openvpn@{SRV_NAME}"},
        "network":{"host_ip":HOST_IP,"port":UDP_PORT,"ufw_udp_open":ufw_allowed(UDP_PORT),"listening":local_listening(UDP_PORT),"ping_ok":ping_ok(),"iface":iface,"rx":rx,"tx":tx},
        "clients":{"count":len([u for u in issued if u["status"]=='active']),"issued":issued,"live":st["clients"],"status_updated":st["updated"]},
        "config":{"path":conf_path,"port":conf.get("port",[str(UDP_PORT)])[0] if conf else None,"proto":(conf.get("proto",[None]) or [None])[0],"cipher":(conf.get("cipher",[None]) or [None])[0],"auth":(conf.get("auth",[None]) or [None])[0],"push":conf.get("push",[]),"dhcp_option":conf.get("dhcp-option",[])},
        "time":{"ntp":timedate_ntp()},
    })

@app.route("/api/service",methods=["POST"])
def api_service():
    data=request.get_json(force=True,silent=True) or {}
    action=str(data.get("action",""))
    action=action.lower()
    if action not in {"start","stop","restart","enable","disable","reload"}:
        abort(400)
    if action=="enable":
        o,c=_sudorun(f"systemctl enable openvpn@{SRV_NAME}")
    elif action=="disable":
        o,c=_sudorun(f"systemctl disable openvpn@{SRV_NAME}")
    else:
        o,c=_sudorun(f"systemctl {action} openvpn@{SRV_NAME}")
    return jsonify({"ok":c==0,"out":o,"active":service_active(),"enabled":service_enabled()})

@app.route("/api/users",methods=["GET","POST"])
def api_users():
    if request.method=="GET":
        return jsonify({"issued":list_clients()})
    data=request.get_json(force=True,silent=True) or {}
    name=str(data.get("name","")).strip()
    cn=str(data.get("cn",name)).strip()
    key_type=str(data.get("key_type","rsa2048")).lower()
    expires=str(data.get("expires","365")).strip()
    protect=bool(data.get("protect",False))
    password=str(data.get("password",""))
    static_ip=str(data.get("ip","")).strip()
    app.logger.info("create_user name=%s cn=%s key_type=%s expires=%s protect=%s ip=%s",name,cn,key_type,expires,protect,static_ip)
    if not _valid_name(name):
        return jsonify({"ok": False, "error": "invalid_name", "hint": "Allowed: A-Z a-z 0-9 . _ - (max 64)"}), 400
    if not _valid_cn(cn):
        return jsonify({"ok": False, "error": "invalid_cn", "hint": "Allowed: A-Z a-z 0-9 . _ - space (max 64)"}), 400
    if static_ip and not _valid_ip(static_ip):
        return jsonify({"ok": False, "error": "invalid_ip", "hint": "Use dotted IPv4, e.g. 10.8.0.23"}), 400
    env=["EASYRSA_BATCH=1"]
    if key_type in ("rsa2048","rsa4096"):
        bits="2048" if key_type=="rsa2048" else "4096"
        env.append("EASYRSA_ALGO=rsa")
        env.append(f"EASYRSA_KEY_SIZE={bits}")
    elif key_type in ("ecdsa256","ecdsa384"):
        curve="prime256v1" if key_type=="ecdsa256" else "secp384r1"
        env.append("EASYRSA_ALGO=ec")
        env.append(f"EASYRSA_CURVE={curve}")
    else:
        env.append("EASYRSA_ALGO=rsa")
        env.append("EASYRSA_KEY_SIZE=2048")
    if expires.isdigit():
        env.append(f"EASYRSA_CERT_EXPIRE={expires}")
    pwflag="nopass"
    if protect:
        if not password:
            return jsonify({"ok":False,"error":"missing_password","hint":"Provide 'password' when protect=true"}),400
        pwflag=""
        env.append(f"EASYRSA_PASSIN=pass:{password}")
        env.append(f"EASYRSA_PASSOUT=pass:{password}")
    cmd=f"cd {shlex.quote(EASYRSA_DIR)} && {' '.join(env)} ./easyrsa build-client-full {shlex.quote(cn)} {pwflag}"
    o,c=_sudorun(cmd)
    if c!=0:
        app.logger.error("easyrsa failed name=%s cn=%s rc=%s out=%s",name,cn,c,o)
        return jsonify({"ok":False,"error":"easyrsa_failed","out":o}),500
    if static_ip:
        try:
            ensure_ccd()
            ccd_path=os.path.join(OVPN_DIR,"ccd",cn)
            mask="255.255.255.0"
            with open(ccd_path,"w") as f:
                f.write(f"ifconfig-push {static_ip} {mask}\n")
        except Exception as e:
            app.logger.exception("ccd write failed cn=%s",cn)
            return jsonify({"ok":False,"error":"ccd_failed","hint":str(e)}),500
    return jsonify({"ok":True,"name":name,"cn":cn})

@app.route("/api/users/<name>/revoke",methods=["POST"])
def api_users_revoke(name: str):
    if not re.match(r"^[A-Za-z0-9._-]{1,64}$",name):
        abort(400)
    o1,c1=_sudorun(f"cd {shlex.quote(EASYRSA_DIR)} && echo yes | ./easyrsa revoke {shlex.quote(name)} && ./easyrsa gen-crl && install -m 644 {shlex.quote(os.path.join(PKI,'crl.pem'))} {shlex.quote(os.path.join(OVPN_DIR,'crl.pem'))}")
    o2,c2=_sudorun("systemctl restart openvpn@{}".format(SRV_NAME))
    return jsonify({"ok":c1==0 and c2==0,"out":o1+"\n"+o2})

@app.route("/api/users/<name>/restore",methods=["POST"])
def api_users_restore(name: str):
    if not re.match(r"^[A-Za-z0-9._-]{1,64}$",name):
        abort(400)
    o,c=_sudorun(f"cd {shlex.quote(EASYRSA_DIR)} && ./easyrsa build-client-full {shlex.quote(name)} nopass")
    return jsonify({"ok":c==0,"out":o})

@app.route("/api/users/<name>/ovpn")
def api_users_ovpn(name: str):
    if not re.match(r"^[A-Za-z0-9._-]{1,64}$",name):
        abort(400)
    try:
        profile=gen_ovpn_inline(name)
        return jsonify({"ok":True,"name":name,"profile":profile})
    except Exception as e:
        app.logger.exception("ovpn build failed name=%s",name)
        return jsonify({"ok":False,"error":"ovpn_build_failed","hint":str(e)}),500

@app.route("/api/logs")
def api_logs():
    n=int(request.args.get("n","200"))
    return jsonify({"lines":logs_tail(n).splitlines()})

@app.route("/api/traffic")
def api_traffic():
    iface,rx,tx=read_bytes()
    now=time.time()
    global _last_snapshot
    if _last_snapshot["ts"]==0:
        _last_snapshot={"ts":now,"rx":rx,"tx":tx}
        return jsonify({"iface":iface,"ts":int(now),"rx_bps":0,"tx_bps":0,"rx":rx,"tx":tx})
    dt=max(1e-6,now-_last_snapshot["ts"])
    rx_bps=max(0,(rx-_last_snapshot["rx"])/dt)
    tx_bps=max(0,(tx-_last_snapshot["tx"])/dt)
    _last_snapshot={"ts":now,"rx":rx,"tx":tx}
    return jsonify({"iface":iface,"ts":int(now),"rx_bps":rx_bps,"tx_bps":tx_bps,"rx":rx,"tx":tx})

@app.route("/api/ports",methods=["GET","POST"])
def api_ports():
    if request.method=="GET":
        proto=request.args.get("proto","udp")
        port=int(request.args.get("port",UDP_PORT))
        return jsonify({"port":port,"proto":proto,"ufw_allowed":ufw_allowed(port,proto),"listening":local_listening(port,proto)})
    data=request.get_json(force=True,silent=True) or {}
    port=int(data.get("port",UDP_PORT))
    proto=str(data.get("proto","udp")).lower()
    allow=bool(data.get("allow",True))
    if proto not in {"udp","tcp"}:
        abort(400)
    if allow:
        o,c=_sudorun(f"ufw allow {port}/{proto}")
    else:
        o,c=_sudorun(f"ufw delete allow {port}/{proto} || true")
    return jsonify({"ok":True,"out":o,"ufw_allowed":ufw_allowed(port,proto)})

@app.route("/api/config",methods=["GET","POST"])
def api_config():
    if request.method=="GET":
        p,cfg=read_server_conf()
        return jsonify({"path":p,"data":cfg})
    data=request.get_json(force=True,silent=True) or {}
    ok,out=write_server_conf(data)
    if not ok:
        return jsonify({"ok":False,"out":out}),400
    _sudorun(f"systemctl restart openvpn@{SRV_NAME}")
    return jsonify({"ok":True})

@app.route("/api/health")
def api_health():
    iface,rx,tx=read_bytes()
    st=parse_status_file()
    return jsonify({
        "service":service_active(),
        "port_udp_open":ufw_allowed(UDP_PORT,"udp"),
        "listening_udp":local_listening(UDP_PORT,"udp"),
        "ping_ok":ping_ok(),
        "ntp":timedate_ntp(),
        "iface":iface,
        "rx":rx,"tx":tx,
        "live_clients":len(st["clients"])
    })

def create_app():
    return app

if __name__=="__main__":
    app.run(host="0.0.0.0",port=APP_PORT, debug=True)