import os, subprocess, datetime, re, time, shlex, json, ipaddress
from typing import Tuple, Dict, Any, List
import logging
from flask import Flask, render_template, request, send_file, redirect, url_for, jsonify, abort

APP_PORT=int(os.environ.get("APP_PORT","8088"))
WG_IFACE=os.environ.get("WG_IFACE","wg0")
WG_DIR=os.environ.get("WG_DIR","/etc/wireguard")
WG_CONF=os.environ.get("WG_CONF",f"/etc/wireguard/{WG_IFACE}.conf")
WG_PORT=int(os.environ.get("WG_PORT","51820"))
SERVER_ADDR_ENV=os.environ.get("SERVER_ADDR","10.8.0.1/24")
HOST_IP=subprocess.check_output(["bash","-lc","hostname -I | awk '{print $1}'"]).decode().strip()
UNIT=f"wg-quick@{WG_IFACE}"
PEERS_DB=os.path.join(WG_DIR,"peers.json")
SUDO_BIN=os.environ.get("SUDO_BIN","/usr/bin/sudo")
BASH_BIN=os.environ.get("BASH_BIN","/bin/bash")

app=Flask(__name__)
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
app.logger.setLevel(logging.INFO)

def _run(cmd: str) -> Tuple[str,int]:
    r=subprocess.run(cmd,shell=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True)
    return r.stdout.strip(), r.returncode

_last_run = {"cmd":"", "rc":None, "out":""}

def _sudorun(cmd: str) -> Tuple[str,int]:
    app.logger.info("run: %s", cmd)
    full = f"{SUDO_BIN} -n {BASH_BIN} -lc {shlex.quote(cmd)}"
    o,c=_run(full)
    app.logger.info("rc=%s", c)
    global _last_run
    _last_run = {"cmd": cmd, "rc": c, "out": o}
    if c != 0:
        app.logger.warning("command failed: rc=%s\nstdout+stderr:\n%s", c, o)
    return o,c

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

def service_active() -> bool:
    o,c=_run(f"systemctl is-active {UNIT}")
    return o.strip()=="active"

def service_enabled() -> bool:
    o,c=_run(f"systemctl is-enabled {UNIT} || true")
    return o.strip()=="enabled"

def ufw_allowed(port: int, proto: str="udp") -> bool:
    o,c=_run("ufw status numbered | grep -E '\\b{}/{}\\b' || true".format(port,proto))
    return bool(o)

def local_listening(port: int, proto: str="udp") -> bool:
    if proto=="udp":
        o,c=_run("ss -lunp | grep -E ':{0} \\b.*\\b' || true".format(port))
    else:
        o,c=_run("ss -ltnp | grep -E ':{0} \\b.*\\b' || true".format(port))
    return bool(o)

def ping_ok() -> bool:
    o,c=_run("ping -c1 -W1 1.1.1.1 >/dev/null 2>&1")
    return c==0

def timedate_ntp() -> str:
    o,c=_run("timedatectl 2>/dev/null | awk -F': ' '/NTP service:|System clock synchronized:/{print $2}' | xargs | sed 's/ /, /g'")
    return o.strip()

def logs_tail(n: int=200) -> str:
    o,c=_run(f"journalctl -u {UNIT} -n {int(n)} --no-pager || true")
    return o

def _read_conf() -> Dict[str,Any]:
    data={"Interface":{}, "Peers":[]}
    if not os.path.isfile(WG_CONF):
        return data
    cur=None
    cur_peer={}
    for ln in open(WG_CONF,encoding="utf-8",errors="ignore"):
        s=ln.strip()
        if not s or s.startswith("#"):
            continue
        if s.lower()=="[interface]":
            cur="iface"
            continue
        if s.lower()=="[peer]":
            if cur_peer:
                data["Peers"].append(cur_peer)
            cur_peer={}
            cur="peer"
            continue
        if "=" in s:
            k,v=[x.strip() for x in s.split("=",1)]
            if cur=="iface":
                data["Interface"][k]=v
            elif cur=="peer":
                cur_peer[k]=v
    if cur_peer:
        data["Peers"].append(cur_peer)
    return data

def _write_conf(data: Dict[str,Any]) -> None:
    lines=[]
    iface=data.get("Interface",{})
    lines.append("[Interface]")
    for k,v in iface.items():
        lines.append(f"{k} = {v}")
    for p in data.get("Peers",[]):
        lines.append("")
        lines.append("[Peer]")
        for k,v in p.items():
            lines.append(f"{k} = {v}")
    tmp=WG_CONF+".tmp"
    with open(tmp,"w",encoding="utf-8") as f:
        f.write("\n".join(lines).strip()+"\n")
    _sudorun(f"install -m 600 {shlex.quote(tmp)} {shlex.quote(WG_CONF)} && rm -f {shlex.quote(tmp)}")

def _iface_name() -> str:
    return WG_IFACE

def read_bytes() -> Tuple[str,int,int]:
    iface=_iface_name()
    rx=f"/sys/class/net/{iface}/statistics/rx_bytes"
    tx=f"/sys/class/net/{iface}/statistics/tx_bytes"
    try:
        with open(rx) as fr: r=int(fr.read().strip())
        with open(tx) as ft: t=int(ft.read().strip())
        return iface,r,t
    except:
        return iface,0,0

def _server_pubkey() -> str:
    o,c=_sudorun(f"wg show {WG_IFACE} public-key || true")
    if o.strip():
        return o.strip()
    conf=_read_conf()
    priv=conf.get("Interface",{}).get("PrivateKey","").strip()
    if not priv:
        return ""
    o,c=_sudorun(f"bash -lc 'printf %s {shlex.quote(priv)} | wg pubkey'")
    return o.strip()

def _load_peers_db() -> Dict[str,Any]:
    if not os.path.isdir(WG_DIR):
        _sudorun(f"install -d -m 700 {shlex.quote(WG_DIR)}")
    if not os.path.isfile(PEERS_DB):
        return {}
    try:
        return json.load(open(PEERS_DB,"r"))
    except:
        return {}

def _save_peers_db(db: Dict[str,Any]) -> None:
    tmp=PEERS_DB+".tmp"
    with open(tmp,"w") as f:
        json.dump(db,f,indent=2)
    _sudorun(f"install -m 600 {shlex.quote(tmp)} {shlex.quote(PEERS_DB)} && rm -f {shlex.quote(tmp)}")

def _valid_name(x: Any) -> bool:
    return bool(re.match(r"^[A-Za-z0-9._-]{1,64}$", str(x or "").strip()))

def _valid_ip(x: Any) -> bool:
    try:
        ipaddress.ip_interface(str(x))
        return True
    except:
        return False

def _server_subnets() -> List[ipaddress.IPv4Network]:
    nets=[]
    conf=_read_conf()
    addrs=conf.get("Interface",{}).get("Address","") or SERVER_ADDR_ENV
    for part in re.split(r"[,\s]+", addrs.strip()):
        part=part.strip()
        if not part:
            continue
        try:
            iface=ipaddress.ip_interface(part)
            if isinstance(iface.ip, ipaddress.IPv4Address):
                nets.append(iface.network)
        except:
            continue
    return nets

def _assigned_ips() -> List[ipaddress.IPv4Interface]:
    conf=_read_conf()
    res=[]
    for peer in conf.get("Peers",[]):
        a=peer.get("AllowedIPs","").strip()
        for piece in re.split(r"[,\s]+", a):
            piece=piece.strip()
            if not piece: continue
            try:
                iface=ipaddress.ip_interface(piece)
                res.append(iface)
            except:
                continue
    return res

def _next_client_ip() -> str:
    nets=_server_subnets()
    if not nets:
        return ""
    net=nets[0]
    used=set()
    for iface in _assigned_ips():
        if iface.ip in net:
            used.add(int(iface.ip))
    srv_iface=_read_conf().get("Interface",{}).get("Address","") or SERVER_ADDR_ENV
    for part in re.split(r"[,\s]+", srv_iface.strip()):
        part=part.strip()
        if not part:
            continue
        try:
            ii=ipaddress.ip_interface(part)
            if ii.ip in net:
                used.add(int(ii.ip))
        except:
            pass
    for host in net.hosts():
        if host == net.network_address or host == net.broadcast_address:
            continue
        if str(host).endswith(".1"):
            continue
        if int(host) not in used:
            return f"{host}/32"
    return ""

def list_clients() -> List[Dict[str,Any]]:
    db=_load_peers_db()
    show,c=_run(f"wg show {WG_IFACE} dump || true")
    peers=[]
    lines=[ln for ln in show.splitlines()[1:] if ln.strip()]
    now=int(time.time())
    for ln in lines:
        p=ln.split("\t")
        if len(p)<9:
            continue
        pub=p[1]
        ep=p[4]
        lh=int(p[5]) if p[5].isdigit() else 0
        rx=int(p[6]) if p[6].isdigit() else 0
        tx=int(p[7]) if p[7].isdigit() else 0
        allowed=p[8]
        name=None
        for k,v in db.items():
            if v.get("public_key")==pub:
                name=k
                break
        peers.append({
            "name":name or pub[:8],
            "cn":name or pub[:8],
            "remote":ep or "",
            "bytes_recv":rx,
            "bytes_sent":tx,
            "since":datetime.datetime.utcfromtimestamp(lh).strftime("%Y-%m-%d %H:%M:%S") if lh>0 and lh<now+10 else "",
            "allowed_ips":allowed,
            "public_key":pub
        })
    issued=[]
    for name,meta in db.items():
        status="active"
        created=meta.get("created","")
        issued.append({"name":name,"status":status,"created":created,"public_key":meta.get("public_key",""),"ip":meta.get("address","")})
    return issued,peers

def gen_client_conf(name: str) -> Tuple[str,str]:
    db=_load_peers_db()
    meta=db.get(name) or {}
    if not meta:
        raise FileNotFoundError("peer not found")
    client_priv=meta["private_key"]
    client_addr=meta["address"]
    dns=_read_conf().get("Interface",{}).get("DNS","").strip()
    srv_pub=_server_pubkey()
    conf=_read_conf()
    lp=conf.get("Interface",{}).get("ListenPort",str(WG_PORT))
    endpoint=f"{HOST_IP}:{lp}"
    allowed_client="0.0.0.0/0, ::/0"
    keepalive="25"
    txt=[]
    txt.append("[Interface]")
    txt.append(f"PrivateKey = {client_priv}")
    txt.append(f"Address = {client_addr}")
    if dns:
        txt.append(f"DNS = {dns}")
    txt.append("")
    txt.append("[Peer]")
    txt.append(f"PublicKey = {srv_pub}")
    txt.append(f"AllowedIPs = {allowed_client}")
    txt.append(f"Endpoint = {endpoint}")
    txt.append(f"PersistentKeepalive = {keepalive}")
    return "\n".join(txt).strip()+"\n", meta.get("public_key","")

def _ensure_peer_removed_from_conf(pubkey: str) -> None:
    data=_read_conf()
    data["Peers"]=[p for p in data.get("Peers",[]) if p.get("PublicKey","").strip()!=pubkey.strip()]
    _write_conf(data)

@app.route("/")
def home():
    issued,live=list_clients()
    data={
        "service_active":service_active(),
        "service_enabled":service_enabled(),
        "host_ip":HOST_IP,
        "udp_port":WG_PORT,
        "unit":UNIT,
        "local_listen":local_listening(WG_PORT),
        "ufw_open":ufw_allowed(WG_PORT),
        "ping_ok":ping_ok(),
        "ntp":timedate_ntp(),
        "clients":len(issued),
        "logs":logs_tail(60)
    }
    iface,_,_=read_bytes()
    return render_template("index.html",data=data,users=issued,iface=iface)

@app.route("/action/<what>")
def action(what: str):
    if what=="restart":
        _sudorun(f"systemctl restart {UNIT}")
    elif what=="stop":
        _sudorun(f"systemctl stop {UNIT}")
    elif what=="start":
        _sudorun(f"systemctl start {UNIT}")
    return redirect(url_for("home"))

@app.route("/api/status")
def api_status():
    try:
        iface,rx,tx=read_bytes()
    except:
        iface,rx,tx=WG_IFACE,0,0
    try:
        conf=_read_conf()
    except:
        conf={}
    try:
        issued,live=list_clients()
    except:
        issued,live=[],[]
    try:
        ntp=timedate_ntp()
    except:
        ntp="unknown"
    lp=(conf.get("Interface",{}).get("ListenPort") or str(WG_PORT))
    payload={
        "service":{"active":False,"enabled":False,"unit":UNIT},
        "network":{"host_ip":HOST_IP,"port":int(lp),"ufw_udp_open":False,"listening":False,"ping_ok":False,"iface":iface,"rx":rx,"tx":tx},
        "clients":{"count":len(issued),"issued":issued,"live":live,"status_updated":None},
        "config":{
            "path":WG_CONF,
            "port":lp,
            "proto":"udp",
            "cipher":None,
            "auth":None,
            "push":[],
            "dhcp_option":[]
        },
        "time":{"ntp":ntp},
    }
    try:
        payload["service"]["active"]=service_active()
    except:
        pass
    try:
        payload["service"]["enabled"]=service_enabled()
    except:
        pass
    try:
        payload["network"]["ufw_udp_open"]=ufw_allowed(int(lp),"udp")
    except:
        pass
    try:
        payload["network"]["listening"]=local_listening(int(lp),"udp")
    except:
        pass
    try:
        payload["network"]["ping_ok"]=ping_ok()
    except:
        pass
    return jsonify(payload)

@app.route("/api/service",methods=["POST"])
def api_service():
    data=request.get_json(force=True,silent=True) or {}
    action=str(data.get("action","")).lower()
    if action not in {"start","stop","restart","enable","disable","reload"}:
        abort(400)
    if action=="enable":
        o,c=_sudorun(f"systemctl enable {UNIT}")
    elif action=="disable":
        o,c=_sudorun(f"systemctl disable {UNIT}")
    elif action=="reload":
        o,c=_sudorun(f"wg syncconf {WG_IFACE} <(wg-quick strip {WG_IFACE})")
    else:
        o,c=_sudorun(f"systemctl {action} {UNIT}")
    return jsonify({"ok":c==0,"out":o,"active":service_active(),"enabled":service_enabled()})

@app.route("/api/users",methods=["GET","POST"])
def api_users():
    if request.method=="GET":
        issued,live=list_clients()
        return jsonify({"issued":issued})
    data=request.get_json(force=True,silent=True) or {}
    name=str(data.get("name","")).strip()
    cn=str(data.get("cn",name)).strip()
    static_ip=str(data.get("ip","")).strip()
    if not _valid_name(name):
        return jsonify({"ok": False, "error": "invalid_name", "hint": "Allowed: A-Z a-z 0-9 . _ - (max 64)"}), 400
    if static_ip and not _valid_ip(static_ip if "/" in static_ip else static_ip+"/32"):
        return jsonify({"ok": False, "error": "invalid_ip", "hint": "Use 10.8.0.23 or 10.8.0.23/32"}), 400
    db=_load_peers_db()
    if name in db:
        return jsonify({"ok": False, "error": "already_exists", "hint": "Peer already exists"}), 409
    o_priv,c=_sudorun("wg genkey")
    if c!=0 or not o_priv.strip():
        return jsonify({"ok":False,"error":"keygen_failed","out":o_priv}),500
    client_priv=o_priv.strip()
    o_pub,c=_sudorun(f"bash -lc 'printf %s {shlex.quote(client_priv)} | wg pubkey'")
    if c!=0 or not o_pub.strip():
        return jsonify({"ok":False,"error":"pubkey_failed","out":o_pub}),500
    client_pub=o_pub.strip()
    addr=static_ip if static_ip else _next_client_ip()
    if not addr:
        return jsonify({"ok":False,"error":"addr_failed","hint":"No free IP in server subnet"}),500
    server_lp=_read_conf().get("Interface",{}).get("ListenPort",str(WG_PORT))
    _sudorun(f"wg set {WG_IFACE} peer {shlex.quote(client_pub)} allowed-ips {shlex.quote(addr)}")
    conf=_read_conf()
    peers=conf.get("Peers",[])
    peers=[p for p in peers if p.get("PublicKey","")!=client_pub]
    peers.append({"PublicKey":client_pub,"AllowedIPs":addr})
    conf["Peers"]=peers
    _write_conf(conf)
    db[name]={"public_key":client_pub,"private_key":client_priv,"address":addr,"created":datetime.datetime.utcnow().strftime("%Y-%m-%d")}
    _save_peers_db(db)
    return jsonify({"ok":True,"name":name,"cn":cn,"port":int(server_lp)})

@app.route("/api/users/<name>/revoke",methods=["POST"])
def api_users_revoke(name: str):
    db=_load_peers_db()
    meta=db.get(name)
    if not meta:
        abort(404)
    pub=meta.get("public_key","")
    _sudorun(f"wg set {WG_IFACE} peer {shlex.quote(pub)} remove || true")
    _ensure_peer_removed_from_conf(pub)
    del db[name]
    _save_peers_db(db)
    _sudorun(f"systemctl reload {UNIT} || true")
    return jsonify({"ok":True})

@app.route("/api/users/<name>/restore",methods=["POST"])
def api_users_restore(name: str):
    db=_load_peers_db()
    meta=db.get(name)
    if not meta:
        abort(404)
    pub=meta.get("public_key","")
    addr=meta.get("address","")
    _sudorun(f"wg set {WG_IFACE} peer {shlex.quote(pub)} allowed-ips {shlex.quote(addr)}")
    conf=_read_conf()
    peers=conf.get("Peers",[])
    if not any(p.get("PublicKey","")==pub for p in peers):
        peers.append({"PublicKey":pub,"AllowedIPs":addr})
        conf["Peers"]=peers
        _write_conf(conf)
    return jsonify({"ok":True})

@app.route("/api/users/<name>/ovpn")
def api_users_conf(name: str):
    try:
        txt,pub=gen_client_conf(name)
        return jsonify({"ok":True,"name":name,"profile":txt})
    except Exception as e:
        app.logger.exception("conf build failed name=%s",name)
        return jsonify({"ok":False,"error":"conf_build_failed","hint":str(e)}),500

@app.route("/api/logs")
def api_logs():
    n=int(request.args.get("n","200"))
    return jsonify({"lines":logs_tail(n).splitlines()})

@app.route("/api/traffic")
def api_traffic():
    iface,rx,tx=read_bytes()
    now=time.time()
    global _last_run
    if "_snap" not in app.config:
        app.config["_snap"]={"ts":now,"rx":rx,"tx":tx}
        return jsonify({"iface":iface,"ts":int(now),"rx_bps":0,"tx_bps":0,"rx":rx,"tx":tx})
    snap=app.config["_snap"]
    dt=max(1e-6,now-snap["ts"])
    rx_bps=max(0,(rx-snap["rx"])/dt)
    tx_bps=max(0,(tx-snap["tx"])/dt)
    app.config["_snap"]={"ts":now,"rx":rx,"tx":tx}
    return jsonify({"iface":iface,"ts":int(now),"rx_bps":rx_bps,"tx_bps":tx_bps,"rx":rx,"tx":tx})

@app.route("/api/ports",methods=["GET","POST"])
def api_ports():
    if request.method=="GET":
        proto=request.args.get("proto","udp")
        port=int(request.args.get("port",WG_PORT))
        return jsonify({"port":port,"proto":proto,"ufw_allowed":ufw_allowed(port,proto),"listening":local_listening(port,proto)})
    data=request.get_json(force=True,silent=True) or {}
    port=int(data.get("port",WG_PORT))
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
        return jsonify({"path":WG_CONF,"data":_read_conf()})
    data=request.get_json(force=True,silent=True) or {}
    conf=_read_conf()
    iface=conf.get("Interface",{})
    if "ListenPort" in data:
        iface["ListenPort"]=str(data["ListenPort"])
    if "DNS" in data:
        iface["DNS"]=str(data["DNS"])
    if "Address" in data:
        iface["Address"]=str(data["Address"])
    conf["Interface"]=iface
    _write_conf(conf)
    _sudorun(f"systemctl restart {UNIT}")
    return jsonify({"ok":True})

@app.route("/api/health")
def api_health():
    iface,rx,tx=read_bytes()
    lp=_read_conf().get("Interface",{}).get("ListenPort",str(WG_PORT))
    return jsonify({
        "service":service_active(),
        "port_udp_open":ufw_allowed(int(lp),"udp"),
        "listening_udp":local_listening(int(lp),"udp"),
        "ping_ok":ping_ok(),
        "ntp":timedate_ntp(),
        "iface":iface,
        "rx":rx,"tx":tx,
        "live_clients":len(list_clients()[1])
    })

@app.route("/api/diag/last")
def api_diag_last():
    global _last_run
    return jsonify(_last_run)

@app.route("/download/<name>.conf")
def download_conf(name: str):
    txt,_=gen_client_conf(name)
    p=f"/tmp/{name}.conf"
    with open(p,"w") as f:
        f.write(txt)
    return send_file(p,as_attachment=True,download_name=f"{name}.conf")

def create_app():
    return app

if __name__=="__main__":
    app.run(host="0.0.0.0",port=APP_PORT, debug=True)