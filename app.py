import os, subprocess, datetime, re, time, shlex, json, ipaddress, urllib.request
from typing import Tuple, Dict, Any, List
import logging
from flask import Flask, render_template, request, send_file, redirect, url_for, jsonify, abort

APP_PORT=int(os.environ.get("APP_PORT","8088"))
WG_IFACE=os.environ.get("WG_IFACE","wg0")
WG_DIR=os.environ.get("WG_DIR","/etc/wireguard")
WG_CONF=os.environ.get("WG_CONF",f"/etc/wireguard/{WG_IFACE}.conf")
WG_PORT=int(os.environ.get("WG_PORT","51820"))
SERVER_ADDR_ENV=os.environ.get("SERVER_ADDR","10.8.0.1/24")
CLIENT_DNS=os.environ.get("CLIENT_DNS","1.1.1.1, 1.0.0.1")
HOST_IP=subprocess.check_output(["bash","-lc","hostname -I | awk '{print $1}'"]).decode().strip()
UNIT=f"wg-quick@{WG_IFACE}"

def _detect_public_ip() -> str:
    if os.environ.get("SERVER_PUBLIC_IP"):
        return os.environ["SERVER_PUBLIC_IP"].strip()
    for url in ("https://api.ipify.org","https://ifconfig.me/ip","https://icanhazip.com"):
        try:
            return urllib.request.urlopen(url, timeout=4).read().decode().strip()
        except Exception:
            continue
    return HOST_IP

PUBLIC_IP = _detect_public_ip()

PEERS_DB=os.path.join(WG_DIR,"peers.json")
TRAFFIC_HISTORY=os.environ.get("TRAFFIC_HISTORY", os.path.join(WG_DIR, "traffic_history.json"))
TRAFFIC_RETENTION_SECONDS=24*60*60
TRAFFIC_FLUSH_SECONDS=10
GEO_CACHE_SECONDS=6*60*60
SUDO_BIN=os.environ.get("SUDO_BIN","/usr/bin/sudo")
BASH_BIN=os.environ.get("BASH_BIN","/bin/bash")

app=Flask(__name__)
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
app.logger.setLevel(logging.INFO)

def _run(cmd: str) -> Tuple[str,int]:
    r=subprocess.run(cmd,shell=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True)
    return r.stdout.strip(), r.returncode

_last_run = {"cmd":"", "rc":None, "out":""}
_geo_cache: Dict[str, Dict[str, Any]] = {}

# Helper function to sudo cat a file, checking common locations for cat
def _sudo_cat(path: str) -> Tuple[str, int]:
    for cat_bin in ("/bin/cat", "/usr/bin/cat"):
        out, rc = _sudo([cat_bin, path])
        if rc == 0:
            return out, 0
    return "", 1

def _sudo(args: List[str], input_data: bytes = None) -> Tuple[str,int]:
    try:
        cmd = [SUDO_BIN, "-n"] + args
        app.logger.info("run_exec: %s", " ".join(shlex.quote(a) for a in cmd))
        r = subprocess.run(cmd, input=input_data, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        out = r.stdout.decode().strip()
    except Exception as e:
        out = str(e)
        r = type("obj", (), {"returncode": 1})()
    rc = r.returncode if hasattr(r, "returncode") else 1
    global _last_run
    _last_run = {"cmd": " ".join(args), "rc": rc, "out": out}
    if rc != 0:
        app.logger.warning("command failed: rc=%s\nstdout+stderr:\n%s", rc, out)
    return out, rc

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
    flag = "u" if proto == "udp" else "t"
    o,_=_run(f"ss -l{flag}np 2>/dev/null | grep ':{port}' || true")
    return bool(o.strip())

def ping_ok() -> bool:
    o,c=_run("ping -c1 -W1 1.1.1.1 >/dev/null 2>&1")
    return c==0

def timedate_ntp() -> str:
    o,c=_run("timedatectl 2>/dev/null | awk -F': ' '/NTP service:|System clock synchronized:/{print $2}' | xargs | sed 's/ /, /g'")
    return o.strip()

def logs_tail(n: int=200, verbose: bool=False) -> str:
    fmt = "short-precise" if verbose else "short"
    args = ["/usr/bin/journalctl", "-u", UNIT, "-n", str(int(n)), "--no-pager", f"--output={fmt}"]
    o, _ = _sudo(args)
    return o

def _read_conf() -> Dict[str,Any]:
    data = {"Interface": {}, "Peers": []}
    content = ""
    try:
        with open(WG_CONF, encoding="utf-8", errors="ignore") as f:
            content = f.read()
    except FileNotFoundError:
        return data
    except PermissionError:
        out, rc = _sudo_cat(WG_CONF)
        if rc != 0 or not out:
            return data
        content = out
    cur = None
    cur_peer = {}
    for ln in content.splitlines():
        s = ln.strip()
        if not s or s.startswith("#"):
            continue
        if s.lower() == "[interface]":
            cur = "iface"
            continue
        if s.lower() == "[peer]":
            if cur_peer:
                data["Peers"].append(cur_peer)
            cur_peer = {}
            cur = "peer"
            continue
        if "=" in s:
            k, v = [x.strip() for x in s.split("=", 1)]
            if cur == "iface":
                data["Interface"][k] = v
            elif cur == "peer":
                cur_peer[k] = v
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
    import tempfile
    fd,tmp_path = tempfile.mkstemp(prefix="wg0.", suffix=".conf.tmp", dir="/tmp")
    try:
        with os.fdopen(fd,"w",encoding="utf-8") as f:
            f.write("\n".join(lines).strip()+"\n")
        _sudo(["/usr/bin/install","-m","640","-o","root","-g","www-data",tmp_path,WG_CONF])
    finally:
        try:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
        except:
            pass

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

def _valid_traffic_sample(x: Any) -> bool:
    return (
        isinstance(x, dict)
        and isinstance(x.get("ts"), (int, float))
        and isinstance(x.get("rx_bps"), (int, float))
        and isinstance(x.get("tx_bps"), (int, float))
    )

def _load_traffic_history() -> List[Dict[str, Any]]:
    content = ""
    try:
        with open(TRAFFIC_HISTORY, "r", encoding="utf-8") as f:
            content = f.read()
    except FileNotFoundError:
        return []
    except PermissionError:
        out, rc = _sudo_cat(TRAFFIC_HISTORY)
        if rc != 0:
            return []
        content = out
    except Exception:
        return []
    try:
        raw = json.loads(content)
    except Exception:
        return []
    if not isinstance(raw, list):
        return []
    cutoff = time.time() - TRAFFIC_RETENTION_SECONDS
    history = []
    for sample in raw:
        if not _valid_traffic_sample(sample):
            continue
        ts = float(sample["ts"])
        if ts < cutoff:
            continue
        history.append({
            "ts": ts,
            "rx_bps": max(0.0, float(sample.get("rx_bps", 0))),
            "tx_bps": max(0.0, float(sample.get("tx_bps", 0))),
            "rx": int(sample.get("rx", 0) or 0),
            "tx": int(sample.get("tx", 0) or 0),
        })
    history.sort(key=lambda s: s["ts"])
    return history

def _save_traffic_history(history: List[Dict[str, Any]]) -> None:
    import tempfile
    fd,tmp_path = tempfile.mkstemp(prefix="traffic.", suffix=".json.tmp", dir="/tmp")
    try:
        with os.fdopen(fd,"w",encoding="utf-8") as f:
            json.dump(history, f, separators=(",", ":"))
        try:
            os.makedirs(os.path.dirname(TRAFFIC_HISTORY), exist_ok=True)
            os.replace(tmp_path, TRAFFIC_HISTORY)
            return
        except Exception:
            pass
        _sudo(["/usr/bin/install","-m","640","-o","root","-g","www-data",tmp_path,TRAFFIC_HISTORY])
    finally:
        try:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
        except:
            pass

def _traffic_history() -> List[Dict[str, Any]]:
    if "_traffic_history" not in app.config:
        app.config["_traffic_history"] = _load_traffic_history()
        app.config["_traffic_last_flush"] = 0.0
    return app.config["_traffic_history"]

def _prune_traffic_history(history: List[Dict[str, Any]], now: float = None) -> List[Dict[str, Any]]:
    cutoff = (now if now is not None else time.time()) - TRAFFIC_RETENTION_SECONDS
    return [s for s in history if s.get("ts", 0) >= cutoff]

def _record_traffic_sample(sample: Dict[str, Any]) -> None:
    history = _traffic_history()
    if history and sample["ts"] <= history[-1]["ts"]:
        history[-1] = sample
    else:
        history.append(sample)
    history = _prune_traffic_history(history, sample["ts"])
    app.config["_traffic_history"] = history
    last_flush = float(app.config.get("_traffic_last_flush", 0) or 0)
    if sample["ts"] - last_flush >= TRAFFIC_FLUSH_SECONDS:
        _save_traffic_history(history)
        app.config["_traffic_last_flush"] = sample["ts"]

def _downsample_traffic(samples: List[Dict[str, Any]], max_points: int) -> List[Dict[str, Any]]:
    if max_points <= 0 or len(samples) <= max_points:
        return samples
    bucket_size = max(1, int((len(samples) + max_points - 1) / max_points))
    out = []
    for i in range(0, len(samples), bucket_size):
        bucket = samples[i:i + bucket_size]
        if not bucket:
            continue
        out.append({
            "ts": bucket[-1]["ts"],
            "rx_bps": sum(s["rx_bps"] for s in bucket) / len(bucket),
            "tx_bps": sum(s["tx_bps"] for s in bucket) / len(bucket),
            "rx": bucket[-1].get("rx", 0),
            "tx": bucket[-1].get("tx", 0),
        })
    return out

def _endpoint_ip(endpoint: str) -> str:
    endpoint = str(endpoint or "").strip()
    if not endpoint or endpoint == "(none)" or endpoint == "—":
        return ""
    host = endpoint
    if endpoint.startswith("["):
        end = endpoint.find("]")
        if end > 0:
            host = endpoint[1:end]
    elif endpoint.count(":") == 1:
        host = endpoint.rsplit(":", 1)[0]
    try:
        ipaddress.ip_address(host)
        return host
    except Exception:
        return ""

def _ping_ip(ip: str) -> Any:
    try:
        ipaddress.ip_address(ip)
    except Exception:
        return None
    try:
        r = subprocess.run(
            ["/bin/ping", "-c", "1", "-W", "1", ip],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=2,
        )
    except Exception:
        return None
    if r.returncode != 0:
        return None
    m = re.search(r"time[=<]([\d.]+)\s*ms", r.stdout)
    if not m:
        return None
    return round(float(m.group(1)), 1)

def _lookup_location(ip: str) -> Dict[str, Any]:
    try:
        addr = ipaddress.ip_address(ip)
    except Exception:
        return {"label": "—"}
    if addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_multicast or addr.is_reserved:
        return {"ip": ip, "label": "Private network"}
    cached = _geo_cache.get(ip)
    now = time.time()
    if cached and now - cached.get("ts", 0) < GEO_CACHE_SECONDS:
        return cached.get("data", {"ip": ip, "label": "—"})
    data = {"ip": ip, "label": "—"}
    try:
        url = f"https://ipwho.is/{ip}"
        with urllib.request.urlopen(url, timeout=3) as res:
            raw = json.loads(res.read().decode())
        if raw.get("success"):
            city = str(raw.get("city") or "").strip()
            region = str(raw.get("region") or "").strip()
            country = str(raw.get("country") or "").strip()
            parts = [p for p in (city, region, country) if p]
            data = {
                "ip": ip,
                "city": city,
                "region": region,
                "country": country,
                "label": ", ".join(parts) if parts else country or ip,
            }
    except Exception:
        pass
    _geo_cache[ip] = {"ts": now, "data": data}
    return data

def _server_pubkey() -> str:
    if os.path.exists("/usr/bin/wg"):
        o,c=_sudo(["/usr/bin/wg","show",WG_IFACE,"public-key"]) 
    else:
        o,c=_run(f"wg show {WG_IFACE} public-key || true")
    if o.strip():
        return o.strip()
    conf=_read_conf()
    priv=conf.get("Interface",{}).get("PrivateKey","").strip()
    if not priv:
        return ""
    o,c=_sudo(["/usr/bin/wg","pubkey"], input_data=(priv+"\n").encode())
    return o.strip()

def _load_peers_db() -> Dict[str,Any]:
    if not os.path.isdir(WG_DIR):
        _sudo(["/usr/bin/install","-d","-m","700",WG_DIR])
    if not os.path.isfile(PEERS_DB):
        return {}
    try:
        with open(PEERS_DB, "r", encoding="utf-8") as f:
            return json.load(f)
    except PermissionError:
        out, rc = _sudo_cat(PEERS_DB)
        if rc == 0 and out:
            try:
                return json.loads(out)
            except Exception:
                return {}
        return {}
    except Exception:
        return {}

def _save_peers_db(db: Dict[str,Any]) -> None:
    import tempfile
    fd,tmp_path = tempfile.mkstemp(prefix="peers.", suffix=".json.tmp", dir="/tmp")
    try:
        with os.fdopen(fd,"w",encoding="utf-8") as f:
            json.dump(db,f,indent=2)
        _sudo(["/usr/bin/install","-m","640","-o","root","-g","www-data",tmp_path,PEERS_DB])
    finally:
        try:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
        except:
            pass

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

def list_clients() -> List[Dict[str, Any]]:
    db = _load_peers_db()

    # get live state from wg
    if os.path.exists("/usr/bin/wg"):
        show, c = _sudo(["/usr/bin/wg", "show", WG_IFACE, "dump"])
    else:
        show, c = _run(f"wg show {WG_IFACE} dump || true")

    live = []
    lines = [ln for ln in show.splitlines()[1:] if ln.strip()]  # skip interface line
    now = int(time.time())

    for ln in lines:
        p = ln.split("\t")
        # peer line must have at least 8 fields
        # 0 pubkey
        # 1 psk
        # 2 endpoint
        # 3 allowed-ips
        # 4 latest-handshake
        # 5 transfer-rx
        # 6 transfer-tx
        # 7 keepalive
        if len(p) < 8:
            continue

        pub = p[0].strip()
        endpoint = p[2].strip()
        allowed = p[3].strip()

        try:
            lh_raw = int(p[4])  # unix ts
        except ValueError:
            lh_raw = 0

        try:
            rx = int(p[5])
        except ValueError:
            rx = 0

        try:
            tx = int(p[6])
        except ValueError:
            tx = 0

        # map to name from db (peers.json)
        name = None
        for k, v in db.items():
            if v.get("public_key") == pub:
                name = k
                break

        live.append({
            "name": name or pub[:8],
            "cn": name or pub[:8],
            "remote": endpoint,
            "bytes_recv": rx,   # client → server
            "bytes_sent": tx,   # server → client
            "last_handshake": lh_raw if lh_raw > 0 and lh_raw < now + 10 else 0,
            "since": (
                datetime.datetime.utcfromtimestamp(lh_raw).strftime("%Y-%m-%d %H:%M:%S")
                if lh_raw > 0 and lh_raw < now + 10 else ""
            ),
            "allowed_ips": allowed,
            "public_key": pub,
        })

    # issued peers from our DB
    issued = []
    for name, meta in db.items():
        issued.append({
            "name": name,
            "status": "active",
            "created": meta.get("created", ""),
            "public_key": meta.get("public_key", ""),
            "ip": meta.get("address", "")
        })

    return issued, live

def gen_client_conf(name: str) -> Tuple[str,str]:
    db=_load_peers_db()
    meta=db.get(name) or {}
    if not meta:
        lname = name.lower()
        for k,v in db.items():
            if k.lower() == lname:
                meta = v
                name = k
                break
    if not meta:
        raise FileNotFoundError("peer not found")
    client_priv=meta["private_key"]
    client_addr=meta["address"]
    conf=_read_conf()
    dns=conf.get("Interface",{}).get("DNS","").strip() or CLIENT_DNS
    srv_pub=_server_pubkey()
    lp=conf.get("Interface",{}).get("ListenPort",str(WG_PORT))
    endpoint=f"{PUBLIC_IP}:{lp}"
    allowed_client="0.0.0.0/0, ::/0"
    keepalive="25"
    txt=[]
    txt.append("[Interface]")
    txt.append(f"PrivateKey = {client_priv}")
    txt.append(f"Address = {client_addr}")
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
        _sudo(["/usr/bin/systemctl","restart",UNIT])
    elif what=="stop":
        _sudo(["/usr/bin/systemctl","stop",UNIT])
    elif what=="start":
        _sudo(["/usr/bin/systemctl","start",UNIT])
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
        o,c=_sudo(["/usr/bin/systemctl","enable",UNIT])
    elif action=="disable":
        o,c=_sudo(["/usr/bin/systemctl","disable",UNIT])
    elif action=="reload":
        so,sc=_sudo(["/usr/bin/wg-quick","strip",WG_IFACE])
        if sc==0:
            import tempfile
            fd,tp=tempfile.mkstemp(prefix="wgstrip.",dir="/tmp")
            try:
                with os.fdopen(fd,"w",encoding="utf-8") as f: f.write(so)
                o,c=_sudo(["/usr/bin/wg","syncconf",WG_IFACE,tp])
            finally:
                try: os.remove(tp)
                except: pass
        else:
            o, c = so, sc
    else:
        o,c=_sudo(["/usr/bin/systemctl",action,UNIT])
    return jsonify({"ok":c==0,"out":o,"active":service_active(),"enabled":service_enabled()})

@app.route("/api/users",methods=["GET","POST"])
def api_users():
    if request.method=="GET":
        issued,live=list_clients()
        return jsonify({"issued":issued,"live":live})
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
    o_priv,c=_sudo(["/usr/bin/wg","genkey"])
    if c!=0 or not o_priv.strip():
        return jsonify({"ok":False,"error":"keygen_failed","out":o_priv}),500
    client_priv=o_priv.strip()
    o_pub,c=_sudo(["/usr/bin/wg","pubkey"], input_data=(client_priv+"\n").encode())
    if c!=0 or not o_pub.strip():
        return jsonify({"ok":False,"error":"pubkey_failed","out":o_pub}),500
    client_pub=o_pub.strip()
    addr=static_ip if static_ip else _next_client_ip()
    if not addr:
        return jsonify({"ok":False,"error":"addr_failed","hint":"No free IP in server subnet"}),500
    server_lp=_read_conf().get("Interface",{}).get("ListenPort",str(WG_PORT))
    _sudo(["/usr/bin/wg","set",WG_IFACE,"peer",client_pub,"allowed-ips",addr])
    conf=_read_conf()
    peers=conf.get("Peers",[])
    peers=[p for p in peers if p.get("PublicKey","")!=client_pub]
    peers.append({"PublicKey":client_pub,"AllowedIPs":addr})
    conf["Peers"]=peers
    _write_conf(conf)
    db[name]={"public_key":client_pub,"private_key":client_priv,"address":addr,"created":datetime.datetime.utcnow().strftime("%Y-%m-%d")}
    _save_peers_db(db)
    try:
        profile_text, _ = gen_client_conf(name)
    except Exception:
        profile_text = None
    return jsonify({"ok": True, "name": name, "cn": cn, "port": int(server_lp), "profile": profile_text})

@app.route("/api/users/<name>/rename",methods=["POST"])
def api_users_rename(name: str):
    data=request.get_json(force=True,silent=True) or {}
    new_name=str(data.get("name","")).strip()
    if not _valid_name(new_name):
        return jsonify({"ok":False,"error":"invalid_name","hint":"Allowed: A-Z a-z 0-9 . _ - (max 64)"}),400
    db=_load_peers_db()
    if name not in db:
        abort(404)
    if new_name!=name and new_name in db:
        return jsonify({"ok":False,"error":"already_exists","hint":"A peer with that name already exists"}),409
    db[new_name]=db.pop(name)
    _save_peers_db(db)
    return jsonify({"ok":True,"name":new_name})

@app.route("/api/users/<name>/revoke",methods=["POST"])
def api_users_revoke(name: str):
    db=_load_peers_db()
    meta=db.get(name)
    if not meta:
        abort(404)
    pub=meta.get("public_key","")
    _sudo(["/usr/bin/wg","set",WG_IFACE,"peer",pub,"remove"])
    _ensure_peer_removed_from_conf(pub)
    del db[name]
    _save_peers_db(db)
    _sudo(["/usr/bin/systemctl","reload",UNIT])
    return jsonify({"ok":True})

@app.route("/api/users/<name>/restore",methods=["POST"])
def api_users_restore(name: str):
    db=_load_peers_db()
    meta=db.get(name)
    if not meta:
        abort(404)
    pub=meta.get("public_key","")
    addr=meta.get("address","")
    _sudo(["/usr/bin/wg","set",WG_IFACE,"peer",pub,"allowed-ips",addr])
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
        txt, pub = gen_client_conf(name)
        return jsonify({"ok": True, "name": name, "profile": txt})
    except FileNotFoundError:
        return jsonify({
            "ok": False,
            "error": "peer_not_found",
            "hint": "Create the peer first via POST /api/users with {name}, then retry /api/users/<name>/ovpn."
        }), 404
    except Exception as e:
        app.logger.exception("conf build failed name=%s", name)
        return jsonify({"ok": False, "error": "conf_build_failed", "hint": str(e)}), 500

@app.route("/api/users/<name>/diag")
def api_users_diag(name: str):
    issued, live = list_clients()
    peer = next((p for p in live if p.get("name") == name or p.get("cn") == name), None)
    if not peer:
        db = _load_peers_db()
        if name not in db:
            abort(404)
        return jsonify({
            "ok": True,
            "name": name,
            "endpoint": "—",
            "endpoint_ip": "",
            "ping_ms": None,
            "location": {"label": "—"},
        })
    endpoint = peer.get("remote", "")
    endpoint_ip = _endpoint_ip(endpoint)
    ping_ms = _ping_ip(endpoint_ip) if endpoint_ip else None
    location = _lookup_location(endpoint_ip) if endpoint_ip else {"label": "—"}
    return jsonify({
        "ok": True,
        "name": name,
        "endpoint": endpoint or "—",
        "endpoint_ip": endpoint_ip,
        "ping_ms": ping_ms,
        "location": location,
    })

@app.route("/api/diag/peers")
def api_diag_peers():
    db = _load_peers_db()
    show, _ = _sudo(["/usr/bin/wg", "show", WG_IFACE, "dump"]) if os.path.exists("/usr/bin/wg") else ("", 0)
    return jsonify({"db_keys": sorted(list(db.keys())), "db": db, "wg_dump": show})


@app.route("/api/diag/perms")
def api_diag_perms():
    import stat, pwd, grp
    info = {}
    try:
        st = os.stat(WG_CONF)
        mode_dec = st.st_mode & 0o777
        mode_oct_str = f"{mode_dec:03o}"
        try:
            owner = pwd.getpwuid(st.st_uid).pw_name
        except Exception:
            owner = str(st.st_uid)
        try:
            group = grp.getgrgid(st.st_gid).gr_name
        except Exception:
            group = str(st.st_gid)
        info["wg_conf"] = {
            "path": str(WG_CONF),
            "exists": True,
            "mode_decimal_str": str(mode_dec),
            "mode_octal": "0" + mode_oct_str,
            "uid_str": str(st.st_uid),
            "gid_str": str(st.st_gid),
            "owner": owner,
            "group": group,
            "size_bytes_str": str(st.st_size)
        }
    except Exception as e:
        info["wg_conf_error"] = str(e)
    out_cat, rc_cat = _sudo_cat(WG_CONF)
    info["sudo_cat_rc_str"] = str(rc_cat)
    info["sudo_cat_ok"] = (rc_cat == 0)
    info["sudo_cat_len_str"] = str(len(out_cat) if isinstance(out_cat, str) else 0)
    info["sudo_cat_head"] = out_cat[:120] if isinstance(out_cat, str) else ""
    return jsonify(info)


@app.route("/api/logs")
def api_logs():
    n=int(request.args.get("n","200"))
    verbose=request.args.get("verbose","0")=="1"
    lines=logs_tail(n, verbose).splitlines()
    return jsonify({"lines":lines,"verbose":verbose,"count":len(lines)})

@app.route("/api/logs/retention",methods=["POST"])
def api_logs_retention():
    data=request.get_json(force=True,silent=True) or {}
    retention=str(data.get("retention","7d")).strip()
    if retention not in {"1d","7d","30d","forever"}:
        abort(400)
    if retention=="forever":
        return jsonify({"ok":True,"retention":retention,"out":"No vacuum needed"})
    vacuum_map={"1d":"1d","7d":"7d","30d":"30d"}
    o,c=_sudo(["/usr/bin/journalctl",f"--vacuum-time={vacuum_map[retention]}"])
    return jsonify({"ok":c==0,"retention":retention,"out":o})

@app.route("/api/traffic")
def api_traffic():
    iface,rx,tx=read_bytes()
    now=time.time()
    global _last_run
    if "_snap" not in app.config:
        app.config["_snap"]={"ts":now,"rx":rx,"tx":tx}
        sample={"ts":now,"rx_bps":0.0,"tx_bps":0.0,"rx":rx,"tx":tx}
        _record_traffic_sample(sample)
        return jsonify({"iface":iface,**sample})
    snap=app.config["_snap"]
    dt=max(1e-6,now-snap["ts"])
    rx_bps=max(0,(rx-snap["rx"])/dt)
    tx_bps=max(0,(tx-snap["tx"])/dt)
    app.config["_snap"]={"ts":now,"rx":rx,"tx":tx}
    sample={"ts":now,"rx_bps":rx_bps,"tx_bps":tx_bps,"rx":rx,"tx":tx}
    _record_traffic_sample(sample)
    return jsonify({"iface":iface,**sample})

@app.route("/api/traffic/history")
def api_traffic_history():
    range_arg=str(request.args.get("range","1m")).lower()
    ranges={"1m":60,"5m":5*60,"1h":60*60,"24h":24*60*60}
    seconds=ranges.get(range_arg, 60)
    try:
        max_points=int(request.args.get("max_points","1200"))
    except (TypeError, ValueError):
        max_points=1200
    max_points=max(2, min(5000, max_points))
    now=time.time()
    history=_prune_traffic_history(_traffic_history(), now)
    app.config["_traffic_history"]=history
    cutoff=now-seconds
    samples=[s for s in history if s.get("ts", 0) >= cutoff]
    samples=_downsample_traffic(samples, max_points)
    return jsonify({
        "range": range_arg if range_arg in ranges else "1m",
        "seconds": seconds,
        "retention_seconds": TRAFFIC_RETENTION_SECONDS,
        "samples": samples,
    })

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
        o,c=_sudo(["/usr/sbin/ufw","allow",f"{port}/{proto}"])
    else:
        o,c=_sudo(["/usr/sbin/ufw","delete","allow",f"{port}/{proto}"])
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
    _sudo(["/usr/bin/systemctl","restart",UNIT])
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

@app.route("/api/diag/vpn")
def api_diag_vpn():
    conf=_read_conf()
    iface_cfg=conf.get("Interface",{})
    lp=iface_cfg.get("ListenPort",str(WG_PORT))
    ip_fwd,_=_run("cat /proc/sys/net/ipv4/ip_forward 2>/dev/null || echo 0")
    wg_show,_=_sudo(["/usr/bin/wg","show"]) if os.path.exists("/usr/bin/wg") else ("","")
    journal,_=_sudo(["/usr/bin/journalctl","-u",UNIT,"-n","15","--no-pager"])
    return jsonify({
        "public_ip": PUBLIC_IP,
        "host_ip": HOST_IP,
        "ip_forward": ip_fwd.strip()=="1",
        "has_postup": "PostUp" in iface_cfg,
        "service_active": service_active(),
        "port": int(lp),
        "listening": local_listening(int(lp),"udp"),
        "ufw_allowed": ufw_allowed(int(lp),"udp"),
        "wg_show": wg_show,
        "journal": [l for l in journal.strip().splitlines() if l.strip()][-12:],
    })

@app.route("/api/fix",methods=["POST"])
def api_fix():
    actions=[]
    errors=[]
    # 1. ip_forward
    fwd,_=_run("cat /proc/sys/net/ipv4/ip_forward 2>/dev/null || echo 0")
    if fwd.strip()!="1":
        _,c=_sudo(["/usr/bin/sysctl","-w","net.ipv4.ip_forward=1"])
        if c==0:
            actions.append("Enabled ip_forward")
        else:
            errors.append("Could not enable ip_forward")
    # 2. PostUp / PostDown
    conf=_read_conf()
    iface_cfg=conf.get("Interface",{})
    if "PostUp" not in iface_cfg:
        net_if,_=_run("ip route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++){if($i==\"dev\"){print $(i+1); exit}}}'")
        net_if=net_if.strip()
        if net_if:
            iface_cfg["PostUp"]=f"iptables -A FORWARD -i %i -j ACCEPT; iptables -A FORWARD -o %i -j ACCEPT; iptables -t nat -A POSTROUTING -o {net_if} -j MASQUERADE"
            iface_cfg["PostDown"]=f"iptables -D FORWARD -i %i -j ACCEPT; iptables -D FORWARD -o %i -j ACCEPT; iptables -t nat -D POSTROUTING -o {net_if} -j MASQUERADE"
            conf["Interface"]=iface_cfg
            _write_conf(conf)
            actions.append(f"Added NAT PostUp/PostDown (via {net_if})")
        else:
            errors.append("Could not detect outgoing network interface")
    # 3. UFW allow port
    lp=int(iface_cfg.get("ListenPort",WG_PORT))
    if not ufw_allowed(lp,"udp"):
        _,c=_sudo(["/usr/sbin/ufw","allow",f"{lp}/udp"])
        if c==0:
            actions.append(f"Opened UDP {lp} in UFW")
    # 4. Start / restart service
    svc_was=service_active()
    if svc_was and actions:
        o,c=_sudo(["/usr/bin/systemctl","restart",UNIT])
        if c==0:
            actions.append("Restarted wg-quick to apply changes")
        else:
            errors.append(f"Restart failed: {o[:300]}")
    elif not svc_was:
        o,c=_sudo(["/usr/bin/systemctl","start",UNIT])
        if c==0:
            actions.append("Started wg-quick service")
        else:
            errors.append(f"Start failed — check logs: {o[:300]}")
    return jsonify({"ok":len(errors)==0,"actions":actions,"errors":errors,"service_active":service_active()})

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
