from tunnel_identity import session_tunnels, tunnel_key
import os
import sys
import redis
import ast
import ipaddress
from scapy.all import sniff
from scapy.contrib.pfcp import PFCP

# -------------------------
# Config
# -------------------------
interface = os.getenv("smf_sniffer_iface")
if not interface:
    if len(sys.argv) > 1:
        interface = sys.argv[1]
    else:
        print("❌ Error: No interface provided. Set smf_sniffer_iface or pass as argument.")
        sys.exit(1)

redis_host = os.getenv("REDIS_HOST", "redis.open5gs.svc.cluster.local")
print(f"🔗 Connecting to Redis at {redis_host}:6379...")
rdb = redis.Redis(host=redis_host, port=6379, decode_responses=True)

DEBUG = os.getenv("PFCP_DEBUG", "0") in ("1", "true", "True", "YES", "yes")

# -------------------------
# State
# -------------------------
seid_ctx: dict[int, dict] = {}     # canonical_seid -> {"ue_ip":..., "imsi":..., "ul_teid":..., "dl_teid":...}
seid_alias: dict[int, int] = {}   # seid -> canonical_seid (Open5GS flips SEID by direction)

# NEW: correlate by PFCP sequence number (50/51 share same seq)
seq_cache: dict[int, dict] = {}   # seq -> {"ue_ip":..., "imsi":...}

def canon(seid: int) -> int:
    """Resolve alias chain to canonical SEID."""
    if not seid:
        return 0
    while seid in seid_alias and seid_alias[seid] != seid:
        seid = seid_alias[seid]
    return seid

def get_ctx(seid: int) -> dict:
    c = canon(seid)
    if c not in seid_ctx:
        seid_ctx[c] = {}
        seid_alias.setdefault(c, c)
    return seid_ctx[c]

def merge_ctx(a: dict, b: dict):
    """Merge b into a without deleting."""
    for k in b:
        if k not in a:
            a[k] = b[k]

def union_seids(a: int, b: int):
    """
    Bidirectionally link SEIDs so either endpoint SEID resolves to the same canonical session.
    """
    if not a or not b:
        return

    seid_alias.setdefault(a, a)
    seid_alias.setdefault(b, b)

    ca, cb = canon(a), canon(b)
    if ca == 0:
        ca = a
        seid_alias[a] = a
        seid_ctx.setdefault(a, {})
    if cb == 0:
        cb = b
        seid_alias[b] = b
        seid_ctx.setdefault(b, {})

    if ca == cb:
        return

    root = min(ca, cb)
    other = max(ca, cb)

    rctx = get_ctx(root)
    octx = get_ctx(other)
    merge_ctx(rctx, octx)
    seid_alias[other] = root

def cleanup_pfcp_session(seid_for_cleanup: int):
    """
    Delete Redis mappings for a single PFCP session (one PDU session).
    Trigger this on PFCP Session Deletion Request (type 54).
    """
    cseid = canon(seid_for_cleanup)
    ctx = seid_ctx.get(cseid, {})

    ue_ip = ctx.get("ue_ip")
    imsi = ctx.get("imsi")
    ul = ctx.get("ul_teid")
    dl = ctx.get("dl_teid")

    for _direction, endpoint, teid in session_tunnels(ctx):
        key = tunnel_key(endpoint, teid)
        if key and rdb.hget("pfcp-tunnel:" + key, "session_key") == ctx.get("session_key"):
            rdb.delete("pfcp-tunnel:" + key)
    # Legacy identity aliases must not delete a replacement session's binding.
    for key, value in ((f"ip:{ue_ip}", ul), (f"imsi:{imsi}", ul)):
        if value and rdb.get(key) == value:
            rdb.delete(key)

    seid_ctx.pop(cseid, None)
    for k, v in list(seid_alias.items()):
        if canon(k) == cseid or v == cseid:
            seid_alias.pop(k, None)

    print(f"[🧹][SMF] PFCP session deleted: seid={seid_for_cleanup} canon={cseid} "
          f"imsi={imsi or '-'} ip={ue_ip or '-'} ul={ul or '-'} dl={dl or '-'}")

# -------------------------
# Helpers
# -------------------------
def normalize_teid(teid) -> str | None:
    try:
        if teid is None:
            return None
        if isinstance(teid, int):
            return f"{teid:08x}"
        s = str(teid).strip()
        if s.startswith("0x"):
            return f"{int(s, 16):08x}"
        if s.isdigit():
            return f"{int(s):08x}"
        return f"{int(s, 16):08x}"
    except Exception:
        return None

def tbcd_to_digits(b: bytes) -> str:
    digits = []
    for byte in b:
        lo = byte & 0x0F
        hi = (byte >> 4) & 0x0F
        if lo != 0x0F:
            digits.append(str(lo))
        if hi != 0x0F:
            digits.append(str(hi))
    return "".join(digits)

def normalize_imsi(v) -> str | None:
    if v is None:
        return None
    if isinstance(v, (bytes, bytearray)):
        d = tbcd_to_digits(bytes(v))
        return d if d else None
    if isinstance(v, str) and v.startswith("b'"):
        try:
            b = ast.literal_eval(v)
            d = tbcd_to_digits(b)
            return d if d else None
        except Exception:
            return None
    digits = "".join(ch for ch in str(v) if ch.isdigit())
    return digits if digits else None

def extract_all_ies(obj):
    ies = []
    stack = [obj]
    seen = set()
    while stack:
        cur = stack.pop()
        cid = id(cur)
        if cid in seen:
            continue
        seen.add(cid)

        if hasattr(cur, "ietype"):
            ies.append(cur)
        if hasattr(cur, "IE_list") and isinstance(cur.IE_list, list):
            stack.extend(cur.IE_list)
    return ies

def ie_name(ie) -> str:
    return type(ie).__name__

def ie_type(ie) -> int | None:
    return getattr(ie, "ietype", None)

def get_attr(obj, *names):
    for n in names:
        if hasattr(obj, n):
            v = getattr(obj, n)
            if v is not None:
                return v
    return None

def extract_ipv4_from_ue_ip_ie(ie) -> str | None:
    for attr in ("ipv4", "IPv4", "v4", "ip", "addr", "address", "ipv4_address", "ue_ip"):
        v = getattr(ie, attr, None)
        if v is None:
            continue
        if isinstance(v, str) and "." in v:
            return v
        if isinstance(v, int):
            try:
                return str(ipaddress.IPv4Address(v))
            except Exception:
                pass
        if isinstance(v, (bytes, bytearray)) and len(v) >= 4:
            try:
                return str(ipaddress.IPv4Address(v[-4:]))
            except Exception:
                pass

    try:
        b = bytes(ie)
        if len(b) >= 4:
            return str(ipaddress.IPv4Address(b[-4:]))
    except Exception:
        pass

    s = str(ie)
    for token in s.replace(",", " ").replace(";", " ").split():
        if token.count(".") == 3:
            return token.strip()

    return None

def store_teid_hash(teid_hex8, ue_ip, direction, imsi, endpoint=None, session_key=None, session_metadata=None):
    """PFCP identity is scoped to the receiving N3 endpoint, never a bare TEID."""
    key = tunnel_key(endpoint, teid_hex8)
    if not key or not session_key:
        return
    mapping = {"dir": direction, "session_key": session_key}
    mapping.update(session_metadata or {})
    if ue_ip:
        mapping["ue_ip"] = ue_ip
    if imsi:
        mapping["imsi"] = imsi
    rdb.hset("pfcp-tunnel:" + key, mapping=mapping)


def tunnel_endpoint(ie):
    """Read the IPv4 endpoint carried by PFCP F-TEID/Outer Header Creation."""
    value = get_attr(ie, "ipv4", "IPv4", "ipv4_address")
    try:
        return str(ipaddress.ip_address(value)) if value is not None else None
    except ValueError:
        return None


def looks_like_ngap_known_teid(teid_hex8: str, endpoint=None) -> bool:
    key = tunnel_key(endpoint, teid_hex8)
    h = rdb.hgetall("tunnel:" + key) if key else {}
    return ("ran_ue_id" in h) or ("sst" in h) or ("sd" in h)

# -------------------------
# PFCP parsing strategy
# -------------------------
def is_access_interface(val) -> bool:
    if val is None:
        return False
    if isinstance(val, int):
        return val == 0
    s = str(val).strip()
    if s.isdigit():
        return int(s) == 0
    return "access" in s.lower()

def parse_pfcp(pkt):
    pfcp = pkt[PFCP]
    msg_type = int(getattr(pfcp, "message_type", -1))
    hdr_seid = int(getattr(pfcp, "seid", 0) or 0)
    seq = int(getattr(pfcp, "seq", 0) or 0)

    ies = extract_all_ies(pfcp)

    if DEBUG:
        ie_types = [ie_type(x) for x in ies if ie_type(x) is not None]
        print(f"[PFCP][DBG] msg_type={msg_type} seq={seq} hdr_seid={hdr_seid} ie_types(sample)={ie_types[:20]}")

    # Teardown: PFCP Session Deletion Request
    if msg_type == 54 and hdr_seid:
        cleanup_pfcp_session(hdr_seid)
        return

    peer_fseid = None
    fseid_ip = None
    found_ip = None
    found_imsi = None

    ul_candidates = []
    dl_candidates = []
    endpoints = {}

    # --- pass 1: UE IP, IMSI, and peer F-SEID ---
    for ie in ies:
        t = ie_type(ie)
        n = ie_name(ie)

        # F-SEID IE type is 57
        if t == 57 or "FSEID" in n.upper():
            v = get_attr(ie, "SEID", "seid")
            if v is not None:
                try:
                    peer_fseid = int(v)
                    fseid_ip = get_attr(ie, "ipv4") if get_attr(ie, "v4") else get_attr(ie, "ipv6")
                except Exception:
                    pass

        # UE IP Address IE type is 93
        if t == 93 or ("UE" in n.upper() and "IP" in n.upper()):
            ip = extract_ipv4_from_ue_ip_ie(ie)
            if ip:
                found_ip = ip

        if n in ("IE_User_ID", "IE_UserID", "IE_UserId"):
            raw = get_attr(ie, "IMSI", "imsi")
            x = normalize_imsi(raw)
            if not x:
                digits = "".join(ch for ch in str(ie) if ch.isdigit())
                if len(digits) >= 10:
                    x = digits
            if x:
                found_imsi = x

    # Cache by seq (50/51 share seq) so response can inherit UE IP even if it isn't repeated
    if seq:
        if found_ip:
            seq_cache.setdefault(seq, {})["ue_ip"] = found_ip
        if found_imsi:
            seq_cache.setdefault(seq, {})["imsi"] = found_imsi

    # Determine session key for this packet
    ctx_seid = hdr_seid or peer_fseid or 0

    # Link endpoint SEIDs if both present
    if hdr_seid and peer_fseid:
        union_seids(hdr_seid, peer_fseid)

    # If we didn't find UE IP in this message, try to inherit from seq cache
    if not found_ip and seq and seq in seq_cache:
        found_ip = seq_cache[seq].get("ue_ip") or found_ip
    if not found_imsi and seq and seq in seq_cache:
        found_imsi = seq_cache[seq].get("imsi") or found_imsi

    # Update session context
    ctx = get_ctx(ctx_seid)
    # Establishment request carries CP F-SEID; response carries UP F-SEID.
    if peer_fseid is not None and msg_type in (50, 51):
        role = "smf" if msg_type == 50 else "upf"
        ctx[role + "_seid"] = str(peer_fseid)
        if fseid_ip:
            ctx[role + "_pfcp_ip"] = str(fseid_ip)
    ip = pkt.getlayer("IP") or pkt.getlayer("IPv6")
    if ip is not None:
        peer = "|".join(sorted((str(ip.src), str(ip.dst))))
        ctx["session_key"] = f"pfcp:{peer}:{canon(ctx_seid)}"
    if found_ip:
        ctx["ue_ip"] = found_ip
    if found_imsi:
        ctx["imsi"] = found_imsi

    # --- pass 2: UL candidates ---
    if msg_type == 51:
        for ie in ies:
            if ie_name(ie) == "IE_CreatedPDR":
                inner = extract_all_ies(ie)
                for x in inner:
                    if ie_name(x) == "IE_FTEID":
                        teid_val = get_attr(x, "TEID", "teid")
                        teid_hex = normalize_teid(teid_val)
                        if teid_hex:
                            ul_candidates.append(teid_hex)
                            endpoints[("UL", teid_hex)] = tunnel_endpoint(x)

    if not ul_candidates:
        for ie in ies:
            if ie_name(ie) == "IE_FTEID":
                teid_val = get_attr(ie, "TEID", "teid")
                teid_hex = normalize_teid(teid_val)
                if teid_hex:
                    ul_candidates.append(teid_hex)
                    endpoints[("UL", teid_hex)] = tunnel_endpoint(ie)

    # --- pass 3: DL candidates with context (Destination Interface == Access) ---
    def walk_with_context(node, dest_if=None):
        # Destination Interface and Outer Header Creation are sibling IEs.
        for child in getattr(node, "IE_list", []) or []:
            if ie_name(child) == "IE_DestinationInterface":
                dest_if = get_attr(child, "interface", "Interface", "dst_iface", "destination_interface")
        if hasattr(node, "ietype"):
            n = ie_name(node)

            if n == "IE_DestinationInterface":
                di = get_attr(node, "interface", "Interface", "dst_iface", "destination_interface")
                dest_if = di if di is not None else dest_if

            if n == "IE_OuterHeaderCreation":
                if is_access_interface(dest_if):
                    teid_val = get_attr(node, "TEID", "teid")
                    teid_hex = normalize_teid(teid_val)
                    if teid_hex:
                        dl_candidates.append(teid_hex)
                        endpoints[("DL", teid_hex)] = tunnel_endpoint(node)

        for ch in getattr(node, "IE_list", []) or []:
            walk_with_context(ch, dest_if)

    walk_with_context(pfcp, None)

    # --- choose UL TEID ---
    ul_teid = None
    if ul_candidates:
        if len(ul_candidates) > 1:
            for cand in ul_candidates:
                if looks_like_ngap_known_teid(cand, endpoints.get(("UL", cand))):
                    ul_teid = cand
                    break
        ul_teid = ul_teid or ul_candidates[0]

    # --- choose DL TEID ---
    dl_teid = None
    if dl_candidates:
        if len(dl_candidates) > 1:
            for cand in dl_candidates:
                if looks_like_ngap_known_teid(cand, endpoints.get(("DL", cand))):
                    dl_teid = cand
                    break
        dl_teid = dl_teid or dl_candidates[0]

    # Save chosen TEIDs into session context for cleanup later
    if ul_teid:
        ctx["ul_teid"] = ul_teid
        if endpoints.get(("UL", ul_teid)):
            ctx["upf_n3_ip"] = endpoints[("UL", ul_teid)]
    if dl_teid:
        ctx["dl_teid"] = dl_teid
        if endpoints.get(("DL", dl_teid)):
            ctx["gnb_n3_ip"] = endpoints[("DL", dl_teid)]

    ue_ip = get_ctx(ctx_seid).get("ue_ip")
    imsi = get_ctx(ctx_seid).get("imsi")

    if DEBUG and msg_type in (50, 51, 52) and not ue_ip:
        print(f"[PFCP][DBG] no ue_ip yet: msg_type={msg_type} seq={seq} hdr_seid={hdr_seid} peer_fseid={peer_fseid}")

    current_keys = {"pfcp-tunnel:" + tunnel_key(endpoint, teid)
                    for _, endpoint, teid in session_tunnels(ctx) if endpoint and teid}
    for key, owner in ctx.get("tunnel_keys", {}).items():
        if key not in current_keys and rdb.hget(key, "session_key") == owner:
            rdb.delete(key)
    ctx["tunnel_keys"] = {key: ctx.get("session_key") for key in current_keys}

    session_metadata = {key: ctx[key] for key in ("smf_seid", "smf_pfcp_ip", "upf_seid", "upf_pfcp_ip") if key in ctx}
    if ul_teid:
        store_teid_hash(ul_teid, ue_ip, "UL", imsi, ctx.get("upf_n3_ip"), ctx.get("session_key"), session_metadata)
    if dl_teid:
        store_teid_hash(dl_teid, ue_ip, "DL", imsi, ctx.get("gnb_n3_ip"), ctx.get("session_key"), session_metadata)

def handle_pfcp(pkt):
    if not pkt.haslayer(PFCP):
        return
    try:
        parse_pfcp(pkt)
    except Exception:
        return

def main():
    print(f"🚀 PFCP sniffer running on '{interface}' (udp/8805)...")
    sniff(filter="udp port 8805", iface=interface, prn=handle_pfcp, store=0)

if __name__ == "__main__":
    main()
