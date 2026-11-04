from tunnel_identity import tunnel_key
from flask import Flask, Response, jsonify, request
from prometheus_client import CONTENT_TYPE_LATEST, CollectorRegistry, Gauge, generate_latest
import redis
import os

app = Flask(__name__)

redis_host = os.getenv("REDIS_HOST", "redis")
rdb = redis.Redis(host=redis_host, port=6379, decode_responses=True)


# -------------------------------------------------
# Helpers
# -------------------------------------------------


def norm_hex(s: str, width: int) -> str:
    if not s:
        return ""
    s = str(s).strip().lower().replace("0x", "").replace(":", "")
    if not s:
        return ""
    return s.zfill(width)


def normalize_sst(sst: str | None) -> str:
    s = (sst or "").strip().lower()
    if not s or s in ("unknown", "none", "null"):
        return "01"
    return norm_hex(s, 2)


def normalize_sd(sd: str | None) -> str:
    s = (sd or "").strip().lower().replace(":", "")
    if not s or s in ("unknown", "none", "null"):
        return "ffffff"
    return norm_hex(s, 6)


def slice_id_from_sst_sd(sst: str, sd: str) -> str:
    sst_n = normalize_sst(sst)
    sd_n = normalize_sd(sd)
    return f"{sst_n}:{sd_n}"


def make_teid_args(ul_teid: str = "", dl_teid: str = "", slice_id: str = "") -> str:
    """
    gtp_latency_user supports:
      - single: 0xTEID@slice
      - pair:   0xUL:0xDL@slice
    """
    ul_teid = norm_hex(ul_teid, 8)
    dl_teid = norm_hex(dl_teid, 8)

    if not slice_id:
        slice_id = "01:ffffff"

    if ul_teid and dl_teid:
        return f"0x{ul_teid}:0x{dl_teid}@{slice_id}"
    if ul_teid:
        return f"0x{ul_teid}@{slice_id}"
    if dl_teid:
        return f"0x{dl_teid}@{slice_id}"
    return ""


def build_inventory_rows(limit: int = 500):
    """
    Build clean inventory rows for the controller.

    Strategy:
      1) Read session-scoped ran:* keys, including legacy ran:<id> records.
      2) Enrich from endpoint-scoped PFCP tunnel records.
      3) Emit only rows that have BOTH ul_teid and dl_teid.
      4) Always normalize missing/unknown sd -> ffffff.
    """
    rows = []
    seen_pairs = set()

    ran_keys = sorted(rdb.keys("ran:*"))
    for ran_key in ran_keys:
        ran_info = rdb.hgetall(ran_key) or {}
        ran_id = ran_info.get("ran_ue_id") or ran_key.split("ran:", 1)[1]

        ul = norm_hex(ran_info.get("ul_teid", ""), 8)
        dl = norm_hex(ran_info.get("dl_teid", ""), 8)

        # Controller only wants real pairs
        if not ul or not dl:
            continue

        ul_key = tunnel_key(ran_info.get("upf_n3_ip"), ul)
        dl_key = tunnel_key(ran_info.get("gnb_n3_ip"), dl)
        ul_h = rdb.hgetall("pfcp-tunnel:" + ul_key) if ul_key else {}
        dl_h = rdb.hgetall("pfcp-tunnel:" + dl_key) if dl_key else {}
        # Prefer IMSI from UL (Open5GS UL side usually carries the longer IMSI)
        imsi = ul_h.get("imsi") or ran_info.get("imsi") or dl_h.get("imsi") or None

        ue_ip = ul_h.get("ue_ip") or dl_h.get("ue_ip") or ran_info.get("ue_ip") or None

        sst = ran_info.get("sst") or ul_h.get("sst") or dl_h.get("sst") or "01"

        sd = ran_info.get("sd") or ul_h.get("sd") or dl_h.get("sd") or "ffffff"

        sst_n = normalize_sst(sst)
        sd_n = normalize_sd(sd)
        slice_id = slice_id_from_sst_sd(sst_n, sd_n)

        pair_key = (ul, dl, ran_key)
        if pair_key in seen_pairs:
            continue
        seen_pairs.add(pair_key)

        rows.append(
            {
                "imsi": imsi,
                "session_key": ran_key,
                "gnb_id": ran_info.get("gnb_n3_ip") or ran_info.get("ngap_scope"),
                "gnb_n3_ip": ran_info.get("gnb_n3_ip"),
                "upf_n3_ip": ran_info.get("upf_n3_ip"),
                **{key: ul_h.get(key) or dl_h.get(key) for key in
                   ("smf_seid", "smf_pfcp_ip", "upf_seid", "upf_pfcp_ip")},
                "ran_ue_id": ran_id,
                "ue_ip": ue_ip,
                "sst": sst_n,
                "sd": sd_n,
                "slice_id": slice_id,
                "ul_teid": f"0x{ul}",
                "dl_teid": f"0x{dl}",
                "teid_args": make_teid_args(ul, dl, slice_id),
                "source": "inventory -> ran:*",
            }
        )

        if len(rows) >= limit:
            break

    return rows[:limit]


# -------------------------------------------------
# Basic lookup endpoints
# -------------------------------------------------


# Return all TEID matches, or a unique identity match, optionally filtered by endpoint.
def lookup_session(field, value):
    endpoint = request.args.get("endpoint")
    rows = build_inventory_rows(limit=2000)
    if field == "teid":
        rows = [
            row
            for row in rows
            if value in (norm_hex(row["ul_teid"], 8), norm_hex(row["dl_teid"], 8))
            and (
                not endpoint
                or (
                    endpoint == row.get("upf_n3_ip")
                    and value == norm_hex(row["ul_teid"], 8)
                )
                or (
                    endpoint == row.get("gnb_n3_ip")
                    and value == norm_hex(row["dl_teid"], 8)
                )
            )
        ]
    else:
        rows = [
            row
            for row in rows
            if row.get(field) == value
            and (
                not endpoint or endpoint in (row.get("gnb_n3_ip"), row.get("upf_n3_ip"))
            )
        ]
    if field == "teid":
        return jsonify(rows)
    if not rows:
        return jsonify({"error": "Session not found"}), 404
    if len(rows) > 1:
        return jsonify(
            {
                "error": "Ambiguous session; specify a receiving endpoint",
                "sessions": rows,
            }
        ), 409
    return jsonify(rows[0])


@app.route("/teid/<teid>")
def get_teid(teid):
    return lookup_session("teid", norm_hex(teid, 8))


@app.route("/all-teids")
def list_all_teids():
    keys = sorted(rdb.keys("tunnel:*"))[: int(request.args.get("limit", 500))]
    entries = {key: rdb.hgetall(key) for key in keys}
    return jsonify({"count": len(entries), "cursor": 0, "entries": entries})


@app.route("/ip/<ue_ip>")
def get_by_ip(ue_ip):
    return lookup_session("ue_ip", ue_ip)


@app.route("/imsi/<imsi>")
def get_by_imsi(imsi):
    return lookup_session("imsi", imsi)


# -------------------------------------------------
# Resolver endpoints
# -------------------------------------------------


@app.route("/resolve/ue/imsi/<imsi>")
def resolve_ue_by_imsi(imsi):
    return lookup_session("imsi", imsi)


@app.route("/resolve/slice")
def resolve_slice():
    sst = request.args.get("sst")
    sd = request.args.get("sd")

    if not sst:
        return jsonify({"error": "missing sst query param"}), 400

    sst_n = normalize_sst(sst)
    sd_n = normalize_sd(sd)
    sid = slice_id_from_sst_sd(sst_n, sd_n)

    inventory = build_inventory_rows(limit=500)
    ues = []
    teid_args_list = []

    for ue in inventory:
        if ue.get("sst") != sst_n:
            continue
        if ue.get("sd") != sd_n:
            continue

        ues.append(ue)
        if ue.get("teid_args"):
            teid_args_list.append(ue["teid_args"])

    return jsonify(
        {
            "sst": sst_n,
            "sd": sd_n,
            "slice_id": sid,
            "ues": ues,
            "teid_args": " ".join(teid_args_list),
        }
    )


# -------------------------------------------------
# Inventory endpoint used by controller
# -------------------------------------------------


@app.route("/inventory/ues")
def inventory_ues():
    limit = int(request.args.get("limit", 500))
    rows = build_inventory_rows(limit=limit)
    return jsonify({"count": len(rows), "limit": limit, "ues": rows})


# Generate current session metadata on each scrape so released sessions disappear.
@app.route("/metrics")
def session_metrics():
    labels = ("imsi", "ue_ip", "gnb_id", "slice_id", "session_key",
              "smf_seid", "smf_pfcp_ip", "upf_seid", "upf_pfcp_ip")
    registry = CollectorRegistry()
    metric = Gauge("fiveg_ue_session_info", "Current UE to PFCP session mapping", labels, registry=registry)
    for row in build_inventory_rows(limit=2000):
        if row.get("imsi"):
            metric.labels(**{field: str(row.get(field) or "") for field in labels}).set(1)
    return Response(generate_latest(registry), content_type=CONTENT_TYPE_LATEST)


# -------------------------------------------------
# Root
# -------------------------------------------------


@app.route("/")
def root():
    return jsonify(
        {
            "status": "UE mapper API running",
            "endpoints": [
                "/teid/<teid>",
                "/all-teids",
                "/ip/<ue_ip>",
                "/imsi/<imsi>",
                "/resolve/ue/imsi/<imsi>",
                "/resolve/slice?sst=..&sd=..",
                "/inventory/ues",
                "/metrics",
            ],
        }
    )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
