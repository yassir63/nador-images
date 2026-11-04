"""GTP tunnel identity shared by the controller, exporters and sniffers."""

import ipaddress


def normalize_teid(value):
    """Use one representation for integer, prefixed and eight-digit TEIDs."""
    if value in (None, ""):
        return ""
    text = str(value).strip().lower()
    number = (
        value
        if isinstance(value, int)
        else int(
            text,
            16
            if text.startswith("0x")
            or len(text) == 8
            or any(c in text for c in "abcdef")
            else 10,
        )
    )
    return f"0x{number:08x}"


def tunnel_key(endpoint, teid):
    """A TEID identifies a tunnel only within its receiving GTP endpoint."""
    if not endpoint or not teid:
        return ""
    return f"{ipaddress.ip_address(endpoint)}|{normalize_teid(teid)}"


def session_tunnels(ue):
    """Return the receiving endpoint and TEID for each session direction."""
    return (
        ("ul", ue.get("upf_n3_ip"), ue.get("ul_teid")),
        ("dl", ue.get("gnb_n3_ip"), ue.get("dl_teid")),
    )


def load_tunnel_map(parsed):
    """Retain scoped keys; accept legacy TEID keys for older single-UE maps."""
    return {
        key if "|" in key else normalize_teid(key): dict(value)
        for key, value in parsed.items()
        if isinstance(value, dict)
    }


def metadata_for_event(mapping, event):
    """Resolve by the packet's receiving endpoint; never guess between gNBs."""
    endpoint = event.get("outer_dst_ip")
    teid = event.get("teid")
    if endpoint:
        return mapping.get(tunnel_key(endpoint, teid), {})
    return mapping.get(normalize_teid(teid), {})
