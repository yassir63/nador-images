"""Allowlisted, bounded source-netns TCP/SCTP connect and PFCP heartbeat checks.

CLI stdin: {"target": {...}, "timeout": 2, "allowlist": [...]}. One JSON result.
No target is implicitly approved. DNS and socket operations run in a killable
child. The integrating parent must also bound its nsenter subprocess.
"""

import argparse
import errno
import ipaddress
import json
import math
import secrets
import socket
import struct
import subprocess
import sys
import time


MAX_INPUT = 65536
MAX_OUTPUT = 4096
START_NTP = (int(time.time()) + 2208988800) & 0xffffffff


class CheckError(ValueError):
    pass


def validate_request(request, timeout_override=None):
    if not isinstance(request, dict):
        raise CheckError("invalid_request")
    target = request.get("target")
    timeout = timeout_override if timeout_override is not None else request.get("timeout", 2)
    if type(timeout) not in (int, float) or not math.isfinite(timeout) or not 0.05 <= timeout <= 10:
        raise CheckError("invalid_timeout")
    if not isinstance(target, dict):
        raise CheckError("invalid_target")
    host, port, transport = target.get("host"), target.get("port"), target.get("transport")
    if not isinstance(host, str) or not 1 <= len(host) <= 253 or any(c.isspace() for c in host) or "\x00" in host:
        raise CheckError("invalid_host")
    if type(port) is not int or not 1 <= port <= 65535 or transport not in ("tcp", "sctp", "pfcp_heartbeat"):
        raise CheckError("invalid_endpoint")
    if target.get("source_category") not in (None, "core", "ran"):
        raise CheckError("invalid_source_category")
    if target.get("source_component") is not None and not isinstance(target["source_component"], str):
        raise CheckError("invalid_source_component")
    if transport == "pfcp_heartbeat" and (target.get("source_component") or target.get("isolated_test_peer") is not True):
        raise CheckError("pfcp_requires_isolated_test_peer")
    allowlist = request.get("allowlist", [])
    if not isinstance(allowlist, list) or len(allowlist) > 128:
        raise CheckError("invalid_allowlist")
    addresses = set()
    for entry in allowlist:
        if not isinstance(entry, dict):
            raise CheckError("invalid_allowlist")
        if (entry.get("host"), entry.get("port"), entry.get("transport")) == (host, port, transport):
            pins = entry.get("addresses", [])
            if not isinstance(pins, list) or not 1 <= len(pins) <= 16:
                raise CheckError("invalid_address_pins")
            try:
                addresses.update(str(ipaddress.ip_address(pin)) for pin in pins)
            except ValueError:
                raise CheckError("invalid_address_pins") from None
    if not addresses:
        raise CheckError("endpoint_not_allowlisted")
    return target, float(timeout), addresses


def heartbeat_request(sequence, recovery_timestamp=START_NTP):
    if not 0 <= sequence < 1 << 24 or not 0 <= recovery_timestamp < 1 << 32:
        raise CheckError("invalid_pfcp_values")
    recovery = struct.pack("!HHI", 96, 4, recovery_timestamp)
    return b"\x20\x01\x00\x0c" + sequence.to_bytes(3, "big") + b"\0" + recovery


def validate_heartbeat_response(data, sequence):
    """Strict v1 node-level response, matching sequence, complete IE framing."""
    if len(data) < 8 or len(data) > 4096:
        raise CheckError("pfcp_length")
    # Version=1; heartbeat has no SEID/priority. Spare bits must be zero.
    if data[0] != 0x20:
        raise CheckError("pfcp_version_or_flags")
    if data[1] != 2:
        raise CheckError("pfcp_type")
    if int.from_bytes(data[2:4], "big") + 4 != len(data):
        raise CheckError("pfcp_length")
    if int.from_bytes(data[4:7], "big") != sequence:
        raise CheckError("pfcp_sequence")
    if data[7] != 0:
        raise CheckError("pfcp_spare")
    offset, recovery = 8, None
    while offset < len(data):
        if offset + 4 > len(data):
            raise CheckError("pfcp_ie_short")
        kind, length = struct.unpack_from("!HH", data, offset)
        offset += 4
        if offset + length > len(data):
            raise CheckError("pfcp_ie_length")
        if kind == 96:
            if length != 4 or recovery is not None:
                raise CheckError("pfcp_recovery_ie")
            recovery = int.from_bytes(data[offset:offset + length], "big")
        offset += length
    if recovery is None:
        raise CheckError("pfcp_recovery_missing")
    return recovery


def result(status, capability="unknown", success=False, **evidence):
    return dict(schema=1, status=status, capability=capability, success=success,
                timestamp=time.time(), **evidence)


def perform_check(request, resolver=socket.getaddrinfo, socket_factory=socket.socket):
    target, timeout, pins = validate_request(request)
    start = time.monotonic()
    deadline = start + timeout
    transport = target["transport"]
    socktype = socket.SOCK_DGRAM if transport == "pfcp_heartbeat" else socket.SOCK_STREAM
    protocol = socket.IPPROTO_UDP if transport == "pfcp_heartbeat" else (132 if transport == "sctp" else socket.IPPROTO_TCP)
    phase = "dns"
    try:
        records = resolver(target["host"], target["port"], socket.AF_UNSPEC, socktype, protocol)
        approved = []
        for family, stype, proto, _, address in records[:64]:
            if family in (socket.AF_INET, socket.AF_INET6) and stype == socktype and proto == protocol and str(ipaddress.ip_address(address[0])) in pins:
                approved.append((family, stype, proto, address))
        if not approved:
            return result("resolved_address_not_allowlisted", "available", phase=phase)
        # One address and one attempt only. Do not multiply the timeout per address.
        family, stype, proto, address = approved[0]
        phase = "socket"
        with socket_factory(family, stype, proto) as sock:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError()
            sock.settimeout(remaining)
            phase = "connect"
            sock.connect(address)
            if transport == "pfcp_heartbeat":
                phase = "heartbeat"
                sequence = secrets.randbelow(1 << 24)
                sock.settimeout(max(0.001, deadline - time.monotonic()))
                sock.send(heartbeat_request(sequence))
                sock.settimeout(max(0.001, deadline - time.monotonic()))
                data = sock.recv(4097)
                validate_heartbeat_response(data, sequence)
            return result("ok", "available", True, phase=phase,
                          duration_seconds=time.monotonic() - start,
                          semantics="pfcp_heartbeat_response" if transport == "pfcp_heartbeat" else "transport_connect_only")
    except socket.gaierror:
        return result("dns_failed", "available", phase=phase)
    except (TimeoutError, socket.timeout):
        return result("timeout", "available", phase=phase)
    except CheckError as exc:
        return result(str(exc), "available", phase=phase)
    except OSError as exc:
        if exc.errno in (errno.EPROTONOSUPPORT, errno.EAFNOSUPPORT, errno.ESOCKTNOSUPPORT, errno.ENOPROTOOPT):
            return result("transport_unsupported", "unsupported", phase=phase)
        if exc.errno in (errno.EACCES, errno.EPERM):
            return result("permission_denied", "unavailable", phase=phase)
        return result("network_failure", "available", phase=phase, errno=exc.errno)


def run_check(request, timeout_override=None):
    """Public API. Supervisor bounds DNS + connect + receive, no resolver threads."""
    start = time.monotonic()
    try:
        _, timeout, _ = validate_request(request, timeout_override)
    except (CheckError, TypeError, ValueError):
        return result("configuration_rejected", "not_attempted", attempted=False)
    request = dict(request, timeout=timeout)
    payload = json.dumps(request).encode()
    if len(payload) > MAX_INPUT:
        return result("configuration_rejected", "not_attempted", attempted=False)
    try:
        process = subprocess.Popen([sys.executable, __file__, "--internal"], stdin=subprocess.PIPE,
                                   stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    except OSError:
        return result("worker_start_failed", "unavailable", attempted=False)
    try:
        # Internal child has fixed-size JSON output; no untrusted service data is
        # written to stdout. Outer parent should impose its own output cap too.
        output, _ = process.communicate(payload, timeout=timeout)
        if process.returncode or len(output) > MAX_OUTPUT:
            return result("worker_failed", "unavailable", attempted=True)
        response = json.loads(output)
        response.update(attempted=True, elapsed_seconds=time.monotonic() - start)
        return response
    except subprocess.TimeoutExpired:
        return result("deadline_exceeded", "unknown", attempted=True,
                      elapsed_seconds=time.monotonic() - start,
                      semantics="dns_or_transport_not_completed_within_total_deadline")
    except (ValueError, OSError):
        return result("worker_failed", "unavailable", attempted=True)
    finally:
        if process.poll() is None:
            process.kill()
        process.communicate()


def eligible_sources(active, target, category_for_source=None, target_filter=None, limit=8):
    """Filter node UID -> (PID, identity); never guess core/ran from pod names.

    category_for_source(uid, identity) -> core|ran; target_filter(uid,pid,identity,
    target) -> bool. Category requested without callback is a configuration error.
    Returns (selected mapping, omitted count).
    """
    category = target.get("source_category")
    component = target.get("source_component")
    if category not in (None, "core", "ran") or (category and category_for_source is None):
        raise CheckError("source_category_callback_required")
    if type(limit) is not int or not 1 <= limit <= 64:
        raise CheckError("invalid_source_limit")
    selected = {}
    for uid, (pid, identity) in sorted(active.items()):
        if category and category_for_source(uid, identity) != category:
            continue
        if component and identity[3] != component:
            continue
        if target_filter and not target_filter(uid, pid, identity, target):
            continue
        selected[uid] = (pid, identity)
    return dict(list(selected.items())[:limit]), max(0, len(selected) - limit)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--timeout", type=float)
    parser.add_argument("--internal", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    try:
        raw = sys.stdin.buffer.read(MAX_INPUT + 1)
        if len(raw) > MAX_INPUT:
            raise CheckError("input_limit")
        request = json.loads(raw)
        if args.internal:
            response = perform_check(request)
        else:
            response = run_check(request, args.timeout)
    except (CheckError, ValueError, TypeError):
        response = result("configuration_rejected", "not_attempted", attempted=False)
    print(json.dumps(response, separators=(",", ":")), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
