"""Conservative, bounded, PDU-local F1AP/E1AP evidence and setup matching.

No internal locks: consume(), snapshot(), expire(), reset_scope(), and collect()
must be serialized by the owning Worker lock. Use a different, nonempty scope
for every capture anchor AND every tshark process generation. No cross-scope,
cross-protocol, IMSI, RNTI, or inferred subscriber joins are performed.

Field provenance, integration, and unavoidable passive-capture limits: README.md.
"""

from collections import Counter
from dataclasses import dataclass, field
from hashlib import sha256
from ipaddress import ip_address
import json
import math
import re


KINDS = ("initiatingMessage", "successfulOutcome", "unsuccessfulOutcome")
ID_FIELDS = {
    "f1ap": ("GNB_CU_UE_F1AP_ID", "GNB_DU_UE_F1AP_ID"),
    "e1ap": ("GNB_CU_CP_UE_E1AP_ID", "GNB_CU_UP_UE_E1AP_ID"),
}
# key -> match discriminator; only these reviewed setup procedures can be timed.
SETUPS = {("f1ap", 1): "transaction", ("f1ap", 5): "ue",
          ("e1ap", 3): "transaction", ("e1ap", 4): "transaction",
          ("e1ap", 8): "ue"}
RELEASE = {"f1ap": 6, "e1ap": 11}
INTERFACE_RELEASE = {"f1ap": 26, "e1ap": 7}


class Untrackable(ValueError):
    """A bounded reason code, never arbitrary packet text."""


def _fields(root, name):
    return [f for f in root.iter("field") if f.get("name") == name]


def _uint(element, maximum=0xffffffff):
    # show is the decoded numeric value; PDML value may be PER bytes/bitmasks.
    raw = element.get("show", "")
    if len(raw) > 12 or not re.fullmatch(r"[0-9]+|0[xX][0-9a-fA-F]+", raw):
        raise Untrackable("invalid_numeric_field")
    value = int(raw, 16 if raw.lower().startswith("0x") else 10)
    if not 0 <= value <= maximum:
        raise Untrackable("invalid_numeric_field")
    return value


def _one(root, name, maximum=0xffffffff, optional=False):
    values = _fields(root, name)
    if not values and optional:
        return None
    if len(values) != 1:
        raise Untrackable("missing_or_ambiguous_field")
    return _uint(values[0], maximum)


@dataclass(frozen=True)
class AssociationKey:
    scope: str
    assoc_index: int
    endpoints: tuple


@dataclass(frozen=True)
class CGIFact:
    container: str
    plmn_hex: str
    cell_field: str
    cell_hex: str


@dataclass(frozen=True)
class Observation:
    protocol: str
    procedure_code: int | None
    kind: str
    association: AssociationKey | None
    observation_time: float
    status: str
    reason: str = ""
    local_ids: tuple = ()
    cgis: tuple = ()
    duration_seconds: float | None = None
    packet_time: float | None = None
    timestamp_basis: str = "none"


@dataclass
class _Association:
    last: float
    tags: dict = field(default_factory=dict)
    init_tags: dict = field(default_factory=dict)
    last_capture_time: float | None = None


@dataclass
class _Pending:
    start: float
    sender: tuple
    fingerprint: str
    ids: tuple
    timestamp: float


def _capture_time(packet):
    frames = [p for p in packet.iter("proto") if p.get("name") == "frame"]
    if len(frames) != 1:
        return None, "missing_or_ambiguous_capture_time"
    fields = _fields(frames[0], "frame.time_epoch")
    if len(fields) != 1:
        return None, "missing_or_ambiguous_capture_time"
    raw = fields[0].get("show", "")
    if len(raw) > 32 or not re.fullmatch(r"[0-9]+(?:\.[0-9]+)?", raw):
        return None, "invalid_capture_time"
    value = float(raw)
    if not math.isfinite(value):
        return None, "invalid_capture_time"
    return value, ""


def _transport(packet, scope):
    if not isinstance(scope, str) or not scope or len(scope) > 512:
        raise Untrackable("missing_or_invalid_scope")
    sctps = [p for p in packet.iter("proto") if p.get("name") == "sctp"]
    ips = [p for p in packet.iter("proto") if p.get("name") in ("ip", "ipv6")]
    if len(sctps) != 1 or len(ips) != 1:
        raise Untrackable("missing_or_ambiguous_transport")
    sctp, ip = sctps[0], ips[0]
    assoc = _one(sctp, "sctp.assoc_index", 65535, optional=True)
    if assoc is None:
        raise Untrackable("missing_assoc_index")
    prefix = ip.get("name")
    endpoints = []
    for direction in ("src", "dst"):
        addresses = _fields(ip, prefix + "." + direction)
        if len(addresses) != 1:
            raise Untrackable("missing_or_ambiguous_endpoint")
        try:
            address = str(ip_address(addresses[0].get("show", "")))
        except ValueError:
            raise Untrackable("invalid_endpoint") from None
        port = _one(sctp, "sctp." + direction + "port", 65535)
        if port == 0:
            raise Untrackable("invalid_endpoint")
        endpoints.append((address, port))
    if endpoints[0] == endpoints[1]:
        raise Untrackable("ambiguous_direction")
    return AssociationKey(scope, assoc, tuple(sorted(endpoints))), endpoints[0], sctp


def _ie_values(pdu, protocol):
    """Top-level IE payloads only; never nested UE lists or diagnostics."""
    def visit(node):
        for child in node:
            if child.tag == "proto":
                continue
            if child.get("name") == protocol + ".ProtocolIE_Field_element":
                for value in child:
                    if value.get("name") in (protocol + ".value_element",
                                             protocol + ".ie_field_value_element"):
                        yield from value
                # Do not descend into reset lists, extensions, or referenced UEs.
            else:
                yield from visit(child)
    return list(visit(pdu))


def _pdu_data(pdu, protocol):
    if any(f.get("name") == "_ws.malformed" or
           f.get("name", "").startswith("_ws.malformed.")
           for f in pdu.iter()):
        raise Untrackable("malformed_pdu")
    codes = [f for f in pdu if f.get("name") == protocol + ".procedureCode"]
    if len(codes) != 1:
        raise Untrackable("missing_or_ambiguous_procedure")
    code = _uint(codes[0], 255)
    payloads = _ie_values(pdu, protocol)
    ids = []
    tx = None
    for suffix in (*ID_FIELDS[protocol], "TransactionID"):
        matches = [f for f in payloads if f.get("name") == protocol + "." + suffix]
        if len(matches) > 1:
            raise Untrackable("ambiguous_identifiers")
        if matches:
            number = _uint(matches[0], 255 if suffix == "TransactionID" else 0xffffffff)
            if suffix == "TransactionID":
                tx = number
            else:
                ids.append((suffix, number))
    cgis = []
    cell_names = ({"f1ap.nRCellIdentity": 10, "f1ap.nr_cell_ID": 10}
                  if protocol == "f1ap" else
                  {"e1ap.nR_Cell_Identity": 10, "e1ap.eUTRAN_Cell_Identity": 8})
    # A PLMN and a cell must be direct siblings, not a packet-wide/cartesian join.
    for parent in pdu.iter("field"):
        cells = [c for c in parent if c.get("name") in cell_names]
        plmns = [c for c in parent if c.get("name") == protocol + ".pLMN_Identity"]
        if not cells or len(cells) != 1 or len(plmns) != 1:
            continue
        cell, plmn = cells[0], plmns[0]
        cell_hex, plmn_hex = cell.get("value", "").lower(), plmn.get("value", "").lower()
        length = cell_names[cell.get("name")]
        if (re.fullmatch(r"[0-9a-f]{6}", plmn_hex) and
                re.fullmatch(r"[0-9a-f]{%d}" % length, cell_hex) and
                cell_hex.endswith("0")):
            cgis.append(CGIFact(parent.get("name", ""), plmn_hex,
                                cell.get("name"), cell_hex))
    canonical = [(f.get("name", ""), f.get("show"), f.get("value"))
                 for f in pdu.iter("field") if not f.get("name", "").startswith("_ws.")]
    digest = sha256(json.dumps(canonical, separators=(",", ":")).encode()).hexdigest()
    return code, tuple(ids), tx, tuple(cgis), digest


class SplitContextTracker:
    """One tracker per Worker. Caller owns locking and source/generation scope.

    consume returns immutable observations, one per independent PDU wrapper.
    snapshot copies counters and exposes bounded last-PDU context facts.
    collect eagerly snapshots and returns Prometheus families (optional dependency).
    """

    def __init__(self, *, setup_procedures=tuple(SETUPS), pending_ttl=30.0,
                 context_ttl=300.0, association_ttl=600.0, quarantine_ttl=60.0,
                 max_pending=4096, max_contexts=4096, max_associations=1024,
                 max_quarantine=8192, max_cgis_per_pdu=64, timestamp_basis="capture"):
        if timestamp_basis not in ("capture", "processing"):
            raise ValueError("timestamp_basis must be capture or processing")
        self.timestamp_basis = timestamp_basis
        self.setup_procedures = frozenset(setup_procedures)
        if not self.setup_procedures <= SETUPS.keys():
            raise ValueError("Only reviewed setup procedure keys may be configured")
        for name, value in (("pending_ttl", pending_ttl), ("context_ttl", context_ttl),
                            ("association_ttl", association_ttl), ("quarantine_ttl", quarantine_ttl)):
            if not math.isfinite(value) or value <= 0:
                raise ValueError(name + " must be finite and positive")
            setattr(self, name, float(value))
        for name, value in (("max_pending", max_pending), ("max_contexts", max_contexts),
                            ("max_associations", max_associations),
                            ("max_quarantine", max_quarantine), ("max_cgis_per_pdu", max_cgis_per_pdu)):
            if not isinstance(value, int) or isinstance(value, bool) or value < 1:
                raise ValueError(name + " must be a positive integer")
            setattr(self, name, value)
        self._associations = {}
        self._pending = {}
        self._contexts = {}
        self._quarantine = {}
        self._released = {}
        self._counts = Counter()
        self._timings = {}
        self._now = None
        self._timing_disabled_until = float("-inf")

    def _count(self, event, protocol="", code="", kind="", reason=""):
        self._counts[(event, protocol, str(code), kind, reason)] += 1

    def _advance(self, now):
        if isinstance(now, bool) or not isinstance(now, (int, float)) or not math.isfinite(now):
            raise ValueError("observation_time must be finite seconds")
        if self._now is not None and now < self._now:
            self._count("untrackable", reason="time_regression")
            return False
        self._now = float(now)
        self.expire(now)
        return True

    def _retire(self, key, now):
        self._pending.pop(key, None)
        if key in self._quarantine:
            return
        if len(self._quarantine) + len(self._released) >= self.max_quarantine:
            # Never evict a live duplicate guard and then emit unsafe timings.
            self._pending.clear()
            self._quarantine.clear()
            self._timing_disabled_until = now + self.pending_ttl + self.quarantine_ttl
            self._count("capacity", reason="quarantine_fail_closed")
        else:
            self._quarantine[key] = now + self.quarantine_ttl

    def _invalidate(self, assoc, reason):
        for mapping in (self._pending, self._contexts, self._quarantine, self._released):
            for key in list(mapping):
                if key[0] == assoc:
                    del mapping[key]
        self._associations.pop(assoc, None)
        self._count("association_invalidated", reason=reason)

    def reset_scope(self, scope):
        """Call under lock at teardown; never reuse that scope for a new decoder."""
        for assoc in list(self._associations):
            if assoc.scope == scope:
                self._invalidate(assoc, "scope_reset")

    def expire(self, observation_time):
        """Expire during quiet periods too. Use the same clock as consume()."""
        now = observation_time
        if not isinstance(now, (int, float)) or not math.isfinite(now):
            raise ValueError("observation_time must be finite seconds")
        if self._now is not None and now < self._now:
            raise ValueError("expiration time must not go backwards")
        self._now = float(now)
        for mapping in (self._quarantine, self._released):
            for key, deadline in list(mapping.items()):
                if now >= deadline:
                    del mapping[key]
        for key, pending in list(self._pending.items()):
            if now - pending.start >= self.pending_ttl:
                self._retire(key, now)
                self._count("pending_expired", key[1], key[2])
        for key, observation in list(self._contexts.items()):
            if now - observation.observation_time >= self.context_ttl:
                del self._contexts[key]
                self._count("context_expired", key[1])
        for assoc, state in list(self._associations.items()):
            if now - state.last >= self.association_ttl:
                self._invalidate(assoc, "ttl")

    def _association(self, assoc, sender, sctp, now):
        for old in list(self._associations):
            if old.scope == assoc.scope and old.endpoints == assoc.endpoints and old != assoc:
                self._invalidate(old, "assoc_index_changed")
        state = self._associations.get(assoc)
        tag = _one(sctp, "sctp.verification_tag", optional=True)
        if tag is None:
            raise Untrackable("missing_verification_tag")
        chunks = [_uint(f, 255) for f in _fields(sctp, "sctp.chunk_type")]
        init = _one(sctp, "sctp.init_initiate_tag", optional=True)
        initack = _one(sctp, "sctp.initack_initiate_tag", optional=True)
        if state and ((sender in state.tags and tag != 0 and state.tags[sender] != tag) or
                      (init is not None and state.init_tags.get((sender, "init")) != init) or
                      (initack is not None and state.init_tags.get((sender, "ack")) != initack)):
            self._invalidate(assoc, "restart_evidence")
            state = None
        if state is None:
            if len(self._associations) >= self.max_associations:
                raise Untrackable("association_capacity")
            state = self._associations[assoc] = _Association(now)
        state.last = now
        if tag:
            state.tags[sender] = tag
        if init is not None:
            state.init_tags[(sender, "init")] = init
        if initack is not None:
            state.init_tags[(sender, "ack")] = initack
        if any(chunk in (6, 7, 8, 14) for chunk in chunks):
            self._invalidate(assoc, "sctp_close")
            raise Untrackable("sctp_close")
        if any(chunk in (1, 2) for chunk in chunks):
            # Handshake-only packets still invalidate state; no AP data expected.
            raise Untrackable("sctp_handshake")
        if tag == 0:
            raise Untrackable("zero_verification_tag")

    def consume(self, packet, observation_time, scope):
        now = observation_time
        if not self._advance(now):
            return (Observation("", None, "unknown", None, now,
                                "untrackable", "time_regression"),)
        transport_error = ""
        assoc = None
        sender = None
        try:
            assoc, sender, sctp = _transport(packet, scope)
            self._association(assoc, sender, sctp, now)
        except Untrackable as exc:
            transport_error = str(exc)
        packet_time, timestamp_error = _capture_time(packet)
        if not transport_error and packet_time is not None:
            state = self._associations[assoc]
            if state.last_capture_time is not None and packet_time < state.last_capture_time:
                timestamp_error = "capture_time_regression"
            else:
                state.last_capture_time = packet_time
        malformed_packet = any(p.get("name", "").startswith("_ws.malformed") for p in packet.iter("proto"))
        results = []
        for proto in packet.iter("proto"):
            protocol = proto.get("name")
            if protocol not in ID_FIELDS:
                continue
            wrappers = [f for f in proto.iter("field")
                        if f.get("name") in {protocol + "." + k + "_element" for k in KINDS}]
            # Nested PDU wrappers are malformed/ambiguous, not separate sessions.
            nested = any(any(c is not w and c in wrappers for c in w.iter("field"))
                         for w in wrappers)
            if not wrappers or nested:
                reason = "nested_pdu_wrappers" if nested else "missing_pdu_wrapper"
                self._count("untrackable", protocol, reason=reason)
                results.append(Observation(protocol, None, "unknown", assoc, now, "untrackable", reason))
                continue
            malformed = malformed_packet or any(f.get("name", "").startswith("_ws.malformed") for f in proto.iter())
            for pdu in wrappers:
                kind = pdu.get("name").split(".", 1)[1].removesuffix("_element")
                code = None
                try:
                    if malformed:
                        raise Untrackable("malformed_pdu")
                    code, ids, tx, cgis, digest = _pdu_data(pdu, protocol)
                    self._count("pdus", protocol, code, kind)
                    if transport_error:
                        raise Untrackable(transport_error)
                    if len(cgis) > self.max_cgis_per_pdu:
                        raise Untrackable("cgi_capacity")
                    result = self._observe(assoc, sender, protocol, code, kind, ids, tx, cgis, digest,
                                           now, packet_time, timestamp_error)
                except Untrackable as exc:
                    self._count("untrackable", protocol, code if code is not None else "", kind, str(exc))
                    result = Observation(protocol, code, kind, assoc, now, "untrackable", str(exc))
                results.append(result)
        return tuple(results)

    def _observe(self, assoc, sender, protocol, code, kind, ids, tx, cgis, digest,
                 now, packet_time, timestamp_error):
        def observed(status, reason="", duration=None):
            return Observation(protocol, code, kind, assoc, now, status, reason, ids, cgis,
                               duration, packet_time, self.timestamp_basis)

        # Reset may contain UE lists; invalidate all protocol evidence conservatively.
        if code == 0 or code == INTERFACE_RELEASE[protocol]:
            for mapping in (self._pending, self._contexts):
                for key in list(mapping):
                    if key[0] == assoc and key[1] == protocol:
                        if mapping is self._pending:
                            self._retire(key, now)
                        else:
                            del mapping[key]
            self._count("protocol_invalidated", protocol, code, kind)
            return observed("invalidated")

        if code == RELEASE[protocol]:
            if len(ids) != 2 or kind == "unsuccessfulOutcome":
                raise Untrackable("release_requires_both_ids")
            released = dict(ids)
            for key in list(self._contexts):
                if key[:2] == (assoc, protocol) and all(released.get(k) == v for k, v in key[2]):
                    del self._contexts[key]
            for key, pending in list(self._pending.items()):
                if key[:2] == (assoc, protocol) and pending.ids and all(released.get(k) == v for k, v in pending.ids):
                    self._retire(key, now)
            for name, value in ids:
                key = (assoc, protocol, name, value)
                if key not in self._released and len(self._released) + len(self._quarantine) >= self.max_quarantine:
                    # No room for a release guard: discard association evidence.
                    self._invalidate(assoc, "release_guard_capacity")
                    raise Untrackable("release_guard_capacity")
                self._released.setdefault(key, now + self.quarantine_ttl)
            self._count("releases", protocol, code, kind)
            return observed("released")

        if any((assoc, protocol, name, value) in self._released for name, value in ids):
            self._count("duplicates", protocol, code, kind, "released_ids")
            return observed("suppressed", "released_ids")

        selected = (protocol, code) in self.setup_procedures
        mode = SETUPS.get((protocol, code))
        if mode == "transaction":
            if tx is None:
                raise Untrackable("missing_transaction_id")
            discriminator = ("transaction", tx)
        elif mode == "ue":
            primary = dict(ids).get(ID_FIELDS[protocol][0])
            if primary is None:
                raise Untrackable("missing_primary_ue_id")
            discriminator = ("ue", primary)
            if kind == "successfulOutcome" and len(ids) != 2:
                raise Untrackable("success_requires_both_ids")
        else:
            if not ids:
                raise Untrackable("missing_ue_ids_or_unsupported_procedure")
            discriminator = None

        if ids:
            context_key = (assoc, protocol, ids)
            if context_key not in self._contexts and len(self._contexts) >= self.max_contexts:
                self._count("capacity", protocol, reason="context_capacity")
            else:
                # Replace the entire last-PDU fact set. Never union CGI across PDUs.
                self._contexts[context_key] = observed("observed")
        if not selected:
            return observed("observed", "timing_not_configured")
        key = (assoc, protocol, code, discriminator, sender if kind == KINDS[0]
               else next(endpoint for endpoint in assoc.endpoints if endpoint != sender))
        if now < self._timing_disabled_until:
            raise Untrackable("timing_capacity_quarantine")
        if self.timestamp_basis == "capture" and timestamp_error:
            self._retire(key, now)
            self._count("untrackable", protocol, code, kind, timestamp_error)
            return observed("untrackable", timestamp_error)
        timestamp = packet_time if self.timestamp_basis == "capture" else now
        if key in self._quarantine:
            self._count("duplicates", protocol, code, kind, "retired_key")
            return observed("suppressed", "retired_key")
        pending = self._pending.get(key)
        if kind == "initiatingMessage":
            if pending is not None:
                if pending.fingerprint == digest:
                    self._count("duplicates", protocol, code, kind, "pending_duplicate")
                    return observed("duplicate", "pending_duplicate")
                self._retire(key, now)
                raise Untrackable("conflicting_initiation")
            if len(self._pending) >= self.max_pending:
                self._retire(key, now)
                raise Untrackable("pending_capacity")
            self._pending[key] = _Pending(now, sender, digest, ids, timestamp)
            self._count("starts", protocol, code)
            return observed("pending")
        if pending is None:
            raise Untrackable("unmatched_outcome")
        if any(dict(ids).get(k) != v for k, v in pending.ids):
            self._retire(key, now)
            raise Untrackable("conflicting_outcome_ids")
        duration = timestamp - pending.timestamp
        if duration < 0 or not math.isfinite(duration):
            self._retire(key, now)
            raise Untrackable("negative_or_invalid_duration")
        self._retire(key, now)
        timing_key = (protocol, code, kind, self.timestamp_basis)
        count, total = self._timings.get(timing_key, (0, 0.0))
        self._timings[timing_key] = (count + 1, total + duration)
        self._count("matched", protocol, code, kind)
        return observed("matched", duration=duration)

    def snapshot(self, observation_time=None):
        """Detached snapshot; supplying time expires idle state under caller lock."""
        if observation_time is not None:
            self.expire(observation_time)
        return {"counters": dict(self._counts), "timings": dict(self._timings),
                "associations": tuple(self._associations),
                "contexts": tuple(self._contexts.values()),
                "pending": len(self._pending), "quarantine": len(self._quarantine),
                "release_guards": len(self._released), "timestamp_basis": self.timestamp_basis,
                "timing_disabled_until": self._timing_disabled_until}

    def collect(self, label_names=(), label_values=(), observation_time=None):
        """Eager detached Prom families, safe to iterate after releasing Worker lock.

        No identifiers, endpoints, or scopes become metric labels. Static Worker
        identity labels may be supplied by the central collector. Do not register
        each Worker separately under identical names; combine families centrally.
        """
        from prometheus_client.core import CounterMetricFamily, GaugeMetricFamily, SummaryMetricFamily

        names, values = list(label_names), list(label_values)
        reserved = {"event", "protocol", "procedure_code", "pdu_kind", "reason", "state", "timestamp_basis"}
        if len(names) != len(values) or len(set(names)) != len(names) or reserved.intersection(names):
            raise ValueError("Invalid static metric identity labels")
        snap = self.snapshot(observation_time)
        events = CounterMetricFamily("nador_split_context_events", "Passive split evidence events, not unique UEs",
                                     labels=names + ["event", "protocol", "procedure_code", "pdu_kind", "reason"])
        for key, count in sorted(snap["counters"].items()):
            events.add_metric(values + list(key), count)
        timing = SummaryMetricFamily("nador_split_setup_observation_seconds",
                                     "Matched setup duration with explicit clock basis; not network RTT",
                                     labels=names + ["protocol", "procedure_code", "pdu_kind", "timestamp_basis"])
        for (protocol, code, kind, basis), (count, total) in sorted(snap["timings"].items()):
            timing.add_metric(values + [protocol, str(code), kind, basis], count, total)
        state = GaugeMetricFamily("nador_split_context_entries", "Bounded retained evidence, not unique UEs",
                                  labels=names + ["state"])
        for name, count in (("associations", len(snap["associations"])),
                            ("contexts", len(snap["contexts"])), ("pending", snap["pending"]),
                            ("quarantine", snap["quarantine"]), ("release_guards", snap["release_guards"])):
            state.add_metric(values + [name], count)
        return iter((events, timing, state))
