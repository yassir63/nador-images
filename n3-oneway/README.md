# Experimental N3 one-way latency

Two TC eBPF observers timestamp the same GTP-U packet at the gNB and UPF N3
interfaces. Each applies deterministic sampling (one in 16 by default)
and sends only a 40-byte record through a BPF ring buffer. No pcap or packet
payload is sent to userspace. One collector continuously estimates each observer's wall clock
offset using a four-timestamp UDP exchange. The collector does not set either
clock. It matches observations by keyed packet digest and exports an estimated
transit-time histogram, independently for uplink and downlink. It polls the
UE mapper's active inventory and resolves the slice by receiving N3 address
and TEID, never by TEID alone. A missing, conflicting, or changed mapping is
reported as `slice="unknown"`; `01:ffffff` remains a valid mapper label. This is **N3
transit between capture hooks**, not UE-to-server latency, radio latency, or
TCP RTT.

TCP and UDP are supported for unfragmented IPv4 inside IPv4 GTP-U on an
Ethernet interface. The fingerprint uses headers and up to 32 payload bytes
in-kernel; duplicates within the matching window are rejected. QUIC
datagrams can be observed as UDP without decryption: the ciphertext bytes
participate in the match. This does not identify QUIC, count QUIC
retransmissions, or measure individual QUIC frames. NAT/rewrites between
anchors, fragmentation, offload-induced packet reshaping and capture loss
can reduce pairing coverage.

## Run on a controlled testbed

Build from the image repository root:

```sh
docker build -f n3-oneway/Dockerfile -t nador-n3-oneway:local .
```

The two modes share one image. For an initial run, start them directly on
the test nodes using the built `nador-n3-observer` binary, Python 3.11+,
libbpf and nsenter. The nodes need TC eBPF and BPF ring buffer support.
Run exactly one
observer per role against one collector. Set the same randomly generated
32-byte hex `NADOR_ONEWAY_TOKEN` in all three process environments
(`openssl rand -hex 32`). Restrict collector access to the test nodes and
Prometheus: observation uploads are authenticated but HTTP is not encrypted.
No packet contents or UE labels leave the capture host. The test does not
require an agent at the UE or at the traffic server.

```sh
# Collector: bind to a reachable test-network address. Allow both TCP and UDP.
python3 oneway.py collector --bind "$COLLECTOR_IP" --port 55393 \
  --mapper-url "$UE_MAPPER_URL"

# Run on each respective NF node, with capture/netns permissions.
# ROLE is gnb on the gNB node and upf on the UPF node.
# NF_PID is that node's actual NF container PID as seen from the host.
python3 oneway.py agent --role "$ROLE" --pid "$NF_PID" \
  --interface "$N3_INTERFACE" --gnb "$GNB_N3_IP" --upf "$UPF_N3_IP" \
  --url "http://$COLLECTOR_IP:55393" --test-port 5202 --sample 1
```

Use the actual N3 interface on each side; it need not be named `n3`.
`--test-port` selects the inner service port (omit it for an unfiltered
protocol experiment). Prefer a larger deterministic sampling factor on
busy deployments; both anchors must use the same factor. Stop the
three processes gracefully to remove the observer's two TC filters. The
observer does not remove the shared clsact qdisc or touch existing filters.

Check `/metrics` on the collector (or add it as a Prometheus scrape target):

- `nador_n3_oneway_seconds`: histogram, by transport and direction.
- `nador_n3_oneway_slice_seconds`: same histogram grouped by slice.
- `nador_n3_oneway_bpf_events_dropped_total`: events lost to a full BPF ring buffer.
- `nador_n3_oneway_observations_total`: observed, matched, unmatched, and
  rejected observations. Unmatched observations are not a packet-loss rate.
- `nador_n3_oneway_clock_uncertainty_seconds` and
  `nador_n3_oneway_calibration_timestamp_seconds`: clock quality and freshness
  at each anchor. Compare their magnitude to the effect you want to measure.

Start with UDP clean, a known N3 delay, and recovery. Repeat with TCP and
then an actual QUIC flow on the selected UDP service port. Compare **deltas**
of the histogram sum/count and rejection counters across phases, not the
cumulative averages. For small delays comparable to the clock uncertainty,
do not infer precise absolute transit times. Software timestamps, clock
drift, and calibration-path asymmetry can affect the estimate.

Add `--log-samples` to the N3 collector to emit one JSON line per accepted
packet pair to stdout (for example, to collect with Loki). Each line has
the protocol, direction, slice, corrected receive timestamp and delay in
nanoseconds, plus `gnb_clock_uncertainty_ns`, `upf_clock_uncertainty_ns`
and their sum, `clock_uncertainty_ns`. These values come from the two
observations used for that pair, not the latest calibration at scrape time.
The sum is a clock-error estimate, not a statistical confidence interval
or a bound on all measurement error. Rejected pairs are not logged as
measurements. If the log sink falls behind, the bounded queue drops log
records and increments `nador_n3_oneway_sample_log_dropped_total` without
dropping their Prometheus histogram samples. Logging is off by default.

## Same-host UPF transit

Run `upf_transit.py` instead of `oneway.py` to measure the interval
from N3 ingress to N6 egress (uplink), or N6 ingress to N3 egress
(downlink). This uses one observer and a shared kernel monotonic clock,
without clock calibration or agents at the UE or traffic server.

```sh
sudo python3 upf_transit.py --pid "$UPF_PID" --n3 "$N3_IFACE" --n6 "$N6_IFACE" \
  --gnb "$GNB_N3_IP" --upf "$UPF_N3_IP" --peer "$SERVER_IP" --port 5202 \
  --mapper-url "$UE_MAPPER_URL" --sample 1
curl -s http://127.0.0.1:55437/metrics
```

The image includes the script at `/app/upf_transit.py`; override the image
entrypoint to run it. N3 and N6 can share an Ethernet interface, as in
Open5GS with masquerading. Set the N6 interface to the actual external
interface, not the internal TUN device. The peer IPv4 address and service
port must be visible on both sides. The fingerprint excludes addresses,
ports and checksums so source NAT does not prevent pairing. It uses
payload length and up to 32 payload bytes plus TCP sequence/ACK fields
and flags where applicable. Identical fingerprints seen more than once
on either hook during the match window are rejected rather than guessed.
Use a dedicated peer and port: this prototype is not a general-purpose
matcher for arbitrary concurrent NATed flows.

The slice comes from the N3 receiving endpoint and TEID. Metrics are
served on loopback under `nador_upf_transit_*`. QUIC is measured and
labeled at UDP datagram granularity, not as a separate protocol. This
interval includes forwarding and any NAT between the hooks; it excludes
the external N6 network, application processing and egress work after
the TC hook. IPv6, fragments and coalesced packets are not supported.
