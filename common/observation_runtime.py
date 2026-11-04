"""Small observation hooks for the current mapping sniffer image sources."""
import os
import time


def enabled(name):
    return os.getenv(name, '').lower() in ('1', 'true', 'yes')


class NgapObserver:
    def __init__(self):
        from ngap_metrics import PduSessionSetupTracker
        from prometheus_client import start_http_server
        self.tracker = PduSessionSetupTracker(float(os.getenv('AMF_NGAP_PENDING_TIMEOUT_SECONDS', '30')))
        start_http_server(int(os.getenv('AMF_NGAP_METRICS_PORT', '9102')), registry=self.tracker.registry)

    def mark_capture_started(self):
        self.tracker.mark_capture_started()

    def observe_layer(self, layer, scope=''):
        try:
            self.tracker.observe_layer(layer, observed_at=time.monotonic(), scope=scope)
        except Exception:
            self.tracker.record_decode_error()


class PfcpObserver:
    def __init__(self):
        from pfcp_metrics import PFCPSessionEstablishmentTracker
        from prometheus_client import start_http_server
        self.tracker = PFCPSessionEstablishmentTracker(float(os.getenv('SMF_PFCP_PENDING_TIMEOUT_SECONDS', '30')))
        start_http_server(int(os.getenv('SMF_PFCP_METRICS_PORT', '9104')), registry=self.tracker.registry)

    def mark_capture_started(self):
        self.tracker.mark_capture_started()

    def observe_packet(self, packet):
        from scapy.contrib.pfcp import PFCP
        from scapy.layers.inet import IP
        from scapy.layers.inet6 import IPv6
        try:
            pfcp = packet[PFCP]
            ip = packet[IP] if packet.haslayer(IP) else packet[IPv6]
            peer = '|'.join(sorted((str(ip.src), str(ip.dst))))
            # Session establishment responses carry Cause as an immediate IE.
            cause = next((getattr(ie, 'cause', None) for ie in getattr(pfcp.payload, 'IE_list', [])
                          if int(getattr(ie, 'ietype', -1)) == 19), None)
            self.tracker.observe(int(pfcp.message_type), int(pfcp.seq), peer,
                                 cause=cause, observed_at=time.monotonic())
        except Exception:
            self.tracker.decode_errors.inc()


def make_ngap_observer():
    return NgapObserver() if enabled('AMF_NGAP_METRICS_ENABLED') else None


def make_pfcp_observer():
    return PfcpObserver() if enabled('SMF_PFCP_METRICS_ENABLED') else None
