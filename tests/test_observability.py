import copy
import hashlib
import json
from pathlib import Path
from unittest.mock import Mock

import pytest
from prometheus_client import generate_latest
from scapy.contrib.pfcp import PFCP, PFCPSessionEstablishmentRequest, PFCPSessionEstablishmentResponse, IE_Cause
from scapy.layers.inet import IP, UDP

from image_matrix import select_components
from mapper_coverage import MapperMetrics
from ngap_metrics import PduSessionSetupTracker
from observation_runtime import PfcpObserver, make_ngap_observer, make_pfcp_observer
from pfcp_metrics import PFCPSessionEstablishmentTracker
from probe import discover_n3_interface, discover_n6_interface, parse_interface_counters
from update_monitoring import apply_records

ROOT = Path(__file__).resolve().parents[1]


class Layer:
    field_names = []
    def __init__(self, response=False):
        self.response = response
    def __str__(self):
        return 'PDUSessionResourceSetupResponse PDUSessionResourceSetupListSURes' if self.response else 'PDUSessionResourceSetupRequest'
    def get_field_values(self, name):
        return {'aMF_UE_NGAP_ID':['1'], 'rAN_UE_NGAP_ID':['2'], 'pDUSessionID':['3']}.get(name, [])


def test_ngap_scoped_matching():
    tracker = PduSessionSetupTracker(clock=lambda: 1)
    assert tracker.observe_layer(Layer(), observed_at=1, scope='gnb-a') == 'request'
    assert tracker.observe_layer(Layer(True), observed_at=2, scope='gnb-b') == 'unmatched_response'
    assert tracker.observe_layer(Layer(True), observed_at=3, scope='gnb-a') == 'success'
    assert b'ngap_pdu_session_setup_duration_seconds_count{outcome="success"} 1.0' in generate_latest(tracker.registry)


def test_pfcp_exact_peers_and_expiry():
    tracker = PFCPSessionEstablishmentTracker(clock=lambda: 1)
    assert tracker.observe(50, 3, 'smf|upf-a', observed_at=1) == 'request'
    assert tracker.observe(51, 3, 'smf|upf-b', cause=1, observed_at=2) == 'unmatched_response'
    assert tracker.observe(51, 3, 'smf|upf-a', cause=1, observed_at=3) == 'accepted'
    tracker.observe(50, 4, 'smf|upf-a', observed_at=-100)
    tracker.expire()
    assert not tracker.pending


def test_actual_pfcp_packet_hook():
    observer = PfcpObserver.__new__(PfcpObserver)
    observer.tracker = PFCPSessionEstablishmentTracker()
    observer.observe_packet(IP(src='10.0.0.1',dst='10.0.0.2') / UDP(sport=8805,dport=8805) /
        PFCP(message_type=50,seq=7) / PFCPSessionEstablishmentRequest())
    observer.observe_packet(IP(src='10.0.0.2',dst='10.0.0.1') / UDP(sport=8805,dport=8805) /
        PFCP(message_type=51,seq=7) / PFCPSessionEstablishmentResponse(IE_list=[IE_Cause(cause=1)]))
    assert observer.tracker.completed.labels('accepted')._value.get() == 1
    assert observer.tracker.decode_errors._value.get() == 0


def test_protocol_hooks_disabled_by_default(monkeypatch):
    monkeypatch.delenv('AMF_NGAP_METRICS_ENABLED', raising=False)
    monkeypatch.delenv('SMF_PFCP_METRICS_ENABLED', raising=False)
    assert make_ngap_observer() is None
    assert make_pfcp_observer() is None


def test_mapper_endpoint_scoped_coverage():
    records = {'ran:a': {'ul_teid':'1', 'dl_teid':'2', 'upf_n3_ip':'10.0.0.1', 'gnb_n3_ip':'10.0.0.2'},
               'ran:b': {'ul_teid':'1', 'dl_teid':'2', 'upf_n3_ip':'10.0.0.3', 'gnb_n3_ip':'10.0.0.4'}}
    for endpoint, teid, identity in [('10.0.0.1','00000001','a'), ('10.0.0.2','00000002','a'),
                                     ('10.0.0.3','00000001','b'), ('10.0.0.4','00000002','b')]:
        records[f'pfcp-tunnel:{endpoint}|0x{teid}'] = {'imsi':identity,'sst':'01','sd':'ffffff'}
    redis = Mock()
    redis.scan.return_value = (0, ['ran:a','ran:b'])
    class Pipe:
        def __enter__(self): self.keys = []; return self
        def __exit__(self,*args): pass
        def hgetall(self,key): self.keys.append(key)
        def execute(self): return [records[key] for key in self.keys]
    redis.pipeline.side_effect = lambda **kw: Pipe()
    assert MapperMetrics(redis).snapshot()['01:ffffff']['ues'] == {'a','b'}
    for key, record in records.items():
        if key.startswith('pfcp-tunnel:'):
            del record['sd']
    group = MapperMetrics(redis).snapshot()['01:ffffff']
    assert group['ues'] == {'a','b'}
    assert group['missing']['slice'] == 2
    assert MapperMetrics(redis,max_records=1).snapshot() is None


def test_idle_and_ambiguous_path_discovery():
    status = json.dumps([{'name':'network/gnb-n3','interface':'n3'}])
    assert discover_n3_interface(status, []).interface == 'n3'
    assert discover_n3_interface('[]', []).interface == ''
    assert discover_n3_interface(status, [], 'explicit').interface == 'explicit'
    assert discover_n3_interface(json.dumps([{'interface':'n3a'},{'interface':'n3b'}]),[]).interface == ''
    assert discover_n6_interface('Iface Destination Gateway Flags\neth0 00000000 00000000 0003').interface == 'eth0'
    assert parse_interface_counters('n3: 100 2 3 4 0 0 0 0 200 5 6 7 0 0 0 0')['n3'].transmit_bytes == 200


def test_path_image_selected_by_changed_source():
    images = json.loads((ROOT/'images.json').read_text())
    assert [x['component'] for x in select_components(images,['user-plane-path/probe.py'])] == ['user-plane-path']
    shared = {x['component'] for x in select_components(images,['common/observation_runtime.py'])}
    assert {'amf-sniffer','smf-sniffer'} <= shared


def test_ml_publications_do_not_retag_stable_components():
    images = json.loads((ROOT/'images.json').read_text())
    selected = select_components(images, None, 'refs/heads/ml-observability')
    assert {item['component'] for item in selected} == {'amf-sniffer','smf-sniffer','ue-mapper','user-plane-path'}
    assert all(item['current_version'].endswith('-ml') for item in selected)
    images['amf-sniffer']['current_version'] = 'stable'
    with pytest.raises(ValueError, match='separate -ml'):
        select_components(images, None, 'refs/heads/ml-observability')


def test_optional_path_publication_does_not_enable_monitoring():
    images = json.loads((ROOT/'images.json').read_text())
    record = {'component':'user-plane-path','source_commit':'a'*40,
        'tags':['ghcr.io/yassir63/user-plane-path-probe:sha-'+'a'*40], 'digest':'sha256:'+'b'*64,
        'source_repository':'yassir63/fiveg-lens-images','source_change':'Add path probe'}
    manifest = {'probes':{},'components':{},'builds':{}}
    original = copy.deepcopy(manifest)
    assert 'opt-in' in apply_records(manifest,[record],images)
    assert manifest == original


@pytest.mark.parametrize('component', ['amf-sniffer','smf-sniffer','ue-mapper','user-plane-path'])
def test_prepared_source_records(component):
    images = json.loads((ROOT/'images.json').read_text())
    record = json.loads((ROOT/images[component]['version_record']).read_text())
    assert record['status'] == 'source-prepared-not-published'
    assert record['digest'] is None
    for filename, digest in record['source_files_sha256'].items():
        assert hashlib.sha256((ROOT/filename).read_bytes()).hexdigest() == digest
