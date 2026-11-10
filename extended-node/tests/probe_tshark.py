"""Generate tiny offline dissector-shape probes, NOT standards-conformance traces.

The APER probes omit unrelated mandatory service IEs. They validate tshark's
wrapper/IE/field spelling, not a real successful setup. No live capture/network.
"""
from pathlib import Path
import shutil
import socket
import struct
import subprocess
import xml.etree.ElementTree as ET


def write_probe(directory):
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    frames = []
    probes = []
    for protocol, code, transaction_ie in (("f1ap", 1, 78), ("e1ap", 3, 57), ("e1ap", 4, 57)):
        for choice in (0, 0x40, 0x80):
            probes.append((protocol, code, choice, [(transaction_ie, bytes.fromhex("0001"))]))
    for protocol, code, first, second in (("f1ap", 5, 40, 41), ("e1ap", 8, 2, 3)):
        for choice in (0, 0x40, 0x80):
            ies = [(first, bytes.fromhex("0007"))]
            if choice == 0x40:
                ies.append((second, bytes.fromhex("0009")))
            if protocol == "f1ap":
                ies.append((111, bytes.fromhex("0000f1100000000010")))
            probes.append((protocol, code, choice, ies))
    for protocol, code, choice, ies in probes:
        body = b"\0" + struct.pack("!H", len(ies))
        for ie_id, ie_value in ies:
            body += struct.pack("!HBB", ie_id, 0, len(ie_value)) + ie_value
        payload = bytes((choice if protocol == "f1ap" else choice >> 1, code, 0, len(body))) + body
        reverse = choice != 0
        source = "192.0.2.2" if reverse else "192.0.2.1"
        destination = "192.0.2.1" if reverse else "192.0.2.2"
        chunk = struct.pack("!BBHIHHI", 0, 3, 16 + len(payload), len(frames) + 1, 0, 0,
                            62 if protocol == "f1ap" else 64) + payload
        chunk += b"\0" * (-len(chunk) % 4)
        port = 38472 if protocol == "f1ap" else 38462
        sctp = struct.pack("!HHII", port, port, 0x22222222 if reverse else 0x11111111, 0) + chunk
        ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(sctp), 0, 0, 64, 132, 0,
                         socket.inet_aton(source), socket.inet_aton(destination))
        frames.append(bytes.fromhex("0000000000020000000000010800") + ip + sctp)
    pcap = directory / "tshark_shape_probe.pcap"
    with pcap.open("wb") as out:
        out.write(struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for index, frame in enumerate(frames):
            out.write(struct.pack("<IIII", 1000 + index, 0, len(frame), len(frame)))
            out.write(frame)
    tshark = shutil.which("tshark")
    if not tshark:
        raise RuntimeError("tshark unavailable")
    result = subprocess.run([tshark, "-n", "-r", str(pcap), "-T", "pdml"],
                            capture_output=True, check=True, timeout=30)
    (directory / "tshark_shape_probe.pdml").write_bytes(result.stdout)
    return ET.fromstring(result.stdout)


if __name__ == "__main__":
    root = write_probe(Path(__file__).parent / "fixtures" / "generated")
    for packet in root.findall("packet"):
        for proto in packet.findall("proto"):
            if proto.get("name") in ("f1ap", "e1ap", "_ws.malformed"):
                print(proto.get("showname"))
                for f in proto.iter("field"):
                    if any(s in f.get("name", "") for s in ("UE_F1AP_ID", "UE_E1AP_ID", "CellIdentity", "malformed")):
                        print(f.attrib)
