"""Synthetic PDML builder, not a protocol encoder. Explicit per-PDU IE trees."""
import xml.etree.ElementTree as ET


def field(parent, name, show=None, value=None):
    attrs = {"name": name}
    if show is not None:
        attrs["show"] = str(show)
    if value is not None:
        attrs["value"] = value
    return ET.SubElement(parent, "field", attrs)


def pdu(protocol="f1ap", code=5, kind="initiatingMessage", ids=(7,), tx=None, cgis=()):
    root = ET.Element("proto", name=protocol)
    choice = field(root, protocol + "." + protocol.upper() + "_PDU", show=0)
    wrapper = field(choice, protocol + "." + kind + "_element")
    field(wrapper, protocol + ".procedureCode", code)
    message = field(wrapper, protocol + ".testMessage_element")
    ies = field(message, protocol + ".protocolIEs", len(ids) + (tx is not None))
    names = (("GNB_CU_UE_F1AP_ID", "GNB_DU_UE_F1AP_ID") if protocol == "f1ap"
             else ("GNB_CU_CP_UE_E1AP_ID", "GNB_CU_UP_UE_E1AP_ID"))
    def ie():
        item = field(ies, protocol + ".ProtocolIE_Field_element")
        return field(item, protocol + ".value_element")
    for name, number in zip(names, ids):
        if number is not None:
            field(ie(), protocol + "." + name, number)
    if tx is not None:
        field(ie(), protocol + ".TransactionID", tx)
    for plmn, cell in cgis:
        cgi = field(ie(), protocol + (".nRCGI_element" if protocol == "f1ap" else ".nR_CGI_element"))
        field(cgi, protocol + ".pLMN_Identity", value=plmn)
        field(cgi, protocol + (".nRCellIdentity" if protocol == "f1ap" else ".nR_Cell_Identity"), value=cell)
    return root


def packet(*pdus, assoc=1, reverse=False, endpoints=("192.0.2.1", "192.0.2.2"),
           ports=(38472, 38472), tag=None, chunks=(), init=None, ipv6=False, capture_time=1000.0):
    root = ET.Element("packet")
    if capture_time is not None:
        frame = ET.SubElement(root, "proto", name="frame")
        field(frame, "frame.time_epoch", capture_time)
    prefix = "ipv6" if ipv6 else "ip"
    ip = ET.SubElement(root, "proto", name=prefix)
    source, destination = endpoints[::-1] if reverse else endpoints
    source_port, destination_port = ports[::-1] if reverse else ports
    field(ip, prefix + ".src", source)
    field(ip, prefix + ".dst", destination)
    sctp = ET.SubElement(root, "proto", name="sctp")
    field(sctp, "sctp.srcport", source_port)
    field(sctp, "sctp.dstport", destination_port)
    if assoc is not None:
        field(sctp, "sctp.assoc_index", assoc)
    field(sctp, "sctp.verification_tag", tag if tag is not None else ("0x22222222" if reverse else "0x11111111"))
    for chunk in chunks:
        field(sctp, "sctp.chunk_type", chunk)
    if init is not None:
        field(sctp, "sctp.init_initiate_tag", init)
    root.extend(pdus)
    return root
