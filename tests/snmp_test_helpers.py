"""Minimal SNMP request builders for tests (stdlib only)."""


def build_snmp_pdu(community, oid_hex, request_id=None, version=1, pdu_type=0xA0,
                   non_repeaters=0, max_repetitions=10):
    """Build a short-form BER SNMPv1/v2c Get / GetNext / GetBulk request."""
    if request_id is None:
        request_id = b'\x00\x00\x00\x01'
    community_b = community.encode('latin-1')
    oid_bytes = bytes(oid_hex)

    varbind_inner = bytes([0x06, len(oid_bytes)]) + oid_bytes + bytes([0x05, 0x00])
    varbind = bytes([0x30, len(varbind_inner)]) + varbind_inner
    vb_list = bytes([0x30, len(varbind)]) + varbind

    req = bytes([0x02, len(request_id)]) + request_id
    if pdu_type == 0xA5:
        err = bytes([0x02, 0x01, non_repeaters & 0xFF, 0x02, 0x01, max_repetitions & 0xFF])
    else:
        err = bytes([0x02, 0x01, 0x00, 0x02, 0x01, 0x00])

    pdu_content = req + err + vb_list
    if len(pdu_content) > 127:
        raise ValueError("PDU too large for short-form test helper")
    pdu_bytes = bytes([pdu_type, len(pdu_content)]) + pdu_content

    body = bytes([0x02, 0x01, version, 0x04, len(community_b)]) + community_b + pdu_bytes
    if len(body) > 127:
        raise ValueError("Message too large for short-form test helper")
    return bytes([0x30, len(body)]) + body


def oid_sysdescr_hex():
    # .1.3.6.1.2.1.1.1.0 → 2b 06 01 02 01 01 01 00
    return bytearray(b'\x2b\x06\x01\x02\x01\x01\x01\x00')
