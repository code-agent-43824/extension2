"""Independent verifier for GOST R 34.10-2012/256 CMS signatures made on the stand.

Shares no code with the extension or the Rutoken stack: its own DER walk, Streebog and
GOST signatures from gostcrypto. Checks that
- the Streebog-256 digest of the content equals the messageDigest signed attribute;
- the signature over the signed attributes verifies with the signer certificate's key;
- the signer certificate is signed by the given CA.
Byte-order conventions are the ones in gost_ca.py.

Usage: verify_cms.py CMS_BASE64_FILE CA_PEM [CONTENT_FILE]
CONTENT_FILE is required for a detached signature. Prints a JSON report; exits 0 only
when every check passes.
"""

import base64
import json
import sys

from gostcrypto import gosthash, gostsignature

from gost_ca import CURVE, unpem

OID_SIGNED_DATA = "1.2.840.113549.1.7.2"
OID_CONTENT_TYPE = "1.2.840.113549.1.9.3"
OID_MESSAGE_DIGEST = "1.2.840.113549.1.9.4"
OID_SIGNING_TIME = "1.2.840.113549.1.9.5"
OID_SIGNING_CERTIFICATE_V2 = "1.2.840.113549.1.9.16.2.47"


def tlv(data, offset=0):
    """Returns (tag, contents, end) of the DER element at offset."""
    tag = data[offset]
    length = data[offset + 1]
    header = 2
    if length & 0x80:
        count = length & 0x7F
        length = int.from_bytes(data[offset + 2 : offset + 2 + count], "big")
        header += count
    start = offset + header
    return tag, data[start : start + length], start + length


def items(contents):
    result = []
    offset = 0
    while offset < len(contents):
        tag, value, end = tlv(contents, offset)
        result.append((tag, value, contents[offset:end]))
        offset = end
    return result


def decode_oid(value):
    arcs = []
    current = 0
    for byte in value:
        current = current * 128 + (byte & 0x7F)
        if not byte & 0x80:
            if not arcs:
                first = min(2, current // 40)
                arcs += [first, current - first * 40]
            else:
                arcs.append(current)
            current = 0
    return ".".join(map(str, arcs))


def streebog(data):
    return bytes(gosthash.new("streebog256", data=data).digest())


def gost_verify(point_le, data, signature):
    """point_le is the SubjectPublicKeyInfo point (x||y, each little-endian)."""
    public_key = point_le[:32][::-1] + point_le[32:][::-1]
    raw = signature[32:] + signature[:32]
    verifier = gostsignature.new(gostsignature.MODE_256, CURVE)
    return verifier.verify(bytearray(public_key), bytearray(streebog(data)[::-1]), bytearray(raw))


def certificate_parts(cert_der):
    """Returns (tbs_der, signature, serial, public_key_point) of an X.509 certificate."""
    _, cert, _ = tlv(cert_der)
    (_, tbs_value, tbs_der), _, (_, sig_bits, _) = items(cert)
    fields = items(tbs_value)
    if fields[0][0] == 0xA0:
        fields = fields[1:]
    serial = fields[0][1]
    spki = items(fields[5][1])
    _, point_octets, _ = tlv(spki[1][1][1:])  # BIT STRING: unused-bits byte, then OCTET STRING
    return tbs_der, sig_bits[1:], serial, point_octets


def verify(cms_b64, ca_pem, content=None):
    report = {"valid": False, "detached": None, "attributes": [], "checks": {}}
    data = base64.b64decode("".join(cms_b64.split()))
    _, content_info, _ = tlv(data)
    (_, type_oid, _), (_, explicit, _) = items(content_info)
    if decode_oid(type_oid) != OID_SIGNED_DATA:
        raise ValueError("not a SignedData")
    _, signed_data, _ = tlv(explicit)
    parts = items(signed_data)
    encap = items(parts[2][1])
    embedded = None
    if len(encap) > 1:
        _, octets, _ = tlv(encap[1][1])
        embedded = octets
    report["detached"] = embedded is None
    if embedded is not None:
        content = embedded
    if content is None:
        raise ValueError("detached signature needs CONTENT_FILE")
    certificates = [raw for tag, _, raw in items(parts[3][1])] if parts[3][0] == 0xA0 else []
    signer_info = items(parts[-1][1])[0]
    signer = items(signer_info[1])
    sid = items(signer[1][1])
    signer_serial = sid[1][1]
    attrs_tag, attrs_value, attrs_raw = signer[3]
    if attrs_tag != 0xA0:
        raise ValueError("no signed attributes")
    signature = signer[5][1]

    message_digest = None
    for _, attribute, _ in items(attrs_value):
        (_, attr_oid, _), (_, values, _) = items(attribute)
        name = decode_oid(attr_oid)
        report["attributes"].append(name)
        if name == OID_MESSAGE_DIGEST:
            _, message_digest, _ = tlv(values)
        if name == OID_SIGNING_TIME:
            _, when, _ = tlv(values)
            report["signing_time"] = when.decode()

    cert = next(c for c in certificates if certificate_parts(c)[2] == signer_serial)
    cert_tbs, cert_signature, _, point = certificate_parts(cert)
    _, _, _, ca_point = certificate_parts(unpem(ca_pem))

    checks = report["checks"]
    checks["message_digest"] = message_digest == streebog(content)
    # The signature covers the signed attributes re-encoded as a SET (tag 0x31 instead of [0]).
    checks["signature"] = gost_verify(point, b"\x31" + attrs_raw[1:], signature)
    checks["certificate_by_ca"] = gost_verify(ca_point, cert_tbs, cert_signature)
    checks["cades_bes_attributes"] = all(
        oid in report["attributes"] for oid in (OID_CONTENT_TYPE, OID_MESSAGE_DIGEST, OID_SIGNING_CERTIFICATE_V2)
    )
    report["valid"] = all(checks.values())
    return report


if __name__ == "__main__":
    if len(sys.argv) not in (3, 4):
        sys.exit(__doc__)
    content = open(sys.argv[3], "rb").read() if len(sys.argv) == 4 else None
    result = verify(open(sys.argv[1]).read(), open(sys.argv[2]).read(), content)
    print(json.dumps(result, ensure_ascii=False))
    sys.exit(0 if result["valid"] else 1)
