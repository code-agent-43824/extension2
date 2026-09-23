"""Test certificate authority for the stand, independent of the Rutoken stack.

Issues a GOST R 34.10-2012/256 certificate for a PKCS #10 request made on the
fake Rutoken. The CA key lives in software (gostcrypto) under the given
directory and is created on first use.

Byte-order conventions (established on the stand, see docs/JOURNAL.md):
- a public key in SubjectPublicKeyInfo is x||y, each little-endian; gostcrypto
  takes x||y big-endian;
- gostcrypto expects the Streebog digest reversed;
- the signature as stored in X.509/CMS equals gostcrypto's output with its two
  32-byte halves swapped.

Usage: gost_ca.py issue CA_DIR CSR_PEM OUT_CERT_PEM
"""

import base64
import datetime
import os
import secrets
import sys

from asn1crypto import core
from gostcrypto import gosthash, gostsignature

CURVE = gostsignature.CURVES_R_1323565_1_024_2019["id-tc26-gost-3410-2012-256-paramSetB"]  # = CryptoPro-A
OID_PARAMSET_CRYPTOPRO_A = "1.2.643.2.2.35.1"
OID_GOST2012_256 = "1.2.643.7.1.1.1.1"
OID_STREEBOG256 = "1.2.643.7.1.1.2.2"
OID_SIG_GOST2012_256 = "1.2.643.7.1.1.3.2"


def der(tag, body):
    n = len(body)
    if n < 0x80:
        length = bytes([n])
    else:
        raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
        length = bytes([0x80 | len(raw)]) + raw
    return bytes([tag]) + length + body


def seq(*items):
    return der(0x30, b"".join(items))


def oid(dotted):
    return core.ObjectIdentifier(dotted).dump()


def integer(value):
    return core.Integer(value).dump()


def utc(t):
    return core.UTCTime(t).dump()


def bitstring(data):
    return der(0x03, b"\x00" + data)


def octets(data):
    return der(0x04, data)


def explicit(n, body):
    return der(0xA0 + n, body)


def name(cn):
    return seq(der(0x31, seq(oid("2.5.4.3"), core.UTF8String(cn).dump())), der(0x31, seq(oid("2.5.4.6"), core.PrintableString("RU").dump())))


def extension(ext_oid, value, critical=False):
    return seq(oid(ext_oid), core.Boolean(True).dump() if critical else b"", octets(value))


def pem(label, data):
    b64 = base64.b64encode(data).decode()
    lines = [b64[i : i + 64] for i in range(0, len(b64), 64)]
    return f"-----BEGIN {label}-----\n" + "\n".join(lines) + f"\n-----END {label}-----\n"


def unpem(text):
    body = "".join(line for line in text.strip().splitlines() if not line.startswith("-----"))
    return base64.b64decode(body)


def gost_sign(private_key, data):
    signer = gostsignature.new(gostsignature.MODE_256, CURVE)
    digest = bytes(gosthash.new("streebog256", data=data).digest())
    raw = bytes(signer.sign(bytearray(private_key), bytearray(digest[::-1])))
    return raw[32:] + raw[:32]


def spki_for(private_key):
    signer = gostsignature.new(gostsignature.MODE_256, CURVE)
    pub = bytes(signer.public_key_generate(bytearray(private_key)))
    point = pub[:32][::-1] + pub[32:][::-1]
    algorithm = seq(oid(OID_GOST2012_256), seq(oid(OID_PARAMSET_CRYPTOPRO_A), oid(OID_STREEBOG256)))
    return seq(algorithm, bitstring(octets(point)))


def certificate(serial, issuer, subject, spki, not_before, not_after, extensions, signing_key):
    sig_alg = seq(oid(OID_SIG_GOST2012_256))
    tbs = seq(
        explicit(0, integer(2)),
        integer(serial),
        sig_alg,
        issuer,
        seq(utc(not_before), utc(not_after)),
        subject,
        spki,
        explicit(3, seq(*extensions)),
    )
    return seq(tbs, sig_alg, bitstring(gost_sign(signing_key, tbs)))


def load_or_create_ca(ca_dir):
    key_path = os.path.join(ca_dir, "ca.key")
    cert_path = os.path.join(ca_dir, "ca.pem")
    if os.path.exists(key_path):
        return bytes.fromhex(open(key_path).read().strip()), unpem(open(cert_path).read())
    os.makedirs(ca_dir, exist_ok=True)
    key = (secrets.randbelow(int(CURVE["q"]) - 1) + 1).to_bytes(32, "big")
    now = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)
    ca_name = name("Stand Test CA")
    cert = certificate(
        secrets.randbits(127) | 1,
        ca_name,
        ca_name,
        spki_for(key),
        now - datetime.timedelta(days=1),
        now + datetime.timedelta(days=3650),
        [
            extension("2.5.29.19", seq(core.Boolean(True).dump()), critical=True),
            extension("2.5.29.15", core.BitString((0, 0, 0, 0, 0, 1, 1)).dump(), critical=True),
        ],
        key,
    )
    open(key_path, "w").write(key.hex())
    open(cert_path, "w").write(pem("CERTIFICATE", cert))
    return key, cert


def issue(ca_dir, csr_pem_path, out_path):
    ca_key, ca_cert = load_or_create_ca(ca_dir)
    request = core.load(unpem(open(csr_pem_path).read()))
    info = request[0]
    subject = info[1].dump()
    spki = info[2].dump()
    ca_subject = core.load(ca_cert)[0][5].dump()
    now = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)
    cert = certificate(
        secrets.randbits(127) | 1,
        ca_subject,
        subject,
        spki,
        now - datetime.timedelta(days=1),
        now + datetime.timedelta(days=730),
        [
            # digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment, keyAgreement
            extension("2.5.29.15", core.BitString((1, 1, 1, 1, 1)).dump(), critical=True),
            extension("2.5.29.37", seq(oid("1.3.6.1.5.5.7.3.2"), oid("1.3.6.1.5.5.7.3.4"))),
        ],
        ca_key,
    )
    open(out_path, "w").write(pem("CERTIFICATE", cert))


if __name__ == "__main__":
    if len(sys.argv) == 5 and sys.argv[1] == "issue":
        issue(sys.argv[2], sys.argv[3], sys.argv[4])
    else:
        sys.exit(__doc__)
