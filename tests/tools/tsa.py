"""Timestamp service (RFC 3161) for the stand, independent of the Rutoken stack.

Answers a TimeStampReq posted over HTTP with a TimeStampResp whose token is signed with
GOST R 34.10-2012/256 by a key in software: the TSA certificate is issued by the stand's
test CA (gost_ca.py) on first use and kept beside it (tsa.key, tsa.pem), with the critical
timeStamping extended key usage RFC 3161 requires. The token carries the CAdES-style signed
attributes: content type, message digest (Streebog-256 of TSTInfo) and signing-certificate-v2.

Usage: tsa.py CA_DIR
Listens on 127.0.0.1 on a free port, prints "port N" once ready, serves until killed.
"""

import datetime
import http.server
import os
import secrets
import sys

from asn1crypto import core, tsp
from gostcrypto import gosthash

from gost_ca import (
    CURVE,
    certificate,
    der,
    explicit,
    extension,
    gost_sign,
    integer,
    load_or_create_ca,
    name,
    octets,
    oid,
    pem,
    seq,
    spki_for,
    unpem,
)

OID_SIGNED_DATA = "1.2.840.113549.1.7.2"
OID_TST_INFO = "1.2.840.113549.1.9.16.1.4"
OID_CONTENT_TYPE = "1.2.840.113549.1.9.3"
OID_MESSAGE_DIGEST = "1.2.840.113549.1.9.4"
OID_SIGNING_CERTIFICATE_V2 = "1.2.840.113549.1.9.16.2.47"
OID_STREEBOG256 = "1.2.643.7.1.1.2.2"
OID_GOST2012_256 = "1.2.643.7.1.1.1.1"
OID_TIME_STAMPING = "1.3.6.1.5.5.7.3.8"
# The policy when a request names none: an OID of the arc reserved for examples.
OID_STAND_POLICY = "2.999.1"


def streebog256(data):
    return bytes(gosthash.new("streebog256", data=data).digest())


def set_of(*elements):
    # DER orders the elements of a SET OF by their encodings.
    return der(0x31, b"".join(sorted(elements)))


def load_or_create_tsa(ca_dir):
    key_path = os.path.join(ca_dir, "tsa.key")
    cert_path = os.path.join(ca_dir, "tsa.pem")
    if os.path.exists(key_path):
        return bytes.fromhex(open(key_path).read().strip()), unpem(open(cert_path).read())
    ca_key, ca_cert = load_or_create_ca(ca_dir)
    ca_subject = core.load(ca_cert)[0][5].dump()
    key = (secrets.randbelow(int(CURVE["q"]) - 1) + 1).to_bytes(32, "big")
    now = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)
    cert = certificate(
        secrets.randbits(127) | 1,
        ca_subject,
        name("Stand TSA"),
        spki_for(key),
        now - datetime.timedelta(days=1),
        now + datetime.timedelta(days=3650),
        [
            # digitalSignature, nonRepudiation
            extension("2.5.29.15", core.BitString((1, 1)).dump(), critical=True),
            extension("2.5.29.37", seq(oid(OID_TIME_STAMPING)), critical=True),
        ],
        ca_key,
    )
    open(key_path, "w").write(key.hex())
    open(cert_path, "w").write(pem("CERTIFICATE", cert))
    return key, cert


def token(request_der, key, cert):
    request = tsp.TimeStampReq.load(request_der)
    policy = request["req_policy"].dotted if request["req_policy"].native is not None else OID_STAND_POLICY
    now = datetime.datetime.now(datetime.timezone.utc)
    tst_fields = [
        integer(1),
        oid(policy),
        request["message_imprint"].dump(),
        integer(secrets.randbits(63) | 1),
        der(0x18, now.strftime("%Y%m%d%H%M%SZ").encode()),
    ]
    if request["nonce"].native is not None:
        tst_fields.append(request["nonce"].dump())
    tst_info = seq(*tst_fields)

    tbs = core.load(cert)[0]
    issuer = tbs[3].dump()
    serial = tbs[1].dump()
    streebog_id = seq(oid(OID_STREEBOG256))
    attributes = [
        seq(oid(OID_CONTENT_TYPE), set_of(oid(OID_TST_INFO))),
        seq(oid(OID_MESSAGE_DIGEST), set_of(octets(streebog256(tst_info)))),
        # SigningCertificateV2 ::= SEQUENCE { certs SEQUENCE OF ESSCertIDv2 }, ESSCertIDv2 with its hash algorithm.
        seq(oid(OID_SIGNING_CERTIFICATE_V2), set_of(seq(seq(seq(streebog_id, octets(streebog256(cert))))))),
    ]
    signed_attributes = set_of(*attributes)
    signer_info = seq(
        integer(1),
        seq(issuer, serial),
        streebog_id,
        b"\xa0" + signed_attributes[1:],
        seq(oid(OID_GOST2012_256)),
        octets(gost_sign(key, signed_attributes)),
    )
    certificates = b"\xa0" + set_of(cert)[1:] if request["cert_req"].native else b""
    signed_data = seq(
        integer(3),
        set_of(streebog_id),
        seq(oid(OID_TST_INFO), explicit(0, octets(tst_info))),
        certificates,
        set_of(signer_info),
    )
    content_info = seq(oid(OID_SIGNED_DATA), explicit(0, signed_data))
    # TimeStampResp: status granted (0), then the token.
    return seq(seq(integer(0)), content_info)


def main():
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    key, cert = load_or_create_tsa(sys.argv[1])

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
            try:
                answer = token(body, key, cert)
                self.send_response(200)
                self.send_header("Content-Type", "application/timestamp-reply")
            except Exception as error:  # noqa: BLE001 - any bad request gets a plain HTTP error
                answer = str(error).encode()
                self.send_response(400)
                self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(answer)))
            self.end_headers()
            self.wfile.write(answer)

        def log_message(self, *args):
            pass

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    print(f"port {server.server_address[1]}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
