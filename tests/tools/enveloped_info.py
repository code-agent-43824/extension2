"""Says what a CMS EnvelopedData is encrypted with and for, independent of the extension's code.

The content cannot be checked here: the recipient's key is on the (fake) token. Reads the BER with
indefinite lengths the Rutoken Plugin writes.

Usage: enveloped_info.py CMS_BASE64_FILE
Prints JSON: the content encryption algorithm's OID, for GOST 28147-89 its parameter set's OID
(Gost28147-89-Parameters, RFC 4357: the IV and the set), and for each recipient its kind, the key
encryption algorithm's OID and the certificate's serial number (upper-case hex) or key identifier.
"""

import base64
import json
import sys

from asn1crypto import cms, core

GOST_28147 = "1.2.643.2.2.21"


class Gost28147Parameters(core.Sequence):
    _fields = [("iv", core.OctetString), ("encryption_param_set", core.ObjectIdentifier)]


def recipient(info):
    kind = info.name
    chosen = info.chosen
    if kind == "ktri":
        rid = chosen["rid"]
        named = {"serial": "%X" % rid.chosen["serial_number"].native} if rid.name == "issuer_and_serial_number" else {"key_id": rid.chosen.native.hex().upper()}
        return {"kind": kind, "key_encryption": chosen["key_encryption_algorithm"]["algorithm"].dotted, **named}
    if kind == "kari":
        keys = []
        for key in chosen["recipient_encrypted_keys"]:
            rid = key["rid"]
            keys.append({"serial": "%X" % rid.chosen["serial_number"].native} if rid.name == "issuer_and_serial_number" else {"key_id": rid.chosen["subject_key_identifier"].native.hex().upper()})
        return {"kind": kind, "key_encryption": chosen["key_encryption_algorithm"]["algorithm"].dotted, "keys": keys}
    return {"kind": kind}


def main():
    data = base64.b64decode("".join(open(sys.argv[1]).read().split()))
    info = cms.ContentInfo.load(data)
    if info["content_type"].native != "enveloped_data":
        raise SystemExit("not an EnvelopedData: %s" % info["content_type"].native)
    enveloped = info["content"]
    algorithm = enveloped["encrypted_content_info"]["content_encryption_algorithm"]
    result = {"content_encryption": algorithm["algorithm"].dotted}
    if algorithm["algorithm"].dotted == GOST_28147:
        result["content_param_set"] = Gost28147Parameters.load(algorithm["parameters"].dump())["encryption_param_set"].dotted
    result["recipients"] = [recipient(item) for item in enveloped["recipient_infos"]]
    print(json.dumps(result))


if __name__ == "__main__":
    main()
