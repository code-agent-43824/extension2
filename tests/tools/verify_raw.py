"""Independent check of a bare GOST R 34.10-2012 signature, as CAdESCOM.RawSignature gives it.

CryptoPro's documentation: the signature of RFC 4491, 2.2.2 (s||r, big-endian, as in CMS) with
its bytes in reverse order, as hex pairs with spaces. Hashes the content itself (Streebog of the
key's size) and checks the signature with the certificate's key, through verify_cms.py's DER walk
and gostcrypto: no code of the extension.

Usage: verify_raw.py CERT_PEM CONTENT_FILE SIGNATURE_HEX
Prints a JSON report; exits 0 only when the signature verifies.
"""

import json
import sys

from gost_ca import unpem
from verify_cms import certificate_parts, gost_verify


def verify(cert_pem, content, signature_hex):
    _, _, _, key = certificate_parts(unpem(cert_pem))
    cms_order = bytes.fromhex("".join(signature_hex.split()))[::-1]
    return {"valid": bool(gost_verify(key, content, cms_order)), "length": len(cms_order)}


if __name__ == "__main__":
    if len(sys.argv) != 4:
        sys.exit(__doc__)
    result = verify(open(sys.argv[1]).read(), open(sys.argv[2], "rb").read(), sys.argv[3])
    print(json.dumps(result))
    sys.exit(0 if result["valid"] else 1)
