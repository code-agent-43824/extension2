"""Independent verifier for GOST XMLDSig and XAdES signatures (CAdESCOM.SignedXML output).

Usage: verify_xmldsig.py <signed.xml> <ca.pem> [<signer.pem>, when KeyInfo has no certificate]
Prints JSON: {"valid": bool, "signatures": [{"references": [...], "checks": {...}}]}.

Canonicalization is libxml2's (lxml), digests and signatures are gostcrypto's (through verify_cms.py);
nothing here is shared with the extension's JavaScript. Every ds:Signature in the document is checked:
each Reference's digest over its transformed data, the signature over the canonical SignedInfo with the
certificate from KeyInfo, and that certificate against the CA. A XAdES signature (ETSI TS 101 903 v1.3.2)
also: its QualifyingProperties aim at the signature, a Reference of the SignedProperties type covers the
signed properties, the signing time is an xsd:dateTime, SigningCertificate names the KeyInfo certificate by
digest and by issuer (an RFC 4514 string, parsed here) and serial number; XAdES-T's SignatureTimeStamp is
checked as verify_cms.py checks CAdES-T's, over the SignatureValue canonicalized as the timestamp says.
"""

import base64
import copy
import datetime
import json
import re
import string
import sys

from lxml import etree

from verify_cms import certificate_parts, decode_oid, gost_verify, items, streebog, tlv, verify_timestamp

DS = "http://www.w3.org/2000/09/xmldsig#"
XADES = "http://uri.etsi.org/01903/v1.3.2#"
NS = {"ds": DS, "xades": XADES}
SIGNED_PROPERTIES_TYPE = "http://uri.etsi.org/01903#SignedProperties"
INCLUSIVE_C14N = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"
ENVELOPED = DS + "enveloped-signature"
C14N = {
    "http://www.w3.org/TR/2001/REC-xml-c14n-20010315": (False, False),
    "http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments": (False, True),
    "http://www.w3.org/2001/10/xml-exc-c14n#": (True, False),
    "http://www.w3.org/2001/10/xml-exc-c14n#WithComments": (True, True),
}
DIGESTS = {
    "urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34112012-256": 32,
    "urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34112012-512": 64,
}
SIGNATURES = {
    "urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34102012-gostr34112012-256": 32,
    "urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34102012-gostr34112012-512": 64,
}
ID_ATTRIBUTES = ["{http://www.w3.org/XML/1998/namespace}id", "Id", "ID", "id"]


XML_NS = "{http://www.w3.org/XML/1998/namespace}"


def canonical(node, algorithm, prefixes=None, comments=None):
    exclusive, with_comments = C14N[algorithm]
    if comments is not None:
        with_comments = comments
    if not exclusive and isinstance(node, etree._Element) and node.getparent() is not None:
        # Inclusive C14N gives the apex of a subset the xml: attributes of its ancestors (C14N 1.0, 2.4);
        # lxml carries the in-scope namespaces over but not these.
        inherited = {}
        for ancestor in node.iterancestors():
            for name, value in ancestor.attrib.items():
                if name.startswith(XML_NS) and name not in node.attrib:
                    inherited.setdefault(name, value)
        # Set on the node itself for the moment: a copy would lose the unused inherited namespaces.
        for name, value in inherited.items():
            node.set(name, value)
        try:
            return etree.tostring(node, method="c14n", exclusive=exclusive, with_comments=with_comments)
        finally:
            for name in inherited:
                del node.attrib[name]
    return etree.tostring(node, method="c14n", exclusive=exclusive, with_comments=with_comments, inclusive_ns_prefixes=prefixes)


def dereference(tree, signature, uri):
    """A copy of what the Reference points at, and the signature inside that copy (or None)."""
    nodes = list(tree.iter())
    copied = copy.deepcopy(tree)
    twins = list(copied.iter())
    inner = twins[nodes.index(signature)]
    if uri == "":
        return copied, inner
    if not uri.startswith("#"):
        raise ValueError(f"unsupported Reference URI {uri!r}")
    target = next((el for el in nodes if isinstance(el.tag, str) and any(el.get(a) == uri[1:] for a in ID_ATTRIBUTES)), None)
    if target is None:
        raise ValueError(f"no element with id {uri[1:]!r}")
    node = twins[nodes.index(target)]
    return node, inner if node in inner.iterancestors() else None


def check_reference(tree, signature, reference):
    uri = reference.get("URI", "")
    node, inner = dereference(tree, signature, uri)
    algorithm = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"
    prefixes = None
    for transform in reference.findall("ds:Transforms/ds:Transform", NS):
        name = transform.get("Algorithm")
        if name == ENVELOPED:
            if inner is not None:
                inner.getparent().remove(inner)
        elif name in C14N:
            algorithm = name
            listed = transform.find("{http://www.w3.org/2001/10/xml-exc-c14n#}InclusiveNamespaces")
            prefixes = listed.get("PrefixList").split() if listed is not None else None
        else:
            raise ValueError(f"unsupported transform {name}")
    # Same-document references drop comments whatever the canonicalization says (XMLDSig 4.4.3.3).
    data = canonical(node, algorithm, prefixes, comments=False)
    method = reference.find("ds:DigestMethod", NS).get("Algorithm")
    size = DIGESTS.get(method)
    if size is None:
        raise ValueError(f"unsupported digest {method}")
    value = base64.b64decode(reference.findtext("ds:DigestValue", namespaces=NS))
    return {"uri": uri, "digest_method": method, "digest": streebog(data, size) == value}


def check_signature(tree, signature, ca_der, cert_der=None):
    references = [check_reference(tree, signature, r) for r in signature.findall("ds:SignedInfo/ds:Reference", NS)]
    signed_info = signature.find("ds:SignedInfo", NS)
    method = signed_info.find("ds:SignatureMethod", NS).get("Algorithm")
    if method not in SIGNATURES:
        raise ValueError(f"unsupported signature method {method}")
    data = canonical(signed_info, signed_info.find("ds:CanonicalizationMethod", NS).get("Algorithm"))
    included = signature.findtext("ds:KeyInfo/ds:X509Data/ds:X509Certificate", namespaces=NS)
    if included:
        cert_der = base64.b64decode(included)
    if cert_der is None:
        raise ValueError("no certificate in KeyInfo and none given")
    tbs, cert_signature, _, key = certificate_parts(cert_der)
    ca_key = certificate_parts(ca_der)[3]
    value = base64.b64decode(signature.findtext("ds:SignatureValue", namespaces=NS))
    checks = {
        "references": bool(references) and all(r["digest"] for r in references),
        "signature": len(value) == 2 * SIGNATURES[method] and gost_verify(key, data, value),
        "certificate_by_ca": gost_verify(ca_key, tbs, cert_signature),
    }
    report = {"signature_method": method, "references": references, "checks": checks}
    check_xades(signature, cert_der, ca_key, checks, report)
    return report


# The short names of RFC 4514, section 3; any other type is written as a dotted OID.
RFC4514_NAMES = {
    "CN": "2.5.4.3",
    "L": "2.5.4.7",
    "ST": "2.5.4.8",
    "O": "2.5.4.10",
    "OU": "2.5.4.11",
    "C": "2.5.4.6",
    "STREET": "2.5.4.9",
    "DC": "0.9.2342.19200300.100.1.25",
    "UID": "0.9.2342.19200300.100.1.1",
}
STRING_CODECS = {0x0C: "utf-8", 0x12: "ascii", 0x13: "ascii", 0x16: "ascii", 0x14: "latin-1", 0x1E: "utf-16-be", 0x1C: "utf-32-be"}


def parse_rfc4514(text):
    """The RDNs of an RFC 4514 string in its own order (the reverse of DER's): lists of (OID, value), the value a
    str, or the BER bytes of a "#hex" value."""
    rdns, attributes, i = [], [], 0
    while True:
        equals = text.index("=", i)
        key = text[i:equals].strip()
        oid = RFC4514_NAMES.get(key.upper(), key)
        if not re.fullmatch(r"\d+(\.\d+)+", oid):
            raise ValueError(f"unknown attribute type {key!r}")
        i = equals + 1
        if text.startswith("#", i):
            end = i + 1
            while end < len(text) and text[end] in string.hexdigits:
                end += 1
            value, i = bytes.fromhex(text[i + 1 : end]), end
        else:
            raw = bytearray()
            while i < len(text) and text[i] not in ",+":
                if text[i] == "\\":
                    pair = text[i + 1 : i + 3]
                    if len(pair) == 2 and all(c in string.hexdigits for c in pair):
                        raw.append(int(pair, 16))
                        i += 3
                    else:
                        raw += text[i + 1].encode()
                        i += 2
                else:
                    raw += text[i].encode()
                    i += 1
            value = raw.decode("utf-8")
        attributes.append((oid, value))
        if i < len(text) and text[i] == "+":
            i += 1
            continue
        rdns.append(attributes)
        attributes = []
        if i >= len(text):
            return rdns
        i += 1


def issuer_rdns(cert_der):
    """The issuer's RDNs in DER order: lists of (OID, tag, contents, encoding) of each attribute value."""
    _, cert, _ = tlv(cert_der)
    fields = items(items(cert)[0][1])
    if fields[0][0] == 0xA0:
        fields = fields[1:]
    result = []
    for _, rdn, _ in items(fields[2][1]):
        attributes = []
        for _, pair, _ in items(rdn):
            (_, oid, _), (tag, value, raw) = items(pair)
            attributes.append((decode_oid(oid), tag, value, raw))
        result.append(attributes)
    return result


def attribute_matches(written, der_attribute):
    oid, value = written
    der_oid, tag, contents, raw = der_attribute
    if oid != der_oid:
        return False
    if isinstance(value, bytes):
        return value == raw
    return tag in STRING_CODECS and contents.decode(STRING_CODECS[tag]) == value


def same_name(parsed, der_rdns):
    """Whether RFC 4514 RDNs name the DER issuer: the same RDNs in reverse order, each value as written (a string,
    or "#hex" of its BER); the attributes of a multi-valued RDN in any order."""
    written_rdns = list(reversed(parsed))
    return len(written_rdns) == len(der_rdns) and all(
        len(written) == len(rdn) and all(any(attribute_matches(w, d) for d in rdn) for w in written)
        for written, rdn in zip(written_rdns, der_rdns)
    )


def check_xades(signature, cert_der, ca_point, checks, report):
    """The XAdES properties of the signature, if it has them; adds to checks and report."""
    qualifying = signature.find("ds:Object/xades:QualifyingProperties", NS)
    if qualifying is None:
        return
    signed = qualifying.find("xades:SignedProperties", NS)
    properties = signed.find("xades:SignedSignatureProperties", NS) if signed is not None else None
    signing_time = properties.findtext("xades:SigningTime", namespaces=NS) if properties is not None else None
    report["xades"] = {"signing_time": signing_time}
    checks["xades_target"] = qualifying.get("Target") == "#" + (signature.get("Id") or "")
    covering = [r for r in signature.findall("ds:SignedInfo/ds:Reference", NS) if r.get("Type") == SIGNED_PROPERTIES_TYPE]
    checks["xades_signed_properties_covered"] = signed is not None and [r.get("URI") for r in covering] == ["#" + (signed.get("Id") or "")]
    try:
        checks["xades_signing_time"] = datetime.datetime.fromisoformat(signing_time.replace("Z", "+00:00")).tzinfo is not None
    except (AttributeError, ValueError):
        checks["xades_signing_time"] = False
    cert = properties.find("xades:SigningCertificate/xades:Cert", NS) if properties is not None else None
    if cert is None:
        checks["xades_certificate_digest"] = checks["xades_issuer_serial"] = False
    else:
        method = cert.find("xades:CertDigest/ds:DigestMethod", NS).get("Algorithm")
        value = base64.b64decode(cert.findtext("xades:CertDigest/ds:DigestValue", namespaces=NS))
        checks["xades_certificate_digest"] = method in DIGESTS and streebog(cert_der, DIGESTS[method]) == value
        name = cert.findtext("xades:IssuerSerial/ds:X509IssuerName", namespaces=NS) or ""
        serial = cert.findtext("xades:IssuerSerial/ds:X509SerialNumber", namespaces=NS) or ""
        report["xades"]["issuer"] = name
        expected_serial = int.from_bytes(certificate_parts(cert_der)[2], "big", signed=True)
        checks["xades_issuer_serial"] = same_name(parse_rfc4514(name), issuer_rdns(cert_der)) and serial.strip() == str(expected_serial)
    stamp = qualifying.find("xades:UnsignedProperties/xades:UnsignedSignatureProperties/xades:SignatureTimeStamp", NS)
    if stamp is not None:
        method = stamp.find("ds:CanonicalizationMethod", NS)
        data = canonical(signature.find("ds:SignatureValue", NS), method.get("Algorithm") if method is not None else INCLUSIVE_C14N)
        token = base64.b64decode(stamp.findtext("xades:EncapsulatedTimeStamp", namespaces=NS))
        verify_timestamp(token, data, ca_point, checks, report)


def pem_to_der(pem):
    return base64.b64decode("".join(line for line in pem.splitlines() if "-----" not in line))


# cert_pem is for signatures whose KeyInfo carries no certificate.
def verify(xml_bytes, ca_pem, cert_pem=None):
    ca_der = pem_to_der(ca_pem)
    cert_der = pem_to_der(cert_pem) if cert_pem else None
    tree = etree.ElementTree(etree.fromstring(xml_bytes))
    # An unfilled template (no SignedInfo, or no SignatureValue text) is not a signature.
    found = [s for s in tree.getroot().iter("{%s}Signature" % DS) if s.find("ds:SignedInfo", NS) is not None and (s.findtext("ds:SignatureValue", namespaces=NS) or "").strip()]
    signatures = [check_signature(tree, s, ca_der, cert_der) for s in found]
    return {"valid": bool(signatures) and all(all(s["checks"].values()) for s in signatures), "signatures": signatures}


if __name__ == "__main__":
    with open(sys.argv[1], "rb") as xml_file, open(sys.argv[2]) as ca_file:
        signer = open(sys.argv[3]).read() if len(sys.argv) > 3 else None
        print(json.dumps(verify(xml_file.read(), ca_file.read(), signer)))
