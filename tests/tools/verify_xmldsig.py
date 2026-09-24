"""Independent verifier for GOST XMLDSig signatures (CAdESCOM.SignedXML output).

Usage: verify_xmldsig.py <signed.xml> <ca.pem> [<signer.pem>, when KeyInfo has no certificate]
Prints JSON: {"valid": bool, "signatures": [{"references": [...], "checks": {...}}]}.

Canonicalization is libxml2's (lxml), digests and signatures are gostcrypto's (through verify_cms.py);
nothing here is shared with the extension's JavaScript. Every ds:Signature in the document is checked:
each Reference's digest over its transformed data, the signature over the canonical SignedInfo with the
certificate from KeyInfo, and that certificate against the CA.
"""

import base64
import copy
import json
import sys

from lxml import etree

from verify_cms import certificate_parts, gost_verify, streebog

DS = "http://www.w3.org/2000/09/xmldsig#"
NS = {"ds": DS}
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
    return {"signature_method": method, "references": references, "checks": checks}


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
