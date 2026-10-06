#!/usr/bin/env python3
"""Splice a critical, unknown singleExtension into leaf.ocsp.

gcert_ocsp_status must refuse to answer from an entry carrying a critical
extension it does not understand. Building that by hand is the only way to get
one: OpenSSL's responder will not emit an unknown critical singleExtension, and
the rule is exactly the one nothing tested.

The signature no longer covers the modified tbsResponseData, which does not
matter to the test - gcert_ocsp_status does not check the signature, and
gcert_ocsp_signed_by is tested against tampering elsewhere. The fixture says so
in its name.

Usage: tools/make-ocsp-ext.py [tests/data/certs]
"""
import pathlib
import sys

OUT = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else "tests/data/certs")


def enc_len(n):
    if n < 0x80:
        return bytes([n])
    body = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(body)]) + body


def tlv(tag, body):
    return bytes([tag]) + enc_len(len(body)) + body


def read_len(data, i):
    """(value_length, index_of_contents)"""
    b = data[i]
    if b < 0x80:
        return b, i + 1
    n = b & 0x7F
    return int.from_bytes(data[i + 1:i + 1 + n], "big"), i + 1 + n


def walk(data, i):
    """(tag, contents_start, contents_len, total_end) of the TLV at i."""
    tag = data[i]
    length, start = read_len(data, i + 1)
    return tag, start, length, start + length


def main():
    base = (OUT / "leaf.ocsp").read_bytes()

    # OCSPResponse ::= SEQUENCE { responseStatus ENUMERATED,
    #                             responseBytes [0] EXPLICIT ResponseBytes }
    # ResponseBytes ::= SEQUENCE { responseType OID, response OCTET STRING }
    _, top, _, _ = walk(base, 0)
    _, sti, stl, ste = walk(base, top)                 # responseStatus
    status = base[sti - 2:ste]                         # keep it byte for byte
    _, rbi, _, rbe = walk(base, ste)                   # [0] responseBytes
    _, bsi, _, _ = walk(base, rbi)                     # ResponseBytes SEQUENCE
    rt_tag, rti, rtl, rte = walk(base, bsi)            # responseType OID
    response_type = base[bsi:rte]
    _, ci, cl, _ = walk(base, rte)                     # response OCTET STRING
    basic = base[ci:ci + cl]

    # BasicOCSPResponse ::= SEQUENCE { tbsResponseData, sigAlg, signature,
    #                                  certs [0] OPTIONAL }
    _, bi, _, _ = walk(basic, 0)
    _, di, dl, de = walk(basic, bi)                    # tbsResponseData
    tbs_inner = basic[di:di + dl]
    after_tbs = basic[de:]

    # Inside ResponseData the SEQUENCE OF SingleResponse is the last universal
    # SEQUENCE: version [0], responderID [1] or [2], producedAt, responses,
    # responseExtensions [1].
    j = 0
    responses = None
    while j < len(tbs_inner):
        tag, s, l, e = walk(tbs_inner, j)
        if tag == 0x30:
            responses = (j, s, l, e)
        j = e
    if responses is None:
        raise SystemExit("no SEQUENCE OF SingleResponse found")
    rj, rs, rl, rend = responses
    singles = tbs_inner[rs:rs + rl]

    # Append the extension to the first SingleResponse.
    _, s, l, e = walk(singles, 0)
    first = singles[s:s + l]
    others = singles[e:]

    # 1.2.3.4.5, critical, empty value. No OCSP extension is defined at that
    # arc, which is the point: the parser cannot know what it means.
    ext = tlv(0x30,
              tlv(0x06, bytes([0x2a, 0x03, 0x04, 0x05]))
              + tlv(0x01, b"\xff")
              + tlv(0x04, b""))

    new_singles = tlv(0x30, tlv(0x30, first + tlv(0xA1, tlv(0x30, ext)))
                      + others)
    new_tbs = tlv(0x30, tbs_inner[:rj] + new_singles + tbs_inner[rend:])
    new_basic = tlv(0x30, new_tbs + after_tbs)
    new_bytes = tlv(0xA0, tlv(0x30, response_type + tlv(0x04, new_basic)))
    out = tlv(0x30, status + new_bytes)

    (OUT / "ocsp-critical-single-ext.der").write_bytes(out)
    print("wrote %s, %d bytes (was %d)"
          % (OUT / "ocsp-critical-single-ext.der", len(out), len(base)))


main()
