#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-3.0-only
#
# Copyright (C) 2026 Corey Pennycuff
#
# This file is part of Ghoti.io Certificate.
#
# Ghoti.io Certificate is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License version 3 as
# published by the Free Software Foundation.
"""The pins agree with each other, and the public API agrees with the registry.

No container. `make check-oracle` is the run that asks the image. This is the
run that fails when two files that are supposed to name one pin have drifted,
or when a primitive was declared without a row saying who judges it.

The classifier is run on a planted declaration before it is trusted on the
tree. A planted `gcert_ssh_cert_parse` is excluded and must be reported. If it is
not, this program is not a gate.
"""

import hashlib
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "oracle"))
import compare
import openssl_kat

ROOT = Path(__file__).resolve().parents[1]
INCLUDE = ROOT / "include"
REGISTRY = ROOT / "tools" / "oracle" / "primitives.txt"
MANIFEST = ROOT / "tests" / "data" / "vectors" / "MANIFEST"
IMAGES = ROOT / "tools" / "oracle" / "containers" / "IMAGES"
CONTAINERFILE = ROOT / "tools" / "oracle" / "containers" / "openssl" / "Containerfile"

DEBIAN_DIGEST = (
    "sha256:7792b1f7702a86946cd518db72b6a407302c3e9bc1635634368b878189e8221c")
OPENSSL_APT = "openssl=3.5.7-1~deb13u2"
IMAGE = "localhost/ghoti-certificate-oracle-openssl:3.5.7"

FOUNDATION = {
    "gcert_allocator_default",
    "gcert_limits_default",
    "gcert_name_options_default",
    "gcert_result_string",
    "gcert_selftest",
    "gcert_version_number",
    "gcert_version_string",
}

DECL = re.compile(r"GCERT_API\b.*\b(gcert_[a-z0-9_]+)\s*\(")


def fail(message):
    print("check-foundation: %s" % message, file=sys.stderr)
    sys.exit(1)


def parse_registry(text):
    rows = []
    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        parts = line.split("\t")
        if len(parts) != 4:
            fail("primitives.txt: not four tab-separated fields: %r" % line)
        ident, status, judge, vectors = parts
        if status not in ("implemented", "pending", "excluded"):
            fail("primitives.txt: bad status %r" % status)
        rows.append({
            "id": ident,
            "status": status,
            "judge": judge,
            "vectors": vectors,
        })
    return rows


def matches(function, ident):
    prefix = "gcert_" + ident
    return function == prefix or function.startswith(prefix + "_")


def classify(functions, rows):
    problems = []
    claimed = set()
    for row in rows:
        hit = sorted(fn for fn in functions if matches(fn, row["id"]))
        if row["status"] == "implemented":
            if not hit:
                problems.append(
                    "%s is implemented and no gcert_%s function is declared"
                    % (row["id"], row["id"]))
            claimed.update(hit)
            if row["judge"] in (
                    "openssl", "nist", "rfc", "wycheproof", "libcrypt") \
                    and row["vectors"] == "-":
                problems.append(
                    "%s is judged by %s and has no vector file"
                    % (row["id"], row["judge"]))
        elif hit:
            problems.append(
                "%s is %s but declares %s"
                % (row["id"], row["status"], ", ".join(hit)))
    for function in sorted(functions):
        if function in FOUNDATION or function in claimed:
            continue
        problems.append(
            "%s is declared and is neither foundation nor an implemented "
            "primitive" % function)
    return problems


def declarations():
    found = set()
    for path in INCLUDE.rglob("*.h"):
        for line in path.read_text(encoding="utf-8").splitlines():
            match = DECL.search(line)
            if match:
                found.add(match.group(1))
    return found


# Encodings gcert_selftest does not exercise, each with the reason. A
# power-on self test answers "is this build computing what it was built to
# compute"; a parser with no writer cannot answer that without a fixture
# compiled into the library, and a PFX is 1.5 KB of one. Those are covered by
# the vector corpus instead, which is where a parser's known answers belong.
SELFTEST_EXCLUDED = {
    "pkcs8": "parses only; its known answers are pkcs8.vec and the fixtures",
    "pkcs12": "parses only; a PFX in the library would be 1.5 KB of fixture",
    "x509": "parses and issues; issuance needs a key and a clock",
    "crl": "parses only; its known answer is a fixture",
    "ocsp": "parses only; its known answer is a fixture",
    "key": "loads and signs; its known answers are the signature round trips in test_key.cpp against signatures OpenSSL wrote (tests/data/keys)",
    "chain": "a search whose verdict is gcert_x509_path's; its tests build hierarchies",
    "trust": "a container of caller-supplied certificates; nothing here has a known answer of its own",
}


def check_selftest(rows):
    """Every implemented primitive is exercised by gcert_selftest or excused.

    The claim that the self-test covers each implemented primitive was made in
    design.md and enforced nowhere, and it had stopped being true: ECDSA P-384
    signing, the AEAD and CBC decrypt directions, and every encoding but DER
    were absent. The oracle probe's coverage is checked exactly this way a few
    lines above; this is the same check for the other set.
    """
    source = (ROOT / "src" / "core" / "selftest.c").read_text(encoding="utf-8")
    called = set(re.findall(r"\b(gcert_[a-z0-9_]+)\s*\(", source))
    problems = []
    for row in rows:
        if row["status"] != "implemented":
            continue
        ident = row["id"]
        if ident in SELFTEST_EXCLUDED:
            if any(matches(fn, ident) for fn in called):
                problems.append(
                    "%s is in SELFTEST_EXCLUDED and gcert_selftest calls it; "
                    "drop the exclusion" % ident)
            continue
        if not any(matches(fn, ident) for fn in called):
            problems.append(
                "gcert_selftest calls nothing matching %s: add a known answer, "
                "or add it to SELFTEST_EXCLUDED with the reason" % ident)
    for ident in sorted(SELFTEST_EXCLUDED):
        if not any(row["id"] == ident for row in rows):
            problems.append("SELFTEST_EXCLUDED names %s, which is not a "
                            "registry row" % ident)
    return problems


def check_manifest():
    if not MANIFEST.is_file():
        fail("no %s" % MANIFEST.relative_to(ROOT))
    seen = []
    for line in MANIFEST.read_text(encoding="utf-8").splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) != 2:
            fail("MANIFEST: expected digest and path: %r" % line)
        digest, rel = parts
        path = ROOT / rel
        if not path.is_file():
            fail("MANIFEST names a missing file: %s" % rel)
        got = hashlib.sha256(path.read_bytes()).hexdigest()
        if not compare.hex_equal(got, digest):
            fail("%s sha256 is %s, MANIFEST says %s" % (rel, got, digest))
        seen.append(rel)
    if not seen:
        fail("MANIFEST is empty")
    return seen


def main():
    compare.self_test()
    rows = parse_registry(REGISTRY.read_text(encoding="utf-8"))
    # The implemented set alone must be clean. Adding one pending primitive
    # must be reported. A classifier that only runs on the tree cannot tell
    # those apart: both look like whatever the headers happen to say.
    present = {
        "gcert_der_tlv",
        "gcert_pem_decode", "gcert_pem_encode",
        "gcert_pkcs8_parse", "gcert_pkcs8_decrypt",
        "gcert_pkcs12_open",
        "gcert_crl_parse", "gcert_crl_signed_by", "gcert_crl_contains",
        "gcert_ocsp_parse", "gcert_ocsp_signed_by", "gcert_ocsp_status",
        "gcert_x509_parse", "gcert_x509_signed_by", "gcert_x509_path",
        "gcert_x509_hostname", "gcert_x509_issue", "gcert_ip_parse",
        "gcert_x509_verify_dns", "gcert_x509_verify_ip",
        "gcert_x509_verify_uri", "gcert_x509_verify_email",
        "gcert_x509_verify_host", "gcert_pem_next",
        "gcert_trust_new", "gcert_trust_free", "gcert_trust_count",
        "gcert_trust_add_der", "gcert_trust_add_pem", "gcert_trust_add_file",
        "gcert_trust_add_system", "gcert_trust_get", "gcert_trust_find_issuers", "gcert_chain_build",
        "gcert_crl_check", "gcert_ocsp_check", "gcert_revocation_policy_default",
        "gcert_revocation_verdict", "gcert_x509_verify_signature",
        "gcert_x509_san_next", "gcert_x509_name_attr",
        "gcert_key_from_pkcs8", "gcert_key_from_pem", "gcert_key_free", "gcert_key_kind",
        "gcert_key_matches", "gcert_key_scheme_fits", "gcert_key_sign",
    }
    clean = classify(present, rows)
    if clean:
        fail("the implemented set was rejected: %r" % clean)
    planted = classify(present | {"gcert_ssh_cert_parse"}, rows)
    if not any("ssh_cert" in item and "excluded" in item for item in planted):
        fail("a planted gcert_ssh_cert_parse was not rejected: %r" % planted)

    functions = declarations()
    missing = sorted(FOUNDATION - functions)
    if missing:
        fail("foundation functions missing from the headers: %s"
            % ", ".join(missing))
    problems = classify(functions, rows)
    if problems:
        for problem in problems:
            print("check-foundation: " + problem, file=sys.stderr)
        return 1

    outside = [
        row["id"] for row in rows
        if row["status"] == "implemented" and row["judge"] not in ("self", "none")]
    if set(outside) != set(openssl_kat.COVERED):
        missing = sorted(set(outside) - set(openssl_kat.COVERED))
        extra = sorted(set(openssl_kat.COVERED) - set(outside))
        fail("oracle coverage missing %s extra %s" % (missing, extra))

    problems = check_selftest(rows)
    if problems:
        for problem in problems:
            print("check-foundation: " + problem, file=sys.stderr)
        return 1

    listed = check_manifest()
    for row in rows:
        if row["vectors"] == "-":
            continue
        path = ROOT / row["vectors"]
        if not path.is_file():
            fail("%s names a missing vector file %s" % (row["id"], row["vectors"]))
        if row["vectors"] not in listed:
            fail("%s is not in the vector MANIFEST" % row["vectors"])

    text = CONTAINERFILE.read_text(encoding="utf-8")
    for needle in (DEBIAN_DIGEST, OPENSSL_APT, "LANG=C.UTF-8",
            "trixie-security"):
        if needle not in text:
            fail("Containerfile does not pin %s" % needle)
    images = IMAGES.read_text(encoding="utf-8")
    if IMAGE not in images or "OpenSSL 3.5.7" not in images:
        fail("IMAGES does not name the openssl image and its version")
    print("check-foundation: registry, manifest, and oracle pins agree")
    return 0


if __name__ == "__main__":
    sys.exit(main())
