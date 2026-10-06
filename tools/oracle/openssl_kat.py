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
"""Ask the pinned image whether it is the reference, then whether we match it.

SHA-256 of the three bytes 61 62 63 is the NIST known answer
ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad. That
judges the oracle. What follows has OpenSSL write a certificate, a PEM block,
a PKCS#8 key, a PKCS#12 file, a CRL and an OCSP response, and has this
library read them. The example programs are built by `make check-oracle` and
named in GCERT_*_BIN.

The primitives under these encodings are judged in `security`, against
OpenSSL and Wycheproof there. This file judges the encodings.
"""

import datetime
import ipaddress
import os
import shutil
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import compare
import oracle_env

HERE = os.path.dirname(os.path.abspath(__file__))
SHA256_ABC = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"

# Every implemented encoding with an outside judge. check_foundation
# requires this set to match primitives.txt. Each name is passed to saw()
# when that comparison actually runs, and finish() fails if one did not.
COVERED = (
    "der", "pem", "pkcs8", "x509", "crl", "ocsp", "pkcs12",
    "x509_verify", "ip", "chain", "key", "revocation",
)
SEEN = set()


def saw(*idents):
    SEEN.update(idents)


def finish():
    missing = [name for name in COVERED if name not in SEEN]
    extra = sorted(name for name in SEEN if name not in COVERED)
    if missing or extra:
        sys.stderr.write(
            "oracle coverage missing %s extra %s\n" % (missing, extra))
        return 1
    return 0


def last_field(text):
    parts = text.strip().split()
    if not parts:
        raise SystemExit("oracle produced no digest")
    return parts[-1]


def main():
    compare.self_test()
    sha = subprocess.run(
        oracle_env.command("openssl", ["openssl", "dgst", "-sha256"]),
        input=b"abc", capture_output=True)
    if sha.returncode != 0:
        sys.stderr.write(sha.stderr.decode("utf-8", "replace"))
        return 1
    got = last_field(sha.stdout.decode("utf-8", "replace"))
    if not compare.hex_equal(got, SHA256_ABC):
        sys.stderr.write(
            "openssl SHA-256(\"abc\") is %s, NIST says %s\n" % (got, SHA256_ABC))
        return 1
    print("sha256(abc) %s" % got)
    only = [n for n in os.environ.get("GCERT_ORACLE_ONLY", "").split(",") if n]
    if only:
        # A development aid: run just these comparisons. It never reports
        # success for the target, because coverage is not checked.
        known = {"names": diff_names, "chain": diff_chain,
                 "signature": diff_signature, "revocation": diff_revocation}
        for name in only:
            if known[name]() != 0:
                return 1
        sys.stderr.write("GCERT_ORACLE_ONLY: ran %s only; this is not a pass\n" % ",".join(only))
        return 3
    return diff_certs()


MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}


def openssl_unix(text):
    parts = text.split()
    if len(parts) != 5 or parts[4] != "GMT" or parts[0] not in MONTHS:
        raise ValueError(text)
    hour, minute, second = parts[2].split(":")
    moment = datetime.datetime(
        int(parts[3]), MONTHS[parts[0]], int(parts[1]),
        int(hour), int(minute), int(second),
        tzinfo=datetime.timezone.utc)
    return int(moment.timestamp())


def diff_certs():
    saw("der", "pem", "pkcs8", "x509")
    """OpenSSL writes a certificate, a PEM block, and a PKCS#8 key. This library reads them."""
    x509_bin = os.environ["GCERT_X509_BIN"]
    pem_bin = os.environ["GCERT_PEM_BIN"]
    pkcs8_bin = os.environ["GCERT_PKCS8_BIN"]
    der_bin = os.environ["GCERT_DER_BIN"]
    der_vec = os.path.join(oracle_env.ROOT, "tests", "data", "vectors", "der.vec")
    integer = None
    with open(der_vec, "r", encoding="utf-8") as handle:
        for line in handle:
            if line.startswith("hex "):
                integer = line.split()[1]
    if integer != "020101":
        sys.stderr.write("der.vec integer is %s\n" % integer)
        return 1
    parsed = subprocess.run([der_bin, integer], capture_output=True, text=True)
    shown = subprocess.run(oracle_env.command("openssl", [
        "openssl", "asn1parse", "-inform", "DER"]),
        input=bytes.fromhex(integer), capture_output=True)
    if parsed.returncode != 0 or parsed.stdout.strip() != "0 0 2":
        sys.stderr.write("der tag is %s\n" % parsed.stdout.strip())
        return 1
    asn = shown.stdout.decode("utf-8", "replace")
    if shown.returncode != 0 or "prim: INTEGER" not in asn:
        sys.stderr.write(asn)
        return 1
    print("der integer 0 0 2")

    kinds = (
        ("rsa", ["-newkey", "rsa:2048", "-sha256"]),
        ("p256", ["-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
            "-sha256"]),
        ("p384", ["-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:secp384r1",
            "-sha384"]),
        ("ed25519", ["-newkey", "ed25519"]),
    )
    config = (
        "[req]\n"
        "distinguished_name = dn\n"
        "x509_extensions = ext\n"
        "prompt = no\n"
        "[dn]\n"
        "CN = oracle\n"
        "[ext]\n"
        "basicConstraints = critical,CA:TRUE\n")
    for kind, arguments in kinds:
        scratch = tempfile.mkdtemp(prefix="gcert-cert-")
        try:
            cfg = os.path.join(scratch, "openssl.cnf")
            key = os.path.join(scratch, "key.pem")
            cert = os.path.join(scratch, "cert.pem")
            der = os.path.join(scratch, "cert.der")
            pkcs8 = os.path.join(scratch, "key.der")
            with open(cfg, "w", encoding="utf-8") as handle:
                handle.write(config)
            made = subprocess.run(oracle_env.command("openssl", [
                "openssl", "req", "-x509", "-nodes", "-days", "2",
                "-config", cfg, "-keyout", key, "-out", cert] + arguments,
                scratch=scratch), capture_output=True)
            if made.returncode != 0:
                sys.stderr.write(made.stderr.decode("utf-8", "replace"))
                return 1
            written = subprocess.run(oracle_env.command("openssl", [
                "openssl", "x509", "-in", cert, "-outform", "DER", "-out", der,
            ], scratch=scratch), capture_output=True)
            if written.returncode != 0:
                sys.stderr.write(written.stderr.decode("utf-8", "replace"))
                return 1
            dates = subprocess.run(oracle_env.command("openssl", [
                "openssl", "x509", "-in", der, "-inform", "DER",
                "-noout", "-startdate", "-enddate",
            ], scratch=scratch), capture_output=True, text=True)
            if dates.returncode != 0:
                sys.stderr.write(dates.stderr)
                return 1
            start = end = None
            for line in dates.stdout.splitlines():
                if line.startswith("notBefore="):
                    start = openssl_unix(line.split("=", 1)[1])
                elif line.startswith("notAfter="):
                    end = openssl_unix(line.split("=", 1)[1])
            viewed = subprocess.run([x509_bin, der], capture_output=True, text=True)
            fields = viewed.stdout.split()
            if viewed.returncode != 0 or fields != [kind, str(start), str(end)]:
                sys.stderr.write("x509 %s is %r, openssl says %s %s\n" % (
                    kind, viewed.stdout.strip(), start, end))
                return 1
            with open(cert, "rb") as handle:
                pem_text = handle.read()
            decoded = subprocess.run([pem_bin], input=pem_text, capture_output=True)
            with open(der, "rb") as handle:
                der_bytes = handle.read()
            if decoded.returncode != 0 or decoded.stdout != der_bytes:
                sys.stderr.write("pem %s did not match the DER\n" % kind)
                return 1
            exported = subprocess.run(oracle_env.command("openssl", [
                "openssl", "pkcs8", "-topk8", "-nocrypt", "-in", key,
                "-outform", "DER", "-out", pkcs8,
            ], scratch=scratch), capture_output=True)
            if exported.returncode != 0:
                sys.stderr.write(exported.stderr.decode("utf-8", "replace"))
                return 1
            named = subprocess.run([pkcs8_bin, pkcs8], capture_output=True, text=True)
            if named.returncode != 0 or named.stdout.strip() != kind:
                sys.stderr.write("pkcs8 %s is %r\n" % (kind, named.stdout.strip()))
                return 1
            tagged = subprocess.run(
                [der_bin, der_bytes.hex()], capture_output=True, text=True)
            if tagged.returncode != 0 or tagged.stdout.strip() != "0 1 16":
                sys.stderr.write("cert %s tag is %r\n" % (kind, tagged.stdout.strip()))
                return 1
            print("cert %s %s %s" % (kind, start, end))
        finally:
            shutil.rmtree(scratch)
    if diff_pkcs8_encrypted() != 0 or diff_pkcs12() != 0 \
            or diff_crl() != 0 or diff_ocsp() != 0 or diff_names() != 0 \
            or diff_chain() != 0 or diff_signature() != 0 or diff_revocation() != 0:
        return 1
    return finish()


def diff_pkcs8_encrypted():
    """OpenSSL encrypts a key. This library decrypts it and names the kind."""
    binary = os.environ["GCERT_PKCS8_BIN"]
    scratch = tempfile.mkdtemp(prefix="gcert-p8-")
    try:
        key = os.path.join(scratch, "key.pem")
        made = subprocess.run(oracle_env.command("openssl", [
            "openssl", "genpkey", "-algorithm", "EC",
            "-pkeyopt", "ec_paramgen_curve:prime256v1", "-out", key,
        ], scratch=scratch), capture_output=True)
        if made.returncode != 0:
            sys.stderr.write(made.stderr.decode("utf-8", "replace"))
            return 1
        schemes = (
            ("pbes2", ["-v2", "aes-256-cbc"]),
            ("pbes1", ["-provider", "legacy", "-provider", "default",
                "-v1", "PBE-SHA1-3DES"]),
        )
        for name, arguments in schemes:
            out = os.path.join(scratch, name + ".p8")
            written = subprocess.run(oracle_env.command("openssl", [
                "openssl", "pkcs8", "-topk8", "-in", key, "-outform", "DER",
                "-out", out, "-passout", "pass:secret"] + arguments,
                scratch=scratch), capture_output=True)
            if written.returncode != 0:
                sys.stderr.write(written.stderr.decode("utf-8", "replace"))
                return 1
            named = subprocess.run(
                [binary, "decrypt", "secret", out], capture_output=True, text=True)
            if named.returncode != 0 or named.stdout.strip() != "p256":
                sys.stderr.write("pkcs8 %s is %r\n" % (name, named.stdout.strip()))
                return 1
            print("pkcs8 %s p256" % name)
    finally:
        shutil.rmtree(scratch)
    return 0


def diff_pkcs12():
    saw("pkcs12")
    binary = os.environ["GCERT_PKCS12_BIN"]
    scratch = tempfile.mkdtemp(prefix="gcert-p12-")
    try:
        key = os.path.join(scratch, "key.pem")
        cert = os.path.join(scratch, "cert.pem")
        der = os.path.join(scratch, "cert.der")
        archive = os.path.join(scratch, "out.p12")
        made = subprocess.run(oracle_env.command("openssl", [
            "openssl", "req", "-x509", "-newkey", "ec",
            "-pkeyopt", "ec_paramgen_curve:prime256v1", "-keyout", key,
            "-out", cert, "-nodes", "-days", "2", "-subj", "/CN=oracle",
        ], scratch=scratch), capture_output=True)
        if made.returncode != 0:
            sys.stderr.write(made.stderr.decode("utf-8", "replace"))
            return 1
        written = subprocess.run(oracle_env.command("openssl", [
            "openssl", "x509", "-in", cert, "-outform", "DER", "-out", der,
        ], scratch=scratch), capture_output=True)
        if written.returncode != 0:
            sys.stderr.write(written.stderr.decode("utf-8", "replace"))
            return 1
        with open(der, "rb") as handle:
            cert_hex = handle.read().hex()
        exported = subprocess.run(oracle_env.command("openssl", [
            "openssl", "pkcs12", "-export", "-inkey", key, "-in", cert,
            "-out", archive, "-passout", "pass:secret",
            "-keypbe", "AES-256-CBC", "-certpbe", "AES-256-CBC",
        ], scratch=scratch), capture_output=True)
        if exported.returncode != 0:
            sys.stderr.write(exported.stderr.decode("utf-8", "replace"))
            return 1
        opened = subprocess.run(
            [binary, "secret", archive], capture_output=True, text=True)
        lines = opened.stdout.splitlines()
        if opened.returncode != 0 or len(lines) != 2 or lines[0] != "p256 1" \
                or not compare.hex_equal(lines[1], cert_hex):
            sys.stderr.write("pkcs12 is %r\n" % opened.stdout.strip())
            return 1
        print("pkcs12 p256 1")
    finally:
        shutil.rmtree(scratch)
    return 0


def diff_crl():
    saw("crl")
    binary = os.environ["GCERT_CRL_BIN"]
    scratch = tempfile.mkdtemp(prefix="gcert-crl-")
    try:
        key = os.path.join(scratch, "ca.key")
        cert = os.path.join(scratch, "ca.pem")
        der = os.path.join(scratch, "ca.der")
        crl_pem = os.path.join(scratch, "crl.pem")
        crl_der = os.path.join(scratch, "crl.der")
        config = os.path.join(scratch, "ca.cnf")
        made = subprocess.run(oracle_env.command("openssl", [
            "openssl", "req", "-x509", "-newkey", "ec",
            "-pkeyopt", "ec_paramgen_curve:prime256v1", "-keyout", key,
            "-out", cert, "-nodes", "-days", "2", "-subj", "/CN=ca",
        ], scratch=scratch), capture_output=True)
        if made.returncode != 0:
            sys.stderr.write(made.stderr.decode("utf-8", "replace"))
            return 1
        with open(config, "w", encoding="utf-8") as handle:
            handle.write(
                "[ca]\ndefault_ca = CA_default\n"
                "[CA_default]\ndatabase = %s\ncrlnumber = %s\n"
                "default_md = sha256\ndefault_crl_days = 1\n" % (
                    os.path.join(scratch, "index.txt"),
                    os.path.join(scratch, "crlnumber")))
        with open(os.path.join(scratch, "index.txt"), "w", encoding="utf-8") as handle:
            handle.write("R\t270101120000Z\t260101120000Z\t01\tunknown\t/CN=leaf\n")
        with open(os.path.join(scratch, "crlnumber"), "w", encoding="utf-8") as handle:
            handle.write("02\n")
        issued = subprocess.run(oracle_env.command("openssl", [
            "openssl", "ca", "-gencrl", "-config", config,
            "-keyfile", key, "-cert", cert, "-out", crl_pem,
        ], scratch=scratch), capture_output=True)
        if issued.returncode != 0:
            sys.stderr.write(issued.stderr.decode("utf-8", "replace"))
            return 1
        written = subprocess.run(oracle_env.command("openssl", [
            "openssl", "crl", "-in", crl_pem, "-outform", "DER", "-out", crl_der,
        ], scratch=scratch), capture_output=True)
        if written.returncode != 0:
            sys.stderr.write(written.stderr.decode("utf-8", "replace"))
            return 1
        shown = subprocess.run(oracle_env.command("openssl", [
            "openssl", "x509", "-in", cert, "-outform", "DER", "-out", der,
        ], scratch=scratch), capture_output=True)
        dated = subprocess.run(oracle_env.command("openssl", [
            "openssl", "crl", "-in", crl_der, "-inform", "DER",
            "-noout", "-lastupdate",
        ], scratch=scratch), capture_output=True, text=True)
        if shown.returncode != 0 or dated.returncode != 0:
            sys.stderr.write(dated.stderr)
            return 1
        stamp = openssl_unix(dated.stdout.split("=", 1)[1].strip())
        opened = subprocess.run(
            [binary, crl_der, der, "01"], capture_output=True, text=True)
        if opened.returncode != 0 or opened.stdout.strip() != "signed %s" % stamp:
            sys.stderr.write("crl is %r, openssl says %s\n" % (
                opened.stdout.strip(), stamp))
            return 1
        print("crl signed %s" % stamp)
    finally:
        shutil.rmtree(scratch)
    return 0


def diff_ocsp():
    saw("ocsp")
    binary = os.environ["GCERT_OCSP_BIN"]
    scratch = tempfile.mkdtemp(prefix="gcert-ocsp-")
    try:
        key = os.path.join(scratch, "ca.key")
        cert = os.path.join(scratch, "ca.pem")
        der = os.path.join(scratch, "ca.der")
        leaf_key = os.path.join(scratch, "leaf.key")
        leaf_csr = os.path.join(scratch, "leaf.csr")
        leaf = os.path.join(scratch, "leaf.pem")
        request = os.path.join(scratch, "req.der")
        response = os.path.join(scratch, "resp.der")
        made = subprocess.run(oracle_env.command("openssl", [
            "openssl", "req", "-x509", "-newkey", "ec",
            "-pkeyopt", "ec_paramgen_curve:prime256v1", "-keyout", key,
            "-out", cert, "-nodes", "-days", "2", "-subj", "/CN=ca",
        ], scratch=scratch), capture_output=True)
        if made.returncode != 0:
            sys.stderr.write(made.stderr.decode("utf-8", "replace"))
            return 1
        asked = subprocess.run(oracle_env.command("openssl", [
            "openssl", "req", "-newkey", "ec",
            "-pkeyopt", "ec_paramgen_curve:prime256v1", "-keyout", leaf_key,
            "-out", leaf_csr, "-nodes", "-subj", "/CN=leaf",
        ], scratch=scratch), capture_output=True)
        if asked.returncode != 0:
            sys.stderr.write(asked.stderr.decode("utf-8", "replace"))
            return 1
        signed = subprocess.run(oracle_env.command("openssl", [
            "openssl", "x509", "-req", "-in", leaf_csr, "-CA", cert,
            "-CAkey", key, "-set_serial", "01", "-out", leaf, "-days", "1",
        ], scratch=scratch), capture_output=True)
        if signed.returncode != 0:
            sys.stderr.write(signed.stderr.decode("utf-8", "replace"))
            return 1
        requested = subprocess.run(oracle_env.command("openssl", [
            "openssl", "ocsp", "-issuer", cert, "-cert", leaf,
            "-reqout", request, "-no_nonce",
        ], scratch=scratch), capture_output=True)
        if requested.returncode != 0:
            sys.stderr.write(requested.stderr.decode("utf-8", "replace"))
            return 1
        with open(os.path.join(scratch, "index.txt"), "w", encoding="utf-8") as handle:
            handle.write("R\t270101120000Z\t260101120000Z\t01\tunknown\t/CN=leaf\n")
        answered = subprocess.run(oracle_env.command("openssl", [
            "openssl", "ocsp", "-index", os.path.join(scratch, "index.txt"),
            "-CA", cert, "-rsigner", cert, "-rkey", key,
            "-reqin", request, "-respout", response, "-no_nonce",
        ], scratch=scratch), capture_output=True)
        if answered.returncode != 0:
            sys.stderr.write(answered.stderr.decode("utf-8", "replace"))
            return 1
        shown = subprocess.run(oracle_env.command("openssl", [
            "openssl", "x509", "-in", cert, "-outform", "DER", "-out", der,
        ], scratch=scratch), capture_output=True)
        text = subprocess.run(oracle_env.command("openssl", [
            "openssl", "ocsp", "-respin", response, "-text", "-noverify",
        ], scratch=scratch), capture_output=True, text=True)
        if shown.returncode != 0 or text.returncode != 0:
            sys.stderr.write(text.stderr)
            return 1
        when = None
        for line in text.stdout.splitlines():
            line = line.strip()
            if line.startswith("Revocation Time:"):
                when = openssl_unix(line.split(":", 1)[1].strip())
        if when is None:
            sys.stderr.write(text.stdout)
            return 1
        opened = subprocess.run(
            [binary, response, der, "01"], capture_output=True, text=True)
        if opened.returncode != 0 or opened.stdout.strip() != "revoked %s" % when:
            sys.stderr.write("ocsp is %r, openssl says %s\n" % (
                opened.stdout.strip(), when))
            return 1
        print("ocsp revoked %s" % when)
    finally:
        shutil.rmtree(scratch)
    return 0


# ---------------------------------------------------------------------------
# Names, chains, signatures and revocation: policy over the encodings above.
#
# Each comparison is a differential on a population this file makes, and each
# has a short list of *declared* differences: places where this library
# differs from the reference on purpose. A disagreement that is not on the
# list fails. A declared difference that stops happening also fails, because
# a list that no longer describes anything is how a rule gets silently dropped.
# ---------------------------------------------------------------------------



def ossl(args, scratch, stdin=None):
    return subprocess.run(
        oracle_env.command("openssl", ["openssl"] + args, scratch=scratch),
        input=stdin, capture_output=True)


def must(done, what):
    if done.returncode != 0:
        sys.stderr.write("%s failed:\n%s\n" % (
            what, done.stderr.decode("utf-8", "replace")))
        raise SystemExit(1)
    return done


def write(path, text):
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(text)


def to_der(scratch, pem, der):
    must(ossl(["x509", "-in", pem, "-outform", "DER", "-out", der], scratch),
         "x509 -outform DER")


class Declared:
    """Counts of agreements and of each declared difference."""

    def __init__(self, label, allowed):
        self.label = label
        self.allowed = dict(allowed)
        self.seen = {name: 0 for name in allowed}
        self.agreed = 0

    def agree(self):
        self.agreed += 1

    def differ(self, name, detail):
        if name not in self.allowed:
            sys.stderr.write("%s: undeclared difference (%s): %s\n" % (
                self.label, name, detail))
            raise SystemExit(1)
        self.seen[name] += 1

    def finish(self):
        for name, count in self.seen.items():
            if count == 0:
                sys.stderr.write(
                    "%s: declared difference %r never happened; remove it "
                    "from the list or find out why\n" % (self.label, name))
                raise SystemExit(1)
        print("%s: %d agree%s" % (
            self.label, self.agreed,
            "".join(", %s x%d" % (k, v) for k, v in self.seen.items())))


def diff_names():
    saw("x509_verify", "ip")
    binary = os.environ["GCERT_NAMES_BIN"]
    scratch = tempfile.mkdtemp(prefix="gcert-names-")
    try:
        key = os.path.join(scratch, "k.pem")
        must(ossl(["genpkey", "-algorithm", "EC", "-pkeyopt",
                   "ec_paramgen_curve:P-256", "-out", key], scratch), "genpkey")
        certs = {}

        def make(name, subject, san):
            pem = os.path.join(scratch, name + ".pem")
            der = os.path.join(scratch, name + ".der")
            args = ["req", "-x509", "-key", key, "-subj", subject, "-days", "2",
                    "-out", pem]
            if san:
                args += ["-addext", "subjectAltName=" + san]
            must(ossl(args, scratch), "req " + name)
            to_der(scratch, pem, der)
            certs[name] = (pem, der)

        make("dns", "/CN=ignored.example",
             "DNS:www.example.com,DNS:*.wild.example.org,DNS:exact.example.net,"
             "DNS:UPPER.Example.COM")
        make("weak", "/CN=x", "DNS:*.com,DNS:f*.partial.example,DNS:*.co.uk,"
             "DNS:*.*.example.org,DNS:*.example.net")
        make("addr", "/CN=x", "IP:192.0.2.1,IP:2001:db8::1,email:Alice@Example.com,"
             "URI:spiffe://example.org/web,DNS:host.example")
        make("cn", "/CN=cn.example.com", None)

        declared = Declared("names", {
            "partial wildcard": "OpenSSL matches f*.example, RFC 9525 does not",
            "absolute name": "a reference with a trailing dot is the same name here; OpenSSL refuses it",
        })

        def theirs(kind, cert, value):
            flag = {"dns": "-checkhost", "ip": "-checkip", "email": "-checkemail"}[kind]
            done = ossl(["x509", "-in", certs[cert][0], "-noout", flag, value], scratch)
            text = done.stdout.decode("utf-8", "replace")
            if "does match" in text:
                return True
            if "does NOT match" in text:
                return False
            sys.stderr.write("names: cannot read OpenSSL's answer %r\n" % text)
            raise SystemExit(1)

        def ours(kind, cert, value, extra=()):
            done = subprocess.run([binary, certs[cert][1], kind, value] + list(extra),
                                  capture_output=True, text=True)
            if done.returncode == 3:
                sys.stderr.write("names: %s\n" % done.stderr)
                raise SystemExit(1)
            return done.returncode == 0

        def compare(kind, cert, value, extra=(), why=None, lenient=None):
            a = ours(kind, cert, value, extra)
            b = theirs(kind, cert, value)
            if a == b:
                declared.agree()
            elif why is not None and b and not a:
                declared.differ(why, "%s %s %s" % (kind, cert, value))
            elif lenient is not None and a and not b:
                declared.differ(lenient, "%s %s %s" % (kind, cert, value))
            else:
                sys.stderr.write("names: %s %s %r: this library %s, OpenSSL %s\n" % (
                    kind, cert, value, a, b))
                raise SystemExit(1)

        cn = ("0", "cn")
        compare("dns", "dns", "www.example.com.", cn, lenient="absolute name")
        for host in ("www.example.com", "WWW.EXAMPLE.COM",
                     "example.com", "a.www.example.com", "x.wild.example.org",
                     "wild.example.org", "a.b.wild.example.org", "exact.example.net",
                     "exact.example.org", "upper.example.com", "UPPER.EXAMPLE.COM",
                     "ignored.example", "xwww.example.com",
                     "www.example.com.evil.example", "www-example.com"):
            compare("dns", "dns", host, cn)
        for host in ("ignored.example", "cn.example.com", "CN.Example.Com",
                     "other.example.com", "x.cn.example.com"):
            compare("dns", "cn", host, cn)
        for host in ("example.com", "foo.example.org", "x.y.example.org", "a.co.uk",
                     "foo.example.net", "example.net", "a.b.example.net"):
            compare("dns", "weak", host, cn)
        for host in ("foo.partial.example", "fxx.partial.example"):
            compare("dns", "weak", host, cn, why="partial wildcard")
        for value in ("192.0.2.1", "192.0.2.2", "192.0.2.10", "2001:db8::1",
                      "2001:0db8:0:0:0:0:0:1", "2001:DB8::1", "::1", "2001:db8::2",
                      "10.0.0.1"):
            compare("ip", "addr", value)
        for value in ("Alice@Example.com", "Alice@example.com", "Alice@EXAMPLE.COM",
                      "alice@example.com", "bob@example.com", "Alice@Example.org"):
            compare("email", "addr", value)
        declared.finish()

        # The address parser, against Python's. OpenSSL's command line says
        # "does match" for text it cannot parse (it prints the result of a
        # function that returns -1 for an error), so it cannot judge this half.
        zone = Declared("ip parse", {
            "zone id": "Python reads fe80::1%eth0; a certificate has no use for one",
        })
        texts = [
            "0.0.0.0", "255.255.255.255", "1.2.3.4", "192.0.2.1", "1.2.3", "1.2.3.4.5",
            "1.2.3.256", "01.2.3.4", "1.2.3.04", "1..2.3", ".1.2.3", "1.2.3.", "a.b.c.d",
            "0x1.2.3.4", "1.2.3.4/8", " 1.2.3.4", "1.2.3.4 ", "",
            "::", "::1", "1::", "1::2", "2001:db8::ff00:42:8329",
            "2001:0db8:0000:0000:0000:ff00:0042:8329", "::ffff:192.0.2.1", "::192.0.2.1",
            "1:2:3:4:5:6:7:8", "1:2:3:4:5:6:7::", "::2:3:4:5:6:7:8", "1:2:3:4:5:6:1.2.3.4",
            "1:2:3:4:5:6:7", "1:2:3:4:5:6:7:8:9", ":", ":::", "1::2::3", "12345::",
            "g::", ":1:2:3:4:5:6:7", "1:2:3:4:5:6:7:", "1::2:", "::1.2.3", "::1.2.3.4:5",
            "[::1]", "1:2:3:4:5:6:7:1.2.3.4", "::01.2.3.4", "1:2:3:4:5:6:7:8::",
            "::ffff:1.2.3.256", "FE80::1", "fe80::1%eth0", "1:2:3:4:5:6:7:8%1",
        ]
        for text in texts:
            done = subprocess.run([binary, certs["dns"][1], "ipparse", text],
                                  capture_output=True, text=True)
            got = done.stdout.strip()
            try:
                want = ipaddress.ip_address(text).packed.hex()
            except ValueError:
                want = "invalid"
            if got == want:
                zone.agree()
            elif "%" in text and want != "invalid" and got == "invalid":
                zone.differ("zone id", text)
            else:
                sys.stderr.write("ip parse %r: this library %r, Python %r\n" % (
                    text, got, want))
                raise SystemExit(1)
        zone.finish()
    finally:
        shutil.rmtree(scratch, ignore_errors=True)
    return 0


class Pki:
    """A scratch directory of certificates made with the reference."""

    def __init__(self, scratch):
        self.dir = scratch
        self.serial = 100
        self.certs = {}

    def path(self, name, ext):
        return os.path.join(self.dir, "%s.%s" % (name, ext))

    def key(self, name, algo="ec"):
        args = {
            "ec": ["-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256"],
            "rsa1024": ["-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:1024"],
            "rsa2048": ["-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048"],
        }[algo]
        must(ossl(["genpkey"] + args + ["-out", self.path(name, "key")], self.dir),
             "genpkey " + name)

    def cert(self, name, subject, signer=None, ca=False, pathlen=None, eku=None,
             nc=None, days=3650, algo="ec", digest="sha256", san=None, key_of=None):
        """Issue `name`. `signer` is another name, or None for self-signed.
        `key_of` reuses another certificate's key (a reissue)."""
        keyname = key_of or name
        if key_of is None:
            self.key(name, algo)
        lines = ["[ext]"]
        if ca:
            lines.append("basicConstraints = critical,CA:TRUE" +
                         (",pathlen:%d" % pathlen if pathlen is not None else ""))
            lines.append("keyUsage = critical,keyCertSign,cRLSign")
        else:
            lines.append("basicConstraints = critical,CA:FALSE")
        if eku:
            lines.append("extendedKeyUsage = " + eku)
        if san:
            lines.append("subjectAltName = " + san)
        if nc:
            lines.append("nameConstraints = critical," + nc)
        lines.append("subjectKeyIdentifier = hash")
        if signer:
            lines.append("authorityKeyIdentifier = keyid")
        write(self.path(name, "cnf"), "\n".join(lines) + "\n")
        must(ossl(["req", "-new", "-key", self.path(keyname, "key"), "-subj", subject,
                   "-out", self.path(name, "csr")], self.dir), "req " + name)
        self.serial += 1
        if signer:
            args = ["x509", "-req", "-in", self.path(name, "csr"),
                    "-CA", self.path(signer, "pem"), "-CAkey", self.path(signer, "key"),
                    "-set_serial", str(self.serial)]
        else:
            args = ["x509", "-req", "-in", self.path(name, "csr"),
                    "-signkey", self.path(keyname, "key"),
                    "-set_serial", str(self.serial)]
        args += ["-days", str(days), "-" + digest, "-extfile", self.path(name, "cnf"),
                 "-extensions", "ext", "-out", self.path(name, "pem")]
        must(ossl(args, self.dir), "x509 -req " + name)
        to_der(self.dir, self.path(name, "pem"), self.path(name, "der"))
        # For a reissue the key file is the original's.
        if key_of is not None:
            shutil.copy(self.path(key_of, "key"), self.path(name, "key"))
        return name

    def bundle(self, name, members):
        with open(self.path(name, "pem"), "w", encoding="utf-8") as out:
            for member in members:
                with open(self.path(member, "pem"), "r", encoding="utf-8") as one:
                    out.write(one.read())
        return self.path(name, "pem")


def diff_chain():
    saw("chain")
    binary = os.environ["GCERT_CHAIN_BIN"]
    scratch = tempfile.mkdtemp(prefix="gcert-chain-")
    try:
        pki = Pki(scratch)
        now = int(time.time())
        pki.cert("root", "/CN=root", ca=True)
        pki.cert("i1", "/CN=i1", "root", ca=True)
        pki.cert("i2", "/CN=i2", "i1", ca=True)
        pki.cert("leaf", "/CN=leaf", "i2", san="DNS:leaf.example.org")
        pki.cert("stray_root", "/CN=stray", ca=True)
        pki.cert("stray", "/CN=stray-sub", "stray_root", ca=True)
        pki.cert("other_root", "/CN=other-root", ca=True)
        # A re-issue of i1 that has already expired by the time we ask, and one
        # that is good, both with i1's key and name.
        pki.cert("i1_old", "/CN=i1", "root", ca=True, days=1, key_of="i1")
        pki.cert("i1_new", "/CN=i1", "root", ca=True, key_of="i1")
        # i1 signed by a second root: a cross-signature.
        pki.cert("root2", "/CN=root2", ca=True)
        pki.cert("i1_x", "/CN=i1", "root2", ca=True, key_of="i1")
        # A CA that forbids a CA below it, and a chain that has one.
        pki.cert("pl1", "/CN=pl1", "root", ca=True, pathlen=0)
        pki.cert("pl2", "/CN=pl2", "pl1", ca=True)
        pki.cert("pl_leaf", "/CN=pl-leaf", "pl2")
        # Name constraints.
        pki.cert("nc1", "/CN=nc1", "root", ca=True, nc="permitted;DNS:example.org")
        pki.cert("nc_ok", "/CN=nc-ok", "nc1", san="DNS:www.example.org")
        pki.cert("nc_bad", "/CN=nc-bad", "nc1", san="DNS:www.evil.example")
        # Purposes.
        pki.cert("eku_client", "/CN=eku-client", "i2", eku="clientAuth")
        pki.cert("eku_server", "/CN=eku-server", "i2", eku="serverAuth")
        # A signer that is not a CA.
        pki.cert("notca", "/CN=notca", "root")
        pki.cert("notca_leaf", "/CN=notca-leaf", "notca")
        # Impostor: i2's name, another key.
        pki.cert("i2_fake", "/CN=i2", "i1", ca=True)
        # A root that has expired, and a leaf under it.
        pki.cert("dead_root", "/CN=dead", ca=True, days=1)
        pki.cert("dead_leaf", "/CN=dead-leaf", "dead_root")
        # Weak: a 1024-bit RSA intermediate, and a SHA-1 one.
        pki.cert("rsa_root", "/CN=rsa-root", ca=True, algo="rsa2048")
        pki.cert("rsa_weak", "/CN=rsa-weak", "rsa_root", ca=True, algo="rsa1024")
        pki.cert("rsa_weak_leaf", "/CN=rsa-weak-leaf", "rsa_weak")
        pki.cert("sha1_i", "/CN=sha1-i", "rsa_root", ca=True, algo="rsa2048", digest="sha1")
        pki.cert("sha1_leaf", "/CN=sha1-leaf", "sha1_i")

        declared = Declared("chain", {
            "weak RSA key": "OpenSSL accepts a 1024-bit key at its default level; this library requires 2048",
            "SHA-1 signature": "OpenSSL accepts a SHA-1 link at its default level; this library refuses it",
            "alternative issuer": "OpenSSL takes the first issuer of that name and does not go back; this library tries the others",
        })

        def run_ours(anchors, leaf, pool, t, purpose):
            args = [binary, str(t), purpose, pki.bundle("anchors", anchors),
                    pki.path(leaf, "der")] + [pki.path(p, "der") for p in pool]
            done = subprocess.run(args, capture_output=True, text=True)
            if done.returncode == 2:
                sys.stderr.write("chain: %s\n" % done.stderr)
                raise SystemExit(1)
            return done.returncode == 0, done.stdout.strip()

        def run_theirs(anchors, leaf, pool, t, purpose, partial):
            args = ["verify", "-attime", str(t), "-no-CApath", "-no-CAstore",
                    "-CAfile", pki.bundle("anchors", anchors)]
            if pool:
                args += ["-untrusted", pki.bundle("pool", pool)]
            if purpose != "0":
                args += ["-purpose", "ssl" + purpose]
            if partial:
                args += ["-partial_chain"]
            args += [pki.path(leaf, "pem")]
            done = ossl(args, scratch)
            return done.returncode == 0, (done.stdout + done.stderr).decode("utf-8", "replace")

        def case(label, anchors, leaf, pool, t=None, purpose="0", partial=False, why=None,
                 expect=None, lenient=None):
            t = t if t is not None else now + 60
            a, a_text = run_ours(anchors, leaf, pool, t, purpose)
            b, b_text = run_theirs(anchors, leaf, pool, t, purpose, partial)
            if expect is not None and (a != expect or b != expect):
                sys.stderr.write("chain %s: expected %s, this library %s (%s), OpenSSL %s (%s)\n" % (
                    label, expect, a, a_text, b, b_text.strip()))
                raise SystemExit(1)
            if a == b:
                declared.agree()
            elif why is not None and b and not a:
                declared.differ(why, label)
            elif lenient is not None and a and not b:
                declared.differ(lenient, label)
            else:
                sys.stderr.write("chain %s: this library %s (%s), OpenSSL %s (%s)\n" % (
                    label, a, a_text, b, b_text.strip()))
                raise SystemExit(1)

        later = now + 10 * 86400
        case("in order", ["root"], "leaf", ["i2", "i1"], expect=True)
        case("reversed", ["root"], "leaf", ["i1", "i2"], expect=True)
        case("with extras", ["root"], "leaf", ["stray", "i1", "stray_root", "i2", "i1"], expect=True)
        case("root in the pool only", [], "leaf", ["i2", "i1", "root"], expect=False)
        case("missing intermediate", ["root"], "leaf", ["i2"], expect=False)
        case("no pool", ["root"], "leaf", [], expect=False)
        case("an intermediate as the anchor", ["i1"], "leaf", ["i2"], partial=True, expect=True)
        case("unknown root", ["other_root"], "leaf", ["i2", "i1", "root"], expect=False)
        case("expired reissue only", ["root"], "leaf", ["i2", "i1_old"], t=later, expect=False)
        case("expired reissue beside a good one", ["root"], "leaf", ["i2", "i1_old", "i1_new"],
             t=later, expect=True)
        case("good one first, then the expired", ["root"], "leaf", ["i2", "i1_new", "i1_old"],
             t=later, expect=True)
        case("cross-signed, the usable one first", ["root2"], "leaf", ["i2", "i1_x", "i1"],
             expect=True)
        case("cross-signed, the usable one last", ["root2"], "leaf", ["i2", "i1", "i1_x"],
             lenient="alternative issuer")
        case("cross-signed, only the unknown one", ["root2"], "leaf", ["i2", "i1"], expect=False)
        case("pathlen 0 with a CA below", ["root"], "pl_leaf", ["pl2", "pl1"], expect=False)
        case("name constraint, permitted", ["root"], "nc_ok", ["nc1"], expect=True)
        case("name constraint, excluded", ["root"], "nc_bad", ["nc1"], expect=False)
        case("client auth, asked for server", ["root"], "eku_client", ["i2", "i1"],
             purpose="server", expect=False)
        case("client auth, asked for client", ["root"], "eku_client", ["i2", "i1"],
             purpose="client", expect=True)
        case("server auth, asked for server", ["root"], "eku_server", ["i2", "i1"],
             purpose="server", expect=True)
        case("no extended key usage, asked for server", ["root"], "leaf", ["i2", "i1"],
             purpose="server", expect=True)
        case("a signer that is not a CA", ["root"], "notca_leaf", ["notca"], expect=False)
        case("an impostor with the right name", ["root"], "leaf", ["i2_fake", "i1"], expect=False)
        case("an impostor beside the real one", ["root"], "leaf", ["i2_fake", "i1", "i2"],
             expect=True)
        case("leaf not yet valid", ["root"], "leaf", ["i2", "i1"], t=now - 86400, expect=False)
        case("leaf long expired", ["root"], "leaf", ["i2", "i1"], t=now + 4000 * 86400,
             expect=False)
        case("expired anchor", ["dead_root"], "dead_leaf", [], t=later, expect=False)
        case("a live anchor", ["dead_root"], "dead_leaf", [], t=now + 60, expect=True)
        case("1024-bit RSA intermediate", ["rsa_root"], "rsa_weak_leaf", ["rsa_weak"],
             why="weak RSA key")
        case("SHA-1 intermediate", ["rsa_root"], "sha1_leaf", ["sha1_i"], why="SHA-1 signature")
        declared.finish()
    finally:
        shutil.rmtree(scratch, ignore_errors=True)
    return 0


def diff_signature():
    saw("key")
    binary = os.environ["GCERT_SIGNATURE_BIN"]
    scratch = tempfile.mkdtemp(prefix="gcert-sig-")
    try:
        message = os.path.join(scratch, "msg")
        with open(message, "wb") as handle:
            handle.write(os.urandom(777))
        kinds = (
            ("rsa", ["-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048"], "sha256",
             [("rsa-pkcs1-sha256", "sha256", []), ("rsa-pkcs1-sha384", "sha384", []),
              ("rsa-pkcs1-sha512", "sha512", []),
              ("rsa-pss-sha256", "sha256", "pss"), ("rsa-pss-sha384", "sha384", "pss"),
              ("rsa-pss-sha512", "sha512", "pss")]),
            ("p256", ["-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256"], "sha256",
             [("ecdsa-p256-sha256", "sha256", [])]),
            ("p384", ["-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-384"], "sha384",
             [("ecdsa-p384-sha384", "sha384", [])]),
            ("ed25519", ["-algorithm", "ED25519"], "sha256", [("ed25519", None, [])]),
        )

        def pss(digest):
            return ["-sigopt", "rsa_padding_mode:pss", "-sigopt", "rsa_pss_saltlen:digest",
                    "-sigopt", "rsa_mgf1_md:" + digest]

        count = 0
        for name, genargs, cert_digest, schemes in kinds:
            key = os.path.join(scratch, name + ".key")
            pub = os.path.join(scratch, name + ".pub")
            cert = os.path.join(scratch, name + ".pem")
            der = os.path.join(scratch, name + ".der")
            must(ossl(["genpkey"] + genargs + ["-out", key], scratch), "genpkey " + name)
            must(ossl(["pkey", "-in", key, "-pubout", "-out", pub], scratch), "pkey")
            must(ossl(["req", "-x509", "-key", key, "-subj", "/CN=" + name, "-days", "2",
                       "-out", cert] + ([] if name == "ed25519" else ["-" + cert_digest]),
                      scratch), "req " + name)
            to_der(scratch, cert, der)
            for scheme, digest, mode in schemes:
                opts = pss(digest) if mode == "pss" else []
                # Ours signs; the reference verifies.
                sig = os.path.join(scratch, "ours.sig")
                done = subprocess.run([binary, "sign", key, scheme, message, sig],
                                      capture_output=True)
                if done.returncode != 0:
                    sys.stderr.write("signature sign %s: %s\n" % (scheme, done.stderr.decode()))
                    raise SystemExit(1)

                def theirs_verify(path):
                    if digest is None:
                        return ossl(["pkeyutl", "-verify", "-pubin", "-inkey", pub, "-rawin",
                                     "-in", message, "-sigfile", path], scratch)
                    return ossl(["dgst", "-" + digest, "-verify", pub, "-signature", path]
                                + opts + [message], scratch)

                if theirs_verify(sig).returncode != 0:
                    sys.stderr.write("signature: OpenSSL does not verify what this library signed (%s)\n"
                                     % scheme)
                    raise SystemExit(1)
                with open(sig, "rb") as handle:
                    raw = bytearray(handle.read())
                raw[-1] ^= 1
                tampered = os.path.join(scratch, "tampered.sig")
                with open(tampered, "wb") as handle:
                    handle.write(raw)
                if theirs_verify(tampered).returncode == 0:
                    sys.stderr.write("signature: OpenSSL accepts a damaged signature (%s)\n" % scheme)
                    raise SystemExit(1)
                if subprocess.run([binary, "verify", der, scheme, message, tampered],
                                  capture_output=True).returncode == 0:
                    sys.stderr.write("signature: this library accepts a damaged signature (%s)\n"
                                     % scheme)
                    raise SystemExit(1)
                # The reference signs; ours verifies.
                theirs_sig = os.path.join(scratch, "theirs.sig")
                if digest is None:
                    made = ossl(["pkeyutl", "-sign", "-inkey", key, "-rawin", "-in", message,
                                 "-out", theirs_sig], scratch)
                else:
                    made = ossl(["dgst", "-" + digest, "-sign", key, "-out", theirs_sig]
                                + opts + [message], scratch)
                must(made, "reference signs " + scheme)
                checked = subprocess.run([binary, "verify", der, scheme, message, theirs_sig],
                                         capture_output=True, text=True)
                if checked.returncode != 0:
                    sys.stderr.write("signature: this library does not verify OpenSSL's %s\n"
                                     % scheme)
                    raise SystemExit(1)
                count += 1
        print("signature: %d schemes agree in both directions, a damaged signature refused by both"
              % count)
    finally:
        shutil.rmtree(scratch, ignore_errors=True)
    return 0


def diff_revocation():
    saw("revocation")
    binary = os.environ["GCERT_REVOKE_BIN"]
    scratch = tempfile.mkdtemp(prefix="gcert-revoke-")
    try:
        pki = Pki(scratch)
        pki.cert("ca", "/CN=rev-ca", ca=True, algo="rsa2048")
        pki.cert("good", "/CN=rev-good", "ca", algo="rsa2048")
        pki.cert("revoked", "/CN=rev-revoked", "ca", algo="rsa2048")
        pki.cert("unknown", "/CN=rev-unknown", "ca", algo="rsa2048")
        pki.cert("responder", "/CN=rev-responder", "ca", algo="rsa2048", eku="OCSPSigning")
        pki.cert("plain", "/CN=rev-plain", "ca", algo="rsa2048")
        pki.cert("other", "/CN=rev-ca", ca=True, algo="rsa2048")
        pki.cert("foreign", "/CN=rev-foreign", "other", algo="rsa2048", eku="OCSPSigning")
        # The CA's database: good and revoked are in it, unknown is not.
        db = os.path.join(scratch, "index.txt")
        write(db, "")
        write(os.path.join(scratch, "crlnumber"), "01\n")
        config = os.path.join(scratch, "revca.cnf")
        write(config,
              "[ca]\ndefault_ca = c\n[c]\ndatabase = %s\ncrlnumber = %s\ndefault_md = sha256\n"
              "default_crl_days = 30\n" % (db, os.path.join(scratch, "crlnumber")))

        def serial_of(name):
            done = must(ossl(["x509", "-in", pki.path(name, "pem"), "-noout", "-serial"],
                             scratch), "serial")
            return done.stdout.decode().strip().split("=")[1]

        stamp = "270101120000Z"
        write(db, "V\t%s\t\t%s\tunknown\t/CN=rev-good\nR\t%s\t260101120000Z\t%s\tunknown\t/CN=rev-revoked\n"
              % (stamp, serial_of("good"), stamp, serial_of("revoked")))
        must(ossl(["ca", "-config", config, "-keyfile", pki.path("ca", "key"), "-cert", pki.path("ca", "pem"),
                   "-gencrl", "-out", pki.path("crl", "pem")], scratch), "ca -gencrl")
        must(ossl(["crl", "-in", pki.path("crl", "pem"), "-outform", "DER", "-out",
                   pki.path("crl", "der")], scratch), "crl der")
        now = int(time.time())

        # CRL: the reference's verdict is `openssl verify -crl_check`.
        declared = Declared("revocation", {})

        def crl_theirs(leaf, crl_pem):
            done = ossl(["verify", "-crl_check", "-no-CApath", "-no-CAstore", "-CAfile",
                         pki.path("ca", "pem"), "-CRLfile", crl_pem, pki.path(leaf, "pem")],
                        scratch)
            text = (done.stdout + done.stderr).decode()
            if done.returncode == 0:
                return "good"
            if "certificate revoked" in text:
                return "revoked"
            return "unusable"

        def crl_ours(leaf, crl_der):
            done = subprocess.run([binary, "crl", crl_der, pki.path("ca", "der"),
                                   pki.path(leaf, "der"), str(now)], capture_output=True,
                                  text=True)
            if done.returncode == 3:
                sys.stderr.write("revoke: %s\n" % done.stderr)
                raise SystemExit(1)
            return done.stdout.split()[0]

        tampered_der = pki.path("crl_bad", "der")
        with open(pki.path("crl", "der"), "rb") as handle:
            raw = bytearray(handle.read())
        raw[-2] ^= 1
        with open(tampered_der, "wb") as handle:
            handle.write(raw)
        for leaf in ("good", "revoked"):
            a = crl_ours(leaf, pki.path("crl", "der"))
            b = crl_theirs(leaf, pki.path("crl", "pem"))
            if a != b:
                sys.stderr.write("crl %s: this library %s, OpenSSL %s\n" % (leaf, a, b))
                raise SystemExit(1)
            declared.agree()
        # A damaged list is not evidence of anything: the good leaf is not
        # called good on its strength.
        if crl_ours("good", tampered_der) != "unusable":
            sys.stderr.write("crl: a damaged list was believed\n")
            raise SystemExit(1)
        declared.agree()

        # OCSP, against `openssl ocsp`.
        def respond(name, leaf, signer, extra=()):
            req = pki.path(name, "req")
            must(ossl(["ocsp", "-sha256", "-issuer", pki.path("ca", "pem"), "-cert",
                       pki.path(leaf, "pem"), "-reqout", req], scratch), "ocsp req")
            must(ossl(["ocsp", "-index", db, "-CA", pki.path("ca", "pem"), "-rsigner",
                       pki.path(signer, "pem"), "-rkey", pki.path(signer, "key"),
                       "-reqin", req, "-respout", pki.path(name, "resp"), "-ndays", "7"]
                      + list(extra), scratch), "ocsp respond " + name)
            return pki.path(name, "resp")

        def ocsp_theirs(resp, leaf, verify_other=None):
            args = ["ocsp", "-respin", resp, "-sha256", "-issuer", pki.path("ca", "pem"), "-cert",
                    pki.path(leaf, "pem"), "-CAfile", pki.path("ca", "pem"), "-no_nonce"]
            if verify_other:
                args += ["-verify_other", pki.path(verify_other, "pem")]
            done = ossl(args, scratch)
            text = (done.stdout + done.stderr).decode()
            if "Response verify OK" not in text:
                return "unusable"
            for word in ("good", "revoked"):
                if (".pem: %s" % word) in text:
                    return word
            return "unusable"        # unknown, or nothing it recognises

        def ocsp_ours(resp_path, leaf, responder=None):
            der = resp_path + ".der"
            shutil.copy(resp_path, der)
            args = [binary, "ocsp", der, pki.path("ca", "der"), pki.path(leaf, "der"), str(now)]
            if responder:
                args.append(pki.path(responder, "der"))
            done = subprocess.run(args, capture_output=True, text=True)
            if done.returncode == 3:
                sys.stderr.write("revoke: %s\n" % done.stderr)
                raise SystemExit(1)
            return done.stdout.split()[0]

        cases = [
            ("good by the CA", "good", "ca", None, None, "good"),
            ("revoked by the CA", "revoked", "ca", None, None, "revoked"),
            ("unknown to the CA", "unknown", "ca", None, None, "unusable"),
            ("good by a delegated responder", "good", "responder", None, "responder", "good"),
            ("a responder with no OCSP signing", "good", "plain", None, "plain", "unusable"),
            ("signed by another CA of the same name", "good", "other", None, None, "unusable"),
            ("a responder another CA issued", "good", "foreign", None, "foreign", "unusable"),
        ]
        for index, (label, leaf, signer, _x, other, want) in enumerate(cases):
            name = "resp%d" % index
            extra = ["-resp_no_certs"] if signer != "ca" else []
            resp = respond(name, leaf, signer, extra)
            a = ocsp_ours(resp, leaf, other)
            b = ocsp_theirs(resp, leaf, other)
            if a != b or a != want:
                sys.stderr.write("ocsp %s: this library %s, OpenSSL %s, expected %s\n"
                                 % (label, a, b, want))
                raise SystemExit(1)
            declared.agree()
        declared.finish()
    finally:
        shutil.rmtree(scratch, ignore_errors=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
