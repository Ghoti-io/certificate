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
import os
import shutil
import subprocess
import sys
import tempfile

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
            or diff_crl() != 0 or diff_ocsp() != 0:
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


if __name__ == "__main__":
    sys.exit(main())
