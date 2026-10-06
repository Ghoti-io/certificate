/**
 * @file
 *
 * Loading private keys and signing and verifying by scheme (key.h), against
 * keys and signatures OpenSSL wrote (tools/make-key-fixtures.sh).
 *
 * Copyright 2026 by Corey Pennycuff
 */

#include "test_helpers.h"

#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <string>
#include <vector>

namespace {

typedef std::vector<unsigned char> Bytes;

Bytes load(const std::string & name) {
  std::ifstream in(gsectest::data_dir() + "/keys/" + name, std::ios::binary);
  EXPECT_TRUE(in.good()) << name;
  return Bytes(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
}

struct Case {
  const char * name;
  uint32_t kind;
  struct S {
    GCERT_SigScheme scheme;
    const char * file;
  } schemes[4];
};

const Case kCases[] = {
  {"rsa", GCERT_X509_RSA, {
    {GCERT_SIG_RSA_PKCS1_SHA256, "rsa.pkcs1-sha256.sig"},
    {GCERT_SIG_RSA_PKCS1_SHA384, "rsa.pkcs1-sha384.sig"},
    {GCERT_SIG_RSA_PKCS1_SHA512, "rsa.pkcs1-sha512.sig"},
    {GCERT_SIG_RSA_PSS_SHA256, "rsa.pss-sha256.sig"}}},
  {"p256", GCERT_X509_P256, {{GCERT_SIG_ECDSA_P256_SHA256, "p256.ecdsa-sha256.sig"}}},
  {"p384", GCERT_X509_P384, {{GCERT_SIG_ECDSA_P384_SHA384, "p384.ecdsa-sha384.sig"}}},
  {"ed25519", GCERT_X509_ED25519, {{GCERT_SIG_ED25519, "ed25519.ed25519.sig"}}},
};

struct Loaded {
  GCERT_Key * key = nullptr;
  Bytes cert_der;
  GCERT_X509 cert;
  ~Loaded() { gcert_key_free(key); }
};

void load_case(const Case & c, const std::string & pem_name, Loaded * l) {
  Bytes pem = load(pem_name);
  ASSERT_EQ(gcert_key_from_pem(nullptr, pem.data(), pem.size(), nullptr, 0, nullptr,
      &l->key), GCERT_OK) << pem_name;
  l->cert_der = load(std::string(c.name) + ".cert.der");
  ASSERT_EQ(gcert_x509_parse(l->cert_der.data(), l->cert_der.size(), &l->cert), GCERT_OK);
}

} /* namespace */

TEST(Key, LoadsEveryKindAndMatchesItsCertificate) {
  for (const Case & c : kCases) {
    Loaded l;
    load_case(c, std::string(c.name) + ".pk8.pem", &l);
    EXPECT_EQ(gcert_key_kind(l.key), c.kind) << c.name;
    EXPECT_EQ(gcert_key_matches(l.key, &l.cert), GCERT_OK) << c.name;
  }
  EXPECT_EQ(gcert_key_kind(nullptr), 0u);
  gcert_key_free(nullptr);
}

TEST(Key, ALegacyFileIsTheSameKey) {
  for (const char * name : {"rsa", "p256", "p384"}) {
    const Case * c = nullptr;
    for (const Case & k : kCases) {
      if (std::strcmp(k.name, name) == 0) {
        c = &k;
      }
    }
    ASSERT_NE(c, nullptr);
    Loaded l;
    load_case(*c, std::string(name) + ".legacy.pem", &l);
    EXPECT_EQ(gcert_key_matches(l.key, &l.cert), GCERT_OK) << name;
  }
}

TEST(Key, ACombinedFileYieldsTheKeyAfterTheCertificate) {
  Loaded l;
  load_case(kCases[0], "combined.pem", &l);
  EXPECT_EQ(gcert_key_matches(l.key, &l.cert), GCERT_OK);
  /* A file with only a certificate has no key. */
  Bytes cert_only;
  {
    Bytes pem = load("combined.pem");
    std::string text(pem.begin(), pem.end());
    text = text.substr(0, text.find("-----BEGIN PRIVATE KEY"));
    GCERT_Key * k = nullptr;
    EXPECT_EQ(gcert_key_from_pem(nullptr, text.data(), text.size(), nullptr, 0, nullptr, &k),
        GCERT_ERR_FORMAT);
    EXPECT_EQ(k, nullptr);
  }
  GCERT_Key * k = nullptr;
  EXPECT_EQ(gcert_key_from_pem(nullptr, "", 0, nullptr, 0, nullptr, &k), GCERT_ERR_FORMAT);
}

TEST(Key, AKeyDoesNotMatchAnotherCertificate) {
  Loaded rsa;
  Loaded p256;
  load_case(kCases[0], "rsa.pk8.pem", &rsa);
  load_case(kCases[1], "p256.pk8.pem", &p256);
  EXPECT_EQ(gcert_key_matches(rsa.key, &p256.cert), GCERT_ERR_MISMATCH);   /* another kind */
  EXPECT_EQ(gcert_key_matches(p256.key, &rsa.cert), GCERT_ERR_MISMATCH);
  /* The same kind and another key: a P-256 certificate for a different key. */
  Loaded other;
  load_case(kCases[1], "p384.pk8.pem", &other);  /* a P-384 key, to be paired with ... */
  EXPECT_EQ(gcert_key_matches(other.key, &p256.cert), GCERT_ERR_MISMATCH);
  EXPECT_EQ(gcert_key_matches(nullptr, &p256.cert), GCERT_ERR_INVALID);
  EXPECT_EQ(gcert_key_matches(p256.key, nullptr), GCERT_ERR_INVALID);
}

TEST(Key, RsaNeedsBothModulusAndExponent) {
  Loaded l;
  load_case(kCases[0], "rsa.pk8.pem", &l);
  /* The certificate's own fields, with one changed at a time. */
  static const unsigned char three[1] = {3};
  GCERT_X509 other_e = l.cert;
  other_e.e = three;
  other_e.e_len = 1;
  EXPECT_EQ(gcert_key_matches(l.key, &other_e), GCERT_ERR_MISMATCH);
  Bytes n(l.cert.n, l.cert.n + l.cert.n_len);
  n.back() ^= 1;
  GCERT_X509 other_n = l.cert;
  other_n.n = n.data();
  EXPECT_EQ(gcert_key_matches(l.key, &other_n), GCERT_ERR_MISMATCH);
  /* A leading zero in the certificate's encoding is not a difference. */
  Bytes padded(1, 0);
  padded.insert(padded.end(), l.cert.n, l.cert.n + l.cert.n_len);
  GCERT_X509 zero_padded = l.cert;
  zero_padded.n = padded.data();
  zero_padded.n_len = padded.size();
  EXPECT_EQ(gcert_key_matches(l.key, &zero_padded), GCERT_OK);
}

TEST(Key, SameKindDifferentKey) {
  /* Two P-256 keys made here from fixed scalars. */
  unsigned char s1[32], s2[32], pub1[64], pub2[64];
  std::memset(s1, 0x11, 32);
  std::memset(s2, 0x22, 32);
  ASSERT_EQ(gsec_ecdsa_p256_public(s1, pub1), GSEC_OK);
  ASSERT_EQ(gsec_ecdsa_p256_public(s2, pub2), GSEC_OK);
  /* PKCS#8 for a P-256 key: the fixed prefix, then the SEC1 body with the scalar. */
  static const unsigned char prefix[] = {
    0x30, 0x41, 0x02, 0x01, 0x00, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d,
    0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x04, 0x27,
    0x30, 0x25, 0x02, 0x01, 0x01, 0x04, 0x20};
  Bytes p8(prefix, prefix + sizeof prefix);
  p8.insert(p8.end(), s1, s1 + 32);
  GCERT_Key * k = nullptr;
  ASSERT_EQ(gcert_key_from_pkcs8(nullptr, p8.data(), p8.size(), &k), GCERT_OK);
  EXPECT_EQ(gcert_key_kind(k), GCERT_X509_P256);
  GCERT_X509 cert;
  std::memset(&cert, 0, sizeof cert);
  cert.key = GCERT_X509_P256;
  cert.point = pub1;
  cert.point_len = 64;
  EXPECT_EQ(gcert_key_matches(k, &cert), GCERT_OK);
  cert.point = pub2;
  EXPECT_EQ(gcert_key_matches(k, &cert), GCERT_ERR_MISMATCH);
  gcert_key_free(k);
}

TEST(Key, EncryptedKeys) {
  Bytes pem = load("rsa.enc.pem");
  Bytes pw = load("password");
  Loaded l;
  l.cert_der = load("rsa.cert.der");
  ASSERT_EQ(gcert_x509_parse(l.cert_der.data(), l.cert_der.size(), &l.cert), GCERT_OK);
  ASSERT_EQ(gcert_key_from_pem(nullptr, pem.data(), pem.size(), pw.data(), pw.size(),
      nullptr, &l.key), GCERT_OK);
  EXPECT_EQ(gcert_key_matches(l.key, &l.cert), GCERT_OK);

  GCERT_Key * k = nullptr;
  EXPECT_EQ(gcert_key_from_pem(nullptr, pem.data(), pem.size(), "wrong", 5, nullptr, &k),
      GCERT_ERR_MISMATCH);
  EXPECT_EQ(k, nullptr);
  EXPECT_EQ(gcert_key_from_pem(nullptr, pem.data(), pem.size(), nullptr, 0, nullptr, &k),
      GCERT_ERR_INVALID);
  /* The work factor is the caller's to cap. */
  GCERT_Limits limits;
  gcert_limits_default(&limits);
  limits.max_pbe_iterations = 1;
  EXPECT_EQ(gcert_key_from_pem(nullptr, pem.data(), pem.size(), pw.data(), pw.size(),
      &limits, &k), GCERT_ERR_LIMIT);
}

TEST(Key, SignaturesFromOpenSslVerifyAndOursVerifyToo) {
  Bytes msg = load("message");
  for (const Case & c : kCases) {
    Loaded l;
    load_case(c, std::string(c.name) + ".pk8.pem", &l);
    for (const auto & s : c.schemes) {
      if (s.file == nullptr) {
        continue;
      }
      Bytes theirs = load(s.file);
      EXPECT_EQ(gcert_x509_verify_signature(&l.cert, s.scheme, msg.data(), msg.size(),
          theirs.data(), theirs.size()), GCERT_OK) << "OpenSSL's " << s.file;
      unsigned char sig[GCERT_SIG_MAX];
      size_t n = 0;
      ASSERT_EQ(gcert_key_sign(l.key, s.scheme, msg.data(), msg.size(), sig, sizeof sig, &n),
          GCERT_OK) << s.file;
      EXPECT_EQ(gcert_x509_verify_signature(&l.cert, s.scheme, msg.data(), msg.size(), sig, n),
          GCERT_OK) << "ours, " << s.file;
      /* One altered bit of the message, and one of the signature. */
      Bytes bad = msg;
      bad[0] ^= 1;
      EXPECT_EQ(gcert_x509_verify_signature(&l.cert, s.scheme, bad.data(), bad.size(), sig, n),
          GCERT_ERR_MISMATCH) << s.file;
      sig[n - 1] ^= 1;
      EXPECT_EQ(gcert_x509_verify_signature(&l.cert, s.scheme, msg.data(), msg.size(), sig, n),
          GCERT_ERR_MISMATCH) << s.file;
    }
  }
}

TEST(Key, TheRemainingRsaSchemes) {
  /* Only some RSA schemes have an OpenSSL file in the table above. */
  Bytes msg = load("message");
  Loaded l;
  load_case(kCases[0], "rsa.pk8.pem", &l);
  Bytes pss384 = load("rsa.pss-sha384.sig");
  Bytes pss512 = load("rsa.pss-sha512.sig");
  EXPECT_EQ(gcert_x509_verify_signature(&l.cert, GCERT_SIG_RSA_PSS_SHA384, msg.data(),
      msg.size(), pss384.data(), pss384.size()), GCERT_OK);
  EXPECT_EQ(gcert_x509_verify_signature(&l.cert, GCERT_SIG_RSA_PSS_SHA512, msg.data(),
      msg.size(), pss512.data(), pss512.size()), GCERT_OK);
  /* Not under the wrong digest. */
  EXPECT_EQ(gcert_x509_verify_signature(&l.cert, GCERT_SIG_RSA_PSS_SHA256, msg.data(),
      msg.size(), pss384.data(), pss384.size()), GCERT_ERR_MISMATCH);
  /* PSS signatures are randomised; PKCS#1 ones are not. */
  unsigned char a[GCERT_SIG_MAX], b[GCERT_SIG_MAX];
  size_t an = 0, bn = 0;
  ASSERT_EQ(gcert_key_sign(l.key, GCERT_SIG_RSA_PSS_SHA384, msg.data(), msg.size(), a,
      sizeof a, &an), GCERT_OK);
  ASSERT_EQ(gcert_key_sign(l.key, GCERT_SIG_RSA_PSS_SHA384, msg.data(), msg.size(), b,
      sizeof b, &bn), GCERT_OK);
  EXPECT_FALSE(an == bn && std::memcmp(a, b, an) == 0);
  ASSERT_EQ(gcert_key_sign(l.key, GCERT_SIG_RSA_PKCS1_SHA384, msg.data(), msg.size(), a,
      sizeof a, &an), GCERT_OK);
  ASSERT_EQ(gcert_key_sign(l.key, GCERT_SIG_RSA_PKCS1_SHA384, msg.data(), msg.size(), b,
      sizeof b, &bn), GCERT_OK);
  EXPECT_TRUE(an == bn && std::memcmp(a, b, an) == 0);
  /* A PKCS#1 signature is not a PSS one. */
  EXPECT_EQ(gcert_x509_verify_signature(&l.cert, GCERT_SIG_RSA_PSS_SHA384, msg.data(),
      msg.size(), a, an), GCERT_ERR_MISMATCH);
}

TEST(Key, ASchemeThatDoesNotFitTheKey) {
  Bytes msg = load("message");
  Loaded rsa;
  Loaded ec;
  load_case(kCases[0], "rsa.pk8.pem", &rsa);
  load_case(kCases[1], "p256.pk8.pem", &ec);
  unsigned char sig[GCERT_SIG_MAX];
  size_t n = 99;
  EXPECT_EQ(gcert_key_sign(rsa.key, GCERT_SIG_ECDSA_P256_SHA256, msg.data(), msg.size(),
      sig, sizeof sig, &n), GCERT_ERR_UNSUPPORTED);
  EXPECT_EQ(n, 0u);
  EXPECT_EQ(gcert_key_sign(ec.key, GCERT_SIG_ECDSA_P384_SHA384, msg.data(), msg.size(), sig,
      sizeof sig, &n), GCERT_ERR_UNSUPPORTED);
  EXPECT_EQ(gcert_key_sign(ec.key, GCERT_SIG_ED25519, msg.data(), msg.size(), sig,
      sizeof sig, &n), GCERT_ERR_UNSUPPORTED);
  EXPECT_EQ(gcert_key_sign(ec.key, static_cast<GCERT_SigScheme>(0x0000), msg.data(),
      msg.size(), sig, sizeof sig, &n), GCERT_ERR_UNSUPPORTED);
  EXPECT_EQ(gcert_x509_verify_signature(&ec.cert, GCERT_SIG_RSA_PSS_SHA256, msg.data(),
      msg.size(), sig, 64), GCERT_ERR_UNSUPPORTED);
  EXPECT_EQ(gcert_x509_verify_signature(&rsa.cert, GCERT_SIG_ED25519, msg.data(), msg.size(),
      sig, 64), GCERT_ERR_UNSUPPORTED);
  EXPECT_EQ(gcert_key_scheme_fits(GCERT_SIG_RSA_PSS_SHA256, GCERT_X509_RSA), 1);
  EXPECT_EQ(gcert_key_scheme_fits(GCERT_SIG_RSA_PSS_SHA256, GCERT_X509_P256), 0);
  EXPECT_EQ(gcert_key_scheme_fits(static_cast<GCERT_SigScheme>(7), GCERT_X509_RSA), 0);
}

TEST(Key, EcdsaSignaturesAreStrictDer) {
  Bytes msg = load("message");
  Loaded l;
  load_case(kCases[1], "p256.pk8.pem", &l);
  unsigned char sig[GCERT_SIG_MAX];
  size_t n = 0;
  ASSERT_EQ(gcert_key_sign(l.key, GCERT_SIG_ECDSA_P256_SHA256, msg.data(), msg.size(), sig,
      sizeof sig, &n), GCERT_OK);
  ASSERT_GE(n, 8u);
  EXPECT_EQ(sig[0], 0x30);
  EXPECT_EQ(sig[1], n - 2u);
  auto verify = [&](const Bytes & s) {
    return gcert_x509_verify_signature(&l.cert, GCERT_SIG_ECDSA_P256_SHA256, msg.data(),
        msg.size(), s.data(), s.size());
  };
  Bytes good(sig, sig + n);
  EXPECT_EQ(verify(good), GCERT_OK);
  Bytes trailing = good;
  trailing.push_back(0);
  EXPECT_EQ(verify(trailing), GCERT_ERR_MISMATCH);
  Bytes raw(good.begin(), good.end());
  raw.erase(raw.begin(), raw.begin() + 2);       /* r and s without the SEQUENCE */
  EXPECT_EQ(verify(raw), GCERT_ERR_MISMATCH);
  Bytes truncated(good.begin(), good.end() - 1);
  EXPECT_EQ(verify(truncated), GCERT_ERR_MISMATCH);
  Bytes empty_int = {0x30, 0x06, 0x02, 0x00, 0x02, 0x02, 0x01, 0x01};
  EXPECT_EQ(verify(empty_int), GCERT_ERR_MISMATCH);
  Bytes negative = {0x30, 0x08, 0x02, 0x02, 0xff, 0xff, 0x02, 0x02, 0x01, 0x01};
  EXPECT_EQ(verify(negative), GCERT_ERR_MISMATCH);
  Bytes zero_zero = {0x30, 0x06, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00};
  EXPECT_EQ(verify(zero_zero), GCERT_ERR_MISMATCH);
  Bytes padded_int(good);                        /* an unnecessary leading zero in r */
  padded_int.insert(padded_int.begin() + 4, 0x00);
  padded_int[1] = static_cast<unsigned char>(padded_int[1] + 1);
  padded_int[3] = static_cast<unsigned char>(padded_int[3] + 1);
  EXPECT_EQ(verify(padded_int), GCERT_ERR_MISMATCH);
  EXPECT_EQ(gcert_x509_verify_signature(&l.cert, GCERT_SIG_ECDSA_P256_SHA256, msg.data(),
      msg.size(), nullptr, 0), GCERT_ERR_INVALID);
}

TEST(Key, EveryEcdsaSignatureIsDerForAnyScalarWidth) {
  /* Signatures whose r or s has a high bit, or is short, need a sign byte
   * or a shorter encoding; sign enough that each case turns up. */
  Loaded l;
  load_case(kCases[2], "p384.pk8.pem", &l);
  unsigned lens[200] = {0};
  for (unsigned i = 0; i < 200; i++) {
    unsigned char msg[4] = {static_cast<unsigned char>(i), 1, 2, 3};
    unsigned char sig[GCERT_SIG_MAX];
    size_t n = 0;
    ASSERT_EQ(gcert_key_sign(l.key, GCERT_SIG_ECDSA_P384_SHA384, msg, 4, sig, sizeof sig, &n),
        GCERT_OK);
    EXPECT_EQ(gcert_x509_verify_signature(&l.cert, GCERT_SIG_ECDSA_P384_SHA384, msg, 4, sig, n),
        GCERT_OK) << i;
    lens[i] = static_cast<unsigned>(n);
  }
  /* The lengths are not all the same, which is the sign-byte and
   * leading-zero cases being exercised. */
  bool varied = false;
  for (unsigned i = 1; i < 200; i++) {
    varied = varied || lens[i] != lens[0];
  }
  EXPECT_TRUE(varied);
}

TEST(Key, SigningBufferTooSmall) {
  Bytes msg = load("message");
  for (const Case & c : kCases) {
    Loaded l;
    load_case(c, std::string(c.name) + ".pk8.pem", &l);
    unsigned char sig[GCERT_SIG_MAX];
    size_t n = 0;
    ASSERT_EQ(gcert_key_sign(l.key, c.schemes[0].scheme, msg.data(), msg.size(), sig,
        sizeof sig, &n), GCERT_OK);
    std::vector<unsigned char> exact(n);
    size_t m = 0;
    EXPECT_EQ(gcert_key_sign(l.key, c.schemes[0].scheme, msg.data(), msg.size(), exact.data(),
        exact.size(), &m), GCERT_OK) << c.name;
    EXPECT_EQ(m, n);
    std::vector<unsigned char> small(n - 1u, 0xaa);
    EXPECT_EQ(gcert_key_sign(l.key, c.schemes[0].scheme, msg.data(), msg.size(), small.data(),
        small.size(), &m), GCERT_ERR_LIMIT) << c.name;
    EXPECT_EQ(m, 0u);
  }
}

TEST(Key, AnAlteredRsaKeyIsCaughtWhenLoaded) {
  /* A PKCS#8 file can parse with a damaged private exponent (see
   * gcert_pkcs8_decrypt's note), and such a key signs garbage. The load
   * checks by signing and verifying. */
  Bytes pem = load("rsa.pk8.pem");
  Bytes der(pem.size());
  size_t n = 0;
  char label[32] = {0};
  ASSERT_EQ(gcert_pem_decode(pem.data(), pem.size(), der.data(), der.size(), &n, label,
      sizeof label - 1), GCERT_OK);
  der.resize(n);
  GCERT_Pkcs8 view;
  ASSERT_EQ(gcert_pkcs8_parse(der.data(), der.size(), &view), GCERT_OK);
  GCERT_Key * k = nullptr;
  ASSERT_EQ(gcert_key_from_pkcs8(nullptr, der.data(), der.size(), &k), GCERT_OK);
  gcert_key_free(k);
  unsigned char * d = const_cast<unsigned char *>(view.d);
  d[view.d_len / 2] ^= 0x40;
  EXPECT_EQ(gcert_key_from_pkcs8(nullptr, der.data(), der.size(), &k), GCERT_ERR_MISMATCH);
  EXPECT_EQ(k, nullptr);
}

TEST(Key, MalformedKeysAreRefused) {
  Bytes pem = load("p256.pk8.pem");
  Bytes der(pem.size());
  size_t n = 0;
  char label[32] = {0};
  ASSERT_EQ(gcert_pem_decode(pem.data(), pem.size(), der.data(), der.size(), &n, label,
      sizeof label - 1), GCERT_OK);
  der.resize(n);
  GCERT_Key * k = nullptr;
  EXPECT_EQ(gcert_key_from_pkcs8(nullptr, nullptr, 0, &k), GCERT_ERR_INVALID);
  EXPECT_EQ(gcert_key_from_pkcs8(nullptr, der.data(), der.size(), nullptr), GCERT_ERR_INVALID);
  Bytes truncated(der.begin(), der.end() - 1);
  EXPECT_NE(gcert_key_from_pkcs8(nullptr, truncated.data(), truncated.size(), &k), GCERT_OK);
  EXPECT_EQ(k, nullptr);
  /* A zero scalar is not a key: PKCS#8 for P-256 with 32 zero bytes. */
  static const unsigned char prefix[] = {
    0x30, 0x41, 0x02, 0x01, 0x00, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d,
    0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x04, 0x27,
    0x30, 0x25, 0x02, 0x01, 0x01, 0x04, 0x20};
  Bytes zero(prefix, prefix + sizeof prefix);
  zero.resize(zero.size() + 32, 0);
  EXPECT_NE(gcert_key_from_pkcs8(nullptr, zero.data(), zero.size(), &k), GCERT_OK);
  EXPECT_EQ(k, nullptr);
  /* The group order itself is out of range too: n for P-256. */
  static const unsigned char order[32] = {
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63,
    0x25, 0x51};
  Bytes n_key(prefix, prefix + sizeof prefix);
  n_key.insert(n_key.end(), order, order + 32);
  EXPECT_NE(gcert_key_from_pkcs8(nullptr, n_key.data(), n_key.size(), &k), GCERT_OK);
  EXPECT_EQ(k, nullptr);
}

TEST(Key, EveryAllocationMayFail) {
  Bytes pem = load("rsa.pk8.pem");
  struct Counter {
    size_t calls = 0, fail_at = 0, live = 0;
  } probe;
  auto m = [](void * ctx, size_t n) -> void * {
    auto * f = static_cast<Counter *>(ctx);
    if (++f->calls == f->fail_at) return nullptr;
    void * p = std::malloc(n == 0 ? 1 : n);
    if (p) f->live++;
    return p;
  };
  auto c = [](void * ctx, size_t a, size_t b) -> void * {
    auto * f = static_cast<Counter *>(ctx);
    if (++f->calls == f->fail_at) return nullptr;
    void * p = std::calloc(a, b == 0 ? 1 : b);
    if (p) f->live++;
    return p;
  };
  auto r = [](void * ctx, void * old, size_t n) -> void * {
    auto * f = static_cast<Counter *>(ctx);
    if (++f->calls == f->fail_at) return nullptr;
    void * p = std::realloc(old, n == 0 ? 1 : n);
    if (p && !old) f->live++;
    return p;
  };
  auto fr = [](void * ctx, void * p) {
    auto * f = static_cast<Counter *>(ctx);
    if (p) f->live--;
    std::free(p);
  };
  auto run = [&](Counter * ctr, GCERT_Key ** out) -> GCERT_Result {
    GCERT_Allocator a = {ctr, m, c, r, fr};
    return gcert_key_from_pem(&a, pem.data(), pem.size(), nullptr, 0, nullptr, out);
  };
  GCERT_Key * k = nullptr;
  ASSERT_EQ(run(&probe, &k), GCERT_OK);
  EXPECT_EQ(probe.live, 1u);       /* the key, and nothing else */
  gcert_key_free(k);              /* uses the allocator inside the key */
  EXPECT_EQ(probe.live, 0u);
  for (size_t i = 1; i <= probe.calls; i++) {
    Counter f;
    f.fail_at = i;
    GCERT_Key * kk = nullptr;
    EXPECT_EQ(run(&f, &kk), GCERT_ERR_OOM) << "failing allocation " << i;
    EXPECT_EQ(kk, nullptr);
    EXPECT_EQ(f.live, 0u) << "leak after failing allocation " << i;
  }
}

namespace {

/* An allocator that checks every block it is handed back is all zeros: a
 * secret that was in it was wiped first. Blocks are of whatever size they were
 * asked for, and a block that never held a secret is zero because the
 * allocator zero-fills what it hands out. */
struct Audit {
  std::vector<std::pair<unsigned char *, size_t>> blocks;
  size_t freed = 0;
  size_t dirty = 0;
};

void * a_alloc(void * ctx, size_t n, bool zero) {
  Audit * a = static_cast<Audit *>(ctx);
  unsigned char * p = static_cast<unsigned char *>(std::malloc(n == 0 ? 1 : n));
  /* Fill with a pattern first, so a block that is never written looks dirty. */
  std::memset(p, zero ? 0 : 0xA5, n);
  a->blocks.push_back({p, n});
  return p;
}

} /* namespace */

TEST(Key, EverySecretIsWipedBeforeItsBlockIsFreed) {
  auto m = [](void * ctx, size_t n) -> void * { return a_alloc(ctx, n, false); };
  auto c = [](void * ctx, size_t a, size_t b) -> void * { return a_alloc(ctx, a * b, true); };
  auto r = [](void *, void *, size_t) -> void * { return nullptr; };
  auto fr = [](void * ctx, void * p) {
    Audit * a = static_cast<Audit *>(ctx);
    for (auto & blk : a->blocks) {
      if (blk.first == p) {
        a->freed++;
        for (size_t i = 0; i < blk.second; i++) {
          if (blk.first[i] != 0) {
            a->dirty++;
            break;
          }
        }
        std::free(p);
        blk.first = nullptr;
        return;
      }
    }
  };
  for (const char * file : {"rsa.pk8.pem", "p256.pk8.pem", "ed25519.pk8.pem", "rsa.legacy.pem",
      "rsa.enc.pem"}) {
    Audit audit;
    GCERT_Allocator al = {&audit, m, c, r, fr};
    Bytes pem = load(file);
    Bytes pw = load("password");
    GCERT_Key * k = nullptr;
    ASSERT_EQ(gcert_key_from_pem(&al, pem.data(), pem.size(), pw.data(), pw.size(), nullptr, &k),
        GCERT_OK) << file;
    gcert_key_free(k);
    EXPECT_GE(audit.freed, 2u) << file;      /* the decode buffer and the key, at least */
    EXPECT_EQ(audit.dirty, 0u) << file << ": a block went back to the allocator still holding bytes";
    for (auto & blk : audit.blocks) {
      EXPECT_EQ(blk.first, nullptr) << file << ": a block was never freed";
    }
  }
}

TEST(Key, ALoadThatFailsWipesWhatItCopied) {
  auto m = [](void * ctx, size_t n) -> void * { return a_alloc(ctx, n, false); };
  auto c = [](void * ctx, size_t a, size_t b) -> void * { return a_alloc(ctx, a * b, true); };
  auto r = [](void *, void *, size_t) -> void * { return nullptr; };
  auto fr = [](void * ctx, void * p) {
    Audit * a = static_cast<Audit *>(ctx);
    for (auto & blk : a->blocks) {
      if (blk.first == p) {
        a->freed++;
        for (size_t i = 0; i < blk.second; i++) {
          if (blk.first[i] != 0) {
            a->dirty++;
            break;
          }
        }
        std::free(p);
        blk.first = nullptr;
        return;
      }
    }
  };
  /* An RSA key with a damaged private exponent: it parses, is copied into the
   * key object, and is refused by the load's own signature check. */
  Bytes pem = load("rsa.pk8.pem");
  Bytes der(pem.size());
  size_t n = 0;
  char label[32] = {0};
  ASSERT_EQ(gcert_pem_decode(pem.data(), pem.size(), der.data(), der.size(), &n, label,
      sizeof label - 1), GCERT_OK);
  der.resize(n);
  GCERT_Pkcs8 view;
  ASSERT_EQ(gcert_pkcs8_parse(der.data(), der.size(), &view), GCERT_OK);
  const_cast<unsigned char *>(view.d)[view.d_len / 2] ^= 0x40;
  Audit audit;
  GCERT_Allocator al = {&audit, m, c, r, fr};
  GCERT_Key * k = nullptr;
  EXPECT_EQ(gcert_key_from_pkcs8(&al, der.data(), der.size(), &k), GCERT_ERR_MISMATCH);
  EXPECT_EQ(k, nullptr);
  EXPECT_EQ(audit.freed, 1u);
  EXPECT_EQ(audit.dirty, 0u);
}

int main(int argc, char ** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
