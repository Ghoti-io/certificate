/**
 * @file
 *
 * A basic OCSP response: the happy path, and every way it has to fail.
 *
 * This file used to hold one test and no negative assertion at all, which
 * the audit found by mutating the CertID serial comparison so that every
 * serial matched - reporting one certificate's revocation status for another
 * - and watching `make test` pass. It is the function a caller asks "is this
 * certificate revoked", so the answers it must refuse to give are the point.
 *
 * Copyright 2026 by Corey Pennycuff
 */

#include "test_helpers.h"

#include <cstdint>
#include <cstring>
#include <fstream>
#include <vector>

namespace {

std::vector<unsigned char> load(const char * name) {
  std::ifstream in(gsectest::data_dir() + "/certs/" + name, std::ios::binary);
  EXPECT_TRUE(in.good()) << name;
  return std::vector<unsigned char>(std::istreambuf_iterator<char>(in),
      std::istreambuf_iterator<char>());
}

const unsigned char kSerial[] = {
  0x1d, 0xf0, 0x17, 0x04, 0x5e, 0xa3, 0x08, 0x80, 0x5b, 0x21,
  0x9a, 0x09, 0x22, 0xc6, 0xe6, 0xb4, 0x83, 0xc3, 0x15, 0x50
};

const int64_t kRevokedAt = 1767225600;

/* The two hashes a CertID is keyed by: the issuer's subject name, and its
 * public key as the uncompressed point. */
struct Id {
  unsigned char name[GSEC_SHA1_DIGEST_LEN];
  unsigned char key[GSEC_SHA1_DIGEST_LEN];
};

Id id_of(const GCERT_X509 & ca) {
  Id id;
  unsigned char point[1u + 64u];
  EXPECT_EQ(gsec_sha1(ca.subject, ca.subject_len, id.name), GSEC_OK);
  point[0] = 0x04;
  EXPECT_EQ(ca.point_len, 64u);
  std::memcpy(point + 1, ca.point, ca.point_len);
  EXPECT_EQ(gsec_sha1(point, sizeof point, id.key), GSEC_OK);
  return id;
}

GCERT_Result status_of(const GCERT_Ocsp & ocsp, const Id & id,
    const unsigned char * serial, size_t serial_len,
    GCERT_Ocsp_Single * out) {
  return gcert_ocsp_status(&ocsp, GSEC_HMAC_SHA1, id.name, sizeof id.name,
      id.key, sizeof id.key, serial, serial_len, out);
}

} /* namespace */

TEST(Ocsp, LeafIsRevoked) {
  auto ocsp_der = load("leaf.ocsp");
  auto ca_der = load("ca.der");
  GCERT_Ocsp ocsp;
  GCERT_X509 ca;
  GCERT_Ocsp_Single single;
  ASSERT_EQ(gcert_ocsp_parse(ocsp_der.data(), ocsp_der.size(), &ocsp), GCERT_OK);
  ASSERT_EQ(gcert_x509_parse(ca_der.data(), ca_der.size(), &ca), GCERT_OK);
  EXPECT_EQ(gcert_ocsp_signed_by(&ocsp, &ca), GCERT_OK);
  Id id = id_of(ca);
  ASSERT_EQ(status_of(ocsp, id, kSerial, sizeof kSerial, &single), GCERT_OK);
  EXPECT_EQ(single.status, GCERT_OCSP_REVOKED);
  EXPECT_EQ(single.revoked_at, kRevokedAt);
}

TEST(Ocsp, FreshnessIsVisible) {
  /* The response says when it was produced and what instant it describes.
   * Without these a caller cannot tell a current answer from one replayed
   * out of a capture, which is the cheapest attack on revocation there is. */
  auto ocsp_der = load("leaf.ocsp");
  auto ca_der = load("ca.der");
  GCERT_Ocsp ocsp;
  GCERT_X509 ca;
  GCERT_Ocsp_Single single;
  ASSERT_EQ(gcert_ocsp_parse(ocsp_der.data(), ocsp_der.size(), &ocsp), GCERT_OK);
  ASSERT_EQ(gcert_x509_parse(ca_der.data(), ca_der.size(), &ca), GCERT_OK);
  EXPECT_GT(ocsp.produced_at, 1700000000);
  Id id = id_of(ca);
  ASSERT_EQ(status_of(ocsp, id, kSerial, sizeof kSerial, &single), GCERT_OK);
  EXPECT_GT(single.this_update, 1700000000);
  EXPECT_LE(single.this_update, ocsp.produced_at);
  if (single.have_next_update) {
    EXPECT_GE(single.next_update, single.this_update);
  }
}

TEST(Ocsp, AnotherSerialIsNotThisAnswer) {
  /* The mutation that survived: every serial matching. One byte of the
   * serial changed must be GCERT_ERR_MISMATCH and not a status. */
  auto ocsp_der = load("leaf.ocsp");
  auto ca_der = load("ca.der");
  GCERT_Ocsp ocsp;
  GCERT_X509 ca;
  GCERT_Ocsp_Single single;
  ASSERT_EQ(gcert_ocsp_parse(ocsp_der.data(), ocsp_der.size(), &ocsp), GCERT_OK);
  ASSERT_EQ(gcert_x509_parse(ca_der.data(), ca_der.size(), &ca), GCERT_OK);
  Id id = id_of(ca);

  for (size_t i = 0; i < sizeof kSerial; i++) {
    unsigned char other[sizeof kSerial];
    std::memcpy(other, kSerial, sizeof other);
    other[i] = static_cast<unsigned char>(other[i] ^ 0x01u);
    EXPECT_EQ(status_of(ocsp, id, other, sizeof other, &single),
        GCERT_ERR_MISMATCH) << "serial byte " << i;
  }
  /* A shorter and a longer serial are different serials, not prefixes. */
  EXPECT_EQ(status_of(ocsp, id, kSerial, sizeof kSerial - 1u, &single),
      GCERT_ERR_MISMATCH);
  unsigned char longer[sizeof kSerial + 1u] = {0};
  std::memcpy(longer, kSerial, sizeof kSerial);
  EXPECT_EQ(status_of(ocsp, id, longer, sizeof longer, &single),
      GCERT_ERR_MISMATCH);
}

TEST(Ocsp, AnotherIssuerIsNotThisAnswer) {
  auto ocsp_der = load("leaf.ocsp");
  auto ca_der = load("ca.der");
  GCERT_Ocsp ocsp;
  GCERT_X509 ca;
  GCERT_Ocsp_Single single;
  ASSERT_EQ(gcert_ocsp_parse(ocsp_der.data(), ocsp_der.size(), &ocsp), GCERT_OK);
  ASSERT_EQ(gcert_x509_parse(ca_der.data(), ca_der.size(), &ca), GCERT_OK);

  Id bad_name = id_of(ca);
  bad_name.name[0] = static_cast<unsigned char>(bad_name.name[0] ^ 0x01u);
  EXPECT_EQ(status_of(ocsp, bad_name, kSerial, sizeof kSerial, &single),
      GCERT_ERR_MISMATCH);

  Id bad_key = id_of(ca);
  bad_key.key[19] = static_cast<unsigned char>(bad_key.key[19] ^ 0x80u);
  EXPECT_EQ(status_of(ocsp, bad_key, kSerial, sizeof kSerial, &single),
      GCERT_ERR_MISMATCH);
}

TEST(Ocsp, WrongIssuerDoesNotVerify) {
  auto ocsp_der = load("leaf.ocsp");
  auto other_der = load("p256-ca.der");
  GCERT_Ocsp ocsp;
  GCERT_X509 other;
  ASSERT_EQ(gcert_ocsp_parse(ocsp_der.data(), ocsp_der.size(), &ocsp), GCERT_OK);
  ASSERT_EQ(gcert_x509_parse(other_der.data(), other_der.size(), &other),
      GCERT_OK);
  EXPECT_EQ(gcert_ocsp_signed_by(&ocsp, &other), GCERT_ERR_MISMATCH);
}

TEST(Ocsp, TamperedSignatureDoesNotVerify) {
  auto ca_der = load("ca.der");
  GCERT_X509 ca;
  ASSERT_EQ(gcert_x509_parse(ca_der.data(), ca_der.size(), &ca), GCERT_OK);

  /* Flip one bit inside the signed body. Parsing may still succeed - the
   * bytes stay a valid encoding - but the signature must not. Only the signed
   * body: a response also carries the responder's certificates, which the
   * signature does not cover and which gcert_ocsp_signed_by does not read,
   * because the issuer is the caller's. Flipping a byte out there and
   * expecting a failure would be asserting something untrue. */
  auto base = load("leaf.ocsp");
  GCERT_Ocsp pristine;
  ASSERT_EQ(gcert_ocsp_parse(base.data(), base.size(), &pristine), GCERT_OK);
  size_t tbs_at = static_cast<size_t>(pristine.tbs - base.data());
  ASSERT_LT(tbs_at, base.size());
  ASSERT_LE(tbs_at + pristine.tbs_len, base.size());

  int checked = 0;
  for (size_t i = tbs_at; i < tbs_at + pristine.tbs_len; i += 17) {
    auto bytes = base;
    bytes[i] = static_cast<unsigned char>(bytes[i] ^ 0x01u);
    GCERT_Ocsp ocsp;
    if (gcert_ocsp_parse(bytes.data(), bytes.size(), &ocsp) != GCERT_OK) {
      continue;
    }
    GCERT_Result r = gcert_ocsp_signed_by(&ocsp, &ca);
    EXPECT_NE(r, GCERT_OK) << "byte " << i << " was flipped and it verified";
    checked++;
  }
  EXPECT_GT(checked, 4) << "too few flipped responses parsed for this to mean "
                           "anything";

  /* Not a flip inside the signature: this response is ECDSA, and an ECDSA
   * signature is copied into GCERT_Ocsp::ecdsa_raw rather than left in the
   * caller's buffer, so the parse result does not say where in the input it
   * was. The sweep above is what covers tampering. */
}

TEST(Ocsp, ArgumentsAreChecked) {
  auto ocsp_der = load("leaf.ocsp");
  auto ca_der = load("ca.der");
  GCERT_Ocsp ocsp;
  GCERT_X509 ca;
  GCERT_Ocsp_Single single;
  ASSERT_EQ(gcert_ocsp_parse(ocsp_der.data(), ocsp_der.size(), &ocsp), GCERT_OK);
  ASSERT_EQ(gcert_x509_parse(ca_der.data(), ca_der.size(), &ca), GCERT_OK);
  Id id = id_of(ca);

  EXPECT_EQ(gcert_ocsp_status(nullptr, GSEC_HMAC_SHA1, id.name, sizeof id.name,
      id.key, sizeof id.key, kSerial, sizeof kSerial, &single),
      GCERT_ERR_INVALID);
  EXPECT_EQ(gcert_ocsp_status(&ocsp, GSEC_HMAC_SHA1, id.name, sizeof id.name,
      id.key, sizeof id.key, kSerial, sizeof kSerial, nullptr),
      GCERT_ERR_INVALID);
  /* A digest id that is not one of the four, and a length that is not the
   * digest's, are both the caller's mistake rather than a lookup miss. */
  EXPECT_EQ(gcert_ocsp_status(&ocsp, 0xffffu, id.name, sizeof id.name, id.key,
      sizeof id.key, kSerial, sizeof kSerial, &single), GCERT_ERR_INVALID);
  EXPECT_EQ(gcert_ocsp_status(&ocsp, GSEC_HMAC_SHA1, id.name,
      sizeof id.name - 1u, id.key, sizeof id.key, kSerial, sizeof kSerial,
      &single), GCERT_ERR_INVALID);
  EXPECT_EQ(gcert_ocsp_signed_by(nullptr, &ca), GCERT_ERR_INVALID);
}

TEST(Ocsp, TruncationIsRefused) {
  auto base = load("leaf.ocsp");
  for (size_t n = 1; n < base.size(); n += 11) {
    GCERT_Ocsp ocsp;
    EXPECT_NE(gcert_ocsp_parse(base.data(), n, &ocsp), GCERT_OK)
        << "accepted a response truncated to " << n;
  }
  GCERT_Ocsp ocsp;
  EXPECT_NE(gcert_ocsp_parse(base.data(), 0, &ocsp), GCERT_OK);
}

TEST(Ocsp, CriticalSingleExtensionIsRefused) {
  /* A critical extension the parser does not understand must refuse the
   * answer, not be read past. `skip_extensions` was applied to
   * responseExtensions at parse time and never to a SingleResponse's own, so
   * the entry actually being answered could carry one and be answered anyway -
   * the same shape as accepting a critical extendedKeyUsage and evaluating
   * none of it.
   *
   * The fixture is leaf.ocsp with a critical 1.2.3.4.5 spliced into the first
   * SingleResponse by tools/make-ocsp-ext.py. Its signature no longer covers
   * the modified body, which does not matter here: gcert_ocsp_status does not
   * check signatures, and tampering is covered by the sweep above. */
  auto ocsp_der = load("ocsp-critical-single-ext.der");
  auto ca_der = load("ca.der");
  GCERT_Ocsp ocsp;
  GCERT_X509 ca;
  GCERT_Ocsp_Single single;
  ASSERT_EQ(gcert_ocsp_parse(ocsp_der.data(), ocsp_der.size(), &ocsp), GCERT_OK);
  ASSERT_EQ(gcert_x509_parse(ca_der.data(), ca_der.size(), &ca), GCERT_OK);
  Id id = id_of(ca);
  EXPECT_EQ(status_of(ocsp, id, kSerial, sizeof kSerial, &single),
      GCERT_ERR_UNSUPPORTED);

  /* The control: the same response without the extension answers. Otherwise
   * this test would pass on any response the parser happened to refuse. */
  auto plain = load("leaf.ocsp");
  GCERT_Ocsp ok;
  ASSERT_EQ(gcert_ocsp_parse(plain.data(), plain.size(), &ok), GCERT_OK);
  EXPECT_EQ(status_of(ok, id, kSerial, sizeof kSerial, &single), GCERT_OK);
}

int main(int argc, char ** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
