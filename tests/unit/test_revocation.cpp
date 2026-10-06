/**
 * @file
 *
 * What revocation.h decides, against real CRLs and OCSP responses that
 * OpenSSL wrote (tools/make-revocation-fixtures.sh): revoked, good, from the
 * wrong issuer, signed with the wrong key, stale, not yet valid, a delegated
 * responder, and the decision when there is no usable answer at all.
 *
 * The instant each case evaluates at is read from the parsed CRL or response,
 * so the fixtures do not expire.
 *
 * Copyright 2026 by Corey Pennycuff
 */

#include "test_helpers.h"

#include <cstdint>
#include <cstring>
#include <fstream>
#include <string>
#include <vector>

namespace {

typedef std::vector<unsigned char> Bytes;

Bytes load(const char * name) {
  std::ifstream in(gsectest::data_dir() + "/certs/" + name, std::ios::binary);
  EXPECT_TRUE(in.good()) << name;
  return Bytes(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
}

struct Fx {
  Bytes ca_der = load("rev-ca.der");
  Bytes other_der = load("rev-other-ca.der");
  Bytes good_der = load("rev-good.der");
  Bytes revoked_der = load("rev-revoked.der");
  Bytes responder_der = load("rev-responder.der");
  Bytes plain_der = load("rev-plain-responder.der");
  Bytes foreign_der = load("rev-foreign-responder.der");
  Bytes unknown_der = load("rev-unknown.der");
  Bytes crl_der = load("rev-ca.crl");
  GCERT_X509 ca, other, good, revoked, responder, plain, foreign, unknown;
  GCERT_Crl crl;
  Fx() {
    EXPECT_EQ(gcert_x509_parse(ca_der.data(), ca_der.size(), &ca), GCERT_OK);
    EXPECT_EQ(gcert_x509_parse(other_der.data(), other_der.size(), &other), GCERT_OK);
    EXPECT_EQ(gcert_x509_parse(good_der.data(), good_der.size(), &good), GCERT_OK);
    EXPECT_EQ(gcert_x509_parse(revoked_der.data(), revoked_der.size(), &revoked), GCERT_OK);
    EXPECT_EQ(gcert_x509_parse(responder_der.data(), responder_der.size(), &responder),
        GCERT_OK);
    EXPECT_EQ(gcert_x509_parse(plain_der.data(), plain_der.size(), &plain), GCERT_OK);
    EXPECT_EQ(gcert_x509_parse(foreign_der.data(), foreign_der.size(), &foreign), GCERT_OK);
    EXPECT_EQ(gcert_x509_parse(unknown_der.data(), unknown_der.size(), &unknown), GCERT_OK);
    EXPECT_EQ(gcert_crl_parse(crl_der.data(), crl_der.size(), &crl), GCERT_OK);
  }
};

struct Resp {
  Bytes der;
  GCERT_Ocsp ocsp;
  explicit Resp(const char * name) : der(load(name)) {
    EXPECT_EQ(gcert_ocsp_parse(der.data(), der.size(), &ocsp), GCERT_OK) << name;
  }
};

GCERT_Revocation crl_check(const Fx & f, const GCERT_Crl & crl, const GCERT_X509 & issuer,
    const GCERT_X509 & cert, int64_t now, const GCERT_RevocationPolicy * p = nullptr) {
  GCERT_Revocation r;
  EXPECT_EQ(gcert_crl_check(&crl, &issuer, &cert, now, p, &r), GCERT_OK);
  (void)f;
  return r;
}

GCERT_Revocation ocsp_check(const Resp & r, const GCERT_X509 & issuer,
    const GCERT_X509 * responder, const GCERT_X509 & cert, int64_t now,
    const GCERT_RevocationPolicy * p = nullptr) {
  GCERT_Revocation out;
  EXPECT_EQ(gcert_ocsp_check(&r.ocsp, &issuer, responder, &cert, now, p, &out), GCERT_OK);
  return out;
}

} /* namespace */

/* --- CRL ------------------------------------------------------------------ */

TEST(RevocationCrl, RevokedAndGood) {
  Fx f;
  int64_t now = f.crl.this_update + 3600;
  GCERT_Revocation r = crl_check(f, f.crl, f.ca, f.revoked, now);
  EXPECT_EQ(r.status, GCERT_REVOCATION_REVOKED);
  EXPECT_EQ(r.reason, GCERT_REVOCATION_NONE);
  r = crl_check(f, f.crl, f.ca, f.good, now);
  EXPECT_EQ(r.status, GCERT_REVOCATION_GOOD);
  EXPECT_EQ(r.reason, GCERT_REVOCATION_NONE);
}

TEST(RevocationCrl, FromTheWrongIssuer) {
  Fx f;
  int64_t now = f.crl.this_update + 3600;
  /* A CA with the same name and another key: the names agree, so this is
   * found out by the signature, not by the name. */
  GCERT_Revocation r = crl_check(f, f.crl, f.other, f.revoked, now);
  EXPECT_EQ(r.status, GCERT_REVOCATION_UNUSABLE);
  EXPECT_EQ(r.reason, GCERT_REVOCATION_BAD_SIGNATURE);
  /* A certificate this issuer did not issue is refused by name. */
  auto p256 = load("p256-ca.der");
  GCERT_X509 stranger;
  ASSERT_EQ(gcert_x509_parse(p256.data(), p256.size(), &stranger), GCERT_OK);
  r = crl_check(f, f.crl, stranger, f.revoked, now);
  EXPECT_EQ(r.reason, GCERT_REVOCATION_WRONG_ISSUER);
  /* And a list that names a different issuer than the one asked about. */
  GCERT_X509 renamed = f.ca;
  GCERT_X509 leaf_of_stranger = f.revoked;
  leaf_of_stranger.issuer = stranger.subject;
  leaf_of_stranger.issuer_len = stranger.subject_len;
  r = crl_check(f, f.crl, stranger, leaf_of_stranger, now);
  EXPECT_EQ(r.reason, GCERT_REVOCATION_WRONG_ISSUER);
  (void)renamed;
}

TEST(RevocationCrl, ATamperedListIsNotEvidence) {
  Fx f;
  Bytes bad = f.crl_der;
  bad[bad.size() - 2] ^= 0x01;  /* inside the RSA signature */
  GCERT_Crl crl;
  ASSERT_EQ(gcert_crl_parse(bad.data(), bad.size(), &crl), GCERT_OK);
  GCERT_Revocation r = crl_check(f, crl, f.ca, f.revoked, crl.this_update + 3600);
  EXPECT_EQ(r.status, GCERT_REVOCATION_UNUSABLE);
  EXPECT_EQ(r.reason, GCERT_REVOCATION_BAD_SIGNATURE);
  /* ...which is the whole point: an unsigned "not revoked" would otherwise
   * pass for the revoked certificate. */
}

TEST(RevocationCrl, IssuerThatMayNotSign) {
  Fx f;
  int64_t now = f.crl.this_update + 3600;
  GCERT_X509 no_crl_sign = f.ca;
  no_crl_sign.key_usage_set = 1;
  no_crl_sign.key_usage = 0x04;        /* keyCertSign only */
  EXPECT_EQ(crl_check(f, f.crl, no_crl_sign, f.revoked, now).reason,
      GCERT_REVOCATION_CANNOT_SIGN);
  GCERT_X509 can = f.ca;
  can.key_usage_set = 1;
  can.key_usage = 0x06;                /* keyCertSign and cRLSign */
  EXPECT_EQ(crl_check(f, f.crl, can, f.revoked, now).status, GCERT_REVOCATION_REVOKED);
  GCERT_X509 not_ca = f.ca;
  not_ca.basic_constraints = 1;
  not_ca.ca = 0;
  EXPECT_EQ(crl_check(f, f.crl, not_ca, f.revoked, now).reason,
      GCERT_REVOCATION_CANNOT_SIGN);
}

TEST(RevocationCrl, FreshnessAtTheEdges) {
  Fx f;
  ASSERT_TRUE(f.crl.next_set);
  const int64_t skew = GCERT_REVOCATION_SKEW_DEFAULT;
  /* thisUpdate: skew seconds ahead is tolerated, one more is not. */
  EXPECT_EQ(crl_check(f, f.crl, f.ca, f.revoked, f.crl.this_update - skew).status,
      GCERT_REVOCATION_REVOKED);
  GCERT_Revocation r = crl_check(f, f.crl, f.ca, f.revoked, f.crl.this_update - skew - 1);
  EXPECT_EQ(r.status, GCERT_REVOCATION_UNUSABLE);
  EXPECT_EQ(r.reason, GCERT_REVOCATION_NOT_YET_VALID);
  /* nextUpdate: skew seconds past is tolerated, one more is stale. */
  EXPECT_EQ(crl_check(f, f.crl, f.ca, f.revoked, f.crl.next_update + skew).status,
      GCERT_REVOCATION_REVOKED);
  r = crl_check(f, f.crl, f.ca, f.revoked, f.crl.next_update + skew + 1);
  EXPECT_EQ(r.status, GCERT_REVOCATION_UNUSABLE);
  EXPECT_EQ(r.reason, GCERT_REVOCATION_STALE);

  /* The skew is the policy's, and 0 means the default. */
  GCERT_RevocationPolicy p;
  gcert_revocation_policy_default(&p);
  p.clock_skew = 1;
  EXPECT_EQ(crl_check(f, f.crl, f.ca, f.revoked, f.crl.next_update + 1, &p).status,
      GCERT_REVOCATION_REVOKED);
  EXPECT_EQ(crl_check(f, f.crl, f.ca, f.revoked, f.crl.next_update + 2, &p).reason,
      GCERT_REVOCATION_STALE);
  std::memset(&p, 0, sizeof p);
  EXPECT_EQ(crl_check(f, f.crl, f.ca, f.revoked, f.crl.next_update + skew, &p).status,
      GCERT_REVOCATION_REVOKED);
}

TEST(RevocationCrl, NoNextUpdateUsesTheAgeLimit) {
  Fx f;
  GCERT_Crl crl = f.crl;
  crl.next_set = 0;
  const int64_t age = GCERT_REVOCATION_MAX_AGE_DEFAULT;
  EXPECT_EQ(crl_check(f, crl, f.ca, f.revoked, crl.this_update + age).status,
      GCERT_REVOCATION_REVOKED);
  EXPECT_EQ(crl_check(f, crl, f.ca, f.revoked, crl.this_update + age + 1).reason,
      GCERT_REVOCATION_STALE);
  GCERT_RevocationPolicy p;
  gcert_revocation_policy_default(&p);
  p.max_age = 60;
  EXPECT_EQ(crl_check(f, crl, f.ca, f.revoked, crl.this_update + 61, &p).reason,
      GCERT_REVOCATION_STALE);
}

TEST(RevocationCrl, Arguments) {
  Fx f;
  GCERT_Revocation r;
  EXPECT_EQ(gcert_crl_check(&f.crl, &f.ca, &f.revoked, 0, nullptr, nullptr), GCERT_ERR_INVALID);
  EXPECT_EQ(gcert_crl_check(nullptr, &f.ca, &f.revoked, 0, nullptr, &r), GCERT_ERR_INVALID);
  EXPECT_EQ(r.status, GCERT_REVOCATION_UNUSABLE);  /* never left unset */
  EXPECT_EQ(gcert_crl_check(&f.crl, nullptr, &f.revoked, 0, nullptr, &r), GCERT_ERR_INVALID);
  EXPECT_EQ(gcert_crl_check(&f.crl, &f.ca, nullptr, 0, nullptr, &r), GCERT_ERR_INVALID);
}

/* --- OCSP ------------------------------------------------------------------ */

TEST(RevocationOcsp, GoodRevokedAndTheSha1CertId) {
  Fx f;
  Resp good("rev-ocsp-good.der");
  Resp revoked("rev-ocsp-revoked.der");
  Resp sha1("rev-ocsp-good-sha1.der");
  int64_t now = good.ocsp.produced_at + 60;
  GCERT_Revocation r = ocsp_check(good, f.ca, nullptr, f.good, now);
  EXPECT_EQ(r.status, GCERT_REVOCATION_GOOD);
  r = ocsp_check(revoked, f.ca, nullptr, f.revoked, now);
  EXPECT_EQ(r.status, GCERT_REVOCATION_REVOKED);
  EXPECT_GT(r.revoked_at, 0);
  r = ocsp_check(sha1, f.ca, nullptr, f.good, now);
  EXPECT_EQ(r.status, GCERT_REVOCATION_GOOD);
}

TEST(RevocationOcsp, AnotherCertificateIsNotThisAnswer) {
  Fx f;
  Resp good("rev-ocsp-good.der");
  GCERT_Revocation r = ocsp_check(good, f.ca, nullptr, f.revoked, good.ocsp.produced_at + 60);
  EXPECT_EQ(r.status, GCERT_REVOCATION_UNUSABLE);
  EXPECT_EQ(r.reason, GCERT_REVOCATION_UNKNOWN_CERT);
}

TEST(RevocationOcsp, SignedByTheWrongKey) {
  Fx f;
  Resp forged("rev-ocsp-other-signed.der");
  GCERT_Revocation r = ocsp_check(forged, f.ca, nullptr, f.good, forged.ocsp.produced_at + 60);
  EXPECT_EQ(r.status, GCERT_REVOCATION_UNUSABLE);
  EXPECT_EQ(r.reason, GCERT_REVOCATION_BAD_SIGNATURE);
  /* Handing it the other CA as the responder does not rescue it: that CA did
   * not sign the responder certificate, the real one did not sign it. */
  r = ocsp_check(forged, f.ca, &f.other, f.good, forged.ocsp.produced_at + 60);
  EXPECT_EQ(r.reason, GCERT_REVOCATION_RESPONDER);
}

TEST(RevocationOcsp, ADelegatedResponder) {
  Fx f;
  Resp delegated("rev-ocsp-delegated.der");
  int64_t now = delegated.ocsp.produced_at + 60;
  /* Without being told about the responder the issuer's key is the only one
   * tried, and fails closed. */
  EXPECT_EQ(ocsp_check(delegated, f.ca, nullptr, f.good, now).reason,
      GCERT_REVOCATION_BAD_SIGNATURE);
  EXPECT_EQ(ocsp_check(delegated, f.ca, &f.responder, f.good, now).status,
      GCERT_REVOCATION_GOOD);
  /* A certificate the CA signed but not for OCSP signing is not a responder. */
  Resp plain("rev-ocsp-plain-delegate.der");
  EXPECT_EQ(ocsp_check(plain, f.ca, &f.plain, f.good, plain.ocsp.produced_at + 60).reason,
      GCERT_REVOCATION_RESPONDER);
  /* An authorised responder that is no longer in force is not one. */
  GCERT_X509 old = f.responder;
  old.not_after = now - 1;
  EXPECT_EQ(ocsp_check(delegated, f.ca, &old, f.good, now).reason, GCERT_REVOCATION_RESPONDER);
  GCERT_X509 future = f.responder;
  future.not_before = now + 1;
  EXPECT_EQ(ocsp_check(delegated, f.ca, &future, f.good, now).reason,
      GCERT_REVOCATION_RESPONDER);
  /* One that carries an extendedKeyUsage naming anything but OCSP signing. */
  GCERT_X509 wrong_eku = f.responder;
  wrong_eku.eku = GCERT_X509_EKU_SERVER_AUTH;
  EXPECT_EQ(ocsp_check(delegated, f.ca, &wrong_eku, f.good, now).reason,
      GCERT_REVOCATION_RESPONDER);
  /* anyExtendedKeyUsage is not OCSP signing either. */
  GCERT_X509 any = f.responder;
  any.eku = GCERT_X509_EKU_ANY;
  EXPECT_EQ(ocsp_check(delegated, f.ca, &any, f.good, now).reason, GCERT_REVOCATION_RESPONDER);
}

TEST(RevocationOcsp, UnknownIsNotGood) {
  Fx f;
  Resp unknown("rev-ocsp-unknown.der");
  GCERT_Revocation r = ocsp_check(unknown, f.ca, nullptr, f.unknown,
      unknown.ocsp.produced_at + 60);
  EXPECT_EQ(r.status, GCERT_REVOCATION_UNUSABLE);
  EXPECT_EQ(r.reason, GCERT_REVOCATION_UNKNOWN_CERT);
  /* So a hard-fail policy refuses a certificate its own CA's responder
   * has never heard of. */
  EXPECT_EQ(gcert_revocation_verdict(&r, 1, nullptr), GCERT_ERR_MISMATCH);
}

TEST(RevocationOcsp, AResponderTheIssuerDidNotSign) {
  Fx f;
  Resp foreign("rev-ocsp-foreign.der");
  /* It carries id-kp-OCSPSigning and its own signature is good, but another
   * CA's key signed it. */
  GCERT_Revocation r = ocsp_check(foreign, f.ca, &f.foreign, f.good,
      foreign.ocsp.produced_at + 60);
  EXPECT_EQ(r.status, GCERT_REVOCATION_UNUSABLE);
  EXPECT_EQ(r.reason, GCERT_REVOCATION_RESPONDER);
}

TEST(RevocationOcsp, FreshnessAtTheEdges) {
  Fx f;
  Resp good("rev-ocsp-good.der");
  GCERT_Ocsp_Single single;
  /* Read the response's own thisUpdate and nextUpdate. */
  unsigned char name[32];
  unsigned char key[32];
  ASSERT_EQ(gsec_sha256(f.ca.subject, f.ca.subject_len, name), GSEC_OK);
  ASSERT_EQ(gsec_sha256(f.ca.key_bits, f.ca.key_bits_len, key), GSEC_OK);
  ASSERT_EQ(gcert_ocsp_status(&good.ocsp, GSEC_HMAC_SHA256, name, 32, key, 32,
      f.good.serial, f.good.serial_len, &single), GCERT_OK);
  ASSERT_TRUE(single.have_next_update);
  const int64_t skew = GCERT_REVOCATION_SKEW_DEFAULT;
  EXPECT_EQ(ocsp_check(good, f.ca, nullptr, f.good, single.this_update - skew).status,
      GCERT_REVOCATION_GOOD);
  EXPECT_EQ(ocsp_check(good, f.ca, nullptr, f.good, single.this_update - skew - 1).reason,
      GCERT_REVOCATION_NOT_YET_VALID);
  EXPECT_EQ(ocsp_check(good, f.ca, nullptr, f.good, single.next_update + skew).status,
      GCERT_REVOCATION_GOOD);
  EXPECT_EQ(ocsp_check(good, f.ca, nullptr, f.good, single.next_update + skew + 1).reason,
      GCERT_REVOCATION_STALE);
}

TEST(RevocationOcsp, IssuerThatMayNotSign) {
  Fx f;
  Resp good("rev-ocsp-good.der");
  int64_t now = good.ocsp.produced_at + 60;
  /* The CA signing the response directly does not need cRLSign. */
  GCERT_X509 no_crl_sign = f.ca;
  no_crl_sign.key_usage_set = 1;
  no_crl_sign.key_usage = 0x04;
  EXPECT_EQ(ocsp_check(good, no_crl_sign, nullptr, f.good, now).status, GCERT_REVOCATION_GOOD);
  GCERT_X509 not_ca = f.ca;
  not_ca.basic_constraints = 1;
  not_ca.ca = 0;
  EXPECT_EQ(ocsp_check(good, not_ca, nullptr, f.good, now).reason, GCERT_REVOCATION_CANNOT_SIGN);
  EXPECT_EQ(ocsp_check(good, f.ca, nullptr, f.good, now).status, GCERT_REVOCATION_GOOD);
}

TEST(RevocationOcsp, ACertificateFromAnotherIssuer) {
  Fx f;
  Resp good("rev-ocsp-good.der");
  auto p256 = load("p256-ca.der");
  GCERT_X509 stranger;
  ASSERT_EQ(gcert_x509_parse(p256.data(), p256.size(), &stranger), GCERT_OK);
  EXPECT_EQ(ocsp_check(good, stranger, nullptr, f.good, good.ocsp.produced_at + 60).reason,
      GCERT_REVOCATION_WRONG_ISSUER);
}

/* --- The decision ---------------------------------------------------------- */

TEST(RevocationVerdict, TheDecisionIsMadeInOnePlace) {
  GCERT_Revocation good = {GCERT_REVOCATION_GOOD, GCERT_REVOCATION_NONE, 0};
  GCERT_Revocation revoked = {GCERT_REVOCATION_REVOKED, GCERT_REVOCATION_NONE, 0};
  GCERT_Revocation stale = {GCERT_REVOCATION_UNUSABLE, GCERT_REVOCATION_STALE, 0};
  GCERT_RevocationPolicy hard;
  GCERT_RevocationPolicy soft;
  gcert_revocation_policy_default(&hard);
  gcert_revocation_policy_default(&soft);
  soft.soft_fail = 1;

  EXPECT_EQ(gcert_revocation_verdict(&good, 1, &hard), GCERT_OK);
  EXPECT_EQ(gcert_revocation_verdict(&revoked, 1, &hard), GCERT_ERR_MISMATCH);
  EXPECT_EQ(gcert_revocation_verdict(&revoked, 1, &soft), GCERT_ERR_MISMATCH);

  /* Nothing usable: the policy decides. */
  EXPECT_EQ(gcert_revocation_verdict(&stale, 1, &hard), GCERT_ERR_MISMATCH);
  EXPECT_EQ(gcert_revocation_verdict(&stale, 1, &soft), GCERT_OK);
  EXPECT_EQ(gcert_revocation_verdict(nullptr, 0, &hard), GCERT_ERR_MISMATCH);
  EXPECT_EQ(gcert_revocation_verdict(nullptr, 0, &soft), GCERT_OK);
  EXPECT_EQ(gcert_revocation_verdict(nullptr, 0, nullptr), GCERT_ERR_MISMATCH);  /* hard by default */

  /* Several pieces: unusable never outvotes good, and nothing outvotes revoked. */
  GCERT_Revocation mix[3] = {stale, good, stale};
  EXPECT_EQ(gcert_revocation_verdict(mix, 3, &hard), GCERT_OK);
  GCERT_Revocation worse[3] = {good, stale, revoked};
  EXPECT_EQ(gcert_revocation_verdict(worse, 3, &soft), GCERT_ERR_MISMATCH);
  GCERT_Revocation rev_first[2] = {revoked, good};
  EXPECT_EQ(gcert_revocation_verdict(rev_first, 2, &soft), GCERT_ERR_MISMATCH);

  EXPECT_EQ(gcert_revocation_verdict(nullptr, 1, &hard), GCERT_ERR_INVALID);
}

TEST(RevocationVerdict, FixturesEndToEnd) {
  /* The CRL and the OCSP response agree about both certificates, and the
   * verdict over the pair is what a TLS client would act on. */
  Fx f;
  Resp good("rev-ocsp-good.der");
  Resp revoked("rev-ocsp-revoked.der");
  int64_t now = f.crl.this_update + 3600;
  GCERT_Revocation for_good[2];
  GCERT_Revocation for_revoked[2];
  for_good[0] = crl_check(f, f.crl, f.ca, f.good, now);
  for_good[1] = ocsp_check(good, f.ca, nullptr, f.good, now);
  for_revoked[0] = crl_check(f, f.crl, f.ca, f.revoked, now);
  for_revoked[1] = ocsp_check(revoked, f.ca, nullptr, f.revoked, now);
  EXPECT_EQ(gcert_revocation_verdict(for_good, 2, nullptr), GCERT_OK);
  EXPECT_EQ(gcert_revocation_verdict(for_revoked, 2, nullptr), GCERT_ERR_MISMATCH);
  /* An hour after the CRL's nextUpdate and the OCSP window both closed, the
   * same pair is stale, and the default refuses. */
  int64_t late = f.crl.next_update + 365 * 86400;
  for_good[0] = crl_check(f, f.crl, f.ca, f.good, late);
  for_good[1] = ocsp_check(good, f.ca, nullptr, f.good, late);
  EXPECT_EQ(for_good[0].status, GCERT_REVOCATION_UNUSABLE);
  EXPECT_EQ(for_good[1].status, GCERT_REVOCATION_UNUSABLE);
  EXPECT_EQ(gcert_revocation_verdict(for_good, 2, nullptr), GCERT_ERR_MISMATCH);
}

int main(int argc, char ** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
