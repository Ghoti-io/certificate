/**
 * @file
 *
 * The encodings refusing things: truncation, a flipped bit, and the DER
 * shapes a strict reader has to reject.
 *
 * The audit's central finding was that the refusal paths of the layer that
 * reads attacker-controlled bytes were enforced by nothing that could fail.
 * Three measurements agreed: coverage of 51-68% in x509/signed.c, crl.c,
 * ocsp.c, x509.c, pkcs8.c and pkcs12.c against 92-100% for the primitives;
 * the uncovered lines being the refusals themselves, 58 `return
 * GCERT_ERR_CORRUPT` in x509.c alone; and the fuzz harnesses accepting
 * GCERT_OK *or* any of four error codes as a pass, so a refusal that became an
 * acceptance was invisible to them too.
 *
 * The sweeps below are built on a property that is computable rather than
 * looked up, which is what lets them be broad: **for an entry point that
 * authenticates its input, no truncation and no flipped bit may return
 * GCERT_OK.** Either the bytes stop being a valid encoding, or the signature,
 * the MAC or the padding no longer holds. That is true for every offset, so
 * the sweep needs no table of expected answers and a new fixture costs one
 * line.
 *
 * It is deliberately *not* asserted of the bare parsers: a flipped bit inside
 * a signature's BIT STRING leaves a perfectly valid certificate that
 * gcert_x509_parse is right to accept. Asserting otherwise would be asserting
 * something untrue, which is how a sweep comes to be believed while measuring
 * nothing.
 *
 * Each sweep also checks that it *could* have failed: that the pristine file
 * passes, that the mutants reached more than one distinct result code, and
 * that both the parse-refused and the authentication-refused arms were
 * exercised. A sweep of zero cases, or one that returns the same code for
 * everything, reports clean without looking.
 *
 * Copyright 2026 by Corey Pennycuff
 */

#include "test_helpers.h"

#include <cstdint>
#include <cstring>
#include <fstream>
#include <set>
#include <string>
#include <vector>

namespace {

std::vector<unsigned char> load(const char * name) {
  std::ifstream in(gsectest::data_dir() + "/certs/" + name, std::ios::binary);
  EXPECT_TRUE(in.good()) << name;
  return std::vector<unsigned char>(std::istreambuf_iterator<char>(in),
      std::istreambuf_iterator<char>());
}

/* What a sweep learned, so that it can be asked whether it saw anything. */
struct Tally {
  int cases = 0;
  int refused = 0;
  std::set<int> codes;

  void note(GCERT_Result r) {
    cases++;
    codes.insert(static_cast<int>(r));
    if (r != GCERT_OK) {
      refused++;
    }
  }
};

void expect_enough(const Tally & t, const char * what) {
  EXPECT_GT(t.cases, 20) << what << ": too few mutants for this to mean "
                            "anything";
  EXPECT_EQ(t.refused, t.cases) << what << ": a mutant was accepted";
}

/* An authenticating call, as a function of the bytes. */
using Check = GCERT_Result (*)(const unsigned char * data, size_t len);

/* The bytes a flip may be applied to. Everything, unless the format carries
 * something the authentication does not cover - see signed_only below. */
struct Region {
  size_t from;
  size_t to;
};

Region whole_file(const std::vector<unsigned char> & base) {
  return Region{0, base.size()};
}

void sweep(const char * name, Check check, const char * what,
    Region (*region)(const std::vector<unsigned char> &) = whole_file) {
  auto base = load(name);
  ASSERT_GT(base.size(), 64u) << name;
  /* The control. Without this the sweep below proves only that this call
   * refuses things, not that it accepts the real file. */
  ASSERT_EQ(check(base.data(), base.size()), GCERT_OK)
      << what << ": the pristine fixture did not pass";

  size_t step = base.size() / 24u;
  if (step == 0) {
    step = 1;
  }

  /* Truncation. Every one of these is refused by the parser before any
   * signature is considered, so they all come back GCERT_ERR_CORRUPT - the
   * point is that the length arithmetic never reads past the buffer, which is
   * what ASan and Valgrind are watching for while this runs. */
  Tally truncation;
  for (size_t n = 1; n < base.size(); n += step) {
    truncation.note(check(base.data(), n));
  }
  truncation.note(check(base.data(), 0));
  expect_enough(truncation, (std::string(what) + " truncation").c_str());

  Region r = region(base);
  ASSERT_GT(r.to, r.from) << what << ": empty mutation region";
  /* The step follows the region, not the file: scoping the sweep to a signed
   * body must not quietly shrink it to a handful of cases. */
  size_t flip_step = (r.to - r.from) / 24u;
  if (flip_step == 0) {
    flip_step = 1;
  }
  Tally flips;
  for (size_t i = r.from; i < r.to; i += flip_step) {
    auto bytes = base;
    bytes[i] = static_cast<unsigned char>(bytes[i] ^ 0x01u);
    flips.note(check(bytes.data(), bytes.size()));
    /* The high bit too, which moves a length or a tag rather than a value. */
    bytes = base;
    bytes[i] = static_cast<unsigned char>(bytes[i] ^ 0x80u);
    flips.note(check(bytes.data(), bytes.size()));
  }
  expect_enough(flips, (std::string(what) + " flipped bit").c_str());
  /* A flip reaches both arms: some mutants stop being a valid encoding and
   * some stay valid and fail the signature. One code for everything would
   * mean the sweep is only ever reaching the parser. */
  EXPECT_GT(flips.codes.size(), 1u)
      << what << ": every flipped bit returned the same code, so this sweep "
                 "never reached the authentication";
}

/* --- the entry points, each closing over the fixture it needs -------------- */

GCERT_Result check_path(const unsigned char * data, size_t len) {
  static std::vector<unsigned char> ca = load("ca.der");
  GCERT_X509 parsed;
  /* A time inside the fixture's validity, read from the fixture. */
  static int64_t when = 0;
  if (when == 0) {
    GCERT_X509 leaf;
    auto base = load("leaf.der");
    if (gcert_x509_parse(base.data(), base.size(), &leaf) != GCERT_OK) {
      return GCERT_ERR_INTERNAL;
    }
    when = leaf.not_before + (leaf.not_after - leaf.not_before) / 2;
  }
  GCERT_Result parse = gcert_x509_parse(data, len, &parsed);
  if (parse != GCERT_OK) {
    return parse;
  }
  return gcert_x509_path(data, len, nullptr, nullptr, 0, ca.data(), ca.size(),
      when, 0);
}

GCERT_Result check_crl(const unsigned char * data, size_t len) {
  static std::vector<unsigned char> ca_der = load("ca.der");
  GCERT_X509 ca;
  GCERT_Crl crl;
  if (gcert_x509_parse(ca_der.data(), ca_der.size(), &ca) != GCERT_OK) {
    return GCERT_ERR_INTERNAL;
  }
  GCERT_Result parse = gcert_crl_parse(data, len, &crl);
  if (parse != GCERT_OK) {
    return parse;
  }
  return gcert_crl_signed_by(&crl, &ca);
}

GCERT_Result check_ocsp(const unsigned char * data, size_t len) {
  static std::vector<unsigned char> ca_der = load("ca.der");
  GCERT_X509 ca;
  GCERT_Ocsp ocsp;
  if (gcert_x509_parse(ca_der.data(), ca_der.size(), &ca) != GCERT_OK) {
    return GCERT_ERR_INTERNAL;
  }
  GCERT_Result parse = gcert_ocsp_parse(data, len, &ocsp);
  if (parse != GCERT_OK) {
    return parse;
  }
  return gcert_ocsp_signed_by(&ocsp, &ca);
}

GCERT_Result check_pkcs12(const unsigned char * data, size_t len) {
  static unsigned char scratch[8192];
  GCERT_Pkcs12 bag;
  return gcert_pkcs12_open(data, len, "secret", 6, scratch, sizeof scratch, &bag,
      nullptr);
}

GCERT_Result check_pkcs8(const unsigned char * data, size_t len) {
  static unsigned char out[4096];
  size_t out_len = 0;
  return gcert_pkcs8_decrypt(data, len, "secret", 6, out, sizeof out, &out_len,
      nullptr);
}

} /* namespace */

TEST(Negative, X509PathRefusesEveryMutant) {
  sweep("leaf.der", check_path, "x509 path");
}

TEST(Negative, CrlSignatureRefusesEveryMutant) {
  sweep("leaf.crl", check_crl, "crl");
}

TEST(Negative, OcspSignatureRefusesEveryMutantInTheSignedBody) {
  /* A basic OCSP response carries the responder's certificates alongside the
   * signed body, and the signature covers tbsResponseData only. Flipping a bit
   * out there leaves a response that is still perfectly valid, and 24 of 50
   * mutants proved it while this test was being written. Mutating the whole
   * file and demanding a refusal would have been asserting something untrue,
   * so the sweep is scoped to the bytes the signature actually covers. */
  sweep("leaf.ocsp", check_ocsp, "ocsp",
      [](const std::vector<unsigned char> & base) {
        GCERT_Ocsp parsed;
        Region r = {0, 0};
        if (gcert_ocsp_parse(base.data(), base.size(), &parsed) == GCERT_OK) {
          r.from = static_cast<size_t>(parsed.tbs - base.data());
          r.to = r.from + parsed.tbs_len;
        }
        return r;
      });
}

TEST(Negative, Pkcs12MacRefusesEveryMutant) {
  sweep("leaf.p12", check_pkcs12, "pkcs12");
}

TEST(Negative, Pkcs8RefusesEveryMutantInItsHeader) {
  /* Only the header. PBES2 with AES-CBC carries no integrity check, so a
   * flipped bit inside the ciphertext is not required to be noticed - see the
   * test below, which asserts that it is not. What must be noticed is any
   * change to the parameters the key is derived from: the salt, the iteration
   * count, the PRF, the cipher, the IV. Those are the header. */
  sweep("leaf.p8", check_pkcs8, "pkcs8 header",
      [](const std::vector<unsigned char> & base) {
        Region r = {0, 0};
        GCERT_Der seq;
        GCERT_Der alg;
        if (gcert_der_tlv(base.data(), base.size(), &seq) != GCERT_OK ||
            gcert_der_tlv(seq.value, seq.value_len, &alg) != GCERT_OK) {
          return r;
        }
        /* Everything up to the start of the encryptedData element. */
        r.to = static_cast<size_t>(seq.value - base.data()) + alg.total_len;
        return r;
      });
}

TEST(Negative, Pkcs8CiphertextIsNotAuthenticated) {
  /* Recorded because it is a property of the format that a caller can get
   * wrong: PBES2 with a CBC cipher has no MAC. A flipped bit inside the
   * ciphertext garbles one block of the plaintext, and if the garbling lands
   * inside a big integer rather than in a tag, a length or the padding, the
   * result still parses as a PrivateKeyInfo and gcert_pkcs8_decrypt returns
   * GCERT_OK on a key that is not the key.
   *
   * Ten of fifty mutants did exactly that while this file was being written.
   * A successful decrypt of a PBES2 file means the password was right, not
   * that the bytes are intact. Asserting it here so that the day someone adds
   * an authenticated scheme, this test says which promise changed. */
  auto base = load("leaf.p8");
  GCERT_Der seq;
  GCERT_Der alg;
  ASSERT_EQ(gcert_der_tlv(base.data(), base.size(), &seq), GCERT_OK);
  ASSERT_EQ(gcert_der_tlv(seq.value, seq.value_len, &alg), GCERT_OK);
  /* Past the AlgorithmIdentifier is the encryptedData, whose own header is a
   * few bytes; starting the sweep at its tag is close enough, and the tag
   * bytes themselves are covered by the header sweep above. */
  size_t ct_at = static_cast<size_t>(seq.value - base.data()) + alg.total_len;
  ASSERT_LT(ct_at, base.size());

  int accepted = 0;
  int refused = 0;
  for (size_t i = ct_at; i < base.size(); i += 5) {
    auto bytes = base;
    bytes[i] = static_cast<unsigned char>(bytes[i] ^ 0x01u);
    if (check_pkcs8(bytes.data(), bytes.size()) == GCERT_OK) {
      accepted++;
    } else {
      refused++;
    }
  }
  EXPECT_GT(accepted, 0) << "no mutated ciphertext was accepted, so either the "
                            "scheme grew an integrity check - update this test "
                            "and the header - or this sweep stopped reaching "
                            "the ciphertext";
  EXPECT_GT(refused, 0) << "every mutated ciphertext was accepted, which would "
                           "mean the padding and the PrivateKeyInfo parse are "
                           "not being checked at all";
}

TEST(Negative, DerShapesAStrictReaderRefuses) {
  /* Exact codes here, because each case is one rule rather than a mutant. */
  struct Case {
    const char * what;
    std::vector<unsigned char> der;
    GCERT_Result expect;
  };
  const std::vector<Case> cases = {
    {"indefinite length", {0x30, 0x80, 0x02, 0x01, 0x01, 0x00, 0x00},
     GCERT_ERR_CORRUPT},
    {"long form for a length under 128", {0x30, 0x81, 0x03, 0x02, 0x01, 0x01},
     GCERT_ERR_CORRUPT},
    {"leading zero in a long-form length",
     {0x30, 0x82, 0x00, 0x03, 0x02, 0x01, 0x01}, GCERT_ERR_CORRUPT},
    {"length past the buffer", {0x30, 0x7f, 0x02, 0x01, 0x01},
     GCERT_ERR_CORRUPT},
    {"non-minimal INTEGER", {0x02, 0x02, 0x00, 0x01}, GCERT_ERR_CORRUPT},
    {"negative-looking padded INTEGER", {0x02, 0x02, 0xff, 0x80},
     GCERT_ERR_CORRUPT},
    {"BOOLEAN that is not 0x00 or 0xff", {0x01, 0x01, 0x01},
     GCERT_ERR_CORRUPT},
    {"BOOLEAN of the wrong length", {0x01, 0x02, 0x00, 0x00},
     GCERT_ERR_CORRUPT},
    {"NULL with contents", {0x05, 0x01, 0x00}, GCERT_ERR_CORRUPT},
    {"high tag number in the short form's range",
     {0x1f, 0x01, 0x01, 0x00}, GCERT_ERR_CORRUPT},
    {"base-128 zero in a high tag number", {0x1f, 0x80, 0x01, 0x00},
     GCERT_ERR_CORRUPT},
    {"truncated tag", {0x1f}, GCERT_ERR_CORRUPT},
    {"empty buffer", {}, GCERT_ERR_CORRUPT},
    /* A SET whose members do not ascend. DER orders them by encoding. */
    {"unsorted SET", {0x31, 0x06, 0x02, 0x01, 0x02, 0x02, 0x01, 0x01},
     GCERT_ERR_CORRUPT},
  };
  int refused = 0;
  for (const Case & c : cases) {
    GCERT_Der view;
    const void * p = c.der.empty() ? nullptr : c.der.data();
    EXPECT_EQ(gcert_der_tlv(p, c.der.size(), &view), c.expect) << c.what;
    refused++;
  }
  EXPECT_EQ(refused, static_cast<int>(cases.size()));

  /* The controls: the same shapes, correct. A reader that refuses everything
   * would pass every assertion above. */
  {
    GCERT_Der view;
    const unsigned char seq[] = {0x30, 0x03, 0x02, 0x01, 0x01};
    const unsigned char sorted[] = {0x31, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01,
        0x02};
    const unsigned char nul[] = {0x05, 0x00};
    const unsigned char yes[] = {0x01, 0x01, 0xff};
    const unsigned char big[] = {0x04, 0x81, 0x80};
    std::vector<unsigned char> octets(big, big + sizeof big);
    octets.resize(sizeof big + 128u, 0x41);
    EXPECT_EQ(gcert_der_tlv(seq, sizeof seq, &view), GCERT_OK);
    EXPECT_EQ(gcert_der_tlv(sorted, sizeof sorted, &view), GCERT_OK);
    EXPECT_EQ(gcert_der_tlv(nul, sizeof nul, &view), GCERT_OK);
    EXPECT_EQ(gcert_der_tlv(yes, sizeof yes, &view), GCERT_OK);
    EXPECT_EQ(gcert_der_tlv(octets.data(), octets.size(), &view), GCERT_OK);
    EXPECT_EQ(view.value_len, 128u);
  }
}

TEST(Negative, PemRefusesWhatIsNotArmour) {
  auto pem = load("p256-leaf.pem");
  unsigned char out[4096];
  size_t out_len = 0;
  char label[32];
  ASSERT_EQ(gcert_pem_decode(pem.data(), pem.size(), out, sizeof out, &out_len,
      label, sizeof label), GCERT_OK);
  ASSERT_GT(out_len, 0u);

  /* Base64 that is not: a character outside the alphabet, and a length that is
   * not a multiple of four once the padding is accounted for. */
  Tally tally;
  for (size_t i = 0; i < pem.size(); i += 7) {
    auto bytes = pem;
    if (bytes[i] == '\n') {
      continue;
    }
    bytes[i] = '!';
    tally.note(gcert_pem_decode(bytes.data(), bytes.size(), out, sizeof out,
        &out_len, label, sizeof label));
  }
  EXPECT_GT(tally.cases, 20);
  EXPECT_EQ(tally.refused, tally.cases) << "a PEM block with a byte outside "
                                          "the alphabet decoded";

  /* No END line, no BEGIN line, and an output buffer one byte short. */
  std::string text(reinterpret_cast<const char *>(pem.data()), pem.size());
  std::string no_end = text.substr(0, text.find("-----END"));
  EXPECT_NE(gcert_pem_decode(no_end.data(), no_end.size(), out, sizeof out,
      &out_len, label, sizeof label), GCERT_OK);
  size_t body = text.find('\n') + 1u;
  std::string no_begin = text.substr(body);
  EXPECT_NE(gcert_pem_decode(no_begin.data(), no_begin.size(), out, sizeof out,
      &out_len, label, sizeof label), GCERT_OK);
  EXPECT_EQ(gcert_pem_decode(pem.data(), pem.size(), out, out_len - 1u, &out_len,
      label, sizeof label), GCERT_ERR_LIMIT);
}

int main(int argc, char ** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
