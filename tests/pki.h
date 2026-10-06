/**
 * @file
 *
 * Build small certificate hierarchies for the tests, in memory, with
 * gcert_x509_issue and Ed25519 keys (fast, and no fixture to expire).
 *
 * A certificate is described by a Spec and issued by another key. The
 * validity defaults to a window that contains kNow.
 *
 * Copyright 2026 by Corey Pennycuff
 */

#ifndef GHOTI_IO_GCERT_TEST_PKI_H
#define GHOTI_IO_GCERT_TEST_PKI_H

#include "test_helpers.h"

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

namespace pki {

typedef std::vector<unsigned char> Bytes;

const int64_t kNow = 1700000000;          /* 2023-11-14 */
const int64_t kDay = 86400;

struct Key {
  unsigned char seed[32];
  unsigned char pub[32];
};

inline Key key(unsigned char tag) {
  Key k;
  std::memset(k.seed, tag, sizeof k.seed);
  EXPECT_EQ(gsec_ed25519_public(k.seed, k.pub), GSEC_OK);
  return k;
}

inline void len(Bytes & out, size_t n) {
  if (n < 128) {
    out.push_back(static_cast<unsigned char>(n));
  } else {
    out.push_back(0x82);
    out.push_back(static_cast<unsigned char>(n >> 8));
    out.push_back(static_cast<unsigned char>(n));
  }
}

inline Bytes tlv(unsigned char tag, const Bytes & body) {
  Bytes out{tag};
  len(out, body.size());
  out.insert(out.end(), body.begin(), body.end());
  return out;
}

/** Name ::= one RDN holding commonName. */
inline Bytes name(const std::string & cn) {
  Bytes atv{0x06, 0x03, 0x55, 0x04, 0x03};
  Bytes text(cn.begin(), cn.end());
  Bytes val = tlv(0x0c, text);
  atv.insert(atv.end(), val.begin(), val.end());
  return tlv(0x30, tlv(0x31, tlv(0x30, atv)));
}

struct Spec {
  std::string subject = "leaf";
  std::string issuer = "ca";
  Key subject_key = key(1);
  Key signer = key(2);
  bool ca = false;
  int path_len = -1;
  int64_t not_before = kNow - 30 * kDay;
  int64_t not_after = kNow + 30 * kDay;
  unsigned serial = 1;
  std::string dns;
  std::string uri;
  std::string email;
  Bytes ip;
  Bytes ski;
  Bytes aki;
};

inline Bytes issue(const Spec & s) {
  Bytes subject = name(s.subject);
  Bytes issuer = name(s.issuer);
  unsigned char serial[2] = {static_cast<unsigned char>(s.serial >> 8),
      static_cast<unsigned char>(s.serial)};
  GCERT_X509_Tbs tbs;
  std::memset(&tbs, 0, sizeof tbs);
  tbs.issuer = issuer.data();
  tbs.issuer_len = issuer.size();
  tbs.subject = subject.data();
  tbs.subject_len = subject.size();
  tbs.not_before = s.not_before;
  tbs.not_after = s.not_after;
  tbs.serial = serial;
  tbs.serial_len = 2;
  tbs.subject_key = GCERT_X509_ED25519;
  tbs.point = s.subject_key.pub;
  tbs.point_len = 32;
  tbs.ca = s.ca;
  tbs.path_len_set = s.path_len >= 0;
  tbs.path_len = s.path_len >= 0 ? static_cast<uint32_t>(s.path_len) : 0;
  tbs.dns = s.dns.data();
  tbs.dns_len = s.dns.size();
  tbs.uri = s.uri.data();
  tbs.uri_len = s.uri.size();
  tbs.email = s.email.data();
  tbs.email_len = s.email.size();
  tbs.ip = s.ip.data();
  tbs.ip_len = s.ip.size();
  tbs.ski = s.ski.data();
  tbs.ski_len = s.ski.size();
  tbs.aki = s.aki.data();
  tbs.aki_len = s.aki.size();
  GCERT_X509_Signer signer;
  std::memset(&signer, 0, sizeof signer);
  signer.key = GCERT_X509_ED25519;
  signer.d = s.signer.seed;
  signer.d_len = 32;
  Bytes out(2048);
  size_t n = 0;
  EXPECT_EQ(gcert_x509_issue(&tbs, &signer, out.data(), out.size(), &n), GCERT_OK);
  out.resize(n);
  return out;
}

/** A self-signed CA called @p cn with key @p k. */
inline Bytes root(const std::string & cn, const Key & k, unsigned char id = 0) {
  Spec s;
  s.subject = cn;
  s.issuer = cn;
  s.subject_key = k;
  s.signer = k;
  s.ca = true;
  if (id != 0) {
    s.ski = Bytes(4, id);
  }
  return issue(s);
}

/** @p cn, a CA or a leaf, signed by @p issuer_cn with @p signer. */
inline Bytes signed_by(const std::string & cn, const Key & k,
    const std::string & issuer_cn, const Key & signer, bool ca,
    unsigned char ski = 0, unsigned char aki = 0) {
  Spec s;
  s.subject = cn;
  s.issuer = issuer_cn;
  s.subject_key = k;
  s.signer = signer;
  s.ca = ca;
  if (ski != 0) {
    s.ski = Bytes(4, ski);
  }
  if (aki != 0) {
    s.aki = Bytes(4, aki);
  }
  return issue(s);
}

} /* namespace pki */

#endif /* GHOTI_IO_GCERT_TEST_PKI_H */
