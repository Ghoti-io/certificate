/**
 * @file
 *
 * Reading identities out of a certificate (identity.h): every entry of a
 * subjectAltName in order, and the attributes of a name by kind and index.
 *
 * Copyright 2026 by Corey Pennycuff
 */

#include "pki.h"

#include <cstring>
#include <string>
#include <vector>

namespace {

using pki::Bytes;

Bytes cat(std::initializer_list<Bytes> parts) {
  Bytes out;
  for (const Bytes & p : parts) {
    out.insert(out.end(), p.begin(), p.end());
  }
  return out;
}

/* AttributeTypeAndValue with the given OID content and string tag. */
Bytes atv(const Bytes & oid, unsigned char tag, const std::string & text) {
  Bytes t(text.begin(), text.end());
  return pki::tlv(0x30, cat({pki::tlv(0x06, oid), pki::tlv(tag, t)}));
}

Bytes rdn(std::initializer_list<Bytes> atvs) {
  return pki::tlv(0x31, cat(atvs));
}

const Bytes kCn = {0x55, 0x04, 0x03};
const Bytes kC = {0x55, 0x04, 0x06};
const Bytes kO = {0x55, 0x04, 0x0a};
const Bytes kOu = {0x55, 0x04, 0x0b};
const Bytes kEmail = {0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x01};

std::string attr(const Bytes & name, GCERT_NameAttr a, size_t i, GCERT_Result * r = nullptr) {
  const unsigned char * v = nullptr;
  size_t n = 0;
  GCERT_Result res = gcert_x509_name_attr(name.data(), name.size(), a, i, &v, &n);
  if (r != nullptr) {
    *r = res;
  }
  return res == GCERT_OK ? std::string(reinterpret_cast<const char *>(v), n) : std::string();
}

struct Entry {
  unsigned choice;
  std::string value;
};

std::vector<Entry> sans(const GCERT_X509 & c, GCERT_Result * last = nullptr) {
  std::vector<Entry> out;
  size_t cursor = 0;
  for (;;) {
    unsigned choice = 99;
    const unsigned char * v = nullptr;
    size_t n = 0;
    GCERT_Result r = gcert_x509_san_next(&c, &cursor, &choice, &v, &n);
    if (r != GCERT_OK) {
      if (last != nullptr) {
        *last = r;
      }
      return out;
    }
    out.push_back({choice, std::string(reinterpret_cast<const char *>(v), n)});
  }
}

} /* namespace */

TEST(Identity, NameAttributesByKindAndIndex) {
  Bytes name = pki::tlv(0x30, cat({
      rdn({atv(kC, 19, "US")}),
      rdn({atv(kO, 12, "Example Corp")}),
      rdn({atv(kOu, 12, "Eng")}),
      rdn({atv(kOu, 12, "Ops")}),
      rdn({atv(kCn, 12, "alice"), atv(kEmail, 22, "alice@example.com")}),
  }));
  EXPECT_EQ(attr(name, GCERT_ATTR_COUNTRY, 0), "US");
  EXPECT_EQ(attr(name, GCERT_ATTR_ORGANIZATION, 0), "Example Corp");
  EXPECT_EQ(attr(name, GCERT_ATTR_ORG_UNIT, 0), "Eng");
  EXPECT_EQ(attr(name, GCERT_ATTR_ORG_UNIT, 1), "Ops");
  EXPECT_EQ(attr(name, GCERT_ATTR_COMMON_NAME, 0), "alice");
  /* A multi-valued RDN's second attribute is found too. */
  EXPECT_EQ(attr(name, GCERT_ATTR_EMAIL, 0), "alice@example.com");

  GCERT_Result r;
  attr(name, GCERT_ATTR_ORG_UNIT, 2, &r);
  EXPECT_EQ(r, GCERT_ERR_FORMAT);
  attr(name, GCERT_ATTR_LOCALITY, 0, &r);
  EXPECT_EQ(r, GCERT_ERR_FORMAT);
  attr(name, GCERT_ATTR_COMMON_NAME, 1, &r);
  EXPECT_EQ(r, GCERT_ERR_FORMAT);
}

TEST(Identity, OnlyEncodingsItCanVouchFor) {
  /* A BMPString common name is not returned as bytes that mean something else. */
  Bytes bmp = pki::tlv(0x30, rdn({atv(kCn, 30, std::string("\0a\0b", 4))}));
  GCERT_Result r;
  attr(bmp, GCERT_ATTR_COMMON_NAME, 0, &r);
  EXPECT_EQ(r, GCERT_ERR_UNSUPPORTED);
  Bytes teletex = pki::tlv(0x30, rdn({atv(kCn, 20, "ab")}));
  attr(teletex, GCERT_ATTR_COMMON_NAME, 0, &r);
  EXPECT_EQ(r, GCERT_ERR_UNSUPPORTED);
  /* The one it can't read does not hide the next one that it can. */
  Bytes mixed = pki::tlv(0x30, cat({rdn({atv(kCn, 30, std::string("\0a", 2))}),
      rdn({atv(kCn, 12, "ok")})}));
  attr(mixed, GCERT_ATTR_COMMON_NAME, 0, &r);
  EXPECT_EQ(r, GCERT_ERR_UNSUPPORTED);
  EXPECT_EQ(attr(mixed, GCERT_ATTR_COMMON_NAME, 1), "ok");
  /* An empty name has no attributes. */
  Bytes empty = {0x30, 0x00};
  attr(empty, GCERT_ATTR_COMMON_NAME, 0, &r);
  EXPECT_EQ(r, GCERT_ERR_FORMAT);
}

TEST(Identity, MalformedNamesAndArguments) {
  Bytes good = pki::name("alice");
  const unsigned char * v;
  size_t n;
  Bytes truncated(good.begin(), good.end() - 1);
  EXPECT_EQ(gcert_x509_name_attr(truncated.data(), truncated.size(), GCERT_ATTR_COMMON_NAME, 0,
      &v, &n), GCERT_ERR_CORRUPT);
  Bytes trailing = good;
  trailing.push_back(0);
  EXPECT_EQ(gcert_x509_name_attr(trailing.data(), trailing.size(), GCERT_ATTR_COMMON_NAME, 0,
      &v, &n), GCERT_ERR_CORRUPT);
  Bytes not_a_seq = {0x31, 0x00};
  EXPECT_EQ(gcert_x509_name_attr(not_a_seq.data(), not_a_seq.size(), GCERT_ATTR_COMMON_NAME, 0,
      &v, &n), GCERT_ERR_CORRUPT);
  EXPECT_EQ(gcert_x509_name_attr(good.data(), good.size(), static_cast<GCERT_NameAttr>(0), 0,
      &v, &n), GCERT_ERR_INVALID);
  EXPECT_EQ(gcert_x509_name_attr(good.data(), good.size(), static_cast<GCERT_NameAttr>(99), 0,
      &v, &n), GCERT_ERR_INVALID);
  EXPECT_EQ(gcert_x509_name_attr(nullptr, 0, GCERT_ATTR_COMMON_NAME, 0, &v, &n),
      GCERT_ERR_INVALID);
  EXPECT_EQ(gcert_x509_name_attr(good.data(), good.size(), GCERT_ATTR_COMMON_NAME, 0, nullptr,
      &n), GCERT_ERR_INVALID);
}

TEST(Identity, EverySanEntryInOrder) {
  pki::Spec s;
  s.dns = "www.example.com";
  s.uri = "spiffe://example.org/web";
  s.email = "alice@example.com";
  s.ip = Bytes{192, 0, 2, 1};
  Bytes der = pki::issue(s);
  GCERT_X509 c;
  ASSERT_EQ(gcert_x509_parse(der.data(), der.size(), &c), GCERT_OK);
  GCERT_Result last = GCERT_OK;
  std::vector<Entry> e = sans(c, &last);
  EXPECT_EQ(last, GCERT_ERR_FORMAT);
  ASSERT_EQ(e.size(), 4u);
  EXPECT_EQ(e[0].choice, GCERT_SAN_EMAIL);
  EXPECT_EQ(e[0].value, "alice@example.com");
  EXPECT_EQ(e[1].choice, GCERT_SAN_DNS);
  EXPECT_EQ(e[1].value, "www.example.com");
  EXPECT_EQ(e[2].choice, GCERT_SAN_URI);
  EXPECT_EQ(e[2].value, "spiffe://example.org/web");
  EXPECT_EQ(e[3].choice, GCERT_SAN_IP);
  EXPECT_EQ(e[3].value, std::string("\xc0\x00\x02\x01", 4));
}

TEST(Identity, EntriesOfKindsItDoesNotInterpretAreStillReported) {
  /* otherName [0], directoryName [4] (explicitly tagged, so constructed), and
   * registeredID [8], by hand. */
  Bytes other = pki::tlv(0xa0, Bytes{0x06, 0x01, 0x2a, 0xa0, 0x03, 0x0c, 0x01, 0x78});
  Bytes dirname = pki::tlv(0xa4, pki::name("bob"));
  Bytes regid = pki::tlv(0x88, Bytes{0x2b, 0x06, 0x01});
  Bytes dns = pki::tlv(0x82, Bytes{'a', '.', 'b'});
  Bytes san = pki::tlv(0x30, cat({other, dirname, regid, dns}));
  GCERT_X509 c;
  std::memset(&c, 0, sizeof c);
  c.san = san.data();
  c.san_len = san.size();
  GCERT_Result last = GCERT_OK;
  std::vector<Entry> e = sans(c, &last);
  EXPECT_EQ(last, GCERT_ERR_FORMAT);
  ASSERT_EQ(e.size(), 4u);
  EXPECT_EQ(e[0].choice, GCERT_SAN_OTHER);
  EXPECT_EQ(e[1].choice, GCERT_SAN_DIRECTORY);
  EXPECT_EQ(e[2].choice, GCERT_SAN_REGISTERED_ID);
  EXPECT_EQ(e[3].choice, GCERT_SAN_DNS);
  EXPECT_EQ(e[3].value, "a.b");
  /* The directoryName's content is a Name, which name_attr reads. */
  Bytes inner(reinterpret_cast<const unsigned char *>(e[1].value.data()),
      reinterpret_cast<const unsigned char *>(e[1].value.data()) + e[1].value.size());
  EXPECT_EQ(attr(inner, GCERT_ATTR_COMMON_NAME, 0), "bob");
}

TEST(Identity, NoSanMeansNoEntries) {
  Bytes der = pki::signed_by("leaf", pki::key(1), "ca", pki::key(2), false);
  GCERT_X509 c;
  ASSERT_EQ(gcert_x509_parse(der.data(), der.size(), &c), GCERT_OK);
  GCERT_Result last = GCERT_OK;
  EXPECT_TRUE(sans(c, &last).empty());
  EXPECT_EQ(last, GCERT_ERR_FORMAT);
}

TEST(Identity, AMalformedSanIsAnErrorNotAShorterList) {
  Bytes dns = pki::tlv(0x82, Bytes{'a', '.', 'b'});
  GCERT_X509 c;
  std::memset(&c, 0, sizeof c);
  /* A universal-tagged element where a GeneralName must be. */
  Bytes bad = pki::tlv(0x30, cat({dns, Bytes{0x04, 0x01, 0x00}}));
  c.san = bad.data();
  c.san_len = bad.size();
  GCERT_Result last = GCERT_OK;
  std::vector<Entry> e = sans(c, &last);
  EXPECT_EQ(last, GCERT_ERR_CORRUPT);
  /* The entry before the bad one is reported first, and the bad one is
   * reached by walking to it. */
  EXPECT_EQ(e.size(), 1u);
  /* A choice number above registeredID. */
  Bytes high = pki::tlv(0x30, pki::tlv(0x89, Bytes{1}));
  c.san = high.data();
  c.san_len = high.size();
  sans(c, &last);
  EXPECT_EQ(last, GCERT_ERR_CORRUPT);
  /* Trailing bytes after the sequence. */
  Bytes trailing = pki::tlv(0x30, dns);
  trailing.push_back(0);
  c.san = trailing.data();
  c.san_len = trailing.size();
  sans(c, &last);
  EXPECT_EQ(last, GCERT_ERR_CORRUPT);
  size_t cursor = 0;
  unsigned choice;
  const unsigned char * v;
  size_t n;
  EXPECT_EQ(gcert_x509_san_next(nullptr, &cursor, &choice, &v, &n), GCERT_ERR_INVALID);
  EXPECT_EQ(gcert_x509_san_next(&c, nullptr, &choice, &v, &n), GCERT_ERR_INVALID);
}

int main(int argc, char ** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
