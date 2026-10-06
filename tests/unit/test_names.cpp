/**
 * @file
 *
 * Reference-identity matching (names.h).
 *
 * Most cases build the certificate by hand: a GCERT_X509 whose subjectAltName
 * is whatever bytes the case needs, because no CA would issue most of them
 * and gcert_x509_issue writes one dNSName and nothing else. Only the fields
 * the matcher reads are filled in. A few cases run against real fixtures so
 * the parsed path is exercised too.
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

struct Entry {
  unsigned char tag;
  std::string value;
};

void put_len(std::vector<unsigned char> & out, size_t n) {
  if (n < 128) {
    out.push_back(static_cast<unsigned char>(n));
  } else if (n < 256) {
    out.push_back(0x81);
    out.push_back(static_cast<unsigned char>(n));
  } else {
    out.push_back(0x82);
    out.push_back(static_cast<unsigned char>(n >> 8));
    out.push_back(static_cast<unsigned char>(n));
  }
}

/* A certificate with a subjectAltName of the given entries and nothing else.
 * `tag` is the GeneralName choice number (1 rfc822, 2 dNS, 6 URI, 7 IP). */
struct Fake {
  std::vector<unsigned char> san;
  std::vector<unsigned char> subject;
  GCERT_X509 cert;

  explicit Fake(const std::vector<Entry> & entries, const std::string & cn = "") {
    std::vector<unsigned char> body;
    bool dns = false;
    for (const Entry & e : entries) {
      body.push_back(static_cast<unsigned char>(0x80 | e.tag));
      put_len(body, e.value.size());
      body.insert(body.end(), e.value.begin(), e.value.end());
      dns = dns || e.tag == 2;
    }
    san.push_back(0x30);
    put_len(san, body.size());
    san.insert(san.end(), body.begin(), body.end());
    /* Name ::= SEQUENCE { SET { SEQUENCE { OID commonName, UTF8String } } } */
    std::vector<unsigned char> atv = {0x06, 0x03, 0x55, 0x04, 0x03, 0x0c};
    put_len(atv, cn.size());
    atv.insert(atv.end(), cn.begin(), cn.end());
    std::vector<unsigned char> seq = {0x30};
    put_len(seq, atv.size());
    seq.insert(seq.end(), atv.begin(), atv.end());
    std::vector<unsigned char> set = {0x31};
    put_len(set, seq.size());
    set.insert(set.end(), seq.begin(), seq.end());
    subject.push_back(0x30);
    if (cn.empty()) {
      subject.push_back(0);
    } else {
      put_len(subject, set.size());
      subject.insert(subject.end(), set.begin(), set.end());
    }
    std::memset(&cert, 0, sizeof cert);
    cert.san = san.data();
    cert.san_len = san.size();
    cert.dns_san = dns;
    cert.subject = subject.data();
    cert.subject_len = subject.size();
  }
};

GCERT_Result dns(const Fake & f, const std::string & name,
    const GCERT_NameOptions * o = nullptr) {
  return gcert_x509_verify_dns(&f.cert, name.data(), name.size(), o);
}

Fake dnsfake(const std::string & pattern) {
  return Fake({{2, pattern}});
}

} /* namespace */

/* --- DNS ------------------------------------------------------------------ */

TEST(Names, ExactAndCase) {
  Fake f = dnsfake("www.Example.com");
  EXPECT_EQ(dns(f, "www.example.com"), GCERT_OK);
  EXPECT_EQ(dns(f, "WWW.EXAMPLE.COM"), GCERT_OK);
  EXPECT_EQ(dns(f, "www.example.com."), GCERT_OK);
  EXPECT_EQ(dns(f, "example.com"), GCERT_ERR_MISMATCH);
  EXPECT_EQ(dns(f, "xwww.example.com"), GCERT_ERR_MISMATCH);
  EXPECT_EQ(dns(f, "www.example.com.evil.example"), GCERT_ERR_MISMATCH);
}

TEST(Names, WildcardMatchesExactlyOneWholeLabel) {
  Fake f = dnsfake("*.example.com");
  EXPECT_EQ(dns(f, "www.example.com"), GCERT_OK);
  EXPECT_EQ(dns(f, "a-b.example.com"), GCERT_OK);
  EXPECT_EQ(dns(f, "example.com"), GCERT_ERR_MISMATCH);       /* zero labels */
  EXPECT_EQ(dns(f, "a.b.example.com"), GCERT_ERR_MISMATCH);   /* two labels */
  EXPECT_EQ(dns(f, ".example.com"), GCERT_ERR_INVALID);       /* not a name */
  EXPECT_EQ(dns(f, "wwwexample.com"), GCERT_ERR_MISMATCH);
}

TEST(Names, PartialWildcardsAreNotWildcards) {
  /* RFC 6125 allowed f*.example.com; RFC 9525 section 6.3 does not. */
  for (const char * pat : {"f*.example.com", "*o.example.com", "w*w.example.com",
      "www.*.example.com", "*.*.example.com", "*", "**.example.com"}) {
    Fake f = dnsfake(pat);
    EXPECT_EQ(dns(f, "foo.example.com"), GCERT_ERR_MISMATCH) << pat;
    EXPECT_EQ(dns(f, "www.any.example.com"), GCERT_ERR_MISMATCH) << pat;
    EXPECT_EQ(dns(f, "example"), GCERT_ERR_MISMATCH) << pat;
  }
}

TEST(Names, WildcardNeedsLabelsAfterTheStar) {
  /* Each host below would match if the label count were not checked. */
  Fake tld = dnsfake("*.com");
  EXPECT_EQ(dns(tld, "example.com"), GCERT_ERR_MISMATCH);
  Fake two = dnsfake("*.example.com");
  EXPECT_EQ(dns(two, "www.example.com"), GCERT_OK);

  /* The count is the caller's to raise, and 0 means the default. */
  GCERT_NameOptions o;
  gcert_name_options_default(&o);
  EXPECT_EQ(o.wildcard_min_labels, GCERT_NAME_WILDCARD_MIN_LABELS);
  o.wildcard_min_labels = 3;
  EXPECT_EQ(dns(two, "www.example.com", &o), GCERT_ERR_MISMATCH);
  Fake three = dnsfake("*.shop.example.com");
  EXPECT_EQ(dns(three, "www.shop.example.com", &o), GCERT_OK);
  o.wildcard_min_labels = 1;
  EXPECT_EQ(dns(tld, "example.com", &o), GCERT_OK);
  std::memset(&o, 0, sizeof o);
  EXPECT_EQ(dns(tld, "example.com", &o), GCERT_ERR_MISMATCH);
}

TEST(Names, MalformedPatternsNeverMatch) {
  /* A pattern that is not a host name. Only a wildcard pattern gets here
   * with a remainder the host check has not already vetted, which is why
   * the remainder is checked itself. */
  for (const char * pat : {"*.exa mple.com", "*..example.com", "*.example..com",
      "*.-", ""}) {
    Fake f = dnsfake(pat);
    EXPECT_EQ(dns(f, "www.example.com"), GCERT_ERR_MISMATCH) << pat;
  }
  std::string long_rest = "*." + std::string(64, 'a') + ".example.com";
  Fake f = dnsfake(long_rest);
  EXPECT_EQ(dns(f, "x." + std::string(64, 'a') + ".example.com"),
      GCERT_ERR_INVALID);  /* the host itself is not a name */
  EXPECT_EQ(dns(f, "x.example.com"), GCERT_ERR_MISMATCH);
}

TEST(Names, ReferenceMustBeAName) {
  Fake f = dnsfake("www.example.com");
  EXPECT_EQ(dns(f, ""), GCERT_ERR_INVALID);
  EXPECT_EQ(dns(f, "."), GCERT_ERR_INVALID);
  EXPECT_EQ(dns(f, "www..example.com"), GCERT_ERR_INVALID);
  EXPECT_EQ(dns(f, std::string("www.example.com\0.evil", 20)), GCERT_ERR_INVALID);
  EXPECT_EQ(dns(f, "www.exam\xc3\xa9ple.com"), GCERT_ERR_INVALID);
  EXPECT_EQ(dns(f, "www example.com"), GCERT_ERR_INVALID);
  EXPECT_EQ(dns(f, "www.example.com:443"), GCERT_ERR_INVALID);
  /* A reference of "*.example.com" is not a wildcard reference: it would
   * match a wildcard pattern as a literal first label. */
  Fake wild = dnsfake("*.example.com");
  EXPECT_EQ(dns(wild, "*.example.com"), GCERT_ERR_INVALID);
  EXPECT_EQ(dns(f, std::string(254, 'a')), GCERT_ERR_INVALID);
  EXPECT_EQ(dns(f, std::string(64, 'a') + ".com"), GCERT_ERR_INVALID);
  EXPECT_EQ(gcert_x509_verify_dns(&f.cert, nullptr, 1, nullptr), GCERT_ERR_INVALID);
  EXPECT_EQ(gcert_x509_verify_dns(nullptr, "a", 1, nullptr), GCERT_ERR_INVALID);
}

TEST(Names, CommonNameOnlyWhenAsked) {
  Fake none({}, "www.example.com");
  EXPECT_EQ(dns(none, "www.example.com"), GCERT_ERR_MISMATCH);  /* RFC 9525 */
  GCERT_NameOptions o;
  gcert_name_options_default(&o);
  o.common_name_fallback = 1;
  EXPECT_EQ(dns(none, "www.example.com", &o), GCERT_OK);
  EXPECT_EQ(dns(none, "other.example.com", &o), GCERT_ERR_MISMATCH);

  /* A certificate with a dNSName is never read by its common name. */
  Fake with({{2, "other.example.com"}}, "www.example.com");
  EXPECT_EQ(dns(with, "www.example.com", &o), GCERT_ERR_MISMATCH);

  /* The common name obeys the wildcard rules too. */
  Fake cn_wild({}, "*.com");
  EXPECT_EQ(dns(cn_wild, "example.com", &o), GCERT_ERR_MISMATCH);

  /* gcert_x509_hostname is the same call with the fallback on. */
  EXPECT_EQ(gcert_x509_hostname(&none.cert, "www.example.com", 15), GCERT_OK);
  EXPECT_EQ(gcert_x509_hostname(&cn_wild.cert, "example.com", 11),
      GCERT_ERR_MISMATCH);
}

TEST(Names, EntryOrderDoesNotChangeTheAnswer) {
  /* The walk reads every entry, so a malformed one after a match is still
   * reported, and a match after a mismatch is still found. */
  Fake f({{2, "a.example.com"}, {2, "b.example.com"}, {7, std::string(4, 'x')}});
  EXPECT_EQ(dns(f, "b.example.com"), GCERT_OK);
  EXPECT_EQ(dns(f, "a.example.com"), GCERT_OK);
  EXPECT_EQ(dns(f, "c.example.com"), GCERT_ERR_MISMATCH);

  Fake bad({{2, "a.example.com"}});
  bad.san.push_back(0x82);  /* a truncated entry after the match */
  bad.san[1] = static_cast<unsigned char>(bad.san.size() - 2);
  bad.cert.san = bad.san.data();
  bad.cert.san_len = bad.san.size();
  EXPECT_NE(dns(bad, "a.example.com"), GCERT_OK);
}

/* --- IP ------------------------------------------------------------------- */

namespace {

GCERT_Result ip_text(const char * text, std::vector<unsigned char> * out = nullptr) {
  unsigned char b[16];
  size_t n = 0;
  GCERT_Result r = gcert_ip_parse(text, std::strlen(text), b, &n);
  if (out != nullptr) {
    out->assign(b, b + (r == GCERT_OK ? n : 0));
  }
  return r;
}

} /* namespace */

TEST(Names, IpLiteralsParse) {
  std::vector<unsigned char> v;
  ASSERT_EQ(ip_text("192.0.2.1", &v), GCERT_OK);
  EXPECT_EQ(v, (std::vector<unsigned char>{192, 0, 2, 1}));
  ASSERT_EQ(ip_text("0.0.0.0", &v), GCERT_OK);
  ASSERT_EQ(ip_text("255.255.255.255", &v), GCERT_OK);
  ASSERT_EQ(ip_text("::1", &v), GCERT_OK);
  EXPECT_EQ(v.size(), 16u);
  EXPECT_EQ(v[15], 1);
  ASSERT_EQ(ip_text("::", &v), GCERT_OK);
  EXPECT_EQ(v, std::vector<unsigned char>(16, 0));
  ASSERT_EQ(ip_text("2001:db8::ff00:42:8329", &v), GCERT_OK);
  EXPECT_EQ(v, (std::vector<unsigned char>{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0,
      0xff, 0x00, 0x00, 0x42, 0x83, 0x29}));
  std::vector<unsigned char> full;
  ASSERT_EQ(ip_text("2001:0db8:0000:0000:0000:ff00:0042:8329", &full), GCERT_OK);
  EXPECT_EQ(full, v);
  ASSERT_EQ(ip_text("2001:DB8::FF00:42:8329", &full), GCERT_OK);
  EXPECT_EQ(full, v);
  ASSERT_EQ(ip_text("::ffff:192.0.2.1", &v), GCERT_OK);
  EXPECT_EQ(v[10], 0xff);
  EXPECT_EQ(v[12], 192);
  EXPECT_EQ(v[15], 1);
  ASSERT_EQ(ip_text("1::", &v), GCERT_OK);
  EXPECT_EQ(v[1], 1);
  ASSERT_EQ(ip_text("1:2:3:4:5:6:7::", &v), GCERT_OK);
  ASSERT_EQ(ip_text("::2:3:4:5:6:7:8", &v), GCERT_OK);
  ASSERT_EQ(ip_text("1:2:3:4:5:6:1.2.3.4", &v), GCERT_OK);
}

TEST(Names, IpLiteralsThatAreNotLiterals) {
  for (const char * bad : {"", "1.2.3", "1.2.3.4.5", "1.2.3.256", "01.2.3.4",
      "1.2.3.04", "1..2.3", "1.2.3.", ".1.2.3", "a.b.c.d", "1.2.3.4 ",
      " 1.2.3.4", "0x1.2.3.4", "1.2.3.4/8", "999.1.1.1", "1234.1.1.1",
      ":", ":::", "1::2::3", "1:2:3:4:5:6:7:8:9", "1:2:3:4:5:6:7",
      "::1:2:3:4:5:6:7:8", "12345::", "g::", ":1:2:3:4:5:6:7",
      "1:2:3:4:5:6:7:", "1::2:", "::1.2.3", "::1.2.3.4:5", "[::1]", "::1%eth0",
      "1:2:3:4:5:6:7:1.2.3.4", "::01.2.3.4", "1:2:3:4:5:6:7:8::", "::ffff:1.2.3.256"}) {
    EXPECT_EQ(ip_text(bad), GCERT_ERR_INVALID) << bad;
  }
  unsigned char b[16];
  size_t n;
  EXPECT_EQ(gcert_ip_parse(nullptr, 1, b, &n), GCERT_ERR_INVALID);
  EXPECT_EQ(gcert_ip_parse("1.2.3.4", 7, nullptr, &n), GCERT_ERR_INVALID);
  EXPECT_EQ(gcert_ip_parse("1.2.3.4", 7, b, nullptr), GCERT_ERR_INVALID);
  /* The length is the text's: a longer buffer does not extend it. */
  EXPECT_EQ(gcert_ip_parse("1.2.3.45", 7, b, &n), GCERT_OK);
  EXPECT_EQ(b[3], 4);
  EXPECT_EQ(gcert_ip_parse("1.2.3.4\0" "5", 9, b, &n), GCERT_ERR_INVALID);
}

TEST(Names, IpEntriesMatchOnlyIpEntries) {
  const std::string v4("\xc0\x00\x02\x01", 4);
  Fake f({{7, v4}, {2, "192.0.2.1"}});
  GCERT_Result r;
  unsigned char a4[4] = {192, 0, 2, 1};
  unsigned char b4[4] = {192, 0, 2, 2};
  EXPECT_EQ(gcert_x509_verify_ip(&f.cert, a4, 4), GCERT_OK);
  EXPECT_EQ(gcert_x509_verify_ip(&f.cert, b4, 4), GCERT_ERR_MISMATCH);

  /* A dNSName that spells an address is not an address: */
  Fake dns_only({{2, "192.0.2.1"}});
  EXPECT_EQ(gcert_x509_verify_ip(&dns_only.cert, a4, 4), GCERT_ERR_MISMATCH);
  r = gcert_x509_verify_host(&dns_only.cert, "192.0.2.1", 9, nullptr);
  EXPECT_EQ(r, GCERT_ERR_MISMATCH);
  /* ...and an iPAddress is not a name. */
  Fake ip_only({{7, v4}});
  EXPECT_EQ(gcert_x509_verify_host(&ip_only.cert, "192.0.2.1", 9, nullptr), GCERT_OK);
  EXPECT_EQ(dns(ip_only, "192.0.2.1"), GCERT_ERR_MISMATCH);

  /* IPv6, and a v4 address is not its v4-mapped form. */
  std::string v6(16, '\0');
  v6[15] = 1;
  Fake six({{7, v6}});
  EXPECT_EQ(gcert_x509_verify_host(&six.cert, "::1", 3, nullptr), GCERT_OK);
  EXPECT_EQ(gcert_x509_verify_host(&six.cert, "0:0:0:0:0:0:0:1", 15, nullptr), GCERT_OK);
  EXPECT_EQ(gcert_x509_verify_host(&six.cert, "::2", 3, nullptr), GCERT_ERR_MISMATCH);
  EXPECT_EQ(gcert_x509_verify_host(&ip_only.cert, "::ffff:192.0.2.1", 16, nullptr),
      GCERT_ERR_MISMATCH);

  /* A malformed iPAddress entry (5 bytes) matches nothing. */
  Fake odd({{7, std::string(5, 'x')}});
  unsigned char five[4] = {'x', 'x', 'x', 'x'};
  EXPECT_EQ(gcert_x509_verify_ip(&odd.cert, five, 4), GCERT_ERR_MISMATCH);

  EXPECT_EQ(gcert_x509_verify_ip(&f.cert, a4, 3), GCERT_ERR_INVALID);
  EXPECT_EQ(gcert_x509_verify_ip(&f.cert, nullptr, 4), GCERT_ERR_INVALID);
  EXPECT_EQ(gcert_x509_verify_ip(nullptr, a4, 4), GCERT_ERR_INVALID);
}

TEST(Names, HostRoutesByWhatItLooksLike) {
  Fake f({{2, "www.example.com"}});
  EXPECT_EQ(gcert_x509_verify_host(&f.cert, "www.example.com", 15, nullptr), GCERT_OK);
  EXPECT_EQ(gcert_x509_verify_host(&f.cert, "", 0, nullptr), GCERT_ERR_INVALID);
  EXPECT_EQ(gcert_x509_verify_host(&f.cert, "[::1]", 5, nullptr), GCERT_ERR_INVALID);
}

/* --- URI and mailbox ------------------------------------------------------- */

TEST(Names, UriIsByteExact) {
  Fake f({{6, "spiffe://example.org/ns/prod/sa/web"}});
  auto uri = [&](const std::string & s) {
    return gcert_x509_verify_uri(&f.cert, s.data(), s.size());
  };
  EXPECT_EQ(uri("spiffe://example.org/ns/prod/sa/web"), GCERT_OK);
  EXPECT_EQ(uri("spiffe://example.org/ns/prod/sa/Web"), GCERT_ERR_MISMATCH);
  EXPECT_EQ(uri("SPIFFE://example.org/ns/prod/sa/web"), GCERT_ERR_MISMATCH);
  EXPECT_EQ(uri("spiffe://example.org/ns/prod/sa/we"), GCERT_ERR_MISMATCH);
  EXPECT_EQ(uri("spiffe://example.org/ns/prod/sa/web/"), GCERT_ERR_MISMATCH);
  EXPECT_EQ(uri(""), GCERT_ERR_INVALID);
  EXPECT_EQ(uri(std::string("spiffe://example.org\0x", 22)), GCERT_ERR_INVALID);
  EXPECT_EQ(uri("spiffe://exa mple"), GCERT_ERR_INVALID);
  /* A dNSName is not a URI. */
  Fake d({{2, "example.org"}});
  EXPECT_EQ(gcert_x509_verify_uri(&d.cert, "example.org", 11), GCERT_ERR_MISMATCH);
  EXPECT_EQ(gcert_x509_verify_uri(nullptr, "a", 1), GCERT_ERR_INVALID);
}

TEST(Names, MailboxLocalPartExactDomainFolded) {
  Fake f({{1, "Alice@Example.COM"}});
  auto mail = [&](const std::string & s) {
    return gcert_x509_verify_email(&f.cert, s.data(), s.size());
  };
  EXPECT_EQ(mail("Alice@example.com"), GCERT_OK);
  EXPECT_EQ(mail("Alice@EXAMPLE.com"), GCERT_OK);
  EXPECT_EQ(mail("alice@example.com"), GCERT_ERR_MISMATCH);  /* local part */
  EXPECT_EQ(mail("Alice@example.org"), GCERT_ERR_MISMATCH);
  EXPECT_EQ(mail("Alice@mail.example.com"), GCERT_ERR_MISMATCH);
  EXPECT_EQ(mail("Alice"), GCERT_ERR_INVALID);
  EXPECT_EQ(mail("@example.com"), GCERT_ERR_INVALID);
  EXPECT_EQ(mail("Alice@"), GCERT_ERR_INVALID);
  EXPECT_EQ(mail(""), GCERT_ERR_INVALID);
  /* The split is at the last '@': a quoted local part may contain one. */
  Fake q({{1, "\"a@b\"@example.com"}});
  EXPECT_EQ(gcert_x509_verify_email(&q.cert, "\"a@b\"@example.com", 17), GCERT_OK);
  EXPECT_EQ(gcert_x509_verify_email(&q.cert, "\"a@b\"@evil.com", 14), GCERT_ERR_MISMATCH);
}

/* --- Real certificates ------------------------------------------------------ */

namespace {

std::vector<unsigned char> load(const char * name) {
  std::ifstream in(gsectest::data_dir() + "/certs/" + name, std::ios::binary);
  EXPECT_TRUE(in.good()) << name;
  return std::vector<unsigned char>(std::istreambuf_iterator<char>(in),
      std::istreambuf_iterator<char>());
}

} /* namespace */

TEST(Names, ParsedCertificates) {
  auto der = load("p256-leaf.der");
  GCERT_X509 c;
  ASSERT_EQ(gcert_x509_parse(der.data(), der.size(), &c), GCERT_OK);
  EXPECT_EQ(gcert_x509_verify_host(&c, "www.example.com", 15, nullptr), GCERT_OK);
  EXPECT_EQ(gcert_x509_verify_host(&c, "www.example.org", 15, nullptr),
      GCERT_ERR_MISMATCH);

  auto tld = load("san-wild-tld.der");
  ASSERT_EQ(gcert_x509_parse(tld.data(), tld.size(), &c), GCERT_OK);
  EXPECT_EQ(gcert_x509_verify_host(&c, "example.com", 11, nullptr), GCERT_ERR_MISMATCH);
  GCERT_NameOptions o;
  gcert_name_options_default(&o);
  o.wildcard_min_labels = 1;
  EXPECT_EQ(gcert_x509_verify_host(&c, "example.com", 11, &o), GCERT_OK);
}

int main(int argc, char ** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
