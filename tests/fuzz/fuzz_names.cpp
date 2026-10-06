/**
 * @file
 *
 * libFuzzer harness for reference-identity matching (names.h) and for the IP
 * literal parser.
 *
 * The first byte picks the mode. Mode 0 parses the rest as an IP literal and,
 * when it parses, renders the address back to text and requires that to parse
 * to the same bytes. The other modes take the rest as a subjectAltName (the
 * content of the GeneralNames sequence, wrapped here) and ask each verify
 * function about a reference taken from the input's own tail, so a certificate
 * and the name asked of it come from the same bytes.
 *
 * Invariants beyond "did not crash": the answer is a function of the bytes;
 * DNS matching ignores ASCII case; and a reference that was refused as not a
 * name is refused however it is cased.
 *
 * Copyright 2026 by Corey Pennycuff
 */

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include <ghoti.io/certificate/names.h>

static void allowed(GCERT_Result r) {
  if (r != GCERT_OK && r != GCERT_ERR_MISMATCH && r != GCERT_ERR_INVALID &&
      r != GCERT_ERR_CORRUPT) {
    __builtin_trap();
  }
}

static std::string render(const unsigned char * b, size_t n) {
  char buf[64];
  if (n == 4) {
    std::snprintf(buf, sizeof buf, "%u.%u.%u.%u", b[0], b[1], b[2], b[3]);
    return buf;
  }
  std::string s;
  for (size_t i = 0; i < 16; i += 2) {
    std::snprintf(buf, sizeof buf, "%x%s", (b[i] << 8) | b[i + 1], i < 14 ? ":" : "");
    s += buf;
  }
  return s;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t * data, size_t size) {
  if (size == 0) {
    return 0;
  }
  const unsigned mode = data[0] % 5;
  const uint8_t * rest = data + 1;
  size_t n = size - 1;

  if (mode == 0) {
    unsigned char out[16];
    size_t out_len = 0;
    GCERT_Result r = gcert_ip_parse(reinterpret_cast<const char *>(rest), n, out, &out_len);
    if (r != GCERT_OK && r != GCERT_ERR_INVALID) {
      __builtin_trap();
    }
    if (r == GCERT_OK) {
      if (out_len != 4 && out_len != 16) {
        __builtin_trap();
      }
      std::string text = render(out, out_len);
      unsigned char again[16];
      size_t again_len = 0;
      if (gcert_ip_parse(text.data(), text.size(), again, &again_len) != GCERT_OK ||
          again_len != out_len || std::memcmp(again, out, out_len) != 0) {
        __builtin_trap();
      }
    }
    return 0;
  }

  /* Split the rest: the first half is the SAN content, the second the reference. */
  size_t half = n / 2;
  std::vector<unsigned char> san;
  san.push_back(0x30);
  if (half < 128) {
    san.push_back(static_cast<unsigned char>(half));
  } else {
    san.push_back(0x82);
    san.push_back(static_cast<unsigned char>(half >> 8));
    san.push_back(static_cast<unsigned char>(half));
  }
  san.insert(san.end(), rest, rest + half);
  const char * ref = reinterpret_cast<const char *>(rest + half);
  size_t ref_len = n - half;

  GCERT_X509 cert;
  std::memset(&cert, 0, sizeof cert);
  cert.san = san.data();
  cert.san_len = san.size();
  cert.dns_san = (mode & 1) != 0;       /* the parser's flag; both settings are reachable */
  static const unsigned char kSubject[] = {0x30, 0x00};
  cert.subject = kSubject;
  cert.subject_len = sizeof kSubject;

  GCERT_Result first;
  switch (mode) {
    case 1: {
      GCERT_NameOptions o;
      gcert_name_options_default(&o);
      o.wildcard_min_labels = data[0] >> 5;
      first = gcert_x509_verify_dns(&cert, ref, ref_len, &o);
      allowed(first);
      if (gcert_x509_verify_dns(&cert, ref, ref_len, &o) != first) {
        __builtin_trap();
      }
      /* Case does not matter to a DNS name. */
      std::string upper(ref, ref_len);
      for (char & c : upper) {
        if (c >= 'a' && c <= 'z') {
          c = static_cast<char>(c - 'a' + 'A');
        }
      }
      GCERT_Result second = gcert_x509_verify_dns(&cert, upper.data(), upper.size(), &o);
      if (second != first) {
        __builtin_trap();
      }
      break;
    }
    case 2:
      allowed(gcert_x509_verify_host(&cert, ref, ref_len, nullptr));
      break;
    case 3:
      allowed(gcert_x509_verify_uri(&cert, ref, ref_len));
      allowed(gcert_x509_verify_email(&cert, ref, ref_len));
      break;
    default:
      if (ref_len == 4 || ref_len == 16) {
        allowed(gcert_x509_verify_ip(&cert, ref, ref_len));
      }
      allowed(gcert_x509_hostname(&cert, ref, ref_len));
      break;
  }
  return 0;
}
