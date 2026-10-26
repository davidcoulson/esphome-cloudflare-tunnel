#pragma once
// Wire helpers: base64, tunnel token, serialized response headers.
#include <cstdint>
#include <cstring>

#include "cft_capnp.h"
#include "cft_rpc.h"

namespace cft {

struct Header {
  Bytes name, value;
};

constexpr size_t TOKEN_MAX = 512;
constexpr const char *META_ORIGIN = "{\"src\":\"origin\"}", *META_CONNECTOR = "{\"src\":\"cloudflared\"}";

inline int b64_val(uint8_t c) {
  if (c >= 'A' && c <= 'Z') return c - 'A';
  if (c >= 'a' && c <= 'z') return c - 'a' + 26;
  if (c >= '0' && c <= '9') return c - '0' + 52;
  return c == '+' ? 62 : c == '/' ? 63 : -1;
}

// Standard alphabet, padding optional. Returns decoded length or -1.
inline int b64_decode(const char *s, size_t n, uint8_t *out, size_t cap) {
  while (n && s[n - 1] == '=') n--;
  if (n % 4 == 1) return -1;
  size_t w = 0;
  uint32_t acc = 0;
  int bits = 0;
  for (size_t i = 0; i < n; i++) {
    int v = b64_val(s[i]);
    if (v < 0) return -1;
    acc = (acc << 6) | v;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      if (w == cap) return -1;
      out[w++] = acc >> bits;
      acc &= (1u << bits) - 1;
    }
  }
  return acc ? -1 : (int) w;  // leftover bits must be zero
}

// Standard alphabet, no padding (Go's base64.RawStdEncoding). Returns length or 0 if it does not fit.
inline size_t b64_encode_raw(const uint8_t *in, size_t n, char *out, size_t cap) {
  static const char A[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  size_t need = (n * 8 + 5) / 6;
  if (need > cap) return 0;
  size_t w = 0;
  uint32_t acc = 0;
  int bits = 0;
  for (size_t i = 0; i < n; i++) {
    acc = (acc << 8) | in[i];
    bits += 8;
    while (bits >= 6) {
      bits -= 6;
      out[w++] = A[(acc >> bits) & 63];
    }
  }
  if (bits) out[w++] = A[(acc << (6 - bits)) & 63];
  return w;
}

// "name:value;name:value" with both halves base64-raw encoded. Returns length, or -1 if it does not fit.
inline int encode_headers(const Header *h, size_t count, char *out, size_t cap) {
  size_t w = 0;
  for (size_t i = 0; i < count; i++) {
    if (i && w < cap) out[w++] = ';';
    size_t a = b64_encode_raw(h[i].name.ptr, h[i].name.len, out + w, cap - w);
    if (!a && h[i].name.len) return -1;
    w += a;
    if (w >= cap) return -1;
    out[w++] = ':';
    size_t b = b64_encode_raw(h[i].value.ptr, h[i].value.len, out + w, cap - w);
    if (!b && h[i].value.len) return -1;
    w += b;
  }
  return (int) w;
}

// Flat JSON object of string/number/bool/null members, as in cloudflared's TunnelToken. Finds string member `key`.
inline bool json_string(const char *s, size_t n, const char *key, const char **val, size_t *len) {
  size_t i = 0, klen = strlen(key);
  auto ws = [&] { while (i < n && (s[i] == ' ' || s[i] == '\t' || s[i] == '\n' || s[i] == '\r')) i++; };
  auto str = [&](const char **p, size_t *l) {
    if (i >= n || s[i] != '"') return false;
    size_t st = ++i;
    while (i < n && s[i] != '"') {
      if (s[i] == '\\' || (uint8_t) s[i] < 0x20) return false;  // tokens never contain escapes
      i++;
    }
    if (i >= n) return false;
    *p = s + st;
    *l = i++ - st;
    return true;
  };
  ws();
  if (i >= n || s[i++] != '{') return false;
  bool found = false;
  for (;;) {
    ws();
    if (i < n && s[i] == '}') return found;
    const char *k, *v = nullptr;
    size_t kl, vl = 0;
    if (!str(&k, &kl)) return false;
    ws();
    if (i >= n || s[i++] != ':') return false;
    ws();
    if (i < n && s[i] == '"') {
      if (!str(&v, &vl)) return false;
    } else {
      while (i < n && s[i] != ',' && s[i] != '}') {
        if (s[i] == '{' || s[i] == '[' || s[i] == '"') return false;
        i++;
      }
    }
    if (kl == klen && !memcmp(k, key, klen)) {
      if (found || !v) return false;  // duplicate or not a string
      *val = v;
      *len = vl;
      found = true;
    }
    ws();
    if (i < n && s[i] == ',') i++;
    else if (i >= n || s[i] != '}') return false;
  }
}

inline int hex_val(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  c |= 0x20;
  return c >= 'a' && c <= 'f' ? c - 'a' + 10 : -1;
}

// 8-4-4-4-12 hex UUID to 16 bytes.
inline bool parse_uuid(const char *s, size_t n, uint8_t out[16]) {
  if (n != 36) return false;
  size_t o = 0;
  for (size_t i = 0; i < 36; i++) {
    if (i == 8 || i == 13 || i == 18 || i == 23) {
      if (s[i] != '-') return false;
      continue;
    }
    int hi = hex_val(s[i]), lo = i + 1 < 36 ? hex_val(s[i + 1]) : -1;
    if (hi < 0 || lo < 0) return false;
    out[o++] = hi << 4 | lo;
    i++;
  }
  return true;
}

// token = base64(JSON {"a": account tag, "s": base64 secret, "t": tunnel uuid, "e": endpoint?}).
inline Result parse_token(const char *token, size_t n, Credentials *out) {
  uint8_t json[TOKEN_MAX];
  int jl = b64_decode(token, n, json, sizeof json);
  if (jl < 0) return ERR_FORMAT;
  const char *a, *s, *t;
  size_t al, sl, tl;
  if (!json_string((const char *) json, jl, "a", &a, &al) || !json_string((const char *) json, jl, "s", &s, &sl) ||
      !json_string((const char *) json, jl, "t", &t, &tl))
    return ERR_FORMAT;
  if (!al || al >= sizeof(out->account_tag)) return ERR_FORMAT;
  int secret = b64_decode(s, sl, out->secret, sizeof out->secret);
  if (secret < 32) return ERR_FORMAT;
  if (!parse_uuid(t, tl, out->tunnel_id)) return ERR_FORMAT;
  memcpy(out->account_tag, a, al);
  out->account_tag[al] = 0;
  out->secret_len = secret;
  return OK;
}

}  // namespace cft
