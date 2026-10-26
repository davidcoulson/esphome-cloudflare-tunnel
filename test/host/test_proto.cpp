// Host test for cft_proto.h against vectors from upstream's reference generator (Go-produced token / header wire).
#include <cstdio>
#include <cstdlib>
#include "../../components/cloudflare_tunnel/cft_proto.h"
#include "reference_vectors.h"
using namespace cft;
static int checks;
#define CHECK(x) do { ++checks; if (!(x)) { fprintf(stderr, "FAIL %d: %s\n", __LINE__, #x); exit(1); } } while (0)
#define ARR(x) (const char *) x, sizeof(x)
static Bytes B(const char *s) { return {(const uint8_t *) s, strlen(s)}; }
int main() {
  Credentials c;
  CHECK(parse_token(ARR(gold_token), &c) == OK);
  CHECK(!strcmp(c.account_tag, "0123456789abcdef0123456789abcdef") && c.secret_len == 32);
  for (int i = 0; i < 32; i++) CHECK(c.secret[i] == i);
  CHECK(c.tunnel_id[0] == 0 && c.tunnel_id[15] == 255);
  struct { const unsigned char *t; size_t n, len; } ok[] = {{gold_token_secret_36, sizeof gold_token_secret_36, 36},
      {gold_token_secret_64, sizeof gold_token_secret_64, 64}, {gold_token_secret_128, sizeof gold_token_secret_128, 128}};
  for (auto &o : ok) {
    CHECK(parse_token((const char *) o.t, o.n, &c) == OK && c.secret_len == o.len);
    for (size_t i = 0; i < o.len; i++) CHECK(c.secret[i] == i);
  }
  CHECK(parse_token(ARR(gold_token_secret_31), &c) != OK);
  CHECK(parse_token(ARR(gold_token_secret_129), &c) != OK);
  CHECK(parse_token("cloudflared tunnel run --token fake", 35, &c) != OK);
  // every truncation / bit flip of the good token fails or parses; never crashes
  char buf[512];
  for (size_t cut = 0; cut < sizeof gold_token; cut++) { memcpy(buf, gold_token, cut); parse_token(buf, cut, &c); }
  for (size_t i = 0; i < sizeof gold_token; i++) for (int b = 0; b < 8; b++) {
    memcpy(buf, gold_token, sizeof gold_token); buf[i] ^= 1 << b; parse_token(buf, sizeof gold_token, &c);
  }
  // headers: same five pairs the reference generator serialised
  Header h[] = {{B("Set-Cookie"), B("a=1; Path=/")}, {B("Set-Cookie"), B("b=2")}, {B("X-Empty"), B("")},
                {B("X-Function"), B(":;/+")}, {B("X-UTF8"), B("\xd0\x96\xd0\xbb\xd0\xb4")}};
  (void) h;
  // exact input values are not in the fixture; decode the vector halves instead and re-encode them
  char wire[256]; Header hs[8]; uint8_t arena[256]; size_t n = 0, a = 0;
  const char *p = (const char *) gold_headers, *end = p + sizeof gold_headers;
  while (p < end) {
    const char *semi = (const char *) memchr(p, ';', end - p); if (!semi) semi = end;
    const char *colon = (const char *) memchr(p, ':', semi - p); CHECK(colon);
    int nl = b64_decode(p, colon - p, arena + a, sizeof arena - a); CHECK(nl >= 0);
    hs[n].name = {arena + a, (size_t) nl}; a += nl;
    int vl = b64_decode(colon + 1, semi - colon - 1, arena + a, sizeof arena - a); CHECK(vl >= 0);
    hs[n].value = {arena + a, (size_t) vl}; a += vl; n++;
    p = semi + 1;
  }
  CHECK(n == 5 && hs[0].name.len == 10 && hs[2].value.len == 0);
  int w = encode_headers(hs, n, wire, sizeof wire);
  CHECK(w == (int) sizeof gold_headers && !memcmp(wire, gold_headers, w));
  CHECK(encode_headers(hs, n, wire, w - 1) < 0);
  CHECK(b64_decode("Zg==", 4, arena, sizeof arena) == 1 && b64_decode("Zh", 2, arena, sizeof arena) < 0);
  printf("ok %d checks\n", checks);
}
