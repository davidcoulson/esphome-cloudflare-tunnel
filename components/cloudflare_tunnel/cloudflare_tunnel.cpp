#include "cloudflare_tunnel.h"
#include "esphome/core/log.h"
#include "esphome/components/network/util.h"
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <fcntl.h>
#include <unistd.h>
#include "lwip/dns.h"
#include "lwip/sockets.h"

extern "C" {
#include "cf_h2.h"
#include "cf_credentials.h"
}

namespace esphome {
namespace cloudflare_tunnel {

static const char *const TAG = "cloudflare_tunnel";

// One slot per application stream. A stream serves a static body (page or error) or proxies to the
// local web server over a nonblocking socket that poll_streams() drives from the tunnel task.
constexpr size_t OUT_MAX = 4096, HEAD_MAX = 2048, BODY_MAX = CF_H2_CHUNK, HDR_MAX = 24;
enum ChunkState : uint8_t { SIZE, EXT, SIZE_LF, DATA, CRLF1, CRLF2 };

struct Stream {
  int32_t id{0};
  cf_h2 *h{nullptr};
  const char *sbody{nullptr};  // static body
  size_t slen{0}, sent{0};
  bool head{false}, responded{false};  // responded: the client has seen a response head
  // proxy only
  bool proxy{false}, connected{false}, up_done{false}, chunked{false};
  int fd{-1};
  uint8_t *out{nullptr}, *in{nullptr}, *body{nullptr};
  size_t out_len{0}, out_sent{0}, in_len{0}, body_len{0}, body_pos{0}, ch_left{0};
  int64_t remaining{-1};  // Content-Length bytes still expected; -1 = until close
  ChunkState ch{SIZE};
};
static Stream streams[CF_H2_APPLICATION_MAX];
static const char NOT_FOUND[] = "Not found", BAD_GATEWAY[] = "Bad gateway", TOO_LARGE[] = "Request headers too large",
                  BAD_REQUEST[] = "Bad request", NO_METHOD[] = "Method not allowed";

static Stream *find(int32_t id) {
  for (auto &s : streams)
    if (s.id == id) return &s;
  return nullptr;
}

static void release(Stream *s) {
  if (s->fd >= 0) close(s->fd);
  free(s->out);
  free(s->in);
  free(s->body);
  *s = Stream{};
}

static void environment(void *ctx, esp_cf_environment *out) {
  memset(out, 0, sizeof(*out));
  out->network_ready = network::is_connected();
  out->time_valid = time(nullptr) > 1704067200;  // SNTP has synced
  for (auto ip : network::get_ip_addresses()) {
    if (ip.is_ip4()) {
      ip_addr_t a = ip;
      memcpy(out->local_ip, &ip_2_ip4(&a)->addr, 4);
      break;
    }
  }
  const ip_addr_t *dns = dns_getserver(0);
  if (dns && IP_IS_V4(dns)) memcpy(out->dns_ip, &ip_2_ip4(dns)->addr, 4);
}

static bool json_try_lock(void *) { return true; }  // no other JSON user in this component
static void json_unlock(void *) {}

static cf_result credentials(void *ctx, cf_credentials *out, char hostname[254]) {
  auto *self = static_cast<CloudflareTunnel *>(ctx);
  if (self->hostname().size() > 253) return CF_ERR_STATE;
  uint8_t scratch[CF_TOKEN_JSON_MAX + 1];
  memcpy(hostname, self->hostname().c_str(), self->hostname().size() + 1);
  cf_result rc = cf_credentials_parse({(const uint8_t *) self->token().data(), self->token().size()}, scratch,
                                      sizeof(scratch), out);
  cf_secure_zero(scratch, sizeof(scratch));
  return rc;
}

static cf_result respond(Stream *s, unsigned status, const char *type, const char *body, size_t length) {
  s->sbody = body;
  s->slen = length;
  char len[24];
  snprintf(len, sizeof(len), "%u", (unsigned) length);
#define H(n, v) {{(const uint8_t *) (n), strlen(n)}, {(const uint8_t *) (v), strlen(v)}}
  cf_header headers[] = {H("content-type", type), H("content-length", len), H("cache-control", "no-store"),
                         H("x-content-type-options", "nosniff")};
#undef H
  s->responded = true;
  return cf_h2_respond(s->h, s->id, status, headers, 4, true);
}

// Proxy failed: 502 if the client has seen nothing yet, otherwise reset the stream.
static void fail(Stream *s) {
  if (s->fd >= 0) close(s->fd);
  s->fd = -1;
  s->proxy = false;
  if (s->responded) {
    cf_h2_reset(s->h, s->id, 2);
  } else {
    respond(s, 502, "text/plain", BAD_GATEWAY, sizeof(BAD_GATEWAY) - 1);
  }
}

static bool flush(Stream *s) {
  while (s->connected && s->out_sent < s->out_len) {
    ssize_t n = send(s->fd, s->out + s->out_sent, s->out_len - s->out_sent, 0);
    if (n > 0) {
      s->out_sent += n;
    } else if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
      break;
    } else {
      return false;
    }
  }
  if (s->out_sent == s->out_len) s->out_len = s->out_sent = 0;
  return true;
}

static bool bad_token(cf_bytes b, bool allow_space) {
  for (size_t i = 0; i < b.len; i++)
    if (b.ptr[i] < 0x20 || b.ptr[i] == 0x7f || (!allow_space && b.ptr[i] == ' ')) return true;
  return false;
}

static bool eq(cf_bytes b, const char *lit) { return b.len == strlen(lit) && !memcmp(b.ptr, lit, b.len); }

static bool hop_by_hop(cf_bytes n) {
  return eq(n, "connection") || eq(n, "keep-alive") || eq(n, "transfer-encoding") || eq(n, "upgrade") ||
         eq(n, "proxy-connection") || eq(n, "te") || eq(n, "trailer") || eq(n, "host");
}

// Build "METHOD path HTTP/1.1" plus the forwarded headers into s->out and start the loopback connect.
// Request bodies are not forwarded: only GET and HEAD are proxied (what the web_server UI needs).
static cf_result start_proxy(Stream *s, const cf_h2_request *r, cf_bytes method, cf_bytes path, uint16_t port) {
  cf_bytes auth = cf_h2_header(r, ":authority");
  if (!path.len || bad_token(path, false)) return respond(s, 400, "text/plain", BAD_REQUEST, sizeof(BAD_REQUEST) - 1);
  s->out = (uint8_t *) malloc(OUT_MAX);
  if (!s->out) return respond(s, 503, "text/plain", BAD_GATEWAY, sizeof(BAD_GATEWAY) - 1);
  size_t n = 0;
  bool ok = true;
  auto add = [&](const void *p, size_t len) {
    if (!ok || len > OUT_MAX - n) {
      ok = false;
      return;
    }
    memcpy(s->out + n, p, len);
    n += len;
  };
  auto lit = [&](const char *p) { add(p, strlen(p)); };
  add(method.ptr, method.len);
  lit(" ");
  add(path.ptr, path.len);
  lit(" HTTP/1.1\r\nHost: ");
  if (auth.len && !bad_token(auth, false)) add(auth.ptr, auth.len);
  else lit("localhost");
  lit("\r\n");
  for (size_t i = 0; i < r->count; i++) {
    cf_bytes name = r->headers[i].name, value = r->headers[i].value;
    if (!name.len || name.ptr[0] == ':' || hop_by_hop(name) || bad_token(name, false) || bad_token(value, true))
      continue;
    add(name.ptr, name.len);
    lit(": ");
    add(value.ptr, value.len);
    lit("\r\n");
  }
  lit("Connection: close\r\n\r\n");
  if (!ok) return respond(s, 431, "text/plain", TOO_LARGE, sizeof(TOO_LARGE) - 1);
  s->out_len = n;
  s->fd = socket(AF_INET, SOCK_STREAM, 0);
  if (s->fd < 0) return respond(s, 503, "text/plain", BAD_GATEWAY, sizeof(BAD_GATEWAY) - 1);
  fcntl(s->fd, F_SETFL, fcntl(s->fd, F_GETFL, 0) | O_NONBLOCK);
  sockaddr_in addr = {};
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  if (connect(s->fd, (sockaddr *) &addr, sizeof(addr)) == 0) {
    s->connected = true;
  } else if (errno != EINPROGRESS) {
    close(s->fd);
    s->fd = -1;
    return respond(s, 502, "text/plain", BAD_GATEWAY, sizeof(BAD_GATEWAY) - 1);
  }
  s->proxy = true;
  return CF_OK;
}

static int hexval(uint8_t c) {
  if (c >= '0' && c <= '9') return c - '0';
  c |= 0x20;
  return c >= 'a' && c <= 'f' ? c - 'a' + 10 : -1;
}

// Decode n raw upstream bytes in s->body in place (output never overtakes input).
static bool ingest(Stream *s, size_t n) {
  if (!s->chunked) {
    if (s->remaining >= 0) {
      if ((int64_t) n > s->remaining) n = s->remaining;
      s->remaining -= n;
      if (!s->remaining) s->up_done = true;
    }
    s->body_len = n;
    return true;
  }
  size_t w = 0;
  for (size_t i = 0; i < n && !s->up_done; i++) {
    uint8_t c = s->body[i];
    switch (s->ch) {
      case SIZE:
        if (hexval(c) >= 0) {
          s->ch_left = s->ch_left * 16 + hexval(c);
          if (s->ch_left > 0xFFFFFF) return false;
        } else if (c == ';') {
          s->ch = EXT;
        } else if (c == '\r') {
          s->ch = SIZE_LF;
        } else {
          return false;
        }
        break;
      case EXT:
        if (c == '\r') s->ch = SIZE_LF;
        break;
      case SIZE_LF:
        if (c != '\n') return false;
        if (!s->ch_left) s->up_done = true;  // last chunk; trailers are ignored
        else s->ch = DATA;
        break;
      case DATA:
        s->body[w++] = c;
        if (!--s->ch_left) s->ch = CRLF1;
        break;
      case CRLF1:
        if (c != '\r') return false;
        s->ch = CRLF2;
        break;
      case CRLF2:
        if (c != '\n') return false;
        s->ch = SIZE;
        break;
    }
  }
  s->body_len = w;
  return true;
}

// s->in holds a complete upstream head ending at `end` (index of the blank line's CRLFCRLF).
static void handle_head(Stream *s, size_t end) {
  uint8_t *p = s->in;
  if (end < 12 || memcmp(p, "HTTP/1.", 7) || p[8] != ' ') return fail(s);
  unsigned status = (p[9] - '0') * 100 + (p[10] - '0') * 10 + (p[11] - '0');
  if (status < 200 || status > 599) return fail(s);
  cf_header headers[HDR_MAX];
  size_t count = 0, i = 0;
  while (i < end && p[i] != '\n') i++;
  for (i++; i < end;) {
    size_t eol = i;
    while (eol < end && p[eol] != '\r') eol++;
    size_t colon = i;
    while (colon < eol && p[colon] != ':') colon++;
    if (colon == eol) break;
    for (size_t k = i; k < colon; k++)
      if (p[k] >= 'A' && p[k] <= 'Z') p[k] |= 0x20;
    cf_bytes name = {p + i, colon - i};
    size_t v = colon + 1;
    while (v < eol && p[v] == ' ') v++;
    cf_bytes value = {p + v, eol - v};
    if (eq(name, "transfer-encoding")) {
      s->chunked = value.len >= 7 && !memcmp(value.ptr + value.len - 7, "chunked", 7);
    } else if (eq(name, "content-length")) {
      char tmp[16];
      if (!value.len || value.len >= sizeof(tmp)) return fail(s);
      memcpy(tmp, value.ptr, value.len);
      tmp[value.len] = 0;
      s->remaining = atoll(tmp);
    }
    if (!hop_by_hop(name) && count < HDR_MAX) headers[count++] = {name, value};
    i = eol + 2;
  }
  if (s->head || status == 204 || status == 304) {
    s->remaining = 0;
    s->chunked = false;
  }
  if (s->chunked) s->remaining = -1;
  s->up_done = !s->chunked && s->remaining == 0;
  s->body = (uint8_t *) malloc(BODY_MAX);
  if (!s->body) return fail(s);
  size_t extra = s->in_len - (end + 4);
  memcpy(s->body, p + end + 4, extra);  // extra <= HEAD_MAX <= BODY_MAX
  s->responded = true;
  if (cf_h2_respond(s->h, s->id, status, headers, count, true) != CF_OK) return fail(s);
  free(s->in);
  s->in = nullptr;
  if (extra && !s->up_done && !ingest(s, extra)) fail(s);
}

static void step(Stream *s) {
  if (!s->connected) {
    fd_set w;
    FD_ZERO(&w);
    FD_SET(s->fd, &w);
    timeval none = {0, 0};
    if (select(s->fd + 1, nullptr, &w, nullptr, &none) <= 0) return;
    int err = 0;
    socklen_t len = sizeof(err);
    if (getsockopt(s->fd, SOL_SOCKET, SO_ERROR, &err, &len) < 0 || err) return fail(s);
    s->connected = true;
  }
  if (!flush(s)) return fail(s);
  if (!s->body) {  // still waiting for the upstream response head
    if (!s->in) s->in = (uint8_t *) malloc(HEAD_MAX);
    if (!s->in) return fail(s);
    ssize_t n = recv(s->fd, s->in + s->in_len, HEAD_MAX - s->in_len, 0);
    if (n == 0) return fail(s);
    if (n < 0) {
      if (errno != EAGAIN && errno != EWOULDBLOCK) fail(s);
      return;
    }
    s->in_len += n;
    for (size_t i = 3; i < s->in_len; i++) {
      if (!memcmp(s->in + i - 3, "\r\n\r\n", 4)) return handle_head(s, i - 3);
    }
    if (s->in_len == HEAD_MAX) fail(s);  // head larger than the buffer
    return;
  }
  if (s->body_pos == s->body_len && !s->up_done) {  // body drained: read more
    s->body_pos = s->body_len = 0;
    size_t room = BODY_MAX;
    if (s->remaining >= 0 && (int64_t) room > s->remaining) room = s->remaining;
    ssize_t n = recv(s->fd, s->body, room, 0);
    if (n > 0) {
      if (!ingest(s, n)) return fail(s);
    } else if (n == 0) {
      if (s->chunked || s->remaining > 0) return fail(s);  // truncated
      s->up_done = true;
    } else if (errno != EAGAIN && errno != EWOULDBLOCK) {
      return fail(s);
    }
  }
  if (s->body_len > s->body_pos || s->up_done) cf_h2_resume(s->h, s->id);
}

static bool poll_streams(void *) {
  bool busy = false;
  for (auto &s : streams) {
    if (s.id && s.proxy) {
      busy = true;
      step(&s);
    }
  }
  return busy;
}

static cf_result request(void *ctx, cf_h2 *h, const cf_h2_request *r) {
  auto *self = static_cast<CloudflareTunnel *>(ctx);
  Stream *s = nullptr;
  for (auto &slot : streams)
    if (!slot.id) {
      s = &slot;
      break;
    }
  if (!s) return CF_ERR_LIMIT;
  *s = Stream{};
  s->id = r->stream;
  s->h = h;
  cf_bytes method = cf_h2_header(r, ":method"), path = cf_h2_header(r, ":path");
  s->head = eq(method, "HEAD");
  if (!eq(method, "GET") && !s->head) return respond(s, 405, "text/plain", NO_METHOD, sizeof(NO_METHOD) - 1);
  size_t n = 0;
  while (n < path.len && path.ptr[n] != '?') n++;  // pages ignore the query string
  if (const Page *page = self->find_page((const char *) path.ptr, n))
    return respond(s, 200, page->content_type.c_str(), page->content.data(), page->content.size());
  if (self->upstream_port()) return start_proxy(s, r, method, path, self->upstream_port());
  return respond(s, 404, "text/plain", NOT_FOUND, sizeof(NOT_FOUND) - 1);
}

static cf_result data(void *, int32_t, cf_bytes, bool) { return CF_OK; }  // request bodies are discarded

static cf_result read_response(void *, int32_t id, uint8_t *out, size_t capacity, size_t *written, bool *eof) {
  Stream *s = find(id);
  if (!s) return CF_ERR_STATE;
  if (s->proxy) {
    size_t avail = s->body_len - s->body_pos;
    if (!avail) {
      *written = 0;
      *eof = s->up_done;
      return s->up_done ? CF_OK : CF_ERR_STATE;  // deferred; step() resumes when data arrives
    }
    *written = avail < capacity ? avail : capacity;
    memcpy(out, s->body + s->body_pos, *written);
    s->body_pos += *written;
    *eof = s->up_done && s->body_pos == s->body_len;
    return CF_OK;
  }
  *written = s->head ? 0 : s->slen - s->sent;
  if (*written > capacity) *written = capacity;
  memcpy(out, s->sbody + s->sent, *written);
  s->sent += *written;
  *eof = s->head || s->sent == s->slen;
  return CF_OK;
}

static void closed(void *, int32_t id, uint32_t) {
  Stream *s = find(id);
  if (s) release(s);
}

const Page *CloudflareTunnel::find_page(const char *path, size_t len) const {
  for (auto &p : this->pages_)
    if (p.path.size() == len && !memcmp(p.path.data(), path, len)) return &p;
  return nullptr;
}

void CloudflareTunnel::setup() {
  esp_cf_tunnel_config config = {};
  config.context = this;
  config.environment = environment;
  config.credentials = credentials;
  config.json_try_lock = json_try_lock;
  config.json_unlock = json_unlock;
  config.request = request;
  config.data = data;
  config.read_response = read_response;
  config.closed = closed;
  config.poll = poll_streams;
  config.version = "esphome";
  config.arch = "esp32-espidf";
  config.service = "http://localhost:80";
  config.application_streams = this->streams_;
  if (esp_cf_tunnel_init(&config, &this->tunnel_) != ESP_OK || esp_cf_tunnel_start(this->tunnel_) != ESP_OK) {
    ESP_LOGE(TAG, "Tunnel failed to start");
    this->mark_failed();
  }
}

void CloudflareTunnel::dump_config() {
  ESP_LOGCONFIG(TAG, "Cloudflare Tunnel:");
  ESP_LOGCONFIG(TAG, "  Hostname: %s", this->hostname_.c_str());
  ESP_LOGCONFIG(TAG, "  Streams: %u, pages: %u, upstream port: %u", this->streams_, (unsigned) this->pages_.size(),
                this->upstream_port_);
  if (!this->tunnel_) return;
  esp_cf_tunnel_snapshot snap;
  esp_cf_tunnel_get_snapshot(this->tunnel_, &snap);
  ESP_LOGCONFIG(TAG, "  State: %s", esp_cf_tunnel_state_name(snap.state));
}

}  // namespace cloudflare_tunnel
}  // namespace esphome
