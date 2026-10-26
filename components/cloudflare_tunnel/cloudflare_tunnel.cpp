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


namespace esphome {
namespace cloudflare_tunnel {

static const char *const TAG = "cloudflare_tunnel";

// One slot per application stream. A stream serves a static body (page or error) or proxies to the
// local web server over a nonblocking socket that poll_streams() drives from the tunnel task.
constexpr size_t OUT_MAX = 4096, HEAD_MAX = 2048, BODY_MAX = 2048, HDR_MAX = 24;
using cft::Bytes;
using cft::Header;
enum ChunkState : uint8_t { SIZE, EXT, SIZE_LF, DATA, CRLF1, CRLF2 };

struct Stream {
  int32_t id{0};
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
static Stream streams[cft::MAX_APP_STREAMS];
static cft::Tunnel *tunnel;
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

static void respond(Stream *s, unsigned status, const char *type, const char *body, size_t length) {
  s->sbody = body;
  s->slen = length;
  char len[24];
  snprintf(len, sizeof(len), "%u", (unsigned) length);
#define H(n, v) {{(const uint8_t *) (n), strlen(n)}, {(const uint8_t *) (v), strlen(v)}}
  Header headers[] = {H("content-type", type), H("content-length", len), H("cache-control", "no-store"),
                         H("x-content-type-options", "nosniff")};
#undef H
  s->responded = true;
  tunnel->respond(s->id, status, headers, 4, false);
}

// Proxy failed: 502 if the client has seen nothing yet, otherwise reset the stream.
static void fail(Stream *s) {
  if (s->fd >= 0) close(s->fd);
  s->fd = -1;
  s->proxy = false;
  if (s->responded) {
    tunnel->reset(s->id, 2);
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

static bool bad_token(Bytes b, bool allow_space) {
  for (size_t i = 0; i < b.len; i++)
    if (b.ptr[i] < 0x20 || b.ptr[i] == 0x7f || (!allow_space && b.ptr[i] == ' ')) return true;
  return false;
}

static bool eq(Bytes b, const char *lit) { return b.len == strlen(lit) && !memcmp(b.ptr, lit, b.len); }

static bool hop_by_hop(Bytes n) {
  return eq(n, "connection") || eq(n, "keep-alive") || eq(n, "transfer-encoding") || eq(n, "upgrade") ||
         eq(n, "proxy-connection") || eq(n, "te") || eq(n, "trailer") || eq(n, "host");
}

// Build "METHOD path HTTP/1.1" plus the forwarded headers into s->out and start the loopback connect.
// Request bodies are not forwarded: only GET and HEAD are proxied (what the web_server UI needs).
static void start_proxy(Stream *s, const cft::Request &r, Bytes method, Bytes path, uint16_t port) {
  Bytes auth = r.get(":authority");
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
  for (size_t i = 0; i < r.count; i++) {
    Bytes name = r.headers[i].name, value = r.headers[i].value;
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
  Header headers[HDR_MAX];
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
    Bytes name = {p + i, colon - i};
    size_t v = colon + 1;
    while (v < eol && p[v] == ' ') v++;
    Bytes value = {p + v, eol - v};
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
  if (!tunnel->respond(s->id, status, headers, count, true)) return fail(s);
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
  if (s->body_len > s->body_pos || s->up_done) tunnel->resume(s->id);
}

static bool poll_streams() {
  bool busy = false;
  for (auto &s : streams) {
    if (s.id && s.proxy) {
      busy = true;
      step(&s);
    }
  }
  return busy;
}

bool CloudflareTunnel::request(const cft::Request &r) {
  Stream *s = nullptr;
  for (auto &slot : streams)
    if (!slot.id) {
      s = &slot;
      break;
    }
  if (!s) return false;
  *s = Stream{};
  s->id = r.stream;
  Bytes method = r.get(":method"), path = r.get(":path");
  s->head = eq(method, "HEAD");
  if (!eq(method, "GET") && !s->head) return respond(s, 405, "text/plain", NO_METHOD, sizeof(NO_METHOD) - 1), true;
  size_t n = 0;
  while (n < path.len && path.ptr[n] != '?') n++;  // pages ignore the query string
  if (const Page *page = this->find_page((const char *) path.ptr, n))
    respond(s, 200, page->content_type.c_str(), page->content.data(), page->content.size());
  else if (this->upstream_port_)
    start_proxy(s, r, method, path, this->upstream_port_);
  else
    respond(s, 404, "text/plain", NOT_FOUND, sizeof(NOT_FOUND) - 1);
  return true;
}

bool CloudflareTunnel::data(int32_t, Bytes, bool) { return true; }  // request bodies are discarded

cft::Backend::ReadResult CloudflareTunnel::read(int32_t id, uint8_t *out, size_t capacity, size_t *written, bool *eof) {
  Stream *s = find(id);
  if (!s) return READ_FAIL;
  if (s->proxy) {
    size_t avail = s->body_len - s->body_pos;
    if (!avail) {
      *written = 0;
      *eof = s->up_done;
      return s->up_done ? READ_OK : READ_DEFER;  // step() resumes when data arrives
    }
    *written = avail < capacity ? avail : capacity;
    memcpy(out, s->body + s->body_pos, *written);
    s->body_pos += *written;
    *eof = s->up_done && s->body_pos == s->body_len;
    return READ_OK;
  }
  *written = s->head ? 0 : s->slen - s->sent;
  if (*written > capacity) *written = capacity;
  memcpy(out, s->sbody + s->sent, *written);
  s->sent += *written;
  *eof = s->head || s->sent == s->slen;
  return READ_OK;
}

void CloudflareTunnel::closed(int32_t id) {
  Stream *s = find(id);
  if (s) release(s);
}

bool CloudflareTunnel::network_ready() { return network::is_connected(); }
bool CloudflareTunnel::time_valid() { return time(nullptr) > 1704067200; }  // SNTP has synced
bool CloudflareTunnel::poll() { return poll_streams(); }

bool CloudflareTunnel::local_ip(uint8_t out[4]) {
  for (auto ip : network::get_ip_addresses()) {
    if (!ip.is_ip4()) continue;
    ip_addr_t a = ip;
    memcpy(out, &ip_2_ip4(&a)->addr, 4);
    return true;
  }
  return false;
}

const Page *CloudflareTunnel::find_page(const char *path, size_t len) const {
  for (auto &p : this->pages_)
    if (p.path.size() == len && !memcmp(p.path.data(), path, len)) return &p;
  return nullptr;
}

void CloudflareTunnel::setup() {
  tunnel = &this->tunnel_;
  cft::Config config = {this->token_.c_str(), this->hostname_.c_str(), "esphome", "esp32-espidf", this->streams_, this};
  if (this->hostname_.size() > 253 || !this->tunnel_.start(config)) {
    ESP_LOGE(TAG, "Tunnel failed to start");
    this->mark_failed();
  }
}

void CloudflareTunnel::on_shutdown() { this->tunnel_.stop(); }

void CloudflareTunnel::dump_config() {
  ESP_LOGCONFIG(TAG, "Cloudflare Tunnel:");
  ESP_LOGCONFIG(TAG, "  Hostname: %s", this->hostname_.c_str());
  ESP_LOGCONFIG(TAG, "  Streams: %u, pages: %u, upstream port: %u", this->streams_, (unsigned) this->pages_.size(),
                this->upstream_port_);
  ESP_LOGCONFIG(TAG, "  State: %s", this->tunnel_.status());
}

}  // namespace cloudflare_tunnel
}  // namespace esphome
