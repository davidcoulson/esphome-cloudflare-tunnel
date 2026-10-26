#include "cft_tunnel.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <new>

#include "cJSON.h"
#include "esp_log.h"
#include "esp_random.h"
#include "esp_timer.h"
#include "esp_tls.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "lwip/sockets.h"
#include "nghttp2/nghttp2.h"

extern const unsigned char cf_edge_ca_pem[];
extern const unsigned cf_edge_ca_pem_len;

namespace cft {

static const char *const TAG = "cloudflare_tunnel";

// Edge discovery: cloudflared resolves the SRV record _v2-origintunneld._tcp.argotunnel.com, whose targets are these
// two names (the same ones Cloudflare lists for firewall rules). lwIP has no SRV lookup, so use them directly.
static const char *const EDGE_HOSTS[] = {"region1.v2.argotunnel.com", "region2.v2.argotunnel.com"};
static const char EDGE_TLS_NAME[] = "h2.cftunnel.com";
constexpr int EDGE_PORT = 7844;

constexpr size_t CHUNK = 2048, HEADER_BYTES = 8192, HEADER_MAX = 48, CONFIG_MAX = 4096, RX_MAX = 1024, TX_MAX = 2048;
constexpr uint64_t HANDSHAKE_MS = 30000, STREAM_IDLE_MS = 15000, PING_AFTER_MS = 30000, DEAD_AFTER_MS = 90000;
constexpr size_t SLOTS = MAX_APP_STREAMS + 2;  // application streams + control + configuration

Bytes Request::get(const char *name) const {
  size_t n = strlen(name);
  for (size_t i = 0; i < count; i++)
    if (headers[i].name.len == n && !memcmp(headers[i].name.ptr, name, n)) return headers[i].value;
  return {};
}

static uint64_t now_ms() { return (uint64_t) esp_timer_get_time() / 1000; }
static bool is(Bytes b, const char *s) { return b.len == strlen(s) && !memcmp(b.ptr, s, b.len); }

enum Kind : uint8_t { HTTP, CONTROL, CONFIG };

struct Slot {
  int32_t id{0};
  Kind kind{HTTP};
  bool started{false}, responded{false}, reset{false}, deferred{false};
  uint64_t progress_ms{0};
};

struct Tunnel::Impl {
  Tunnel *owner;
  Config cfg;
  TaskHandle_t task{nullptr};
  volatile bool stop_requested{false}, finished{true};

  // connection
  esp_tls_t *tls{nullptr};
  nghttp2_session *h2{nullptr};
  Slot slots[SLOTS];
  const uint8_t *pending{nullptr};
  size_t pending_len{0};
  uint64_t started_ms{0}, last_rx_ms{0}, last_ping_ms{0}, write_stalled_ms{0};
  bool goaway_seen{false}, fault{false}, stopping{false};
  const char *fail_reason{""};

  char wire[2048];  // serialized response headers

  // header block being received
  Header block[HEADER_MAX];
  size_t block_count{0}, block_used{0};
  int32_t block_stream{0};
  uint8_t block_bytes[HEADER_BYTES];

  // registration
  Rpc rpc;
  Credentials cred;
  RpcOptions opts;
  uint8_t connector_id[16];
  uint32_t attempts{0};
  int32_t control_stream{0}, config_stream{0};
  uint8_t rx[RX_MAX], tx[TX_MAX];
  size_t rx_len{0}, tx_len{0};
  bool registered{false}, configured{false};
  int32_t config_version{-1};
  uint8_t *config_body{nullptr};
  size_t config_len{0};
  char config_reply[64];
  size_t config_reply_len{0}, config_reply_sent{0};
  bool config_ready{false}, config_replied{false};

  // retry
  uint64_t retry_at_ms{0};
  uint32_t backoff_s{1}, retry_hint_ms{0};
  bool rejected_for_good{false};

  void status(const char *s) {
    if (owner->status_ != s) ESP_LOGI(TAG, "%s", s);
    owner->status_ = s;
  }
  Slot *find(int32_t id) {
    for (auto &s : slots)
      if (s.id == id) return &s;
    return nullptr;
  }

  // ---- control stream (registration RPC) ----
  bool queue_tx(const uint8_t *p, size_t n) {
    if (n > TX_MAX - tx_len) return false;
    memcpy(tx + tx_len, p, n);
    tx_len += n;
    resume_slot(control_stream);
    return true;
  }
  void resume_slot(int32_t id) {
    Slot *s = find(id);
    if (s && s->responded && s->deferred && !s->reset && nghttp2_session_resume_data(h2, id) == 0) s->deferred = false;
  }

  bool rpc_frame(Bytes frame) {
    uint8_t out[RPC_TX_MAX];
    size_t n;
    Result r = rpc.receive(frame, out, sizeof out, &n);
    bool ok = n == 0 || queue_tx(out, n);
    if (r != OK || !ok) {
      fail("Registration RPC failed");
      return false;
    }
    if (rpc.state == READY) {
      opts.local_ip = {local_ip, local_ip_len};
      opts.previous_attempts = attempts > 256 ? 255 : (uint8_t) (attempts - 1);
      r = rpc.register_connection(cred, opts, out, sizeof out, &n);
      memset(&cred, 0, sizeof cred);  // the secret is not needed again
      if (r != OK || !queue_tx(out, n)) {
        fail("Could not build registration");
        return false;
      }
    } else if (rpc.state == REGISTERED) {
      registered = true;
      ESP_LOGI(TAG, "Registered with Cloudflare (%s)", rpc.location);
      status(configured ? "Online" : "Waiting for configuration");
      started_ms = now_ms();
    } else if (rpc.state == REJECTED) {
      rejected_for_good = !rpc.should_retry;
      retry_hint_ms = rpc.retry_after_ms;
      fail(rejected_for_good ? "Cloudflare rejected the tunnel credentials" : "Cloudflare asked to retry later");
      return false;
    }
    return true;
  }
  bool rpc_bytes(Bytes in) {
    if (in.len > RX_MAX - rx_len) return fail("RPC frame too large"), false;
    memcpy(rx + rx_len, in.ptr, in.len);
    rx_len += in.len;
    for (;;) {
      size_t total = Reader::frame_size({rx, rx_len});
      if (total == SIZE_MAX || total > RX_MAX) return fail("RPC frame too large"), false;
      if (!total || rx_len < total) return true;
      if (!rpc_frame({rx, total})) return false;
      memmove(rx, rx + total, rx_len - total);
      rx_len -= total;
    }
  }

  // ---- configuration stream ----
  // Body: {"version": N, "config": {"ingress": [{"hostname": ..., "service": ...}, ...]}}. Accepted when some
  // ingress rule is for our hostname; the edge only routes that name here.
  void apply_config() {
    bool ok = false;
    int32_t version = config_version;
    ESP_LOGD(TAG, "Ingress update: %.*s", (int) (config_len > 400 ? 400 : config_len), (const char *) config_body);
    cJSON *root = cJSON_ParseWithLength((const char *) config_body, config_len);
    cJSON *v = cJSON_GetObjectItemCaseSensitive(root, "version");
    cJSON *ingress = cJSON_GetObjectItemCaseSensitive(cJSON_GetObjectItemCaseSensitive(root, "config"), "ingress");
    if (cJSON_IsNumber(v) && v->valuedouble >= 0 && v->valuedouble <= INT32_MAX && cJSON_IsArray(ingress)) {
      if ((int32_t) v->valuedouble <= config_version) {
        ok = true;  // stale or repeated update: keep what we have
      } else {
        cJSON *rule;
        cJSON_ArrayForEach(rule, ingress) {
          cJSON *h = cJSON_GetObjectItemCaseSensitive(rule, "hostname");
          if (cJSON_IsString(h) && !strcmp(h->valuestring, cfg.hostname)) ok = true;
        }
        if (ok) {
          version = (int32_t) v->valuedouble;
          config_version = version;
          configured = true;
          if (registered) status("Online");
        } else {
          ESP_LOGW(TAG, "Ingress update has no rule for %s", cfg.hostname);
        }
      }
    }
    cJSON_Delete(root);
    free(config_body);
    config_body = nullptr;
    config_len = 0;
    config_reply_len = snprintf(config_reply, sizeof config_reply, "{\"lastAppliedVersion\":%ld,\"err\":%s}",
                                (long) config_version, ok ? "null" : "{}");
    config_reply_sent = 0;
    config_ready = true;
    Header ct = {{(const uint8_t *) "content-type", 12}, {(const uint8_t *) "application/json", 16}};
    (void) version;
    submit(config_stream, 200, &ct, 1, nullptr);
  }

  // ---- HTTP/2 ----
  bool fail(const char *why) {
    if (!fault) fail_reason = why;
    fault = true;
    return false;
  }

  void rst(int32_t id, uint32_t code) {
    Slot *s = find(id);
    if (s) {
      if (s->reset) return;
      s->reset = true;
    }
    nghttp2_submit_rst_stream(h2, NGHTTP2_FLAG_NONE, id, code);
  }

  // Sends :status and the given headers; the body comes from read_cb. Real headers only: the caller decides.
  bool submit(int32_t id, unsigned status, const Header *extra, size_t n, const char *meta_or_null) {
    Slot *s = find(id);
    if (!s || !s->started || s->responded || s->reset) return false;
    char code[4];
    snprintf(code, sizeof code, "%u", status);
    nghttp2_nv nva[4 + 2];
    size_t k = 0;
    auto add = [&](const char *name, const char *v, size_t vl) {
      nva[k++] = {(uint8_t *) name, (uint8_t *) v, strlen(name), vl, NGHTTP2_NV_FLAG_NONE};
    };
    add(":status", code, 3);
    (void) meta_or_null;
    for (size_t i = 0; i < n && k < 4 + 2; i++) {
      nva[k++] = {(uint8_t *) extra[i].name.ptr, (uint8_t *) extra[i].value.ptr, extra[i].name.len, extra[i].value.len,
                  NGHTTP2_NV_FLAG_NONE};
    }
    nghttp2_data_provider2 provider = {};
    provider.read_callback = read_cb;
    if (nghttp2_submit_response2(h2, id, nva, k, &provider)) return false;
    s->responded = true;
    return true;
  }

  static Tunnel::Impl *self(void *u) { return static_cast<Tunnel::Impl *>(u); }

  static int on_begin_headers(nghttp2_session *, const nghttp2_frame *f, void *u) {
    Impl *t = self(u);
    t->block_stream = 0;
    if (f->headers.cat != NGHTTP2_HCAT_REQUEST) {  // trailers and pushes are not part of this protocol
      t->rst(f->hd.stream_id, NGHTTP2_PROTOCOL_ERROR);
      return 0;
    }
    for (auto &s : t->slots) {
      if (s.id) continue;
      s = Slot{};
      s.id = f->hd.stream_id;
      s.progress_ms = now_ms();
      t->block_stream = s.id;
      t->block_count = t->block_used = 0;
      return 0;
    }
    t->rst(f->hd.stream_id, NGHTTP2_REFUSED_STREAM);
    return 0;
  }

  static int on_header(nghttp2_session *, const nghttp2_frame *f, const uint8_t *name, size_t nl, const uint8_t *value,
                       size_t vl, uint8_t, void *u) {
    Impl *t = self(u);
    if (t->block_stream != f->hd.stream_id) return 0;
    bool bad = t->block_count == HEADER_MAX || nl > HEADER_BYTES - t->block_used ||
               vl > HEADER_BYTES - t->block_used - nl;
    // A repeated pseudo or cf-cloudflared-* field would make routing ambiguous.
    if (!bad && ((nl && name[0] == ':') || (nl >= 15 && !memcmp(name, "cf-cloudflared-", 15))))
      for (size_t i = 0; i < t->block_count; i++)
        if (t->block[i].name.len == nl && !memcmp(t->block[i].name.ptr, name, nl)) bad = true;
    if (bad) {
      t->block_stream = 0;
      t->rst(f->hd.stream_id, NGHTTP2_ENHANCE_YOUR_CALM);
      return 0;
    }
    uint8_t *p = t->block_bytes + t->block_used;
    memcpy(p, name, nl);
    memcpy(p + nl, value, vl);
    t->block[t->block_count++] = {{p, nl}, {p + nl, vl}};
    t->block_used += nl + vl;
    return 0;
  }

  static int on_frame_recv(nghttp2_session *, const nghttp2_frame *f, void *u) {
    Impl *t = self(u);
    if (f->hd.type == NGHTTP2_GOAWAY) t->goaway_seen = true;
    Slot *s = t->find(f->hd.stream_id);
    if (!s || s->reset) return 0;
    bool end = f->hd.flags & NGHTTP2_FLAG_END_STREAM;
    if (f->hd.type == NGHTTP2_HEADERS && t->block_stream == s->id) {
      t->block_stream = 0;
      t->start_stream(s, end);
    }
    if (end && (f->hd.type == NGHTTP2_HEADERS || f->hd.type == NGHTTP2_DATA) && s->started && !s->reset)
      t->stream_data(s, {nullptr, 0}, true);
    return 0;
  }

  static int on_data_chunk(nghttp2_session *, uint8_t, int32_t id, const uint8_t *data, size_t len, void *u) {
    Impl *t = self(u);
    Slot *s = t->find(id);
    if (!s || s->reset || !s->started) return 0;
    for (size_t off = 0; off < len && !s->reset;) {
      size_t n = len - off < CHUNK ? len - off : CHUNK;
      if (!t->stream_data(s, {data + off, n}, false)) break;
      off += n;
    }
    s->progress_ms = now_ms();
    return 0;
  }

  static int on_stream_close(nghttp2_session *, int32_t id, uint32_t, void *u) {
    Impl *t = self(u);
    Slot *s = t->find(id);
    if (!s) return 0;
    if (s->kind == CONTROL) {
      if (t->control_stream == id && !t->stopping) t->fail("Cloudflare closed the control stream");
      t->control_stream = 0;
    } else if (s->kind == CONFIG) {
      t->config_stream = 0;
      free(t->config_body);
      t->config_body = nullptr;
      t->config_len = 0;
      t->config_ready = t->config_replied = false;
    } else if (s->started) {
      t->cfg.backend->closed(id);
    }
    *s = Slot{};
    return 0;
  }

  static nghttp2_ssize read_cb(nghttp2_session *, int32_t id, uint8_t *buf, size_t cap, uint32_t *flags,
                               nghttp2_data_source *, void *u) {
    Impl *t = self(u);
    Slot *s = t->find(id);
    if (!s || s->reset) return NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
    s->deferred = false;
    if (cap > CHUNK) cap = CHUNK;
    size_t n = 0;
    bool eof = false;
    if (s->kind == CONTROL) {
      n = t->tx_len < cap ? t->tx_len : cap;
      memcpy(buf, t->tx, n);
      t->tx_len -= n;
      memmove(t->tx, t->tx + n, t->tx_len);
      eof = t->rpc.state == CLOSED && !t->tx_len;
    } else if (s->kind == CONFIG) {
      n = t->config_reply_len - t->config_reply_sent;
      if (n > cap) n = cap;
      memcpy(buf, t->config_reply + t->config_reply_sent, n);
      t->config_reply_sent += n;
      eof = t->config_reply_sent == t->config_reply_len;
    } else {
      switch (t->cfg.backend->read(id, buf, cap, &n, &eof)) {
        case Backend::READ_OK: break;
        case Backend::READ_DEFER: n = 0; eof = false; break;
        default: return NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
      }
      if (n > cap) return NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
    }
    if (!n && !eof) {
      s->deferred = true;
      return NGHTTP2_ERR_DEFERRED;
    }
    if (eof) *flags |= NGHTTP2_DATA_FLAG_EOF;
    s->progress_ms = now_ms();
    return (nghttp2_ssize) n;
  }

  // A complete request header block has arrived on stream `s`.
  void start_stream(Slot *s, bool end) {
    Request req{s->id, block, block_count, end};
    Bytes upgrade = req.get("cf-cloudflared-proxy-connection-upgrade");
    ESP_LOGD(TAG, "Stream %d: %.*s", (int) s->id, (int) (upgrade.len ? upgrade.len : 4), upgrade.len ? (const char *) upgrade.ptr : "http");
    if (is(upgrade, "control-stream")) s->kind = CONTROL;
    else if (is(upgrade, "update-configuration")) s->kind = CONFIG;
    else if (upgrade.len) return rst(s->id, NGHTTP2_REFUSED_STREAM);  // websocket and friends are not proxied
    unsigned active = 0;
    for (auto &o : slots)
      if (o.id && o.started && !o.reset && o.kind == s->kind) active++;
    if (active >= (s->kind == HTTP ? cfg.streams : 1)) return rst(s->id, NGHTTP2_REFUSED_STREAM);
    s->started = true;
    if (s->kind == CONTROL) {
      if (end) return rst(s->id, NGHTTP2_PROTOCOL_ERROR);
      uint8_t out[RPC_TX_MAX];
      size_t n;
      control_stream = s->id;
      rpc.reset();
      rx_len = tx_len = 0;
      if (rpc.begin(out, sizeof out, &n) != OK || !queue_tx(out, n)) return (void) fail("Could not start RPC");
      started_ms = now_ms();
      status("Registering");
      submit(s->id, 200, nullptr, 0, nullptr);
    } else if (s->kind == CONFIG) {
      config_stream = s->id;
      config_len = 0;
      config_ready = config_replied = false;
      free(config_body);
      config_body = nullptr;
    } else {
      Bytes auth = req.get(":authority");
      size_t hl = strlen(cfg.hostname);
      if (!online_ready() || auth.len != hl || memcmp(auth.ptr, cfg.hostname, hl) ||
          !cfg.backend->request(req))
        rst(s->id, NGHTTP2_REFUSED_STREAM);
    }
    memset(block_bytes, 0, block_used);
  }
  bool online_ready() const { return registered && configured; }

  bool stream_data(Slot *s, Bytes chunk, bool end) {
    if (s->kind == CONTROL) {
      if (end && rpc.state != CLOSED) return fail("Control stream ended early");
      return chunk.len ? rpc_bytes(chunk) : true;
    }
    if (s->kind == CONFIG) {
      if (config_ready) return true;
      if (chunk.len) {
        if (!config_body) config_body = (uint8_t *) malloc(CONFIG_MAX);
        if (!config_body || chunk.len > CONFIG_MAX - config_len) {
          rst(s->id, NGHTTP2_CANCEL);
          return false;
        }
        memcpy(config_body + config_len, chunk.ptr, chunk.len);
        config_len += chunk.len;
      }
      if (end) apply_config();
      return true;
    }
    if (!cfg.backend->data(s->id, chunk, end)) {
      rst(s->id, NGHTTP2_CANCEL);
      return false;
    }
    return true;
  }

  bool open_h2() {
    nghttp2_option *option;
    nghttp2_session_callbacks *cb;
    if (nghttp2_option_new(&option)) return false;
    if (nghttp2_session_callbacks_new(&cb)) {
      nghttp2_option_del(option);
      return false;
    }
    nghttp2_option_set_no_closed_streams(option, 1);
    nghttp2_option_set_max_reserved_remote_streams(option, 0);
    nghttp2_option_set_max_send_header_block_length(option, HEADER_BYTES);
    nghttp2_option_set_max_settings(option, 16);
    nghttp2_session_callbacks_set_on_begin_headers_callback(cb, on_begin_headers);
    nghttp2_session_callbacks_set_on_header_callback(cb, on_header);
    nghttp2_session_callbacks_set_on_frame_recv_callback(cb, on_frame_recv);
    nghttp2_session_callbacks_set_on_data_chunk_recv_callback(cb, on_data_chunk);
    nghttp2_session_callbacks_set_on_stream_close_callback(cb, on_stream_close);
    int rc = nghttp2_session_server_new2(&h2, cb, this, option);
    nghttp2_option_del(option);
    nghttp2_session_callbacks_del(cb);
    if (rc) return false;
    // cloudflared advertises unlimited concurrency; we refuse excess streams ourselves.
    nghttp2_settings_entry settings[] = {{NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, UINT32_MAX},
                                         {NGHTTP2_SETTINGS_MAX_HEADER_LIST_SIZE, HEADER_BYTES}};
    return nghttp2_submit_settings(h2, NGHTTP2_FLAG_NONE, settings, 2) == 0;
  }

  void close_all() {
    if (h2) {
      for (auto &s : slots)
        if (s.id && s.kind == HTTP && s.started) cfg.backend->closed(s.id);
      nghttp2_session_del(h2);
      h2 = nullptr;
    }
    if (tls) {
      esp_tls_conn_destroy(tls);
      tls = nullptr;
    }
    for (auto &s : slots) s = Slot{};
    free(config_body);
    config_body = nullptr;
    config_len = 0;
    pending = nullptr;
    pending_len = 0;
    memset(&cred, 0, sizeof cred);
    rpc.reset();
    rx_len = tx_len = 0;
    control_stream = config_stream = block_stream = 0;
    registered = configured = fault = goaway_seen = stopping = false;
    config_version = -1;
    config_ready = config_replied = false;
    owner->online_ = false;
  }

  // ---- connection ----
  uint8_t local_ip[16];
  size_t local_ip_len{0};

  bool connect() {
    status("Connecting");
    Result r = parse_token(cfg.token, strlen(cfg.token), &cred);
    if (r != OK) return fail("Invalid tunnel token"), rejected_for_good = true, false;
    if (!(local_ip_len = cfg.backend->local_ip(local_ip))) return fail("No IP address");
    esp_tls_cfg_t tc = {};
    tc.common_name = EDGE_TLS_NAME;
    tc.cacert_buf = cf_edge_ca_pem;
    tc.cacert_bytes = cf_edge_ca_pem_len;
    tc.timeout_ms = 15000;
    tls = esp_tls_init();
    const char *host = EDGE_HOSTS[attempts % 2];
    if (!tls || esp_tls_conn_new_sync(host, strlen(host), EDGE_PORT, &tc, tls) != 1) return fail("Edge connect failed");
    int fd;
    if (esp_tls_get_conn_sockfd(tls, &fd) != ESP_OK) return fail("No socket");
    fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK);
    int one = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
    if (!open_h2()) return fail("Not enough memory for HTTP/2");
    started_ms = last_rx_ms = now_ms();
    status("Waiting for the edge");
    return true;
  }

  // One pass of I/O. False ends the connection (fail_reason says why).
  bool pump() {
    uint8_t in[CHUNK];
    bool want_write = false;
    for (int i = 0; i < 8 && !write_stalled_ms; i++) {
      ssize_t n = esp_tls_conn_read(tls, in, sizeof in);
      if (n == ESP_TLS_ERR_SSL_WANT_READ || n == ESP_TLS_ERR_SSL_WANT_WRITE) {
        want_write = n == ESP_TLS_ERR_SSL_WANT_WRITE;
        break;
      }
      if (n <= 0) return fail("Edge closed the connection");
      last_rx_ms = now_ms();
      ssize_t used = nghttp2_session_mem_recv2(h2, in, n);
      if (used != n) return fail("HTTP/2 protocol error");
    }
    if (fault) return false;
    uint64_t now = now_ms();
    for (auto &s : slots)  // stuck request/response streams (control stays open indefinitely)
      if (s.id && !s.reset && s.kind != CONTROL && now - s.progress_ms > STREAM_IDLE_MS && !(s.kind == CONFIG && !s.started))
        rst(s.id, NGHTTP2_CANCEL);
    bool busy = cfg.backend->poll();
    if (now - last_rx_ms > DEAD_AFTER_MS) return fail("Edge stopped responding");
    if (now - last_rx_ms > PING_AFTER_MS && now - last_ping_ms > PING_AFTER_MS) {
      nghttp2_submit_ping(h2, NGHTTP2_FLAG_NONE, nullptr);
      last_ping_ms = now;
    }
    if (!registered && now - started_ms > HANDSHAKE_MS) return fail("Registration timed out");
    if (registered && !configured && now - started_ms > HANDSHAKE_MS)
      return fail("No ingress configuration received; check the tunnel's public hostname");
    if (goaway_seen && !stopping) return fail("The edge asked for a new connection");

    for (int i = 0; i < 8; i++) {
      if (!pending_len) {
        ssize_t n = nghttp2_session_mem_send2(h2, &pending);
        if (n < 0) return fail("HTTP/2 encode error");
        pending_len = n;
      }
      if (!pending_len) break;
      ssize_t n = esp_tls_conn_write(tls, pending, pending_len < CHUNK ? pending_len : CHUNK);
      if (n == ESP_TLS_ERR_SSL_WANT_READ || n == ESP_TLS_ERR_SSL_WANT_WRITE) {
        if (!write_stalled_ms) write_stalled_ms = now;
        if (now - write_stalled_ms > STREAM_IDLE_MS) return fail("TLS output stalled");
        want_write = n == ESP_TLS_ERR_SSL_WANT_WRITE;
        break;
      }
      if (n <= 0) return fail("TLS write failed");
      write_stalled_ms = 0;
      pending += n;
      pending_len -= n;
    }
    if (fault) return false;
    if (registered && configured) owner->online_ = true;
    int fd;
    if (esp_tls_get_conn_sockfd(tls, &fd) == ESP_OK) {
      fd_set rd, wr;
      FD_ZERO(&rd);
      FD_ZERO(&wr);
      FD_SET(fd, &rd);
      if (pending_len || want_write || nghttp2_session_want_write(h2)) FD_SET(fd, &wr);
      timeval tv = {0, busy ? 5000 : 100000};
      select(fd + 1, &rd, &wr, nullptr, &tv);
    }
    return true;
  }

  void graceful_stop() {
    if (!h2 || rpc.state != REGISTERED) return;
    uint8_t out[RPC_TX_MAX];
    size_t n;
    if (rpc.unregister(out, sizeof out, &n) == OK && queue_tx(out, n)) {
      stopping = true;
      uint64_t end = now_ms() + 2000;
      while (now_ms() < end && rpc.state != CLOSED && pump()) {
      }
      nghttp2_submit_goaway(h2, NGHTTP2_FLAG_NONE, nghttp2_session_get_last_proc_stream_id(h2), NGHTTP2_NO_ERROR, nullptr, 0);
      for (int i = 0; i < 4 && pump(); i++) {
      }
    }
  }

  void run() {
    esp_fill_random(connector_id, sizeof connector_id);
    connector_id[6] = (connector_id[6] & 15) | 64;  // UUID v4
    connector_id[8] = (connector_id[8] & 63) | 128;
    memcpy(opts.connector_id, connector_id, 16);
    opts.version = cfg.version;
    opts.arch = cfg.arch;
    opts.features = FEATURE_REMOTE_CONFIG | FEATURE_SERIALIZED_HEADERS;
    while (!stop_requested) {
      if (rejected_for_good) {
        status("Authentication rejected");
        vTaskDelay(pdMS_TO_TICKS(1000));
        continue;
      }
      if (!cfg.backend->network_ready() || !cfg.backend->time_valid()) {
        status("Waiting for network or clock");
        vTaskDelay(pdMS_TO_TICKS(500));
        continue;
      }
      if (now_ms() < retry_at_ms) {
        vTaskDelay(pdMS_TO_TICKS(250));
        continue;
      }
      attempts++;
      bool up = connect();
      while (up && !stop_requested) up = pump();
      if (stop_requested && !fault) graceful_stop();
      if (!stop_requested || fault) ESP_LOGW(TAG, "Connection ended: %s", fail_reason);
      bool was_registered = registered;
      close_all();
      if (stop_requested) break;
      // Exponential backoff with jitter, reset after a connection that registered.
      backoff_s = was_registered ? 1 : (backoff_s < 60 ? backoff_s * 2 : 60);
      uint32_t wait_ms = backoff_s * 1000 + esp_random() % 1000;
      if (retry_hint_ms > wait_ms) wait_ms = retry_hint_ms;
      retry_hint_ms = 0;
      retry_at_ms = now_ms() + wait_ms;
      fault = false;
      if (!rejected_for_good) status("Retry backoff");
    }
    close_all();
    status("Stopped");
    finished = true;
    task = nullptr;
    vTaskDelete(nullptr);
  }
  static void entry(void *p) { static_cast<Impl *>(p)->run(); }
};

bool Tunnel::start(const Config &config) {
  if (impl_ && !impl_->finished) return false;
  if (!impl_) impl_ = new (std::nothrow) Impl();
  if (!impl_) return false;
  impl_->owner = this;
  impl_->cfg = config;
  impl_->stop_requested = false;
  impl_->finished = false;
  status_ = "Starting";
  if (xTaskCreate(Impl::entry, "cf_tunnel", 14336, impl_, 4, &impl_->task) != pdPASS) {
    impl_->finished = true;
    return false;
  }
  return true;
}

void Tunnel::stop() {
  if (impl_) impl_->stop_requested = true;
}

bool Tunnel::respond(int32_t stream, unsigned status, const Header *headers, size_t count, bool from_origin) {
  Impl *t = impl_;
  if (!t || !t->h2 || status < 200 || status > 599) return false;
  // Response headers travel serialized in one header so HTTP/1 values bypass HTTP/2 validation; the edge
  // rebuilds them. Control-plane names are dropped, content-length is also sent as a real header.
  char *wire = t->wire;  // not thread_local: that adds 2 KB of TLS to every FreeRTOS task's stack
  Header user[24];
  size_t nu = 0;
  Bytes length{};
  for (size_t i = 0; i < count; i++) {
    Bytes n = headers[i].name;
    auto starts = [&](const char *p) { size_t l = strlen(p); return n.len >= l && !memcmp(n.ptr, p, l); };
    if (n.len == 14 && !memcmp(n.ptr, "content-length", 14)) length = headers[i].value;
    if (starts(":") || starts("cf-int-") || starts("cf-cloudflared-") || starts("cf-proxy-")) continue;
    if (nu < 24) user[nu++] = headers[i];
  }
  int wl = encode_headers(user, nu, wire, sizeof t->wire);
  if (wl < 0) return false;
  Slot *s = t->find(stream);
  if (!s || !s->started || s->responded || s->reset) return false;
  char code[4];
  snprintf(code, sizeof code, "%u", status);
  const char *meta = from_origin ? META_ORIGIN : META_CONNECTOR;
  nghttp2_nv nva[4];
  size_t k = 0;
  auto add = [&](const char *name, const char *v, size_t vl) {
    nva[k++] = {(uint8_t *) name, (uint8_t *) v, strlen(name), vl, NGHTTP2_NV_FLAG_NONE};
  };
  add(":status", code, 3);
  add("cf-cloudflared-response-headers", wire, wl);
  add("cf-cloudflared-response-meta", meta, strlen(meta));
  if (length.len) add("content-length", (const char *) length.ptr, length.len);
  nghttp2_data_provider2 provider = {};
  provider.read_callback = Impl::read_cb;
  if (nghttp2_submit_response2(t->h2, stream, nva, k, &provider)) return false;
  s->responded = true;
  return true;
}

void Tunnel::resume(int32_t stream) {
  if (impl_ && impl_->h2) impl_->resume_slot(stream);
}

void Tunnel::reset(int32_t stream, uint32_t code) {
  if (impl_ && impl_->h2) impl_->rst(stream, code);
}

}  // namespace cft
