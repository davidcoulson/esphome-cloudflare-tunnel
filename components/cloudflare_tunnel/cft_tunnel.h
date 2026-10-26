#pragma once
// Cloudflare Tunnel connector: TLS to the edge, HTTP/2 server on that connection, Cap'n Proto registration on the
// control stream, remote ingress configuration, and a Backend that serves the HTTP streams.
#include <cstdint>

#include "cft_proto.h"
#include "cft_rpc.h"

namespace cft {

constexpr unsigned MAX_APP_STREAMS = 4;

struct Request {
  int32_t stream;
  const Header *headers;
  size_t count;
  bool end_stream;
  Bytes get(const char *lowercase_name) const;
};

class Backend {
 public:
  virtual ~Backend() = default;
  virtual bool network_ready() = 0;
  virtual bool time_valid() = 0;  // TLS certificate checks need a sane clock
  virtual bool local_ip(uint8_t out[4]) = 0;
  // All of these run on the tunnel task and must not block.
  virtual bool request(const Request &r) = 0;                       // false: refuse the stream
  virtual bool data(int32_t stream, Bytes chunk, bool end) = 0;     // request body; false: cancel the stream
  enum ReadResult { READ_OK, READ_DEFER, READ_FAIL };               // DEFER: call Tunnel::resume() later
  virtual ReadResult read(int32_t stream, uint8_t *buf, size_t cap, size_t *n, bool *eof) = 0;
  virtual void closed(int32_t stream) = 0;
  virtual bool poll() = 0;  // once per loop; true while work is pending (shortens the loop wait)
};

struct Config {
  const char *token, *hostname, *version, *arch;
  unsigned streams;
  Backend *backend;
};

class Tunnel {
 public:
  bool start(const Config &config);
  void stop();                          // asks the task to unregister and exit
  const char *status() const { return status_; }
  bool online() const { return online_; }

  // For the Backend, from the tunnel task.
  bool respond(int32_t stream, unsigned status, const Header *headers, size_t count, bool from_origin);
  void resume(int32_t stream);
  void reset(int32_t stream, uint32_t http2_error);

  struct Impl;

 private:
  friend struct Impl;
  Impl *impl_{nullptr};
  const char *volatile status_{"Stopped"};
  volatile bool online_{false};
};

}  // namespace cft
