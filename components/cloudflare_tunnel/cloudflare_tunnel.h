#pragma once
#include "esphome/core/component.h"
#include <string>
#include <vector>

#include "cft_tunnel.h"

namespace esphome {
namespace cloudflare_tunnel {

struct Page {
  std::string path, content_type, content;
};

class CloudflareTunnel : public Component, public cft::Backend {
 public:
  void set_token(const std::string &v) { this->token_ = v; }
  void set_hostname(const std::string &v) { this->hostname_ = v; }
  void set_streams(unsigned v) { this->streams_ = v; }
  void set_upstream_port(uint16_t v) { this->upstream_port_ = v; }
  uint16_t upstream_port() const { return this->upstream_port_; }
  void add_page(const std::string &path, const std::string &type, const std::string &content) {
    this->pages_.push_back({path, type, content});
  }
  void setup() override;
  void dump_config() override;
  void on_shutdown() override;
  float get_setup_priority() const override { return setup_priority::AFTER_WIFI; }

  // Called on the tunnel task, not the main loop.
  const Page *find_page(const char *path, size_t len) const;
  const std::string &token() const { return this->token_; }
  const std::string &hostname() const { return this->hostname_; }

  bool network_ready() override;
  bool time_valid() override;
  bool local_ip(uint8_t out[4]) override;
  bool request(const cft::Request &r) override;
  bool data(int32_t stream, cft::Bytes chunk, bool end) override;
  ReadResult read(int32_t stream, uint8_t *buf, size_t cap, size_t *n, bool *eof) override;
  void closed(int32_t stream) override;
  bool poll() override;

 protected:
  std::string token_, hostname_;
  unsigned streams_{4};
  uint16_t upstream_port_{80};
  std::vector<Page> pages_;
  cft::Tunnel tunnel_;
};

}  // namespace cloudflare_tunnel
}  // namespace esphome
