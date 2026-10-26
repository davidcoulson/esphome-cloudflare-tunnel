# ESPHome Cloudflare Tunnel

ESPHome external component: a native Cloudflare Tunnel connector (TLS 1.3, HTTP/2, Cap'n Proto RPC). MIT.

```yaml
external_components:
  - source: github://davidcoulson/esphome-cloudflare-tunnel
cloudflare_tunnel:
  token: !secret cf_tunnel_token   # the base64 token from the Zero Trust dashboard
  hostname: device.example.com     # must match the tunnel's public hostname (service http://localhost:80)
  application_streams: 4           # 2 or 4
  upstream_port: 80                # GET/HEAD not matching a page are proxied to 127.0.0.1:<port> (web_server); 0 disables
  pages:                           # optional static responses, checked before the proxy
    - path: /hello
      content: hello
web_server:                        # what the proxy exposes
```

Needs the `esp-idf` framework (built and tested on 5.5.4, ESP32-S3). Requires WiFi/Ethernet plus `time:` (SNTP) — the tunnel waits for a valid clock.

## How it works
Own implementation, written from the public [cloudflared](https://github.com/cloudflare/cloudflared) sources (no code copied): TLS 1.3 to the edge on 7844 (`h2.cftunnel.com`), the device acts as the HTTP/2 server (nghttp2), registers over Cap'n Proto RPC on the control stream, and takes its ingress config from the edge. Host-side tests of the Cap'n Proto/RPC/token code against Go-generated vectors are in `test/host`.

## Limits
- Edge discovery uses `region1.v2.argotunnel.com` / `region2.v2.argotunnel.com` directly instead of cloudflared's SRV lookup. The token's endpoint field is ignored.
- One edge connection (dashboard shows Degraded). Config check is simple: some ingress rule must name `hostname`.
- Proxy: GET/HEAD only (request bodies dropped), no WebSocket upgrade. Chunked responses and SSE (`/events`) are handled.
- Needs nghttp2 (`espressif/nghttp`) and IDF `json` components, fetched at build.

## Not verified
Compiled (IDF 5.5.4) for ESP32, ESP32-S3, ESP32-C3 and ESP32-P4 (`test/*.yaml`); never flashed and never connected to Cloudflare. The register request has no byte-level oracle beyond self-consistency.
