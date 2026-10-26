# ESPHome Cloudflare Tunnel

ESPHome external component wrapping [frxbg/esp-cf-tunnel](https://github.com/frxbg/esp-cf-tunnel)
(native Cloudflare Tunnel connector: TLS 1.3, HTTP/2, Cap'n Proto RPC). MIT, see `components/cloudflare_tunnel/LICENSE*`.

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

## Differences from upstream
- Builds on IDF 5.5 without the upstream esp-tls patch: the connect poll uses a 5 s `select()` timeout instead (stop can lag by that long).
- TLS alert diagnostics need an mbedTLS getter that 5.5 lacks; `tls_alert` stays -1.
- Sources are flattened (ESPHome copies no subfolders) and the CA bundle is a C array.
- Backend is the proxy/page table above, not the upstream system monitor. The library gained an optional `poll` callback so the proxy can drive its sockets from the tunnel task.
- Proxy limits: GET/HEAD only (request bodies are dropped, so no POST to switches via the tunnel), no WebSocket upgrade. Chunked responses and SSE (`/events`) are handled.

## Not verified
Compiled (IDF 5.5.4) for ESP32, ESP32-S3, ESP32-C3 and ESP32-P4 (`test/*.yaml`). Never flashed, never connected to Cloudflare, proxy never exercised. Upstream is itself experimental (one edge connection, so the dashboard shows Degraded).
