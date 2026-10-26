#pragma once
// Tunnel registration over Cap'n Proto RPC (level 1: Bootstrap, Call, Return, Finish, Release, Abort), following
// cloudflared's tunnelrpc.capnp (RegistrationServer) and capnp's rpc.capnp. One question at a time, no promise
// pipelining: we wait for each Return before using its result.
#include <cstdint>
#include <cstring>

#include "cft_capnp.h"

namespace cft {

enum Result : int { OK = 0, ERR_STATE, ERR_FORMAT, ERR_UNSUPPORTED, ERR_ARGUMENT, ERR_LIMIT };

enum RpcState : uint8_t { IDLE, BOOTSTRAPPING, READY, REGISTERING, REGISTERED, UNREGISTERING, CLOSED, REJECTED, FAILED };

constexpr size_t RPC_TX_MAX = 1024;
constexpr uint32_t FEATURE_REMOTE_CONFIG = 1, FEATURE_SERIALIZED_HEADERS = 2;

struct Credentials {
  char account_tag[33]{};
  uint8_t secret[128]{};
  size_t secret_len{0};
  uint8_t tunnel_id[16]{};
};

struct RpcOptions {
  uint8_t connector_id[16]{};
  Bytes local_ip;  // 4 or 16 bytes
  const char *version{"esphome"}, *arch{"esp32"};
  uint8_t connection_index{0}, previous_attempts{0};
  uint32_t features{0};
};

class Rpc {
 public:
  static constexpr uint64_t REGISTRATION_SERVER = 0xf71695ec7fe85497ull;

  RpcState state{IDLE};
  bool have_capability{false}, remotely_managed{false}, should_retry{false};
  uint32_t capability{0}, retry_after_ms{0};
  uint8_t connection_id[16]{};
  char location[16]{};

  // Bootstrap question 0.
  Result begin(uint8_t *out, size_t cap, size_t *n) {
    *n = 0;
    if (state != IDLE) return ERR_STATE;
    Builder b(seg_, SEG_WORDS);
    uint32_t m = b.make_struct(0, 1, 1);
    b.set16(m, 0, MSG_BOOTSTRAP);
    uint32_t bs = b.make_struct(m + 1, 1, 1);
    b.set32(bs, 0, Q_BOOTSTRAP);
    if (!finish(b, out, cap, n)) return ERR_LIMIT;
    state = BOOTSTRAPPING;
    return OK;
  }

  // RegistrationServer.registerConnection (question 1).
  Result register_connection(const Credentials &c, const RpcOptions &o, uint8_t *out, size_t cap, size_t *n) {
    *n = 0;
    if (state != READY || !have_capability) return ERR_STATE;
    if (o.local_ip.len != 4 && o.local_ip.len != 16) return ERR_ARGUMENT;
    Builder b(seg_, SEG_WORDS);
    uint32_t m = b.make_struct(0, 1, 1);
    b.set16(m, 0, MSG_CALL);
    uint32_t call = b.make_struct(m + 1, 3, 3);
    b.set32(call, 0, Q_REGISTER);
    b.set16(call, 4, 0);  // methodId registerConnection
    b.set64(call, 8, REGISTRATION_SERVER);
    uint32_t target = b.make_struct(call + 3, 1, 1);  // MessageTarget.importedCap
    b.set32(target, 0, capability);
    uint32_t payload = b.make_struct(call + 4, 0, 2);
    uint32_t params = b.make_struct(payload, 1, 3);
    b.set8(params, 0, o.connection_index);
    uint32_t auth = b.make_struct(params + 1, 0, 2);
    b.blob(auth, c.account_tag, strlen(c.account_tag), true);
    b.blob(auth + 1, c.secret, c.secret_len, false);
    b.blob(params + 2, c.tunnel_id, 16, false);
    uint32_t opts = b.make_struct(params + 3, 1, 2);
    b.set8(opts, 2, o.previous_attempts);
    uint32_t client = b.make_struct(opts + 1, 0, 4);
    b.blob(client, o.connector_id, 16, false);
    const char *feat[2];
    size_t nf = 0;
    if (o.features & FEATURE_REMOTE_CONFIG) feat[nf++] = "allow_remote_config";
    if (o.features & FEATURE_SERIALIZED_HEADERS) feat[nf++] = "serialized_headers";
    b.text_list(client + 1, feat, nf);
    b.blob(client + 2, o.version, strlen(o.version), true);
    b.blob(client + 3, o.arch, strlen(o.arch), true);
    b.blob(opts + 2, o.local_ip.ptr, o.local_ip.len, false);
    if (!finish(b, out, cap, n)) return ERR_ARGUMENT;
    state = REGISTERING;
    return OK;
  }

  // RegistrationServer.unregisterConnection (question 2).
  Result unregister(uint8_t *out, size_t cap, size_t *n) {
    *n = 0;
    if (state != REGISTERED) return ERR_STATE;
    Builder b(seg_, SEG_WORDS);
    uint32_t m = b.make_struct(0, 1, 1);
    b.set16(m, 0, MSG_CALL);
    uint32_t call = b.make_struct(m + 1, 3, 3);
    b.set32(call, 0, Q_UNREGISTER);
    b.set16(call, 4, 1);
    b.set64(call, 8, REGISTRATION_SERVER);
    uint32_t target = b.make_struct(call + 3, 1, 1);
    b.set32(target, 0, capability);
    uint32_t payload = b.make_struct(call + 4, 0, 2);
    b.make_struct(payload, 0, 0);
    if (!finish(b, out, cap, n)) return ERR_LIMIT;
    state = UNREGISTERING;
    return OK;
  }

  // Handles one complete incoming frame; a reply (possibly empty) is written to out.
  Result receive(Bytes frame, uint8_t *out, size_t cap, size_t *n) {
    *n = 0;
    if (state == IDLE || state == READY || state == REGISTERED || state == CLOSED || state == REJECTED || state == FAILED)
      return ERR_STATE;
    Result r = handle(frame, out, cap, n);
    if (r != OK) state = FAILED;
    return r;
  }

  void reset() { *this = Rpc(); }

 private:
  static constexpr size_t SEG_WORDS = RPC_TX_MAX / 8;
  enum : uint16_t { MSG_ABORT = 1, MSG_CALL = 2, MSG_RETURN = 3, MSG_FINISH = 4, MSG_RELEASE = 6, MSG_BOOTSTRAP = 8 };
  enum : uint32_t { Q_BOOTSTRAP = 0, Q_REGISTER = 1, Q_UNREGISTER = 2 };

  static bool finish(Builder &b, uint8_t *out, size_t cap, size_t *n) {
    if (!b.ok()) return false;
    *n = b.finish(out, cap);
    return *n != 0;
  }

  // Writes Finish(q) at out, followed by Release(cap) when release_cap is set.
  bool reply_finish(uint32_t q, bool release_cap, uint8_t *out, size_t cap, size_t *n) {
    uint8_t seg[8 * 4];
    Builder b(seg, 4);
    uint32_t m = b.make_struct(0, 1, 1);
    b.set16(m, 0, MSG_FINISH);
    b.set32(b.make_struct(m + 1, 1, 0), 0, q);
    size_t used = b.finish(out, cap);
    if (!used) return false;
    if (release_cap) {
      Builder r(seg, 4);
      uint32_t rm = r.make_struct(0, 1, 1);
      r.set16(rm, 0, MSG_RELEASE);
      uint32_t rel = r.make_struct(rm + 1, 1, 0);
      r.set32(rel, 0, capability);
      r.set32(rel, 4, 1);
      size_t more = r.finish(out + used, cap - used);
      if (!more) return false;
      used += more;
    }
    *n = used;
    return true;
  }

  void abort_reply(const char *reason, uint8_t *out, size_t cap, size_t *n) {
    uint8_t seg[8 * 12];
    Builder b(seg, 12);
    uint32_t m = b.make_struct(0, 1, 1);
    b.set16(m, 0, MSG_ABORT);
    uint32_t ex = b.make_struct(m + 1, 1, 2);
    b.set16(ex, 4, 3);  // unimplemented
    b.blob(ex + 1, reason, strlen(reason), true);
    *n = b.ok() ? b.finish(out, cap) : 0;
  }

  Result handle(Bytes frame, uint8_t *out, size_t cap, size_t *n) {
    Reader rd;
    if (!rd.init(frame)) return ERR_FORMAT;
    Obj msg = rd.root();
    if (!msg.ok()) return ERR_FORMAT;
    if (Reader::u(msg, 0, 2) != MSG_RETURN) return ERR_FORMAT;  // abort, call, exception... are not expected here
    Obj ret = rd.field(msg, 0);
    if (!ret.ok()) return ERR_FORMAT;
    uint32_t id = (uint32_t) Reader::u(ret, 0, 4);
    uint32_t want = state == BOOTSTRAPPING ? Q_BOOTSTRAP : state == REGISTERING ? Q_REGISTER : Q_UNREGISTER;
    if (id != want) return ERR_FORMAT;
    uint16_t kind = Reader::u(ret, 6, 2);  // results, exception, canceled...
    if (state == UNREGISTERING) {          // any answer ends the session; we only care that the edge replied
      if (kind > 1) return ERR_FORMAT;
      if (!reply_finish(id, true, out, cap, n)) return ERR_LIMIT;
      have_capability = false;
      state = CLOSED;
      return OK;
    }
    if (kind != 0) return ERR_FORMAT;
    Obj payload = rd.field(ret, 0);
    if (!payload.ok()) return ERR_FORMAT;
    if (state == BOOTSTRAPPING) {
      int64_t idx = rd.cap(payload, 0);
      Obj table, e;
      size_t count;
      uint16_t dw, pw;
      if (idx < 0 || !rd.struct_list(payload, 1, &table, &count, &dw, &pw) || (size_t) idx >= count) return ERR_FORMAT;
      e = Reader::element(table, idx);
      if (Reader::u(e, 0, 2) != 1) {  // only senderHosted: no promises, third parties or receiver caps
        abort_reply("unsupported capability", out, cap, n);
        return ERR_UNSUPPORTED;
      }
      capability = (uint32_t) Reader::u(e, 4, 4);
      have_capability = true;
      if (!reply_finish(id, false, out, cap, n)) return ERR_LIMIT;
      state = READY;
      return OK;
    }
    Obj resp = rd.field(rd.field(payload, 0), 0);  // results struct { result :ConnectionResponse }
    if (!resp.ok()) return ERR_FORMAT;
    Obj r = rd.field(resp, 0);
    if (!r.ok()) return ERR_FORMAT;
    if (Reader::u(resp, 0, 2) == 0) {  // ConnectionError
      int64_t ns = (int64_t) Reader::u(r, 0, 8);
      should_retry = Reader::u(r, 8, 1) & 1;
      retry_after_ms = ns <= 0 ? 0 : (uint32_t) ((ns > 4000000000000ll ? 4000000000000ll : ns) / 1000000 + (ns % 1000000 != 0));
      state = REJECTED;
    } else {
      Bytes uuid = rd.blob(r, 0);
      Bytes loc = rd.blob(r, 1, true);
      if (uuid.len != 16 || !loc.ptr || loc.len >= sizeof(location)) return ERR_FORMAT;
      memcpy(connection_id, uuid.ptr, 16);
      memcpy(location, loc.ptr, loc.len);
      location[loc.len] = 0;
      remotely_managed = Reader::u(r, 0, 1) & 1;
      if (!remotely_managed) return ERR_UNSUPPORTED;  // we have no local ingress config to fall back on
      state = REGISTERED;
    }
    return reply_finish(id, false, out, cap, n) ? OK : ERR_LIMIT;
  }

  uint8_t seg_[RPC_TX_MAX]{};
};

}  // namespace cft
