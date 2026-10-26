#pragma once
// Minimal Cap'n Proto: a single-segment builder and a bounds-checked multi-segment reader (with far
// pointers). Only what the tunnel RPC needs; written from the encoding spec.
#include <cstddef>
#include <cstdint>
#include <cstring>

namespace cft {

struct Bytes {
  const uint8_t *ptr{nullptr};
  size_t len{0};
};

inline uint16_t rd16(const uint8_t *p) { return p[0] | (p[1] << 8); }
inline uint32_t rd32(const uint8_t *p) { return rd16(p) | ((uint32_t) rd16(p + 2) << 16); }
inline uint64_t rd64(const uint8_t *p) { return rd32(p) | ((uint64_t) rd32(p + 4) << 32); }
inline void wr16(uint8_t *p, uint16_t v) { p[0] = v; p[1] = v >> 8; }
inline void wr32(uint8_t *p, uint32_t v) { wr16(p, v); wr16(p + 2, v >> 16); }
inline void wr64(uint8_t *p, uint64_t v) { wr32(p, v); wr32(p + 4, v >> 32); }

// ---- builder -------------------------------------------------------------------------------
// Word 0 of the segment is the root pointer. Slots are word indexes of pointer words.
class Builder {
 public:
  Builder(uint8_t *buf, size_t cap_words) : buf_(buf), cap_(cap_words) { memset(buf, 0, cap_words * 8); words_ = 1; }

  // Allocate a struct and point `slot` at it. Returns the index of its first data word, or 0 on overflow.
  uint32_t make_struct(uint32_t slot, uint16_t dw, uint16_t pw) {
    uint32_t at = alloc(dw + pw);
    if (!at) return 0;
    if (dw + pw == 0) {  // zero-sized struct: offset -1
      wr64(w(slot), 0xFFFFFFFCull);
      return at;
    }
    wr64(w(slot), ((uint64_t) (uint32_t) (at - slot - 1) << 2) | ((uint64_t) dw << 32) | ((uint64_t) pw << 48));
    return at;
  }
  // Byte list (Data) or Text (NUL terminated, count includes the NUL).
  bool blob(uint32_t slot, const void *p, size_t len, bool text) {
    size_t count = len + (text ? 1 : 0);
    uint32_t at = alloc((count + 7) / 8);
    if (!at && count) return false;
    if (count) memcpy(w(at), p, len);
    wr64(w(slot), ((uint64_t) (at - slot - 1) << 2) | 1 | (2ull << 32) | ((uint64_t) count << 35));
    return true;
  }
  // List(Text)
  bool text_list(uint32_t slot, const char *const *items, size_t n) {
    uint32_t at = alloc(n);
    if (!at && n) return false;
    wr64(w(slot), ((uint64_t) (at - slot - 1) << 2) | 1 | (6ull << 32) | ((uint64_t) n << 35));
    for (size_t i = 0; i < n; i++)
      if (!blob(at + i, items[i], strlen(items[i]), true)) return false;
    return true;
  }
  void set8(uint32_t struct_at, size_t byte, uint8_t v) { w(struct_at)[byte] = v; }
  void set16(uint32_t struct_at, size_t byte, uint16_t v) { wr16(w(struct_at) + byte, v); }
  void set32(uint32_t struct_at, size_t byte, uint32_t v) { wr32(w(struct_at) + byte, v); }
  void set64(uint32_t struct_at, size_t byte, uint64_t v) { wr64(w(struct_at) + byte, v); }

  bool ok() const { return !overflow_; }
  // Frame = segment table (1 segment) + segment. Writes into out; returns bytes or 0.
  size_t finish(uint8_t *out, size_t cap) const {
    if (overflow_ || cap < 8 + words_ * 8) return 0;
    wr32(out, 0);
    wr32(out + 4, words_);
    memcpy(out + 8, buf_, words_ * 8);
    return 8 + words_ * 8;
  }

 private:
  uint8_t *w(uint32_t i) { return buf_ + (size_t) i * 8; }
  uint32_t alloc(size_t n) {
    if (words_ + n > cap_) {
      overflow_ = true;
      return 0;
    }
    uint32_t at = words_;
    words_ += n;
    return n ? at : words_;
  }
  uint8_t *buf_;
  size_t cap_, words_{1};
  bool overflow_{false};
};

// ---- reader --------------------------------------------------------------------------------
constexpr int MAX_SEGMENTS = 8;

struct Obj {  // a resolved struct
  const uint8_t *data{nullptr};
  uint16_t dw{0}, pw{0};
  int seg{0};
  size_t word{0};  // index of the first data word in its segment
  bool ok() const { return data != nullptr; }
};

class Reader {
 public:
  // Parses the segment table of one complete frame. Returns false if malformed.
  bool init(Bytes frame) {
    if (frame.len < 8) return false;
    uint32_t n = rd32(frame.ptr) + 1;
    if (n > MAX_SEGMENTS) return false;
    size_t table = 4 + 4 * n;
    if (table % 8) table += 4;
    if (frame.len < table) return false;
    size_t off = table;
    for (uint32_t i = 0; i < n; i++) {
      size_t words = rd32(frame.ptr + 4 + 4 * i);
      if (words > (frame.len - off) / 8) return false;
      seg_[i] = frame.ptr + off;
      len_[i] = words;
      off += words * 8;
    }
    if (off != frame.len) return false;
    nseg_ = n;
    budget_ = 1 << 16;
    return len_[0] >= 1;
  }
  static size_t frame_size(Bytes head) {  // total frame size once the segment table is complete, else 0
    if (head.len < 4) return 0;
    uint32_t n = rd32(head.ptr) + 1;
    if (n > MAX_SEGMENTS) return SIZE_MAX;
    size_t table = 4 + 4 * n;
    if (table % 8) table += 4;
    if (head.len < table) return 0;
    size_t total = table;
    for (uint32_t i = 0; i < n; i++) total += (size_t) rd32(head.ptr + 4 + 4 * i) * 8;
    return total;
  }

  Obj root() { return resolve_struct(0, 0); }
  // Pointer field `idx` of struct `o` as a struct.
  Obj field(const Obj &o, unsigned idx) {
    if (!o.ok() || idx >= o.pw) return {};
    return resolve_struct(o.seg, o.word + o.dw + idx);
  }
  // Pointer field as a byte list / text (without the NUL).
  Bytes blob(const Obj &o, unsigned idx, bool text = false) {
    if (!o.ok() || idx >= o.pw) return {};
    Loc l = resolve(o.seg, o.word + o.dw + idx);
    if (!l.ok || !l.is_list || l.elem != 2) return {};
    size_t n = l.count;
    if (text) {
      if (!n || l.base[n - 1]) return {};
      n--;
    }
    return {l.base, n};
  }
  // Pointer field as a list of structs. On success first/count/dw/pw describe it; elements are dw+pw words.
  bool struct_list(const Obj &o, unsigned idx, Obj *first, size_t *count, uint16_t *dw, uint16_t *pw) {
    if (!o.ok() || idx >= o.pw) return false;
    Loc l = resolve(o.seg, o.word + o.dw + idx);
    if (!l.ok || !l.is_list || l.elem != 7 || l.word + 1 > len_[l.seg]) return false;
    uint64_t tag = rd64(seg_[l.seg] + l.word * 8);
    if ((tag & 3) != 0) return false;
    *count = (uint32_t) tag >> 2;
    *dw = (tag >> 32) & 0xFFFF;
    *pw = (tag >> 48) & 0xFFFF;
    size_t each = (size_t) *dw + *pw;
    if (each && *count > (len_[l.seg] - l.word - 1) / each) return false;
    if (!each && !spend(*count)) return false;
    *first = {seg_[l.seg] + (l.word + 1) * 8, *dw, *pw, l.seg, l.word + 1};
    return true;
  }
  static Obj element(const Obj &first, size_t i) {
    size_t each = (size_t) first.dw + first.pw;
    return {first.data + i * each * 8, first.dw, first.pw, first.seg, first.word + i * each};
  }
  // Capability pointer index, or -1.
  int64_t cap(const Obj &o, unsigned idx) {
    if (!o.ok() || idx >= o.pw) return -1;
    uint64_t p = rd64(seg_[o.seg] + (o.word + o.dw + idx) * 8);
    return (p & 3) == 3 && (uint32_t) p == 3 ? (int64_t) (p >> 32) : -1;
  }
  // Data fields read as zero when outside the struct's data section (schema evolution).
  static uint64_t u(const Obj &o, size_t byte, size_t size) {
    if (!o.ok() || byte + size > (size_t) o.dw * 8) return 0;
    switch (size) {
      case 1: return o.data[byte];
      case 2: return rd16(o.data + byte);
      case 4: return rd32(o.data + byte);
      default: return rd64(o.data + byte);
    }
  }

 private:
  struct Loc {
    bool ok{false}, is_list{false};
    int seg{0};
    size_t word{0};
    uint16_t dw{0}, pw{0};
    uint8_t elem{0};
    size_t count{0};
    const uint8_t *base{nullptr};
  };
  bool spend(size_t n) {
    if (n > budget_) return false;
    budget_ -= n;
    return true;
  }
  // Follow the pointer stored at (seg, word), through far pointers.
  Loc resolve(int seg, size_t word) {
    Loc l;
    if (seg >= (int) nseg_ || word >= len_[seg] || !spend(1)) return l;
    uint64_t p = rd64(seg_[seg] + word * 8);
    if (!p) return l;
    uint8_t type = p & 3;
    if (type == 2) {  // far
      bool dbl = p & 4;
      size_t pad = (uint32_t) p >> 3;
      uint32_t pseg = (uint32_t) (p >> 32);
      if (pseg >= nseg_ || pad + (dbl ? 2 : 1) > len_[pseg]) return l;
      if (!dbl) return decode(pseg, pad, rd64(seg_[pseg] + pad * 8));
      uint64_t far2 = rd64(seg_[pseg] + pad * 8), tag = rd64(seg_[pseg] + (pad + 1) * 8);
      if ((far2 & 7) != 2 || (tag & 3) == 2 || ((uint32_t) tag >> 2)) return l;
      uint32_t oseg = (uint32_t) (far2 >> 32);
      if (oseg >= nseg_) return l;
      Loc t = decode_at(oseg, (uint32_t) far2 >> 3, tag);  // object starts at the landing offset
      return t;
    }
    return decode(seg, word, p);
  }
  // Pointer word p was read at (seg, word); target is relative to word+1.
  Loc decode(int seg, size_t word, uint64_t p) {
    int32_t off = (int32_t) ((uint32_t) p & ~3u) >> 2;
    int64_t target = (int64_t) word + 1 + off;
    if (target < 0) return {};
    return decode_at(seg, (size_t) target, p);
  }
  Loc decode_at(int seg, size_t target, uint64_t p) {
    Loc l;
    uint8_t type = p & 3;
    l.seg = seg;
    l.word = target;
    if (type == 0) {
      l.dw = (p >> 32) & 0xFFFF;
      l.pw = (p >> 48) & 0xFFFF;
      if (target > len_[seg] || (size_t) l.dw + l.pw > len_[seg] - target) return {};
    } else if (type == 1) {
      l.is_list = true;
      l.elem = (p >> 32) & 7;
      uint32_t count = p >> 35;
      static const uint8_t bits[] = {0, 1, 8, 16, 32, 64, 64, 0};
      size_t words = l.elem == 7 ? count + 1 : ((size_t) count * bits[l.elem] + 63) / 64;
      if (target > len_[seg] || words > len_[seg] - target) return {};
      l.count = count;
    } else {
      return {};
    }
    l.base = seg_[seg] + target * 8;
    l.ok = true;
    return l;
  }
  Obj resolve_struct(int seg, size_t word) {
    Loc l = resolve(seg, word);
    if (!l.ok || l.is_list) return {};
    // A zero-sized struct decodes to a valid object with no data; use a harmless non-null base.
    return {l.base ? l.base : seg_[l.seg], l.dw, l.pw, l.seg, l.word};
  }

  const uint8_t *seg_[MAX_SEGMENTS]{};
  size_t len_[MAX_SEGMENTS]{}, budget_{0};
  uint32_t nseg_{0};
};

}  // namespace cft
