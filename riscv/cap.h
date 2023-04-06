#ifndef __CAPSTONE_CAP_H__
#define __CAPSTONE_CAP_H__

#include <assert.h>
#include <string.h>
#include <cstdint>

struct _uint256_t {
  uint64_t v[4];
};

#ifdef __SIZEOF_INT128__
  #ifndef INT128_DEFINED
    #define INT128_DEFINED
    typedef __int128 int128_t;
    typedef unsigned __int128 uint128_t;
  #endif
#else
  fprintf(stderr, "Capstone extension is not supported on platforms without __int128 type\n");
  abort();
#endif


enum cap_type_t {
  CAP_TYPE_LINEAR = 0,
  CAP_TYPE_NONLINEAR = 1,
  CAP_TYPE_REVOCATION = 2,
  CAP_TYPE_UNINITIALIZED = 3,
  CAP_TYPE_SEALED = 4,
  CAP_TYPE_SEALEDRET = 5
};

enum cap_perm_t {
  CAP_PERM_NA = 0,
  CAP_PERM_RO = 1,
  CAP_PERM_RX = 2,
  CAP_PERM_RW = 3,
  CAP_PERM_RWX = 4
};

/**
 * 
 *  Capability type.
 *  Currently only supports the naive 256-bit format.
 *  128-bit compressed format support under development.
*/
struct cap64_t
{
  uint64_t cursor;
  uint64_t base, end; // base and top addresses;
  uint32_t node_id;
  cap_perm_t perm;
  cap_type_t type;
  
  _uint256_t to256() const {
    _uint256_t res;
    res.v[0] = cursor;
    res.v[1] = base;
    res.v[2] = end;
    res.v[3] = (uint64_t)perm | 
      (((uint64_t)type) << 3) |
      (((uint64_t)node_id) << 6);
    return res;
  }
  
  void from256(const _uint256_t& v) {
    cursor = v.v[0];
    base = v.v[1];
    end = v.v[2];
    perm = (cap_perm_t)(v.v[3] & ((1 << 3) - 1));
    type = (cap_type_t)((v.v[3] >> 3) & ((1 << 3) - 1));
    node_id = (uint32_t)((v.v[3] >> 6) & ((1ULL << 31) - 1));
  }

  uint128_t to128() const
  {
    assert(end >= base);
    uint128_t res;
    uint64_t length = end - base;
    uint8_t E = uint8_t(64 - __builtin_clzll(length >> 13));
    uint8_t Ie = (E == 0 && (length >> 12) == 0)? 0 : 1;
    uint32_t bound;
    if (Ie) {
      assert((base & ((1 << (E + 3)) - 1)) == 0);
      assert((end & ((1 << (E + 3)) - 1)) == 0);
      uint8_t E_2_0 = uint8_t(E & ((1 << 3) - 1));
      uint8_t E_5_3 = uint8_t((E >> 3) & ((1 << 3) - 1));
      uint16_t B_13_3 = uint16_t((base >> (E + 3)) & ((1 << 11) - 1));
      uint16_t T_11_3 = uint16_t((end >> (E + 3)) & ((1 << 9) - 1));
      bound = uint32_t(E_2_0) | (uint32_t(B_13_3) << 3) | (uint32_t(E_5_3) << 14) | (uint32_t(T_11_3) << 17) | (uint32_t(1) << 26);
    }
    else {
      uint16_t B = uint16_t(base & ((1 << 14) - 1));
      uint16_t T = uint16_t(end & ((1 << 12) - 1));
      bound = uint32_t(B) | (uint32_t(T) << 14);
    }

    res = uint128_t(cursor) | (uint128_t(bound) << 64) | (uint128_t(perm) << 91) | (uint128_t(type) << 94) | (uint128_t(node_id) << 97);
    return res;
  }
  
  void from128(const uint128_t& v) {
    cursor = uint64_t(v & ((uint128_t(1) << 64) - 1));
    perm = (cap_perm_t)((v >> 91) & ((uint128_t(1) << 3) - 1));
    type = (cap_type_t)((v >> 94) & ((uint128_t(1) << 3) - 1));
    node_id = uint32_t((v >> 97) & ((uint128_t(1) << 31) - 1));
    
    uint32_t bound = uint32_t((v >> 64) & ((uint128_t(1) << 27) - 1));
    uint8_t Ie = uint8_t((bound >> 26) & 1);
    uint8_t Be = uint8_t(bound & ((1 << 3) - 1));
    uint8_t Te = uint8_t((bound >> 14) & ((1 << 3) - 1));
    uint8_t E, B_2_0, T_2_0, B_13_12, T_13_12;

    uint16_t B_11_3 = uint16_t((bound >> 3) & ((1 << 9) - 1));
    uint16_t T_11_3 = uint16_t((bound >> 17) & ((1 << 9) - 1));
    B_13_12 = uint8_t((bound >> 12) & ((1 << 2) - 1));

    if (Ie) {
      E = (Te << 3) | Be;
      B_2_0 = uint8_t(0);
      T_2_0 = uint8_t(0);
      T_13_12 = B_13_12 + uint8_t(T_11_3 < B_11_3) + uint8_t(1);
    }
    else {
      E = uint8_t(0);
      B_2_0 = Be;
      T_2_0 = Te;
      uint16_t T_11_0 = (T_11_3 << 3) | T_2_0;
      uint16_t B_11_0 = (B_11_3 << 3) | B_2_0;
      T_13_12 = B_13_12 + uint8_t(T_11_0 < B_11_0);
    }

    uint8_t A_3 = uint8_t((cursor >> (E + 11)) & ((1 << 3) - 1));
    uint8_t B_3 = uint8_t((B_13_12 << 1) | (B_11_3 >> 8));
    uint8_t T_3 = uint8_t((T_13_12 << 1) | (T_11_3 >> 8));
    uint8_t R = uint8_t(B_3 - 1);
    
    #define correction(x, y) (x ^ y) ? (x? -1 : 1) : 0
    int ct = correction((A_3 < R), (T_3 < R));
    int cb = correction((A_3 < R), (B_3 < R));

    uint64_t a_top = cursor & ~((uint64_t(1) << (E + 14)) - 1);
    end = (uint64_t((uint16_t(T_13_12) << 12) | (T_11_3 << 3) | T_2_0) << E) | (((a_top >> (E + 14)) + ct) << (E + 14));
    base = (uint64_t((uint16_t(B_13_12) << 12) | (B_11_3 << 3) | B_2_0) << E) | (((a_top >> (E + 14)) + cb) << (E + 14));
  }

  inline bool is_linear() const {
    return type != CAP_TYPE_NONLINEAR;
  }

  inline bool inbound() const {
    return cursor >= base && cursor < end;
  }

  inline bool accessible() const {
    return type == CAP_TYPE_NONLINEAR || type == CAP_TYPE_LINEAR || type == CAP_TYPE_UNINITIALIZED;
  }

  inline bool readable() const {
    return (perm == CAP_PERM_RO || perm == CAP_PERM_RX || perm == CAP_PERM_RWX) && type != CAP_TYPE_UNINITIALIZED;
  }

  inline bool writable() const {
    return perm == CAP_PERM_RW || perm == CAP_PERM_RWX;
  }

  inline bool executable() const {
    return (perm == CAP_PERM_RX || perm == CAP_PERM_RWX) && type != CAP_TYPE_UNINITIALIZED;
  }

  void tighten_perm(uint64_t x) {
    cap_perm_t new_perm = static_cast<cap_perm_t>(x);
  
    if (perm >= new_perm && !(perm == CAP_PERM_RW && new_perm == CAP_PERM_RX)) {
      perm = new_perm;
    }
    else {
      perm = CAP_PERM_NA;
    }
  }

  void init_cap(uint64_t init_base, uint64_t init_size) {
    base = init_base;
    end = init_base + init_size;
    cursor = init_base;
    perm = CAP_PERM_RWX;
    type = CAP_TYPE_LINEAR;
  }

  void shrink(uint64_t new_base, uint64_t new_end) {
    assert(type == CAP_TYPE_NONLINEAR || type == CAP_TYPE_LINEAR);
    assert(new_base < new_end && new_end <= end && new_base >= base);
    base = new_base;
    end = new_end;
  }

  void set_current_cursor(uint64_t new_cursor) {
    assert(type != CAP_TYPE_UNINITIALIZED && type != CAP_TYPE_SEALED);
    cursor = new_cursor;
  }
};

typedef enum
{
  WORD_TAG_DATA, // note: we do not care about the actual value
  WORD_TAG_CAP
} word_tag_t;

struct cap_reg_t
{
  word_tag_t tag;
  cap64_t cap;

  cap_reg_t() { reset(); }

  inline bool is_cap() const { return tag == WORD_TAG_CAP; }
  inline bool is_data() const { return tag == WORD_TAG_DATA; }
  void set_cap(const cap64_t& v) {
    tag = WORD_TAG_CAP;
    cap = v;
  }
  void init_cap(uint64_t init_base, uint64_t init_size) {
    tag = WORD_TAG_CAP;
    cap.init_cap(init_base, init_size);
  }
  inline void set_data() { tag = WORD_TAG_DATA; }
  inline void reset() { set_data(); }
};

#endif
