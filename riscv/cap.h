#ifndef __CAPSTONE_CAP_H__
#define __CAPSTONE_CAP_H__

#include <assert.h>
#include <string.h>
#include <cstdint>

struct _uint256_t {
  uint64_t v[4];
};

struct _uint128_t {
  uint64_t v[2];
};


enum cap_type_t {
  CAP_TYPE_NONLINEAR = 0,
  CAP_TYPE_LINEAR = 1,
  CAP_TYPE_REVOCATION = 2,
  CAP_TYPE_UNINITIALIZED = 3,
  CAP_TYPE_SEALED = 4,
  CAP_TYPE_SEALEDRET = 5
};

enum cap_perm_t {
  CAP_PERM_NA = 0,
  CAP_PERM_RO = 1,
  CAP_PERM_RW = 2,
  CAP_PERM_RX = 3,
  CAP_PERM_RWX = 4
};

/**
 * 
 *  Capability type.
 *  Currently only supports the naive 256-bit format.
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

  // TODO: indicate whether the conversion is successful
  _uint128_t to128() const
  {
    _uint128_t res;
    // TODO
    return res;
  }
  
  void form128(const _uint128_t& v) {
    // TODO
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

  void tighten_perm(cap_perm_t new_perm) {
    if (perm >= new_perm) {
      if (perm == CAP_PERM_RX && new_perm == CAP_PERM_RW)
        return;
      perm = new_perm;
    }
  }

  void increment_cursor() {
    cursor++;
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
  _uint256_t cap;

  cap_reg_t() : tag(WORD_TAG_CAP) {}

  void set_cap(_uint256_t& v) {
    tag = WORD_TAG_CAP;
    cap = v;
  }

  void reset() {
    tag = WORD_TAG_CAP;
    memset(&cap, 0, sizeof(cap));
  }
};

#endif