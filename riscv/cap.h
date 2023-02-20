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
  CAP_PERM_RWX = 3
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
};

typedef enum
{
  WORD_TAG_DATA, // note: we do not care about the actual value
  WORD_TAG_CAP
} word_tag_t;

template <typename T>
struct Reg
{
  union
  {
    T data;
    _uint256_t cap;
  } content;
  word_tag_t tag;

  Reg() : tag(WORD_TAG_CAP) {}

  Reg(T v)
  {
    content.data = v;
    tag = WORD_TAG_DATA;
  }

  Reg &operator=(T v)
  {
    tag = WORD_TAG_DATA;
    content.data = v;
    return *this;
  }

  operator T() const
  {
    return content.data;
  }

  Reg &operator+=(T v)
  {
    assert(tag == WORD_TAG_DATA);
    content.data += v;
    return *this;
  }

  Reg &operator-=(T v)
  {
    assert(tag == WORD_TAG_DATA);
    content.data -= v;
    return *this;
  }

  Reg &operator++()
  {
    assert(tag == WORD_TAG_DATA);
    ++content.data;
    return *this;
  }

  Reg &operator--()
  {
    assert(tag == WORD_TAG_DATA);
    --content.data;
    return *this;
  }

  Reg operator++(int)
  {
    assert(tag == WORD_TAG_DATA);
    Reg old = *this;
    ++content.data;
    return old;
  }

  Reg operator--(int)
  {
    assert(tag == WORD_TAG_DATA);
    Reg old = *this;
    --content.data;
    return old;
  }

  Reg &operator>>=(T v)
  {
    assert(tag == WORD_TAG_DATA);
    content.data >>= v;
    return *this;
  }

  Reg &operator<<=(T v)
  {
    assert(tag == WORD_TAG_DATA);
    content.data <<= v;
    return *this;
  }

  Reg &operator&=(T v)
  {
    assert(tag == WORD_TAG_DATA);
    content.data &= v;
    return *this;
  }

  Reg &operator|=(T v)
  {
    assert(tag == WORD_TAG_DATA);
    content.data |= v;
    return *this;
  }

  Reg &operator^=(T v)
  {
    assert(tag == WORD_TAG_DATA);
    content.data ^= v;
    return *this;
  }
};

inline Reg<uint64_t> to_unsigned_reg(const Reg<int64_t> &s)
{
  Reg<uint64_t> res;
  static_assert(sizeof(s.content) == sizeof(res.content));
  memcpy(&res.content, &s.content, sizeof(s.content));
  res.tag = s.tag;
  return res;
}

inline Reg<int64_t> to_signed_reg(const Reg<uint64_t> &s)
{
  Reg<int64_t> res;
  memcpy(&res.content, &s.content, sizeof(s.content));
  res.tag = s.tag;
  return res;
}

inline Reg<uint64_t> to_unsigned_reg(const Reg<uint64_t> &s)
{
  return s;
}

#endif
