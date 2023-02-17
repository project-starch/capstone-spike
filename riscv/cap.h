#ifndef __CAPSTONE_CAP_H__
#define __CAPSTONE_CAP_H__

#include <assert.h>
#include <string.h>


struct cap64_t {
  
};

typedef enum {
  WORD_TAG_DATA, // note: we do not care about the actual value
  WORD_TAG_CAP
} word_tag_t;

template <typename T>
struct Reg {
  union {
    T data;
    cap64_t cap; 
  } content;
  word_tag_t tag;

  Reg() : tag(WORD_TAG_CAP) {}
  
  Reg(T v) {
    content.data = v;
    tag = WORD_TAG_DATA;
  }

  Reg& operator = (T v) {
    tag = WORD_TAG_DATA;
    content.data = v;
    return *this;
  }
  
  operator T () const {
    return content.data;
  }
  
  Reg& operator += (T v) {
    assert(tag == WORD_TAG_DATA);
    content.data += v;
    return *this;
  }
  
  Reg& operator -= (T v) {
    assert(tag == WORD_TAG_DATA);
    content.data -= v;
    return *this;
  }

  Reg& operator ++ () {
    assert(tag == WORD_TAG_DATA);
    ++ content.data;
    return *this;
  }
  
  Reg& operator -- () {
    assert(tag == WORD_TAG_DATA);
    -- content.data;
    return *this;
  }
  
  Reg operator ++ (int) {
    assert(tag == WORD_TAG_DATA);
    Reg old = *this;
    ++ content.data;
    return old;
  }
  
  Reg operator -- (int) {
    assert(tag == WORD_TAG_DATA);
    Reg old = *this;
    -- content.data;
    return old;
  }
  
  Reg& operator >>= (T v) {
    assert(tag == WORD_TAG_DATA);
    content.data >>= v;
    return *this;
  }
  
  Reg& operator <<= (T v) {
    assert(tag == WORD_TAG_DATA);
    content.data <<= v;
    return *this;
  }

  Reg& operator &= (T v) {
    assert(tag == WORD_TAG_DATA);
    content.data &= v;
    return *this;
  }

  Reg& operator |= (T v) {
    assert(tag == WORD_TAG_DATA);
    content.data |= v;
    return *this;
  }
  
  Reg& operator ^= (T v) {
    assert(tag == WORD_TAG_DATA);
    content.data ^= v;
    return *this;
  }
};

inline Reg<uint64_t> to_unsigned_reg(const Reg<int64_t>& s) {
  Reg<uint64_t> res;
  static_assert(sizeof(s.content) == sizeof(res.content));
  memcpy(&res.content, &s.content, sizeof(s.content));
  res.tag = s.tag;
  return res;
}

inline Reg<int64_t> to_signed_reg(const Reg<uint64_t>& s) {
  Reg<int64_t> res;
  memcpy(&res.content, &s.content, sizeof(s.content));
  res.tag = s.tag;
  return res;
}

inline Reg<uint64_t> to_unsigned_reg(const Reg<uint64_t>& s) {
  return s;
}


#endif
