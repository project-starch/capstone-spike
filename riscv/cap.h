#ifndef __CAPSTONE_CAP_H__
#define __CAPSTONE_CAP_H__

#include <assert.h>
#include <string.h>
#include <cstdint>

#define XLENBYTES 8
#define CLENBYTES 16
// int128_t and uint128_t definition
#ifdef __SIZEOF_INT128__
  #ifndef INT128_DEFINED
    #define INT128_DEFINED
    typedef __int128 int128_t;
    typedef unsigned __int128 uint128_t;
  #endif
#else
  fprintf(stderr, "The simulation is not supported on platforms without __int128 type\n");
  abort();
#endif

/*capstone type field*/
enum cap_type_t {
  CAP_TYPE_LINEAR = 0,
  CAP_TYPE_NONLINEAR = 1,
  CAP_TYPE_REVOCATION = 2,
  CAP_TYPE_UNINITIALIZED = 3,
  CAP_TYPE_SEALED = 4,
  CAP_TYPE_SEALEDRET = 5,
  CAP_TYPE_EXIT = 6
};

/*capstone perms field*/
enum cap_perm_t {
  CAP_PERM_NA = 0,
  CAP_PERM_X = 1,
  CAP_PERM_W = 2,
  CAP_PERM_WX = 3,
  CAP_PERM_R = 4,
  CAP_PERM_RX = 5,
  CAP_PERM_RW = 6,
  CAP_PERM_RWX = 7
};

// perm: a <= b
bool cap_perm_lte(cap_perm_t a, cap_perm_t b) {
  if (a == b) return true;
  if (a == CAP_PERM_NA) return true;
  if (b == CAP_PERM_RWX) return true;

  if (a == CAP_PERM_X) {
    if (b == CAP_PERM_RX || b == CAP_PERM_WX) return true;
  }
  if (a == CAP_PERM_W) {
    if (b == CAP_PERM_RW || b == CAP_PERM_WX) return true;
  }
  if (a == CAP_PERM_R) {
    if (b == CAP_PERM_RW || b == CAP_PERM_RX) return true;
  }
  return false;
}

/*capstone async field*/
enum cap_async_t {
  CAP_ASYNC_SYNC = 0,
  CAP_ASYNC_EXCEPTION = 1,
  CAP_ASYNC_INTERRUPT = 2,
};

/*capstone capability definition*/
struct cap64_t
{
  // fields
  uint32_t node_id; // used in revocation tree, the implementation of valid field
  cap_type_t type;
  uint64_t cursor;
  uint64_t base, end;
  cap_perm_t perm;
  uint8_t reg;
  cap_async_t async;

  /*reset*/
  void reset()
  {
    node_id = uint32_t(0);
    type = CAP_TYPE_LINEAR;
    cursor = uint64_t(0);
    base = uint64_t(0);
    end = uint64_t(0);
    perm = CAP_PERM_NA;
  }

  // capability encoding
  // use the encoding with the closest legal bounds, if the compression check fails
  uint128_t to128() const
  {
    uint128_t res;
    
    if (type == CAP_TYPE_LINEAR || type == CAP_TYPE_NONLINEAR || type == CAP_TYPE_REVOCATION || type == CAP_TYPE_UNINITIALIZED) {
      assert(base < end); // dev check
      uint64_t length = end - base;
      uint8_t E;
      // __builtin_clzll's argument must be nonzero (otherwise, the result is undefined)
      if (length >> 13 == uint64_t(0)) E = uint8_t(0);
      else E = uint8_t(64 - __builtin_clzll(length >> 13)); 
      uint8_t Ie = (E == 0 && (length >> 12) == 0)? 0 : 1;
      uint32_t bound;
      if (Ie) {
        uint64_t encode_base = base;
        uint64_t encode_end = end;
        
        if ((base & ((1 << (E + 3)) - 1)) != 0) {
          encode_base = (base >> (E + 3)) << (E + 3);
        }
        if ((end & ((1 << (E + 3)) - 1)) != 0) {
          encode_end = (end >> (E + 3)) << (E + 3);
        }

        uint8_t E_2_0 = uint8_t(E & ((1 << 3) - 1));
        uint8_t E_5_3 = uint8_t((E >> 3) & ((1 << 3) - 1));
        uint16_t B_13_3 = uint16_t((encode_base >> (E + 3)) & ((1 << 11) - 1));
        uint16_t T_11_3 = uint16_t((encode_end >> (E + 3)) & ((1 << 9) - 1));
        bound = uint32_t(E_2_0) | (uint32_t(B_13_3) << 3) | (uint32_t(E_5_3) << 14) | (uint32_t(T_11_3) << 17) | (uint32_t(1) << 26);
      }
      else {
        uint16_t B = uint16_t(base & ((1 << 14) - 1));
        uint16_t T = uint16_t(end & ((1 << 12) - 1));
        bound = uint32_t(B) | (uint32_t(T) << 14);
      }

      res = uint128_t(cursor) | (uint128_t(bound) << 64) | (uint128_t(perm) << 91) | (uint128_t(type) << 94) | (uint128_t(node_id) << 97);
    }
    else {
      if (type == CAP_TYPE_SEALED) {
        res = uint128_t(base) | (uint128_t(async) << 92) | (uint128_t(type) << 94) | (uint128_t(node_id) << 97);
      }
      else{
        // If the cursor is too large, just use the lower 23 bits
        uint64_t cursor_offset = (cursor - base) & ((1 << 23) - 1);
        uint8_t reg_5bits = reg & ((1 << 5) - 1);

        if (type == CAP_TYPE_SEALEDRET) {
          res = uint128_t(base) | (uint128_t(cursor_offset) << 64) | (uint128_t(reg_5bits) << 87) | (uint128_t(async) << 92) | (uint128_t(type) << 94) | (uint128_t(node_id) << 97);
        }
        else{ // exit type capability
          res = uint128_t(base) | (uint128_t(cursor_offset) << 64) | (uint128_t(reg_5bits) << 94) | (uint128_t(node_id) << 97);
        }
      }
    }
    
    return res;
  }
  
  // capability decoding
  void from128(const uint128_t& v) {
    type = (cap_type_t)((v >> 94) & ((uint128_t(1) << 3) - 1));
    node_id = uint32_t((v >> 97) & ((uint128_t(1) << 31) - 1));

    if (type == CAP_TYPE_LINEAR || type == CAP_TYPE_NONLINEAR || type == CAP_TYPE_REVOCATION || type == CAP_TYPE_UNINITIALIZED) {
      cursor = uint64_t(v & ((uint128_t(1) << 64) - 1));
      perm = (cap_perm_t)((v >> 91) & ((uint128_t(1) << 3) - 1));
      
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
    else {
      base = uint64_t(v & ((uint128_t(1) << 64) - 1));

      if (type == CAP_TYPE_SEALED) {
        async = (cap_async_t)((v >> 92) & ((uint128_t(1) << 2) - 1));
      }
      else{
        uint64_t cursor_offset = uint64_t((v >> 64) & ((uint128_t(1) << 23) - 1));
        cursor = base + cursor_offset;

        if (type == CAP_TYPE_SEALEDRET) {
          async = (cap_async_t)((v >> 92) & ((uint128_t(1) << 2) - 1));
          reg = (uint8_t)((v >> 87) & ((uint128_t(1) << 5) - 1));
        }
      }
    }
  }

  /*type check*/
  bool is_linear() const {
    return type != CAP_TYPE_NONLINEAR;
  }
  bool load_accessible() const {
    if (type == CAP_TYPE_LINEAR || type == CAP_TYPE_NONLINEAR  || type == CAP_TYPE_EXIT) return true;
    if (type == CAP_TYPE_SEALEDRET && async == CAP_ASYNC_SYNC) return true;
    return false;
  }
  bool store_accessible() const {
    if (type == CAP_TYPE_LINEAR || type == CAP_TYPE_NONLINEAR || type == CAP_TYPE_UNINITIALIZED || type == CAP_TYPE_EXIT) return true;
    if (type == CAP_TYPE_SEALEDRET && async == CAP_ASYNC_SYNC) return true;
    return false;
  }
  /*bound check*/
  // size of the load/store need to be provided
  bool in_bound(uint64_t size) const {
    if (type == CAP_TYPE_LINEAR || type == CAP_TYPE_NONLINEAR || type == CAP_TYPE_UNINITIALIZED){
      return cursor >= base && cursor <= end - size;
    }
    if (type == CAP_TYPE_SEALEDRET || type == CAP_TYPE_EXIT) {
      return cursor >= base + 3 * CLENBYTES && cursor <= base + 33 * CLENBYTES - size;
    }
    return false;
  }
  /*initial capability create*/
  void init_cap(uint64_t init_base, uint64_t init_size) {
    base = init_base;
    end = init_base + init_size;
    cursor = init_base;
    perm = CAP_PERM_RWX;
    type = CAP_TYPE_LINEAR;
  }
};

// tag of the register
typedef enum
{
  WORD_TAG_DATA,
  WORD_TAG_CAP
} word_tag_t;

// register
struct cap_reg_t
{
  word_tag_t tag;
  cap64_t cap;

  cap_reg_t() {
    tag = WORD_TAG_DATA;
  }
  /*tag check*/
  bool is_cap() const {
    return tag == WORD_TAG_CAP;
  }
  bool is_data() const {
    return tag == WORD_TAG_DATA;
  }
  /*tag manipulation*/
  void set_cap(const cap64_t& v) {
    tag = WORD_TAG_CAP;
    cap = v;
  }
  void set_data() {
    tag = WORD_TAG_DATA;
  }
  /*initial capability for cinit*/
  void init_cap(uint64_t init_base, uint64_t init_size) {
    tag = WORD_TAG_CAP;
    cap.init_cap(init_base, init_size);
  }
  /*reset*/
  // reset is used in system reset
  void reset() {
    tag = WORD_TAG_DATA;
  }
  // reset_i is used when clear a linear capability
  void reset_i() {
    cap.reset();
  }
};

#endif
