// See LICENSE for license details.

#ifndef _RISCV_SIMIF_H
#define _RISCV_SIMIF_H

#include "decode.h"

// this is the interface to the simulator used by the processors and memory
class simif_t
{
public:
  // should return NULL for MMIO addresses
  virtual char* addr_to_mem(reg_t addr) = 0;
  // used for MMIO addresses
  virtual bool mmio_load(reg_t addr, size_t len, uint8_t* bytes) = 0;
  virtual bool mmio_store(reg_t addr, size_t len, const uint8_t* bytes) = 0;
  // Callback for processors to let the simulation know they were reset.
  virtual void proc_reset(unsigned id) = 0;

  virtual const char* get_symbol(uint64_t addr) = 0;

  virtual TagController& get_tag_controller() = 0;
  virtual RevTree& get_rev_tree() = 0;
  virtual uint64_t get_mem_partition_addr() = 0;
  virtual cap_reg_t& get_secure_mem_init_cap() = 0;
  virtual bool is_cap_debug_enabled() = 0;
};

#endif
