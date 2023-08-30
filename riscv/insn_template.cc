// See LICENSE for license details.

#include "insn_template.h"
#include "insn_macros.h"

/* in the capstone-risc-v spec, the pc is checked in the instruction fetch stage.
 * however, the original spike implementation is not capability-aware, so we
 * check the pc every time it's modified, i.e., end of the instruction execution (here),
 * and end of exception handling (in processor.cc).
 */
#define cap_pc_forward() \
  if (p->is_secure_world()) { \
    /*pc needs to be updated as well in case of an exception during the check below*/ \
    p->get_state()->cap_pc.cursor = npc; \
    p->get_state()->pc = npc; \
    /*cap_pc check; should be during insn fetch in the spec*/ \
    cap64_t cap_pc = p->get_state()->cap_pc; \
    if (!next_pc_is_cap) throw trap_capstone_instruction_access_fault(insn.bits()); \
    bool pc_valid_cap = p->valid_cap(cap_pc.node_id); \
    if (!pc_valid_cap) throw trap_capstone_instruction_access_fault(insn.bits()); \
    bool pc_valid_type = (cap_pc.type == CAP_TYPE_LINEAR || cap_pc.type == CAP_TYPE_NONLINEAR); \
    if (!pc_valid_type) throw trap_capstone_instruction_access_fault(insn.bits()); \
    bool pc_valid_align = ((npc % insn_length(OPCODE)) == 0); \
    if (!pc_valid_align) throw trap_capstone_instruction_address_misaligned(insn.bits()); \
    bool pc_valid_perm = cap_pc.cap_perm_cmp(CAP_PERM_X, false); \
    if (!pc_valid_perm) throw trap_capstone_instruction_access_fault(insn.bits()); \
    bool pc_in_bounds = cap_pc.in_bound(insn_length(OPCODE)); \
    if (!pc_in_bounds) throw trap_capstone_instruction_access_fault(insn.bits()); \
  } \
  else { \
    if (next_pc_is_cap) throw trap_capstone_instruction_access_fault(insn.bits()); \
  }

reg_t rv32i_NAME(processor_t* p, insn_t insn, reg_t pc)
{
  #define xlen 32
  bool next_pc_is_cap = p->is_secure_world();
  reg_t npc = sext_xlen(pc + insn_length(OPCODE));
  #include "insns/NAME.h"
  trace_opcode(p, OPCODE, insn);
  #undef xlen
  return npc;
}

reg_t rv64i_NAME(processor_t* p, insn_t insn, reg_t pc)
{
  #define xlen 64
  bool next_pc_is_cap = p->is_secure_world();
  reg_t npc = sext_xlen(pc + insn_length(OPCODE));
  #include "insns/NAME.h"
  trace_opcode(p, OPCODE, insn);
  #undef xlen
  cap_pc_forward();
  return npc;
}

#undef CHECK_REG
#define CHECK_REG(reg) require((reg) < 16)

reg_t rv32e_NAME(processor_t* p, insn_t insn, reg_t pc)
{
  #define xlen 32
  bool next_pc_is_cap = p->is_secure_world();
  reg_t npc = sext_xlen(pc + insn_length(OPCODE));
  #include "insns/NAME.h"
  trace_opcode(p, OPCODE, insn);
  #undef xlen
  return npc;
}

reg_t rv64e_NAME(processor_t* p, insn_t insn, reg_t pc)
{
  #define xlen 64
  bool next_pc_is_cap = p->is_secure_world();
  reg_t npc = sext_xlen(pc + insn_length(OPCODE));
  #include "insns/NAME.h"
  trace_opcode(p, OPCODE, insn);
  #undef xlen
  cap_pc_forward();
  return npc;
}
