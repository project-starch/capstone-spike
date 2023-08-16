// See LICENSE for license details.

#include "insn_template.h"
#include "insn_macros.h"

#define cap_pc_forward(update_cursor) \
  if (update_cursor && p->is_secure_world()) { \
    cap64_t cap_pc = p->get_state()->cap_pc; \
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
    /*no need to set state.pc here, it's set by the caller*/ \
    p->get_state()->cap_pc.cursor = npc; \
  }

reg_t rv32i_NAME(processor_t* p, insn_t insn, reg_t pc)
{
  #define xlen 32
  reg_t npc = sext_xlen(pc + insn_length(OPCODE));
  #include "insns/NAME.h"
  trace_opcode(p, OPCODE, insn);
  #undef xlen
  return npc;
}

reg_t rv64i_NAME(processor_t* p, insn_t insn, reg_t pc)
{
  #define xlen 64
  reg_t npc = sext_xlen(pc + insn_length(OPCODE));
  bool update_cursor = true;
  #include "insns/NAME.h"
  trace_opcode(p, OPCODE, insn);
  #undef xlen
  cap_pc_forward(update_cursor);
  return npc;
}

#undef CHECK_REG
#define CHECK_REG(reg) require((reg) < 16)

reg_t rv32e_NAME(processor_t* p, insn_t insn, reg_t pc)
{
  #define xlen 32
  reg_t npc = sext_xlen(pc + insn_length(OPCODE));
  #include "insns/NAME.h"
  trace_opcode(p, OPCODE, insn);
  #undef xlen
  return npc;
}

reg_t rv64e_NAME(processor_t* p, insn_t insn, reg_t pc)
{
  #define xlen 64
  reg_t npc = sext_xlen(pc + insn_length(OPCODE));
  bool update_cursor = true;
  #include "insns/NAME.h"
  trace_opcode(p, OPCODE, insn);
  #undef xlen
  cap_pc_forward(update_cursor);
  return npc;
}
