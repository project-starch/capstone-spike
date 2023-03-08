// See LICENSE for license details.

#include "insn_template.h"
#include "insn_macros.h"

#define check_pc() \
  if (p->get_state()->world == WORLD_SECURE) { \
    p->get_state()->cap_pc.cursor = npc; \
    cap_pc = p->get_state()->cap_pc; \
    assert(cap_pc.inbound() && p->valid_cap(cap_pc)); \
  }

reg_t rv32i_NAME(processor_t* p, insn_t insn, reg_t pc)
{
  #define xlen 32
  reg_t npc = sext_xlen(pc + insn_length(OPCODE));
  #include "insns/NAME.h"
  trace_opcode(p, OPCODE, insn);
  #undef xlen
  check_pc();
  return npc;
}

reg_t rv64i_NAME(processor_t* p, insn_t insn, reg_t pc)
{
  #define xlen 64
  reg_t npc = sext_xlen(pc + insn_length(OPCODE));
  #include "insns/NAME.h"
  trace_opcode(p, OPCODE, insn);
  #undef xlen
  check_pc();
  return npc;
}

#undef CHECK_REG
#define CHECK_REG(reg) require((reg) < 16 && STATE.XPR.is_data(reg))

reg_t rv32e_NAME(processor_t* p, insn_t insn, reg_t pc)
{
  #define xlen 32
  reg_t npc = sext_xlen(pc + insn_length(OPCODE));
  #include "insns/NAME.h"
  trace_opcode(p, OPCODE, insn);
  #undef xlen
  check_pc();
  return npc;
}

reg_t rv64e_NAME(processor_t* p, insn_t insn, reg_t pc)
{
  #define xlen 64
  reg_t npc = sext_xlen(pc + insn_length(OPCODE));
  #include "insns/NAME.h"
  trace_opcode(p, OPCODE, insn);
  #undef xlen
  check_pc();
  return npc;
}
