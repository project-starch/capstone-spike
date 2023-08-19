// #include "decode.h"
// #include "trap.h"

/*exception*/
if (!IS_CAP(insn_rs1) || !IS_DATA(insn_rs2))
	throw trap_capstone_unexpected_operand_type(insn.bits());
if (READ_CAP(insn_rs1).type == CAP_TYPE_UNINITIALIZED || READ_CAP(insn_rs1).type == CAP_TYPE_SEALED)
  throw trap_capstone_unexpected_cap_type(insn.bits());
/*set current cursor*/
uint64_t val = RS2;
MOVC(insn_rd, insn_rs1);
if (NOT_ZERO_REG(insn_rd)) {
  READ_CAP(insn_rd).cursor = val;
}
