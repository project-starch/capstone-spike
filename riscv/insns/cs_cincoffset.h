// #include "decode.h"
// #include "trap.h"

/*exception*/
if (!IS_CAP(insn_rs1) || !IS_DATA(insn_rs2))
	throw trap_capstone_unexpected_operand_type(insn.bits());
cap_type_t tmp_type = READ_CAP(insn_rs1).type;
if (tmp_type == CAP_TYPE_UNINITIALIZED || tmp_type == CAP_TYPE_SEALED)
  throw trap_capstone_unexpected_cap_type(insn.bits());
/*increment cursor*/
uint64_t val = RS2;
MOVC(insn_rd, insn_rs1);
if (NOT_ZERO_REG(insn_rd)) {
  READ_CAP(insn_rd).cursor += val;
}
