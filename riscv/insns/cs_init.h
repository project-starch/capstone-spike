// #include "decode.h"
// #include "trap.h"

/*exception*/
if (!IS_CAP(insn_rs1) || !IS_DATA(insn_rs2))
	throw trap_capstone_unexpected_operand_type(insn.bits());
if (READ_CAP(insn_rs1).type != CAP_TYPE_UNINITIALIZED)
	throw trap_capstone_unexpected_cap_type(insn.bits());
if (READ_CAP(insn_rs1).cursor != READ_CAP(insn_rs1).end)
	throw trap_capstone_illegal_operand_value(insn.bits());
/*init an uninitialized capability*/
READ_CAP(insn_rs1).type = CAP_TYPE_LINEAR;
READ_CAP(insn_rs1).cursor = READ_CAP(insn_rs1).base + RS2;
MOVC(insn_rd, insn_rs1);
