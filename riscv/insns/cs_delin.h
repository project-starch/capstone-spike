// #include "decode.h"
// #include "trap.h"

/*exception*/
if (!IS_CAP(insn_rd))
	throw trap_capstone_unexpected_operand_type(insn.bits());
if (READ_CAP(insn_rd).type != CAP_TYPE_LINEAR)
	throw trap_capstone_unexpected_cap_type(insn.bits());
/*delinearization*/
if (insn_rd != 0) {
	READ_CAP(insn_rd).type = CAP_TYPE_NONLINEAR;
	DELINEAR(READ_CAP_NODE(insn_rd));
}
