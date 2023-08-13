// #include "decode.h"
// #include "trap.h"

/*exception*/
if (!IS_CAP(insn_rs1))
	throw trap_capstone_unexpected_operand_type(insn.bits());
/*drop a capability*/
if (VALID_CAP(insn_rs1)) {
	DROP_CAP(READ_CAP_NODE(insn_rs1));
}
