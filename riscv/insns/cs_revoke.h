// #include "decode.h"
// #include "trap.h"

REVOKE_CAP(Rs1);
/*exception*/
if (!IS_CAP(insn_rs1))
	throw trap_capstone_unexpected_operand_type(insn.bits());
if (!VALID_CAP(insn_rs1))
	throw trap_capstone_invalid_capability(insn.bits());
if (READ_CAP(insn_rs1).type != CAP_TYPE_REVOCATION)
		throw trap_capstone_unexpected_cap_type(insn.bits());
/*revocation*/
if (RT_REVOKE(READ_CAP_NODE(insn_rs1)) || !CAP_PERM_GTE(insn_rs1, CAP_PERM_W)) {
	READ_CAP(insn_rs1).type = CAP_TYPE_LINEAR;
}
else {
	READ_CAP(insn_rs1).type = CAP_TYPE_UNINITIALIZED;
	READ_CAP(insn_rs1).cursor = READ_CAP(insn_rs1).base;
}
