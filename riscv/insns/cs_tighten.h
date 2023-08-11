// #include "decode.h"
// #include "trap.h"

/*exception*/
if (!IS_CAP(insn_rs1))
	throw trap_capstone_unexpected_operand_type(insn.bits());
cap_type_t tmp_type = READ_CAP(insn_rs1).type;
if (tmp_type != CAP_TYPE_LINEAR && tmp_type != CAP_TYPE_NONLINEAR && tmp_type != CAP_TYPE_UNINITIALIZED)
	throw trap_capstone_unexpected_cap_type(insn.bits());
if (insn_ri_imm < 7 && !CAP_PERM_GTE(insn_rs1, static_cast<cap_perm_t>(insn_ri_imm)))
	throw trap_capstone_illegal_operand_value(insn.bits());
/*tighten the permission*/
MOVC(insn_rd, insn_rs1);
if (insn_ri_imm > 7) {
	READ_CAP(insn_rd).perm = CAP_PERM_NA;
}
else {
	READ_CAP(insn_rd).perm = static_cast<cap_perm_t>(insn_ri_imm);
}
