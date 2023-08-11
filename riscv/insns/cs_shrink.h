// #include "decode.h"
// #include "trap.h"

/*exception*/
if (!IS_CAP(insn_rd) || !IS_DATA(insn_rs1) || !IS_DATA(insn_rs2))
  throw trap_capstone_unexpected_operand_type(insn.bits());
cap_type_t tmp_type = READ_CAP(insn_rd).type;
if (tmp_type != CAP_TYPE_LINEAR && tmp_type != CAP_TYPE_NONLINEAR && tmp_type != CAP_TYPE_UNINITIALIZED)
	throw trap_capstone_unexpected_cap_type(insn.bits());
if (RS1 >= RS2 || (RS1 < READ_CAP(insn_rd).base || RS2 > READ_CAP(insn_rd).end))
	throw trap_capstone_illegal_operand_value(insn.bits());

/*shrink the bound of x[rd]*/
READ_CAP(insn_rd).base = RS1;
READ_CAP(insn_rd).end = RS2;

if (READ_CAP(insn_rd).cursor < READ_CAP(insn_rd).base)
	READ_CAP(insn_rd).cursor = READ_CAP(insn_rd).base;
if (READ_CAP(insn_rd).cursor > READ_CAP(insn_rd).end)
	READ_CAP(insn_rd).cursor = READ_CAP(insn_rd).end;
