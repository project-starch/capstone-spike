// #include "decode.h"
// #include "trap.h"

/*exception*/
if (!IS_CAP(insn_rs1))
	throw trap_capstone_unexpected_operand_type(insn.bits());
if (READ_CAP(insn_rs1).type != CAP_TYPE_LINEAR)
	throw trap_capstone_unexpected_cap_type(insn.bits());
if (!CAP_PERM_GTE(insn_rs1, CAP_PERM_RW))
	throw trap_capstone_insufficient_cap_perms(insn.bits());
if (READ_CAP(insn_rs1).end - READ_CAP(insn_rs1).base < CLENBYTES * 33)
  throw trap_capstone_illegal_operand_value(insn.bits());
if (READ_CAP(insn_rs1).base % CLENBYTES != 0)
  throw trap_capstone_illegal_operand_value(insn.bits());
/*seal a linear capability*/
MOVC(insn_rd, insn_rs1);
READ_CAP(insn_rd).type = CAP_TYPE_SEALED;
READ_CAP(insn_rd).async = CAP_ASYNC_SYNC;
